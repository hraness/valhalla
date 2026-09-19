#![cfg(unix)]
//! The `rooms submit` and `rooms pending` commands: scriptable signed
//! submissions into a live validator's intake, with marker resolution
//! reported back through the replica. This is the noninteractive half of
//! the room-directory surface — the same signing assembly the TUI runs.

#[cfg(all(
    feature = "experimental-rooms",
    not(feature = "experimental-rooms-tui")
))]
#[test]
fn submit_command_reports_missing_feature() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "rooms",
            "submit",
            "unused",
            "unused",
            "00000000000000000000000000000047",
            "unused",
            "create",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("experimental-rooms-tui"));
}

#[cfg(feature = "experimental-rooms-tui")]
mod enabled {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, Command, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use serde_json::Value;

    const REALM: &str = "00000000000000000000000000000047";
    const DIRECTORY: &str = "9ba57514cf3136a4572dadce837da2262d84bb67a7a9fbcaf8bf3934f3c53498";
    const CAPTURE: u64 = 262_144;
    const NOW: &str = "10";

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "vhalla-cli-submit-{:032x}",
                u128::from_be_bytes(nonce)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    struct Node {
        child: Child,
        stdout: PathBuf,
        stderr: PathBuf,
    }
    impl Node {
        /// The node's first stdout line announces the bound listener.
        fn wait_listening(&self) {
            wait_for(Duration::from_secs(30), "node startup", || {
                fs::read_to_string(&self.stdout)
                    .map(|s| s.contains("\"listening\""))
                    .unwrap_or(false)
            });
        }
    }
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn path(path: &Path) -> &str {
        path.to_str().unwrap()
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn field(value: &Value, name: &str) -> String {
        value
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing string field {name}: {value}"))
            .to_owned()
    }
    fn committed(home: &Path, height: u64) -> bool {
        home.join(format!("app/journal/heights/{height:016x}"))
            .exists()
    }
    fn wait_for(deadline: Duration, what: &str, ready: impl Fn() -> bool) {
        let started = Instant::now();
        while !ready() {
            assert!(started.elapsed() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn run(command: &str, args: &[&str]) -> Output {
        run_input(command, args, None)
    }

    fn run_input(command: &str, args: &[&str], input: Option<&[u8]>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .arg(command)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |pipe: Box<dyn Read + Send>| {
            thread::spawn(move || {
                let mut raw = Vec::new();
                pipe.take(CAPTURE + 1).read_to_end(&mut raw).unwrap();
                raw
            })
        };
        let out = read(Box::new(stdout));
        let err = read(Box::new(stderr));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(15) {
                child.kill().unwrap();
                child.wait().unwrap();
                let _ = out.join();
                let _ = err.join();
                panic!("{command} exceeded bounded process deadline");
            }
            thread::sleep(Duration::from_millis(5));
        };
        Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    }
    fn ok(command: &str, args: &[&str]) -> Value {
        let output = run(command, args);
        assert!(
            output.status.success(),
            "{command} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn fails(command: &str, args: &[&str]) -> String {
        let output = run(command, args);
        assert!(
            !output.status.success(),
            "{command} {args:?} unexpectedly succeeded"
        );
        assert!(output.stdout.is_empty());
        String::from_utf8(output.stderr).unwrap()
    }

    /// One social account: its own store and owner key directory.
    struct Social {
        store: PathBuf,
        key: PathBuf,
        owner: String,
    }
    impl Social {
        fn init(temp: &Temp, label: &str) -> Self {
            let store = temp.path(&format!("{label}-store"));
            let key = temp.path(&format!("{label}-key"));
            let output = ok(
                "social",
                &["init", path(&store), REALM, path(&key), "--now", NOW],
            );
            Self {
                store,
                key,
                owner: field(&output, "owner"),
            }
        }
        fn export(&self, file: &Path) {
            ok(
                "social",
                &["export", path(&self.store), REALM, path(file), "--now", NOW],
            );
        }
        fn import(&self, file: &Path) {
            ok(
                "social",
                &["import", path(&self.store), REALM, path(file), "--now", NOW],
            );
        }
        fn react_into(&self, store: &Path, post: &str) {
            ok(
                "social",
                &[
                    "react",
                    path(store),
                    REALM,
                    path(&self.key),
                    &format!("owner:{}", self.owner),
                    post,
                    "up",
                    post,
                    "--now",
                    NOW,
                ],
            );
        }
    }

    /// alice funded by one eligible source's up-reaction, plus an enrolled
    /// agent — the same shape the `rooms create` tests build.
    struct World {
        alice: Social,
        agent_key_dir: PathBuf,
        agent: String,
        snapshot: PathBuf,
        source_owner: String,
    }
    fn world(temp: &Temp) -> World {
        let alice = Social::init(temp, "alice");
        let post = field(
            &ok(
                "social",
                &[
                    "post",
                    path(&alice.store),
                    REALM,
                    path(&alice.key),
                    &format!("owner:{}", alice.owner),
                    "profile",
                    "original work",
                    "--now",
                    NOW,
                ],
            ),
            "event",
        );
        let source = Social::init(temp, "source");
        let snap = temp.path("source.snap");
        source.export(&snap);
        alice.import(&snap);
        source.react_into(&alice.store, &post);
        let agent_key_dir = temp.path("agent-key");
        let enroll = ok(
            "social",
            &[
                "enroll",
                path(&alice.store),
                REALM,
                path(&alice.key),
                &alice.owner,
                path(&agent_key_dir),
                "all",
                "1000",
                "--now",
                NOW,
            ],
        );
        // The evidence drop: alice's whole archive carries the post, the
        // source's owner chain and the up-reaction the award needs.
        let snapshot = temp.path("alice.snap");
        alice.export(&snapshot);
        World {
            alice,
            agent_key_dir,
            agent: field(&enroll, "agent"),
            snapshot,
            source_owner: source.owner,
        }
    }

    fn config(temp: &Temp, source_owner: &str) -> PathBuf {
        let key = vhalla_rooms_node::PrivateKey::from([9; 32]);
        let config = serde_json::json!({
            "node_key": hex(&[9; 32]),
            "port": 0,
            "peers": [],
            "validators": [{
                "from": 1,
                "key": hex(key.public_key().as_bytes()),
                "power": 1,
            }],
            "realm": REALM,
            "directory": DIRECTORY,
            "policy": {
                "base_cost": 1,
                "window_seconds": 60,
                "max_in_window": 4,
                "support_epoch_seconds": 60,
                "max_lifetime_rooms": 8,
            },
            "eligible": [source_owner],
            "limits": {
                "records": 1024,
                "control_reserve": 128,
                "data_per_owner": 128,
                "data_per_writer": 64,
                "control_per_owner": 32,
                "pending": 128,
                "pending_per_signer": 8,
            },
        });
        let path = temp.path("node.json");
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        path
    }

    fn spawn_node(temp: &Temp, social: &Path, home: &Path, config: &Path) -> Node {
        fs::create_dir_all(home.join("intake")).unwrap();
        let label = home.file_name().unwrap().to_str().unwrap();
        let stdout = temp.path(&format!("{label}.stdout"));
        let stderr = temp.path(&format!("{label}.stderr"));
        let child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node",
                path(social),
                path(home),
                REALM,
                "--config",
                path(config),
            ])
            .stdout(Stdio::from(fs::File::create(&stdout).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Node {
            child,
            stdout,
            stderr,
        }
    }

    fn submit(
        social: &Path,
        replica: &Path,
        home: &Path,
        config: &Path,
        kind_args: &[&str],
    ) -> Value {
        let mut args = vec!["submit", path(social), path(replica), REALM, path(home)];
        args.extend_from_slice(kind_args);
        args.extend(["--config", path(config), "--now", NOW]);
        ok("rooms", &args)
    }

    fn pending(social: &Path, replica: &Path, home: &Path, config: &Path) -> Value {
        ok(
            "rooms",
            &[
                "pending",
                path(social),
                path(replica),
                REALM,
                path(home),
                "--config",
                path(config),
            ],
        )
    }

    /// The marker's last reported state under `pending`, or `missing`.
    fn marker_state(pending: &Value, marker: &str) -> String {
        pending["pending"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["marker"].as_str() == Some(marker))
            .map(|p| field(p, "state"))
            .unwrap_or_else(|| "missing".into())
    }

    /// Rehearse the friends-and-family runbook from empty directories. All
    /// identity, social, network and room state is made by the released CLI
    /// entry points, not by seeding a funded registry or a fixture batch.
    /// Four equal-power members are configured; three live loopback nodes
    /// decide with the fourth absent. This is not overlay qualification.
    #[test]
    fn clean_state_four_member_onboarding_rehearsal() {
        let temp = Temp::new();

        // A standalone paired-chat identity is separate from social init,
        // which creates its own owner identity and requires a fresh path.
        let chat_key = temp.path("paired-chat-key");
        let chat = run("identity", &["init", path(&chat_key)]);
        assert!(chat.status.success());
        assert_eq!(
            chat.stdout,
            run("identity", &["show", path(&chat_key)]).stdout
        );
        let members: Vec<Social> = ["alice", "bob", "carol", "dave"]
            .into_iter()
            .map(|name| Social::init(&temp, name))
            .collect();
        let alice = &members[0];
        let bob = &members[1];
        let backup = run("identity", &["backup", path(&alice.key)]);
        assert!(backup.status.success());
        let backup_path = temp.path("alice-key.backup");
        let mut backup_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&backup_path)
            .unwrap();
        backup_file.write_all(&backup.stdout).unwrap();
        backup_file.sync_all().unwrap();
        assert_eq!(
            fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let restored = temp.path("alice-key-restored");
        let backup_text = std::str::from_utf8(&backup.stdout).unwrap();
        let mnemonic = backup_text
            .lines()
            .find_map(|line| line.strip_prefix("mnemonic "))
            .expect("backup contains the mnemonic line");
        let restore = run_input(
            "identity",
            &["restore", path(&restored)],
            Some(mnemonic.as_bytes()),
        );
        assert!(
            restore.status.success(),
            "{}",
            String::from_utf8_lossy(&restore.stderr)
        );
        assert_eq!(
            run("identity", &["show", path(&restored)]).stdout,
            run("identity", &["show", path(&alice.key)]).stdout
        );

        let agent_key = temp.path("alice-agent-key");
        let enrollment = ok(
            "social",
            &[
                "enroll",
                path(&alice.store),
                REALM,
                path(&alice.key),
                &alice.owner,
                path(&agent_key),
                "all",
                "1000",
                "--now",
                NOW,
            ],
        );
        let agent = field(&enrollment, "agent");
        let actor = format!("agent:{agent}:{}", field(&enrollment, "grant"));
        let post = ok(
            "social",
            &[
                "post",
                path(&alice.store),
                REALM,
                path(&agent_key),
                &actor,
                "profile",
                "A reproducible simulation for our private group.",
                "--now",
                NOW,
            ],
        );
        assert_eq!(post["state"], "provisional");
        let post_id = field(&post, "event");
        ok(
            "social",
            &[
                "seal",
                path(&alice.store),
                REALM,
                path(&alice.key),
                &alice.owner,
                &post_id,
                "--now",
                NOW,
            ],
        );

        // Bob signs in his own store, after importing Alice's sealed work.
        let alice_snapshot = temp.path("alice-work.snapshot");
        alice.export(&alice_snapshot);
        bob.import(&alice_snapshot);
        bob.react_into(&bob.store, &post_id);
        for (index, member) in members.iter().enumerate().skip(1) {
            let snapshot = temp.path(&format!("member-{index}.snapshot"));
            member.export(&snapshot);
            alice.import(&snapshot);
        }
        let genesis_snapshot = temp.path("genesis.snapshot");
        alice.export(&genesis_snapshot);
        for member in &members {
            member.import(&genesis_snapshot);
        }
        // Nodes and fresh replicas always bootstrap from a dedicated frozen
        // archive. Each owner's working social store can evolve independently.
        let genesis_stores: Vec<PathBuf> = (0..4)
            .map(|index| {
                let store = temp.path(&format!("member-{index}-genesis"));
                ok(
                    "social",
                    &["restore-new", path(&store), REALM, path(&genesis_snapshot)],
                );
                store
            })
            .collect();

        // Only these public keys and endpoints are shared between members.
        let keys: Vec<Value> = (0..4).map(|_| ok("rooms", &["keygen"])).collect();
        let validators = keys
            .iter()
            .map(|key| format!("1:{}:1", field(key, "public_key")))
            .collect::<Vec<_>>()
            .join(",");
        let network_path = temp.path("network.json");
        let network = ok(
            "rooms",
            &[
                "network-init",
                path(&network_path),
                "--realm",
                REALM,
                "--directory",
                DIRECTORY,
                "--policy",
                "1,60,4,60,8",
                "--validators",
                &validators,
                "--eligible",
                &bob.owner,
            ],
        );
        assert_eq!(network["quorum_power"], 3);
        assert_eq!(network["absent_power_tolerated"], 1);

        // Reserve distinct ephemeral ports until the complete configuration
        // has been checked, then release them immediately before startup.
        let reservations: Vec<TcpListener> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports: Vec<u16> = reservations
            .iter()
            .map(|listener| listener.local_addr().unwrap().port())
            .collect();
        let homes: Vec<PathBuf> = (0..4)
            .map(|index| temp.path(&format!("member-{index}-node")))
            .collect();
        let configs: Vec<PathBuf> = homes.iter().map(|home| home.join("node.json")).collect();
        let mut archive = None;
        for (index, genesis_store) in genesis_stores.iter().enumerate() {
            let peers = keys
                .iter()
                .enumerate()
                .filter(|(peer, _)| *peer != index)
                .map(|(peer, key)| {
                    format!("{}@127.0.0.1:{}", field(key, "public_key"), ports[peer])
                })
                .collect::<Vec<_>>()
                .join(",");
            let initialized = ok(
                "rooms",
                &[
                    "node-init",
                    path(&homes[index]),
                    "--network",
                    path(&network_path),
                    "--node-key",
                    &field(&keys[index], "node_key"),
                    "--port",
                    &ports[index].to_string(),
                    "--listen",
                    "127.0.0.1",
                    "--peers",
                    &peers,
                    "--peers-only",
                    "true",
                ],
            );
            assert_eq!(initialized["node_key_votes_from"], 1);
            let checked = ok(
                "rooms",
                &[
                    "node-check",
                    path(genesis_store),
                    path(&homes[index]),
                    REALM,
                    "--config",
                    path(&configs[index]),
                ],
            );
            assert_eq!(checked["genesis"], network["genesis"]);
            assert_eq!(checked["pinned_peers"], 3);
            assert_eq!(checked["peers_only"], true);
            assert!(checked["warnings"].as_array().unwrap().is_empty());
            assert_eq!(checked["validator_sets"][0]["quorum_power"], 3);
            assert_eq!(checked["validator_sets"][0]["absent_power_tolerated"], 1);
            let root = field(&checked, "archive");
            assert_eq!(archive.get_or_insert_with(|| root.clone()), &root);
        }
        drop(reservations);
        let nodes: Vec<Node> = (0..3)
            .map(|index| {
                spawn_node(
                    &temp,
                    &genesis_stores[index],
                    &homes[index],
                    &configs[index],
                )
            })
            .collect();
        for node in &nodes {
            node.wait_listening();
        }
        let replica = temp.path("alice-replica");
        let created = submit(
            &genesis_stores[0],
            &replica,
            &homes[0],
            &configs[0],
            &[
                "create",
                path(&alice.key),
                path(&agent_key),
                &alice.owner,
                &agent,
                "work-hall",
                "100",
                "A private group's room directory entry.",
                path(&genesis_snapshot),
            ],
        );
        wait_for(
            Duration::from_secs(90),
            "three-member quorum create",
            || homes[..3].iter().all(|home| committed(home, 1)),
        );
        assert!(!committed(&homes[3], 1), "the absent member never started");
        let report = pending(&genesis_stores[0], &replica, &homes[0], &configs[0]);
        assert_eq!(
            marker_state(&report, &field(&created, "marker")),
            "committed"
        );

        // Normal later owner activity changes the working archive. A brand
        // new read replica must still replay the original network genesis.
        ok(
            "social",
            &[
                "post",
                path(&alice.store),
                REALM,
                path(&alice.key),
                &format!("owner:{}", alice.owner),
                "profile",
                "Later owner work.",
                "--now",
                NOW,
            ],
        );
        let later_owner = temp.path("later-owner.snapshot");
        alice.export(&later_owner);
        assert_ne!(
            fs::read(&later_owner).unwrap(),
            fs::read(&genesis_snapshot).unwrap()
        );
        for (index, store) in genesis_stores.iter().enumerate() {
            let retained = temp.path(&format!("retained-genesis-{index}.snapshot"));
            ok("social", &["export", path(store), REALM, path(&retained)]);
            assert_eq!(
                fs::read(&retained).unwrap(),
                fs::read(&genesis_snapshot).unwrap()
            );
        }
        for index in 0..3 {
            let replica = temp.path(&format!("status-{index}"));
            let report = ok(
                "rooms",
                &[
                    "status",
                    path(&genesis_stores[index]),
                    path(&replica),
                    REALM,
                    path(&homes[index]),
                    "--config",
                    path(&configs[index]),
                ],
            );
            assert_eq!(report["height"], 1);
            assert_eq!(report["quorum"]["threshold"], 3);
            assert_eq!(report["rooms"][0]["slug"], "work-hall");
            assert_eq!(report["rooms"][0]["owner"], alice.owner);
        }
        drop(nodes);

        // Rehearse a future whole-set schedule replacing Dave with Eve.
        // Existing peer lists deliberately stay unchanged: this tests the
        // schedule and fresh genesis bootstrap, not live transport rollout.
        let updated_path = temp.path("network-v2.json");
        let eve = ok("rooms", &["keygen"]);
        let replacement = keys[..3]
            .iter()
            .chain(std::iter::once(&eve))
            .map(|key| format!("{}:1", field(key, "public_key")))
            .collect::<Vec<_>>()
            .join(",");
        let extension = ok(
            "rooms",
            &[
                "network-extend",
                path(&network_path),
                path(&updated_path),
                "--from",
                "10",
                "--validators",
                &replacement,
            ],
        );
        assert_eq!(extension["activation_from"], 10);
        for (index, home) in homes.iter().enumerate() {
            let before: Value =
                serde_json::from_slice(&fs::read(&configs[index]).unwrap()).unwrap();
            let updated = ok(
                "rooms",
                &["node-update", path(home), "--network", path(&updated_path)],
            );
            assert_eq!(updated["committed"], if index < 3 { 1 } else { 0 });
            let after: Value = serde_json::from_slice(&fs::read(&configs[index]).unwrap()).unwrap();
            for field in ["node_key", "port", "listen", "peers", "peers_only"] {
                assert!(before[field] == after[field], "local field {field} changed");
            }
            let checked = ok(
                "rooms",
                &[
                    "node-check",
                    path(&genesis_stores[index]),
                    path(home),
                    REALM,
                    "--config",
                    path(&configs[index]),
                ],
            );
            assert_eq!(checked["genesis"], extension["genesis"]);
            assert_eq!(checked["validator_sets"].as_array().unwrap().len(), 2);
            assert_eq!(checked["validator_sets"][1]["from"], 10);
            assert_eq!(checked["validator_sets"][1]["quorum_power"], 3);
        }

        // An actual newcomer can start from only the shared signed snapshot;
        // social init would add an unwanted owner record and change genesis.
        let eve_store = temp.path("eve-social");
        let restored = ok(
            "social",
            &[
                "restore-new",
                path(&eve_store),
                REALM,
                path(&genesis_snapshot),
            ],
        );
        assert_eq!(field(&restored, "root"), archive.unwrap());
        let eve_snapshot = temp.path("eve.snapshot");
        ok(
            "social",
            &["export", path(&eve_store), REALM, path(&eve_snapshot)],
        );
        assert_eq!(
            fs::read(&eve_snapshot).unwrap(),
            fs::read(&genesis_snapshot).unwrap()
        );
        let eve_home = temp.path("eve-node");
        let eve_config = eve_home.join("node.json");
        let eve_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let eve_port = eve_listener.local_addr().unwrap().port().to_string();
        let eve_peers = keys[..3]
            .iter()
            .enumerate()
            .map(|(peer, key)| format!("{}@127.0.0.1:{}", field(key, "public_key"), ports[peer]))
            .collect::<Vec<_>>()
            .join(",");
        ok(
            "rooms",
            &[
                "node-init",
                path(&eve_home),
                "--network",
                path(&updated_path),
                "--node-key",
                &field(&eve, "node_key"),
                "--port",
                &eve_port,
                "--listen",
                "127.0.0.1",
                "--peers",
                &eve_peers,
                "--peers-only",
                "true",
            ],
        );
        let checked = ok(
            "rooms",
            &[
                "node-check",
                path(&eve_store),
                path(&eve_home),
                REALM,
                "--config",
                path(&eve_config),
            ],
        );
        assert_eq!(checked["genesis"], extension["genesis"]);
        assert_eq!(checked["archive"], restored["root"]);
        assert_eq!(checked["node_key_votes_from"], 10);
        assert!(checked["warnings"].as_array().unwrap().is_empty());
    }

    /// Signed create, describe and archive drops against a live validator —
    /// the full scriptable journey from evidence to committed resolution.
    #[test]
    fn submit_signs_drops_and_resolves_against_a_live_node() {
        let temp = Temp::new();
        let world = world(&temp);
        let config = config(&temp, &world.source_owner);
        let home = temp.path("node-home");
        let replica = temp.path("replica");
        let mut node = spawn_node(&temp, &world.alice.store, &home, &config);
        node.wait_listening();

        // First create: no room-control chain yet — the body carries the
        // grant; alice's snapshot is the award evidence for the charge.
        let created = submit(
            &world.alice.store,
            &replica,
            &home,
            &config,
            &[
                "create",
                path(&world.alice.key),
                path(&world.agent_key_dir),
                &world.alice.owner,
                &world.agent,
                "signal-hall",
                "100",
                "a committed room",
                path(&world.snapshot),
            ],
        );
        let marker = field(&created, "marker");
        wait_for(Duration::from_secs(90), "create commit", || {
            committed(&home, 1)
        });
        let report = pending(&world.alice.store, &replica, &home, &config);
        assert_eq!(report["height"], 1);
        assert_eq!(marker_state(&report, &marker), "committed");

        // Describe: an owner update against the committed head.
        let described = submit(
            &world.alice.store,
            &replica,
            &home,
            &config,
            &[
                "describe",
                path(&world.alice.key),
                "signal-hall",
                "200",
                "the renamed room",
            ],
        );
        wait_for(Duration::from_secs(90), "describe commit", || {
            committed(&home, 2)
        });
        let report = pending(&world.alice.store, &replica, &home, &config);
        assert_eq!(
            marker_state(&report, &field(&described, "marker")),
            "committed"
        );

        // Archive: the owner's last word on the room.
        let archived = submit(
            &world.alice.store,
            &replica,
            &home,
            &config,
            &["archive", path(&world.alice.key), "signal-hall"],
        );
        wait_for(Duration::from_secs(90), "archive commit", || {
            committed(&home, 3)
        });
        let report = pending(&world.alice.store, &replica, &home, &config);
        assert_eq!(
            marker_state(&report, &field(&archived, "marker")),
            "committed"
        );

        // Clean stop, no panic.
        Command::new("kill")
            .args(["-INT", &node.child.id().to_string()])
            .status()
            .unwrap();
        assert!(node.child.wait().unwrap().success());
        let mut err = String::new();
        let _ = fs::File::open(&node.stderr)
            .unwrap()
            .read_to_string(&mut err);
        assert!(!err.contains("panic"), "node stderr: {err}");
    }

    /// Rejection paths that must fail before any intake write.
    #[test]
    fn submit_rejects_bad_evidence_foreign_updates_and_bad_args() {
        let temp = Temp::new();
        let world = world(&temp);
        let config = config(&temp, &world.source_owner);
        let home = temp.path("node-home");
        let replica = temp.path("replica");
        fs::create_dir_all(home.join("intake")).unwrap();

        // A truncated snapshot is refused at the CLI boundary.
        let raw = fs::read(&world.snapshot).unwrap();
        let truncated = temp.path("truncated.snap");
        fs::write(&truncated, &raw[..raw.len() - 5]).unwrap();
        let err = fails(
            "rooms",
            &[
                "submit",
                path(&world.alice.store),
                path(&replica),
                REALM,
                path(&home),
                "create",
                path(&world.alice.key),
                path(&world.agent_key_dir),
                &world.alice.owner,
                &world.agent,
                "signal-hall",
                "100",
                "a room",
                path(&truncated),
                "--config",
                path(&config),
                "--now",
                NOW,
            ],
        );
        assert!(err.contains("truncated") || err.contains("record"), "{err}");

        // Garbage evidence is refused the same way.
        let garbage = temp.path("garbage.rec");
        fs::write(&garbage, b"not a record").unwrap();
        let err = fails(
            "rooms",
            &[
                "submit",
                path(&world.alice.store),
                path(&replica),
                REALM,
                path(&home),
                "create",
                path(&world.alice.key),
                path(&world.agent_key_dir),
                &world.alice.owner,
                &world.agent,
                "signal-hall",
                "100",
                "a room",
                path(&garbage),
                "--config",
                path(&config),
                "--now",
                NOW,
            ],
        );
        assert!(err.contains("not a verified social record"), "{err}");

        // No evidence and no credit: refused before signing.
        let err = fails(
            "rooms",
            &[
                "submit",
                path(&world.alice.store),
                path(&replica),
                REALM,
                path(&home),
                "create",
                path(&world.alice.key),
                path(&world.agent_key_dir),
                &world.alice.owner,
                &world.agent,
                "signal-hall",
                "100",
                "a room",
                "--config",
                path(&config),
                "--now",
                NOW,
            ],
        );
        assert!(err.contains("below the quoted charge"), "{err}");

        // A describe against a room the replica has never committed.
        let err = fails(
            "rooms",
            &[
                "submit",
                path(&world.alice.store),
                path(&replica),
                REALM,
                path(&home),
                "describe",
                path(&world.alice.key),
                "absent-room",
                "200",
                "nothing",
                "--config",
                path(&config),
                "--now",
                NOW,
            ],
        );
        assert!(err.contains("no committed room"), "{err}");

        // Argument and option surface.
        let err = fails(
            "rooms",
            &["submit", path(&world.alice.store), path(&replica), REALM],
        );
        assert!(
            err.contains("--config") || err.contains("NODE_HOME"),
            "{err}"
        );
        assert!(
            !home.join("intake").read_dir().unwrap().next().is_some(),
            "rejected submissions must not write intake drops"
        );
    }
}
