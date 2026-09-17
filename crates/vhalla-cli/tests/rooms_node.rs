#![cfg(unix)]
//! The `rooms node` service: a real CLI subprocess hosting a room-consensus
//! validator — intake-drop submissions, journal-gated commits, clean stop.

#[cfg(all(
    feature = "experimental-rooms",
    not(feature = "experimental-rooms-node")
))]
#[test]
fn node_command_reports_missing_feature() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "rooms",
            "node",
            "unused",
            "unused",
            "00000000000000000000000000000047",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("experimental-rooms-node"));
}

#[cfg(feature = "experimental-rooms-node")]
mod enabled {
    use std::{
        fs,
        io::Read,
        os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use vhalla_rooms_consensus::fixture;
    use vhalla_rooms_node::PrivateKey;
    use vhalla_social_store::Store as SocialStore;

    const REALM_HEX: &str = "0000000000000000000000000000004d"; // fixture REALM = 77

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path = std::env::temp_dir().join(format!(
                "vhalla-cli-node-{:032x}",
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

    /// A running node subprocess that is always reaped before the test ends.
    struct Node {
        child: Child,
        stdout: PathBuf,
        stderr: PathBuf,
    }
    impl Drop for Node {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "hex must have even length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `rooms keygen` prints a fresh consensus seed/public pair; the
    /// public key must be exactly the seed's Ed25519 verification key so
    /// the printed values slot straight into a node config.
    #[test]
    fn keygen_prints_a_consensus_key_pair() {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(["rooms", "keygen"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        let node_key = value["node_key"].as_str().unwrap();
        let public_key = value["public_key"].as_str().unwrap();
        assert_eq!(node_key.len(), 64);
        assert_eq!(public_key.len(), 64);

        let seed: [u8; 32] = unhex(node_key).try_into().unwrap();
        let derived = PrivateKey::from(seed).public_key();
        assert_eq!(hex(derived.as_bytes()), public_key);
    }

    /// `home/app/journal/heights/<016x>` is the durable commit marker.
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

    /// One validator, funded intake submissions, committed heights, SIGINT stop.
    #[test]
    fn node_service_commits_intake_batches_and_stops_clean() {
        let temp = Temp::new();
        let plan = fixture::plan(2, 4, 4);

        // Seed the social store with the genesis snapshot: the node's own
        // genesis archive is read from this committed state.
        let social_dir = temp.path("social-store");
        {
            let mut social =
                SocialStore::create(&social_dir, plan.genesis.realm, plan.genesis.limits).unwrap();
            social
                .commit(plan.genesis.archive.clone(), social.pin())
                .unwrap();
        }

        let key = PrivateKey::from([7; 32]);
        let config = serde_json::json!({
            "node_key": hex(&[7; 32]),
            // Port 0 binds an ephemeral listener — no fixed-port collision.
            "port": 0,
            // An explicit loopback listen exercises the optional field
            // without changing the bind.
            "listen": "127.0.0.1",
            "peers": [],
            "validators": [{
                "from": 1,
                "key": hex(key.public_key().as_bytes()),
                "power": 1,
            }],
            "directory": hex(plan.genesis.directory.as_bytes()),
            "policy": {
                "base_cost": plan.genesis.policy.base_cost,
                "window_seconds": plan.genesis.policy.window_seconds,
                "max_in_window": plan.genesis.policy.max_in_window,
                "support_epoch_seconds": plan.genesis.policy.support_epoch_seconds,
                "max_lifetime_rooms": plan.genesis.policy.max_lifetime_rooms,
            },
            "eligible": plan.genesis
                .eligible
                .iter()
                .map(|id| hex(id.as_bytes()))
                .collect::<Vec<_>>(),
            "limits": {
                "records": plan.genesis.limits.records,
                "control_reserve": plan.genesis.limits.control_reserve,
                "data_per_owner": plan.genesis.limits.data_per_owner,
                "data_per_writer": plan.genesis.limits.data_per_writer,
                "control_per_owner": plan.genesis.limits.control_per_owner,
                "pending": plan.genesis.limits.pending,
                "pending_per_signer": plan.genesis.limits.pending_per_signer,
            },
        });
        let config_path = temp.path("node.json");
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let home = temp.path("node-home");
        fs::create_dir_all(home.join("intake")).unwrap();
        let stdout_path = temp.path("node.stdout");
        let stderr_path = temp.path("node.stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node",
                social_dir.to_str().unwrap(),
                home.to_str().unwrap(),
                REALM_HEX,
                "--config",
                config_path.to_str().unwrap(),
            ])
            .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap();
        let mut node = Node {
            child,
            stdout: stdout_path,
            stderr: stderr_path,
        };

        // A malformed drop is rejected and retained — never silently lost.
        fs::write(home.join("intake/garbage.batch"), b"not a batch").unwrap();
        // Valid canonical batch: commits at the next height this node wins.
        fs::write(home.join("intake/one.batch"), plan.batches[&1].encode()).unwrap();

        wait_for(Duration::from_secs(90), "height 1 commit", || {
            committed(&home, 1)
        });
        wait_for(Duration::from_secs(30), "garbage rejection", || {
            home.join("intake/garbage.rejected").exists()
        });
        assert!(
            !home.join("intake/one.batch").exists(),
            "accepted intake file is consumed"
        );

        // A second submission after the first commit retires cleanly.
        fs::write(home.join("intake/two.batch"), plan.batches[&2].encode()).unwrap();
        wait_for(Duration::from_secs(60), "height 2 commit", || {
            committed(&home, 2)
        });

        // The committed state is a real rooms store under the node home.
        assert!(
            home.join("app/rooms").exists(),
            "node home holds the application stores"
        );

        // SIGINT is the service stop: the run finishes without an error.
        let signaled = Command::new("kill")
            .args(["-INT", &node.child.id().to_string()])
            .status()
            .unwrap();
        assert!(signaled.success());
        let status = node.child.wait().unwrap();
        assert!(status.success(), "node exit: {status}");
        let out = fs::read_to_string(&node.stdout).unwrap_or_default();
        assert!(out.contains("\"listening\""), "startup line: {out}");
        let mut err = String::new();
        let _ = fs::File::open(&node.stderr)
            .unwrap()
            .read_to_string(&mut err);
        assert!(
            !err.contains("panic"),
            "node stderr must not contain a panic: {err}"
        );
    }

    /// `rooms eligible` emits a canonical `*.eligible` intake file whose
    /// deterministic name converges across repeated invocations.
    #[test]
    fn eligible_command_writes_a_canonical_intake_update() {
        let temp = Temp::new();
        let home = temp.path("node-home");
        let (a, b) = ([7u8; 32], [9u8; 32]);
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_vhalla"))
                .env("HRANESS_SUPPORT", "off")
                .args([
                    "rooms",
                    "eligible",
                    "unused-social",
                    home.to_str().unwrap(),
                    REALM_HEX,
                    &format!("{},{}", hex(&a), hex(&b)),
                ])
                .output()
                .unwrap()
        };
        let output = run();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let files: Vec<_> = fs::read_dir(home.join("intake"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(files.len(), 1, "one canonical update file");
        let path = files[0].path();
        assert_eq!(path.extension().and_then(|e| e.to_str()), Some("eligible"));
        let set =
            vhalla_rooms_consensus::decode_eligible_update(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            set,
            vec![
                vhalla_rooms_consensus::OwnerId::from_bytes(a),
                vhalla_rooms_consensus::OwnerId::from_bytes(b),
            ]
        );

        // A repeat converges on the same name — no duplicate drops.
        assert!(run().status.success());
        assert_eq!(fs::read_dir(home.join("intake")).unwrap().count(), 1);
    }

    /// The four-process mesh tests take turns: each holds every member's
    /// libp2p stack, and parallel instances starve each other's consensus
    /// rounds on shared CPU. Light single-node tests stay parallel.
    static MESH: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// One validator member's material: consensus seed and listen port.
    struct Member {
        seed: [u8; 32],
        port: usize,
    }

    /// A random high base port keeps parallel test binaries from racing
    /// each other's listeners; members of one mesh occupy base..base+n.
    fn port_base() -> usize {
        let mut nonce = [0; 2];
        getrandom::fill(&mut nonce).unwrap();
        28_000 + (u16::from_be_bytes(nonce) % 2_000) as usize
    }

    /// Seed a fresh social store with the plan's genesis archive — each
    /// member needs its own copy (the store takes an exclusive lock).
    fn seed_social(path: &Path, plan: &fixture::Plan) {
        let mut social =
            SocialStore::create(path, plan.genesis.realm, plan.genesis.limits).unwrap();
        social
            .commit(plan.genesis.archive.clone(), social.pin())
            .unwrap();
    }

    /// `member`'s `node.json`: own key and port, every other member as a
    /// persistent peer, and the shared genesis fields verbatim — the same
    /// shape the README's private-set runbook hands each friend.
    fn write_mesh_config(path: &Path, member: &Member, members: &[Member], plan: &fixture::Plan) {
        let config = serde_json::json!({
            "node_key": hex(&member.seed),
            "port": member.port,
            "listen": "127.0.0.1",
            "peers": members
                .iter()
                .filter(|m| m.port != member.port)
                .map(|m| format!("127.0.0.1:{}", m.port))
                .collect::<Vec<_>>(),
            "validators": members
                .iter()
                .map(|m| serde_json::json!({
                    "from": 1,
                    "key": hex(PrivateKey::from(m.seed).public_key().as_bytes()),
                    "power": 1,
                }))
                .collect::<Vec<_>>(),
            "directory": hex(plan.genesis.directory.as_bytes()),
            "policy": {
                "base_cost": plan.genesis.policy.base_cost,
                "window_seconds": plan.genesis.policy.window_seconds,
                "max_in_window": plan.genesis.policy.max_in_window,
                "support_epoch_seconds": plan.genesis.policy.support_epoch_seconds,
                "max_lifetime_rooms": plan.genesis.policy.max_lifetime_rooms,
            },
            "eligible": plan.genesis
                .eligible
                .iter()
                .map(|id| hex(id.as_bytes()))
                .collect::<Vec<_>>(),
            "limits": {
                "records": plan.genesis.limits.records,
                "control_reserve": plan.genesis.limits.control_reserve,
                "data_per_owner": plan.genesis.limits.data_per_owner,
                "data_per_writer": plan.genesis.limits.data_per_writer,
                "control_per_owner": plan.genesis.limits.control_per_owner,
                "pending": plan.genesis.limits.pending,
                "pending_per_signer": plan.genesis.limits.pending_per_signer,
            },
        });
        fs::write(path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    }

    /// One member's directories: seeded social store, node home with an
    /// intake directory, and its mesh config at `node-{i}.json`.
    fn member_dirs(
        temp: &Temp,
        i: usize,
        member: &Member,
        members: &[Member],
        plan: &fixture::Plan,
    ) -> (PathBuf, PathBuf) {
        let social = temp.path(&format!("social-{i}"));
        seed_social(&social, plan);
        let home = temp.path(&format!("home-{i}"));
        fs::create_dir_all(home.join("intake")).unwrap();
        write_mesh_config(&temp.path(&format!("node-{i}.json")), member, members, plan);
        (social, home)
    }

    /// Launch member `i`'s node subprocess with captured output.
    fn spawn_member(temp: &Temp, i: usize, social: &Path, home: &Path) -> Node {
        let stdout_path = temp.path(&format!("member-{i}.stdout"));
        let stderr_path = temp.path(&format!("member-{i}.stderr"));
        let config_path = temp.path(&format!("node-{i}.json"));
        let child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node",
                social.to_str().unwrap(),
                home.to_str().unwrap(),
                REALM_HEX,
                "--config",
                config_path.to_str().unwrap(),
            ])
            .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
            .spawn()
            .unwrap();
        Node {
            child,
            stdout: stdout_path,
            stderr: stderr_path,
        }
    }

    /// Four real node subprocesses meshing over loopback: an intake drop
    /// on one member decides on all four, then the set keeps deciding
    /// after one member dies — a 4-member set tolerates exactly one loss
    /// (quorum is strictly over 2/3 of power), the private-network
    /// fault-tolerance proof.
    #[test]
    fn validator_mesh_commits_and_survives_one_loss() {
        let _mesh = MESH.lock().unwrap();
        let temp = Temp::new();
        let plan = fixture::plan(2, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [10 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let mut nodes = Vec::new();
        let mut homes = Vec::new();
        for (i, member) in members.iter().enumerate() {
            let (social, home) = member_dirs(&temp, i, member, &members, &plan);
            homes.push(home.clone());
            nodes.push(spawn_member(&temp, i, &social, &home));
        }

        // Drop the height-1 batch into member 0's intake: whichever
        // validator proposes it, every member must commit the same value.
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        for (i, home) in homes.iter().enumerate() {
            wait_for(Duration::from_secs(150), "height 1 on all members", || {
                committed(home, 1)
            });
            assert!(committed(home, 1), "member {i} missing height 1");
        }

        // Member 3 goes offline mid-flight: the surviving trio still holds
        // the >2/3 quorum and must keep deciding intake submissions.
        let signaled = Command::new("kill")
            .args(["-9", &nodes[3].child.id().to_string()])
            .status()
            .unwrap();
        assert!(signaled.success());
        fs::write(homes[1].join("intake/two.batch"), plan.batches[&2].encode()).unwrap();
        for home in homes.iter().take(3) {
            wait_for(
                Duration::from_secs(150),
                "height 2 past quorum loss",
                || committed(home, 2),
            );
        }
        assert!(committed(&homes[0], 2) && committed(&homes[1], 2) && committed(&homes[2], 2));
        assert!(
            !committed(&homes[3], 2),
            "the dead member cannot commit height 2"
        );
    }

    /// A member whose machine boots late catches up on decided history
    /// over the wire — then its votes become quorum-necessary, proving the
    /// synced state really is a live member and not a stale copy.
    #[test]
    fn late_starting_member_syncs_decided_history() {
        let _mesh = MESH.lock().unwrap();
        let temp = Temp::new();
        let plan = fixture::plan(3, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [20 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let mut nodes = Vec::new();
        let mut homes = Vec::new();
        let mut socials = Vec::new();
        // Members 0, 1 and 2 start alone — 3/4 of the set, enough to decide.
        for (i, member) in members.iter().take(3).enumerate() {
            let (social, home) = member_dirs(&temp, i, member, &members, &plan);
            homes.push(home.clone());
            socials.push(social.clone());
            nodes.push(spawn_member(&temp, i, &social, &home));
        }
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(
            Duration::from_secs(150),
            "height 1 on the early trio",
            || committed(&homes[0], 1) && committed(&homes[1], 1) && committed(&homes[2], 1),
        );
        fs::write(homes[1].join("intake/two.batch"), plan.batches[&2].encode()).unwrap();
        wait_for(
            Duration::from_secs(150),
            "height 2 on the early trio",
            || committed(&homes[0], 2) && committed(&homes[1], 2) && committed(&homes[2], 2),
        );

        // Member 3 boots late: it must sync decided history over the wire
        // rather than starting from a copied store.
        let (social, home) = member_dirs(&temp, 3, &members[3], &members, &plan);
        homes.push(home.clone());
        socials.push(social.clone());
        nodes.push(spawn_member(&temp, 3, &social, &home));
        wait_for(Duration::from_secs(180), "late member catches up", || {
            committed(&homes[3], 2)
        });

        // Now kill member 0 so the late member's votes are quorum-necessary:
        // members 1, 2 and 3 must decide height 3 on their own.
        let killed = Command::new("kill")
            .args(["-9", &nodes[0].child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let _ = nodes[0].child.wait();
        fs::write(
            homes[3].join("intake/three.batch"),
            plan.batches[&3].encode(),
        )
        .unwrap();
        for home in homes.iter().take(4).skip(1) {
            wait_for(
                Duration::from_secs(180),
                "height 3 needs the late member",
                || committed(home, 3),
            );
        }
    }

    /// A validator killed and restarted on the same home resumes from its
    /// journal and WAL, catches up on the height it missed, then keeps
    /// deciding — the friend who restarts their laptop must not corrupt
    /// or fork the set.
    #[test]
    fn restarted_validator_resumes_and_still_decides() {
        let _mesh = MESH.lock().unwrap();
        let temp = Temp::new();
        let plan = fixture::plan(3, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [30 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let mut nodes = Vec::new();
        let mut homes = Vec::new();
        let mut socials = Vec::new();
        for (i, member) in members.iter().enumerate() {
            let (social, home) = member_dirs(&temp, i, member, &members, &plan);
            homes.push(home.clone());
            socials.push(social.clone());
            nodes.push(spawn_member(&temp, i, &social, &home));
        }
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(Duration::from_secs(150), "height 1 set-wide", || {
            homes.iter().all(|h| committed(h, 1))
        });

        // SIGKILL member 1 — no clean shutdown, WAL mid-flight. The
        // surviving trio is exactly quorum and decides height 2.
        let killed = Command::new("kill")
            .args(["-9", &nodes[1].child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let _ = nodes[1].child.wait();
        fs::write(homes[2].join("intake/two.batch"), plan.batches[&2].encode()).unwrap();
        wait_for(
            Duration::from_secs(150),
            "height 2 on the survivors",
            || committed(&homes[0], 2) && committed(&homes[2], 2) && committed(&homes[3], 2),
        );

        // Member 1 restarts on the same home: it must reopen its WAL and
        // journal, rejoin the mesh, and pull the missed height via sync.
        nodes[1] = spawn_member(&temp, 1, &socials[1], &homes[1]);
        wait_for(
            Duration::from_secs(180),
            "restarted member catches up",
            || committed(&homes[1], 2),
        );

        // And it decides again: height 3 is dropped into the restarted
        // member's own intake and commits set-wide.
        fs::write(
            homes[1].join("intake/three.batch"),
            plan.batches[&3].encode(),
        )
        .unwrap();
        wait_for(Duration::from_secs(180), "height 3 set-wide", || {
            homes.iter().all(|h| committed(h, 3))
        });

        // Clean SIGINT stops on the surviving members close the test the
        // way an operator would end it.
        for i in [0, 2, 3] {
            let signaled = Command::new("kill")
                .args(["-INT", &nodes[i].child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(nodes[i].child.wait().unwrap().success());
        }
    }

    /// Run one `vhalla social` command and unwrap its JSON object; the
    /// commands are fast one-shot invocations, no streaming needed.
    fn social_ok(store: &Path, command: &str, args: &[&str]) -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(["social", command])
            .arg(store)
            .arg(REALM_HEX)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "social {command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    /// Run one `vhalla rooms` command and unwrap its JSON object.
    fn rooms_ok(args: &[&str]) -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(["rooms"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rooms {}: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn field(value: &serde_json::Value, name: &str) -> String {
        value[name]
            .as_str()
            .unwrap_or_else(|| panic!("missing string field {name}: {value}"))
            .to_owned()
    }

    /// The full operator journey on real commands, end to end: two members
    /// build their social accounts, one's post earns the other's eligible
    /// support, a live single-validator node decides the `rooms submit
    /// create` body, `rooms pending` reports the commit and `rooms list`
    /// shows the room. Nothing here touches fixtures or test-only paths —
    /// every step is a documented CLI invocation a friend would run.
    #[test]
    fn submit_create_flows_through_a_live_node() {
        let temp = Temp::new();
        let net = temp.path("network-store");

        // Alice: owner, enrolled agent, one committed post.
        let a_key = temp.path("alice-key");
        let a_init = social_ok(&net, "init", &[a_key.to_str().unwrap()]);
        let a_owner = field(&a_init, "owner");
        let a_agent_key = temp.path("alice-agent");
        let a_enroll = social_ok(
            &net,
            "enroll",
            &[
                a_key.to_str().unwrap(),
                &a_owner,
                a_agent_key.to_str().unwrap(),
                "all",
                "9999999999",
            ],
        );
        let a_agent = field(&a_enroll, "agent");
        let a_actor = format!("agent:{}:{}", a_agent, field(&a_enroll, "grant"));
        let post = social_ok(
            &net,
            "post",
            &[a_agent_key.to_str().unwrap(), &a_actor, "profile", "hi all"],
        );
        let post_id = field(&post, "event");
        social_ok(&net, "seal", &[a_key.to_str().unwrap(), &a_owner, &post_id]);

        // Bob: owner, enrolled agent, up-reaction on Alice's post — the
        // eligible support record that funds Alice's first room.
        let b_store = temp.path("bob-store");
        let b_key = temp.path("bob-key");
        let b_init = social_ok(&b_store, "init", &[b_key.to_str().unwrap()]);
        let b_owner = field(&b_init, "owner");
        let b_agent_key = temp.path("bob-agent");
        let b_enroll = social_ok(
            &b_store,
            "enroll",
            &[
                b_key.to_str().unwrap(),
                &b_owner,
                b_agent_key.to_str().unwrap(),
                "all",
                "9999999999",
            ],
        );
        let b_agent = field(&b_enroll, "agent");
        let b_actor = format!("agent:{}:{}", b_agent, field(&b_enroll, "grant"));

        // Bob needs Alice's archive to react on her post — the same
        // `social import` a friend runs to pull her state.
        let snapshot = temp.path("alice.snap");
        social_ok(&net, "export", &[snapshot.to_str().unwrap()]);
        social_ok(&b_store, "import", &[snapshot.to_str().unwrap()]);
        let react = social_ok(
            &b_store,
            "react",
            &[
                b_agent_key.to_str().unwrap(),
                &b_actor,
                &post_id,
                "up",
                &post_id,
            ],
        );
        let react_id = field(&react, "event");
        social_ok(
            &b_store,
            "seal",
            &[b_key.to_str().unwrap(), &b_owner, &react_id],
        );

        // Alice pulls Bob's sealed reaction into her archive — her social
        // store is what the node's genesis seeds from.
        let b_snapshot = temp.path("bob.snap");
        social_ok(&b_store, "export", &[b_snapshot.to_str().unwrap()]);
        social_ok(&net, "import", &[b_snapshot.to_str().unwrap()]);

        // The evidence snapshot Bob carries to the rooms network: his
        // committed up-reaction on Alice's post.
        let evidence = temp.path("evidence.snap");
        social_ok(&b_store, "export", &[evidence.to_str().unwrap()]);

        // A single-validator node seeded from the network store. The
        // config must land at `node-0.json` — `spawn_member` reads that
        // path for member 0.
        let node_seed = [42u8; 32];
        let node_key = PrivateKey::from(node_seed);
        let config = serde_json::json!({
            "node_key": hex(&node_seed),
            "port": 0,
            "listen": "127.0.0.1",
            "peers": [],
            "validators": [{
                "from": 1,
                "key": hex(node_key.public_key().as_bytes()),
                "power": 1,
            }],
            "directory": "0000000000000000000000000000000000000000000000000000000000000007",
            "realm": REALM_HEX,
            "policy": {
                "base_cost": 1,
                "window_seconds": 86400,
                "max_in_window": 8,
                "support_epoch_seconds": 86400,
                "max_lifetime_rooms": 16,
            },
            "eligible": [&b_owner],
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
        let config_path = temp.path("node-0.json");
        fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        let home = temp.path("node-home");
        fs::create_dir_all(home.join("intake")).unwrap();
        let _node = spawn_member(&temp, 0, &net, &home);

        // The real submission: Alice creates her room, Bob's sealed
        // reaction rides along as award evidence.
        let replica_store = temp.path("replica-rooms");
        let expiry = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600)
            .to_string();
        let submitted = rooms_ok(&[
            "submit",
            net.to_str().unwrap(),
            replica_store.to_str().unwrap(),
            REALM_HEX,
            home.to_str().unwrap(),
            "create",
            a_key.to_str().unwrap(),
            a_agent_key.to_str().unwrap(),
            &a_owner,
            &a_agent,
            "first-room",
            &expiry,
            "the first room",
            evidence.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ]);
        assert_eq!(submitted["queued"], true);
        let marker = field(&submitted, "marker");

        // The intake drop must decide and the marker resolve committed.
        wait_for(Duration::from_secs(120), "submission commits", || {
            committed(&home, 1)
        });
        let pending = rooms_ok(&[
            "pending",
            net.to_str().unwrap(),
            replica_store.to_str().unwrap(),
            REALM_HEX,
            home.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ]);
        let rows = pending["pending"].as_array().unwrap();
        let row = rows
            .iter()
            .find(|r| r["marker"].as_str() == Some(marker.as_str()))
            .expect("marker must appear in pending");
        assert_eq!(row["state"].as_str().unwrap(), "committed");

        // And the room is real: the replica materializes its stores under
        // the service root — `rooms/` is the rooms-store `list` opens.
        let listed = rooms_ok(&[
            "list",
            net.to_str().unwrap(),
            replica_store.join("rooms").to_str().unwrap(),
            REALM_HEX,
        ]);
        let rooms = listed["rooms"].as_array().unwrap();
        assert!(
            rooms
                .iter()
                .any(|r| r["slug"].as_str() == Some("first-room")),
            "the committed room must list: {listed}"
        );
    }
}
