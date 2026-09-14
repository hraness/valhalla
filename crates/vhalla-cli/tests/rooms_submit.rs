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
        io::Read,
        os::unix::fs::DirBuilderExt,
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .arg(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
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
        let stdout = temp.path("node.stdout");
        let stderr = temp.path("node.stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
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
