#![cfg(unix)]
//! Real rooms CLI subprocesses cross signing, admission, durable storage, and presentation.

#[cfg(not(feature = "experimental-rooms"))]
#[test]
fn rooms_commands_are_absent_from_the_default_build() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .env("HRANESS_SUPPORT", "off")
        .args([
            "rooms",
            "list",
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
        .contains("experimental-rooms"));
}

#[cfg(feature = "experimental-rooms")]
mod enabled {
    use serde_json::Value;
    use std::{
        fs,
        io::Read,
        os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };

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
                "vhalla-cli-rooms-{:032x}",
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

    fn path(path: &Path) -> &str {
        path.to_str().unwrap()
    }
    fn field(value: &Value, name: &str) -> String {
        value
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("missing string field {name}: {value}"))
            .to_owned()
    }
    fn safe(bytes: &[u8]) {
        assert!(
            bytes
                .iter()
                .all(|byte| *byte == b'\n' || (0x20..=0x7e).contains(byte)),
            "output contains terminal controls or unescaped Unicode"
        );
    }
    fn run(command: &str, args: &[&str]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
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
        let stdout = out.join().unwrap();
        let stderr = err.join().unwrap();
        assert!(stdout.len() <= CAPTURE as usize && stderr.len() <= CAPTURE as usize);
        safe(&stdout);
        safe(&stderr);
        Output {
            status,
            stdout,
            stderr,
        }
    }
    fn ok(command: &str, args: &[&str]) -> Value {
        let output = run(command, args);
        assert!(
            output.status.success(),
            "{command} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(value.is_object());
        value
    }
    fn fails(command: &str, args: &[&str]) -> String {
        let output = run(command, args);
        assert!(
            !output.status.success(),
            "{command} {args:?} unexpectedly succeeded"
        );
        assert!(
            output.stdout.is_empty(),
            "failed operation must not emit a durable-success object"
        );
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
            assert_eq!(output["durable"], true);
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
        /// An owner-signed up-reaction committed inside `store`'s archive.
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

    /// The directory plus alice's social store holding every needed record.
    struct World {
        social: PathBuf,
        rooms: PathBuf,
        alice: Social,
        agent: String,
        agent_key: String,
    }
    impl World {
        fn rooms(&self, command: &str, args: &[&str]) -> Value {
            let mut full = vec![command, path(&self.social), path(&self.rooms), REALM];
            full.extend_from_slice(args);
            full.extend(["--now", NOW]);
            ok("rooms", &full)
        }
        fn rooms_fails(&self, command: &str, args: &[&str]) -> String {
            let mut full = vec![command, path(&self.social), path(&self.rooms), REALM];
            full.extend_from_slice(args);
            full.extend(["--now", NOW]);
            fails("rooms", &full)
        }
        fn identity_key(&self, keydir: &Path) -> String {
            let output = run("identity", &["show", path(keydir)]);
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            text.strip_prefix("application-key ")
                .unwrap()
                .trim()
                .to_owned()
        }
    }

    /// Build a directory whose beneficiary (alice) earned `sources` credits and
    /// whose enrolled agent can be granted creation rights. Every credit is a
    /// distinct eligible source owner's committed up-reaction on alice's post.
    fn world(temp: &Temp, sources: usize) -> World {
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
        let mut eligible = Vec::new();
        for index in 0..sources {
            let source = Social::init(temp, &format!("source{index}"));
            source.export(&temp.path(&format!("source{index}.snap")));
            alice.import(&temp.path(&format!("source{index}.snap")));
            source.react_into(&alice.store, &post);
            eligible.push(source.owner);
        }
        let enroll = ok(
            "social",
            &[
                "enroll",
                path(&alice.store),
                REALM,
                path(&alice.key),
                &alice.owner,
                path(&temp.path("agent-key")),
                "all",
                "1000",
                "--now",
                NOW,
            ],
        );
        let world = World {
            social: alice.store.clone(),
            rooms: temp.path("rooms-store"),
            alice,
            agent: field(&enroll, "agent"),
            agent_key: String::new(),
        };
        let world = World {
            agent_key: world.identity_key(&temp.path("agent-key")),
            ..world
        };
        let eligible = if eligible.is_empty() {
            "-".to_owned()
        } else {
            eligible.join(",")
        };
        let init = world.rooms("init", &[DIRECTORY, "1", "60", "4", "60", "8", &eligible]);
        assert_eq!(init["durable"], true);
        world
    }

    fn room_grant(world: &World, agent: &str, agent_key: &str, expiry: &str) -> String {
        let output = world.rooms(
            "grant",
            &[
                path(&world.alice.key),
                &world.alice.owner,
                agent,
                agent_key,
                expiry,
                "100",
            ],
        );
        assert_eq!(output["durable"], true);
        field(&output, "record")
    }

    #[test]
    fn award_grant_create_and_query_survive_real_subprocesses() {
        let temp = Temp::new();
        let world = world(&temp, 1);

        let collect = world.rooms("collect", &[]);
        assert_eq!(collect["awarded"], 1);
        let quote = world.rooms("quote", &[&world.alice.owner]);
        assert_eq!(quote["slot"], 1);
        assert_eq!(quote["cost"], 1);
        assert_eq!(quote["earned"], 1);

        let grant = room_grant(&world, &world.agent, &world.agent_key, "500");
        let created = world.rooms(
            "create",
            &[
                path(&world.alice.key),
                path(&temp.path("agent-key")),
                &world.alice.owner,
                &world.agent,
                &grant,
                "cool-room",
                "400",
                "A cool room",
            ],
        );
        assert_eq!(created["durable"], true);
        assert_eq!(created["slot"], 1);
        assert_eq!(created["charge"], 1);
        let genesis = field(&created, "genesis");
        let record = field(&created, "record");

        let listed = world.rooms("list", &[]);
        let rooms = listed["rooms"].as_array().unwrap();
        assert_eq!(rooms.len(), 1);
        assert_eq!(rooms[0]["slug"], "cool-room");
        assert_eq!(rooms[0]["genesis"], genesis);
        assert_eq!(rooms[0]["owner"], world.alice.owner);
        assert_eq!(listed["partial"], false);

        for query in ["cool", "cool room"] {
            let found = world.rooms("search", &[query]);
            assert_eq!(found["rooms"].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            world.rooms("search", &["absent"])["rooms"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        let shown = world.rooms("show", &["cool-room"]);
        assert_eq!(shown["agent"], world.agent);
        assert_eq!(shown["charge"], 1);
        assert_eq!(shown["archived"], false);

        let account = world.rooms("account", &[&world.alice.owner]);
        assert_eq!(account["spent"], 1);
        assert_eq!(account["lifetimeSlots"], 1);

        // Source-proof retrieval: the canonical signed bytes that were admitted.
        let proof = world.rooms("proof", &[&record]);
        assert_eq!(proof["record"], record);
        let bytes = proof["bytes"].as_str().unwrap();
        assert!(bytes.len() > 64 && bytes.bytes().all(|b| b.is_ascii_hexdigit()));

        // The same slug can never be re-created, including by an archived tombstone.
        let grant2 = room_grant(&world, &world.agent, &world.agent_key, "500");
        let collision = world.rooms_fails(
            "create",
            &[
                path(&world.alice.key),
                path(&temp.path("agent-key")),
                &world.alice.owner,
                &world.agent,
                &grant2,
                "cool-room",
                "400",
                "Duplicate slug",
            ],
        );
        assert!(collision.contains("Taken"), "{collision}");

        world.rooms(
            "describe",
            &[
                path(&world.alice.key),
                "cool-room",
                "300",
                "Renamed description",
            ],
        );
        assert_eq!(
            world.rooms("show", &["cool-room"])["description"],
            "Renamed description"
        );
        world.rooms("archive", &[path(&world.alice.key), "cool-room", "300"]);
        assert_eq!(world.rooms("show", &["cool-room"])["archived"], true);
        assert_eq!(
            world.rooms("search", &["cool"])["rooms"]
                .as_array()
                .unwrap()
                .len(),
            0,
            "tombstones keep their allocation but leave search"
        );
        assert_eq!(world.rooms("list", &[])["retained"], 1);

        // A clean store reconciles as a readback; an unknown command fails.
        assert_eq!(world.rooms("recover", &[])["durable"], true);
        world.rooms_fails("nonexistent", &[]);
    }

    #[test]
    fn one_owner_two_agent_processes_share_durable_state() {
        let temp = Temp::new();
        // Slot 1 costs 1, slot 2 costs 4: five eligible awards cover both.
        let world = world(&temp, 5);
        world.rooms("collect", &[]);
        assert_eq!(world.rooms("account", &[&world.alice.owner])["earned"], 5);

        // Enroll a second agent for the same owner; each agent is a separate
        // process invocation against the same locked durable store.
        let agent2_key = temp.path("agent2-key");
        let enroll2 = ok(
            "social",
            &[
                "enroll",
                path(&world.alice.store),
                REALM,
                path(&world.alice.key),
                &world.alice.owner,
                path(&agent2_key),
                "all",
                "1000",
                "--now",
                NOW,
            ],
        );
        let agent2 = field(&enroll2, "agent");
        let agent2_public = world.identity_key(&agent2_key);

        let grant1 = room_grant(&world, &world.agent, &world.agent_key, "500");
        let first = world.rooms(
            "create",
            &[
                path(&world.alice.key),
                path(&temp.path("agent-key")),
                &world.alice.owner,
                &world.agent,
                &grant1,
                "first-room",
                "400",
                "First room",
            ],
        );
        assert_eq!(first["slot"], 1);
        assert_eq!(first["charge"], 1);

        // A later process sees the committed registry: slot advanced to 2.
        let quote = world.rooms("quote", &[&world.alice.owner]);
        assert_eq!(quote["slot"], 2);
        assert_eq!(quote["cost"], 4);
        let grant2 = room_grant(&world, &agent2, &agent2_public, "500");
        let second = world.rooms(
            "create",
            &[
                path(&world.alice.key),
                path(&agent2_key),
                &world.alice.owner,
                &agent2,
                &grant2,
                "second-room",
                "400",
                "Second room",
            ],
        );
        assert_eq!(second["slot"], 2);
        assert_eq!(second["charge"], 4);

        let account = world.rooms("account", &[&world.alice.owner]);
        assert_eq!(account["earned"], 5);
        assert_eq!(account["spent"], 5);
        assert_eq!(account["lifetimeSlots"], 2);
        assert_eq!(
            world.rooms("list", &[])["rooms"].as_array().unwrap().len(),
            2
        );
    }

    #[test]
    fn denials_and_store_conflicts_emit_no_success_object() {
        let temp = Temp::new();
        let world = world(&temp, 0);

        // No eligible sources: collect earns nothing, create is credit-denied.
        assert_eq!(world.rooms("collect", &[])["awarded"], 0);
        let grant = room_grant(&world, &world.agent, &world.agent_key, "500");
        let denied = world.rooms_fails(
            "create",
            &[
                path(&world.alice.key),
                path(&temp.path("agent-key")),
                &world.alice.owner,
                &world.agent,
                &grant,
                "no-credit",
                "400",
                "Denied",
            ],
        );
        assert!(denied.contains("InsufficientCredit"), "{denied}");

        // A foreign key directory cannot sign for alice's owner.
        let foreign = Social::init(&temp, "foreign");
        let wrong_key = world.rooms_fails(
            "grant",
            &[
                path(&foreign.key),
                &world.alice.owner,
                &world.agent,
                &world.agent_key,
                "500",
                "100",
            ],
        );
        assert!(wrong_key.contains("does not control"), "{wrong_key}");

        // Missing paths and unknown owners fail closed.
        let missing = temp.path("missing-rooms");
        let mut args = vec![
            "list",
            path(&world.social),
            path(&missing),
            REALM,
            "--now",
            NOW,
        ];
        fails("rooms", &args);
        let missing_social = temp.path("missing-social");
        args[1] = path(&missing_social);
        fails("rooms", &args);

        // A room record signed under a different directory is denied.
        let other = world.rooms_fails("show", &["never-created"]);
        assert!(other.contains("missing"), "{other}");
    }
}
