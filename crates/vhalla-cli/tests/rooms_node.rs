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
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
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
            if std::env::var_os("KEEP_TEMP").is_none() {
                fs::remove_dir_all(&self.0).unwrap();
            } else {
                eprintln!("kept {}", self.0.display());
            }
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
        // The stem must survive the node's intake safety filter — a quoted
        // id in the name would be renamed `.rejected` on first drain.
        let stem = path.file_stem().unwrap().to_str().unwrap();
        assert!(
            stem.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "intake-safe stem: {stem}"
        );
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

    /// Take the mesh gate. A panicking peer test must not poison it for
    /// the rest of the suite - its children are reaped by Node::drop.
    fn mesh() -> std::sync::MutexGuard<'static, ()> {
        MESH.lock().unwrap_or_else(|e| e.into_inner())
    }

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

    /// `member`'s `node.json`: own key and port, the given `peers` as
    /// persistent peers, and the shared genesis fields verbatim — the same
    /// shape the README's private-set runbook hands each friend.
    fn mesh_config(
        member: &Member,
        members: &[Member],
        peers: Vec<String>,
        plan: &fixture::Plan,
    ) -> serde_json::Value {
        serde_json::json!({
            "node_key": hex(&member.seed),
            "port": member.port,
            "listen": "127.0.0.1",
            "peers": peers,
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
        })
    }

    /// `member`'s `node.json` with every other member's real port as a
    /// persistent peer — the direct-loopback mesh.
    fn write_mesh_config(path: &Path, member: &Member, members: &[Member], plan: &fixture::Plan) {
        let peers = members
            .iter()
            .filter(|m| m.port != member.port)
            .map(|m| format!("127.0.0.1:{}", m.port))
            .collect();
        let config = mesh_config(member, members, peers, plan);
        fs::write(path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    }

    /// `member`'s `node.json` where every peer address is the test pipe's
    /// listen port for that directed edge, not the peer's real port.
    fn write_proxied_mesh_config(
        path: &Path,
        i: usize,
        member: &Member,
        members: &[Member],
        links: &BTreeMap<(usize, usize), Link>,
        plan: &fixture::Plan,
    ) {
        let peers = (0..members.len())
            .filter(|j| *j != i)
            .map(|j| format!("127.0.0.1:{}", links[&(i, j)].port))
            .collect();
        let config = mesh_config(member, members, peers, plan);
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

    /// Launch a node subprocess against an explicit config path with
    /// captured output.
    fn spawn_node(temp: &Temp, tag: &str, social: &Path, home: &Path, config: &Path) -> Node {
        let stdout_path = temp.path(&format!("{tag}.stdout"));
        let stderr_path = temp.path(&format!("{tag}.stderr"));
        let child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node",
                social.to_str().unwrap(),
                home.to_str().unwrap(),
                REALM_HEX,
                "--config",
                config.to_str().unwrap(),
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

    /// Launch member `i`'s node subprocess with captured output.
    fn spawn_member(temp: &Temp, i: usize, social: &Path, home: &Path) -> Node {
        spawn_node(
            temp,
            &format!("member-{i}"),
            social,
            home,
            &temp.path(&format!("node-{i}.json")),
        )
    }

    /// Four real node subprocesses meshing over loopback: an intake drop
    /// on one member decides on all four, then the set keeps deciding
    /// after one member dies — a 4-member set tolerates exactly one loss
    /// (quorum is strictly over 2/3 of power), the private-network
    /// fault-tolerance proof.
    #[test]
    fn validator_mesh_commits_and_survives_one_loss() {
        let _mesh = mesh();
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
        let _mesh = mesh();
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
        let _mesh = mesh();
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

    /// An operator-dropped `rooms eligible` update commits as a
    /// config-only body on the live mesh and governs the NEXT height:
    /// a batch whose evidence sources were dropped from the set can no
    /// longer cover its room's charge, so re-prepare fails and the
    /// intake gains a `.rejected` marker while the height stays
    /// undecided — only tombstones can ever be proposed for it. This is
    /// the mid-flight membership change the runbook hands operators.
    #[test]
    fn live_mesh_commits_an_eligible_transition() {
        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(3, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [60 + i; 32],
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

        // Height 1 commits under the genesis eligible set.
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(Duration::from_secs(150), "height 1 set-wide", || {
            homes.iter().all(|h| committed(h, 1))
        });

        // The operator rotates the award-source set mid-flight through
        // the real command: one fresh owner replaces all sixteen genesis
        // sources. The file drains on member 0's next proposer round and
        // the transition decides at height 2.
        let newcomer = hex(&[0xee; 32]);
        let updated = rooms_ok(&[
            "eligible",
            socials[0].to_str().unwrap(),
            homes[0].to_str().unwrap(),
            REALM_HEX,
            &newcomer,
        ]);
        assert_eq!(updated["owners"].as_u64(), Some(1));
        wait_for(
            Duration::from_secs(180),
            "eligible transition at height 2",
            || homes.iter().all(|h| committed(h, 2)),
        );

        // The new set governs: batch 3's evidence comes entirely from
        // the dropped sources, so its room's charge can never be
        // covered — re-prepare fails on every member and the dropping
        // member marks the intake file rejected.
        fs::write(
            homes[1].join("intake/three.batch"),
            plan.batches[&3].encode(),
        )
        .unwrap();
        wait_for(
            Duration::from_secs(180),
            "post-transition batch rejected at prepare",
            || homes[1].join("intake/three.rejected").exists(),
        );
        assert!(
            !homes.iter().any(|h| committed(h, 3)),
            "a value whose charge can never be covered must not decide"
        );

        // Shut the mesh down cleanly first — a node holds its materialized
        // `app/rooms` store under a lifetime writer lock, so the shared
        // reader cannot land until the process exits.
        for node in &mut nodes {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        }

        // The committed registry shows the genesis-era room and never the
        // underfunded one — the swap kept state consistent.
        let listed = rooms_ok(&[
            "list",
            socials[0].to_str().unwrap(),
            homes[0].join("app/rooms").to_str().unwrap(),
            REALM_HEX,
        ]);
        let slugs: Vec<&str> = listed["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["slug"].as_str())
            .collect();
        assert!(
            slugs.contains(&"room-1"),
            "genesis-era room lists: {listed}"
        );
        assert!(
            !slugs.contains(&"room-3"),
            "the underfunded room must not list: {listed}"
        );
    }

    /// The friend-joins-with-voting-power journey end to end on real
    /// commands: a four-member scaffolded mesh commits a height, the
    /// operator extends the shared params with a fifth validator set
    /// activating at height 4, existing members `node-update` and
    /// restart onto it, the joiner `node-init`s fresh and boots, and
    /// heights past the activation decide under the enlarged set — with
    /// one original member killed, the survivors need the joiner's vote
    /// to reach the five-member quorum.
    #[test]
    fn live_mesh_rotates_validator_set_mid_flight() {
        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(5, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..5u8)
            .map(|i| Member {
                seed: [50 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let key = |m: &Member| hex(PrivateKey::from(m.seed).public_key().as_bytes());

        // v1: the original four vote from genesis. The fifth member is
        // not in the file yet — it joins later, as a friend would.
        let validators_v1: String = members[..4]
            .iter()
            .map(|m| format!("1:{}:1", key(m)))
            .collect::<Vec<_>>()
            .join(",");
        let eligible: String = plan
            .genesis
            .eligible
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
            .join(",");
        let net = temp.path("network.json");
        rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            &format!(
                "{},{},{},{},{}",
                plan.genesis.policy.base_cost,
                plan.genesis.policy.window_seconds,
                plan.genesis.policy.max_in_window,
                plan.genesis.policy.support_epoch_seconds,
                plan.genesis.policy.max_lifetime_rooms,
            ),
            "--validators",
            &validators_v1,
            "--eligible",
            &eligible,
        ]);

        // Members 0-3 scaffold and boot on v1.
        let mut homes = Vec::new();
        let mut socials = Vec::new();
        for (i, member) in members[..4].iter().enumerate() {
            let home = temp.path(&format!("home-{i}"));
            let peers = members[..4]
                .iter()
                .filter(|m| m.port != member.port)
                .map(|m| format!("127.0.0.1:{}", m.port))
                .collect::<Vec<_>>()
                .join(",");
            let out = rooms_ok(&[
                "node-init",
                home.to_str().unwrap(),
                "--network",
                net.to_str().unwrap(),
                "--node-key",
                &hex(&member.seed),
                "--port",
                &member.port.to_string(),
                "--peers",
                &peers,
            ]);
            assert_eq!(out["node_key_votes_from"].as_u64(), Some(1));
            let social = temp.path(&format!("social-{i}"));
            seed_social(&social, &plan);
            homes.push(home);
            socials.push(social);
        }
        let mut nodes: Vec<Node> = homes
            .iter()
            .enumerate()
            .map(|(i, home)| {
                spawn_node(
                    &temp,
                    &format!("rot-{i}"),
                    &socials[i],
                    home,
                    &home.join("node.json"),
                )
            })
            .collect();
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(Duration::from_secs(150), "height 1 set-wide", || {
            homes.iter().all(|h| committed(h, 1))
        });

        // The operator schedules the rotation: one complete set of five
        // activates at height 4 — far enough out for everyone to update.
        let net_v2 = temp.path("network-v2.json");
        let ext = rooms_ok(&[
            "network-extend",
            net.to_str().unwrap(),
            net_v2.to_str().unwrap(),
            "--from",
            "4",
            "--validators",
            &members
                .iter()
                .map(|m| format!("{}:1", key(m)))
                .collect::<Vec<_>>()
                .join(","),
        ]);
        assert_eq!(ext["activation_from"].as_u64(), Some(4));
        assert_eq!(ext["validators"].as_u64(), Some(5));

        // Existing members merge the new schedule while running; the
        // frozen check sees height 1 committed and leaves it intact.
        for home in &homes {
            let upd = rooms_ok(&[
                "node-update",
                home.to_str().unwrap(),
                "--network",
                net_v2.to_str().unwrap(),
            ]);
            assert_eq!(upd["committed"].as_u64(), Some(1));
        }
        // The joiner scaffolds straight onto v2 — its key votes from 4.
        let home4 = temp.path("home-4");
        let peers4 = members[..4]
            .iter()
            .map(|m| format!("127.0.0.1:{}", m.port))
            .collect::<Vec<_>>()
            .join(",");
        let out = rooms_ok(&[
            "node-init",
            home4.to_str().unwrap(),
            "--network",
            net_v2.to_str().unwrap(),
            "--node-key",
            &hex(&members[4].seed),
            "--port",
            &members[4].port.to_string(),
            "--peers",
            &peers4,
        ]);
        assert_eq!(out["node_key_votes_from"].as_u64(), Some(4));
        let social4 = temp.path("social-4");
        seed_social(&social4, &plan);
        homes.push(home4);
        socials.push(social4);

        // Restart the incumbents so the updated schedule loads; a node
        // reads its config once at boot.
        for node in nodes.iter_mut() {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        }
        for (i, node) in nodes.iter_mut().enumerate() {
            *node = spawn_node(
                &temp,
                &format!("rot-{i}-r"),
                &socials[i],
                &homes[i],
                &homes[i].join("node.json"),
            );
        }
        // The joiner boots and syncs the decided prefix under the sets
        // each height was actually decided by.
        nodes.push(spawn_node(
            &temp,
            "rot-4",
            &socials[4],
            &homes[4],
            &homes[4].join("node.json"),
        ));

        // Heights 2 and 3 still decide under the original four; member 4
        // follows along on sync without voting.
        for (n, h) in [(2u64, "two"), (3, "three")] {
            fs::write(
                homes[0].join(format!("intake/{h}.batch")),
                plan.batches[&n].encode(),
            )
            .unwrap();
            wait_for(
                Duration::from_secs(150),
                &format!("height {n} set-wide"),
                || homes.iter().all(|home| committed(home, n)),
            );
        }

        // Height 4 is the activation: the five-member set needs 4 votes
        // (strictly over 10/3), so member 4 must vote for it to land.
        fs::write(
            homes[0].join("intake/four.batch"),
            plan.batches[&4].encode(),
        )
        .unwrap();
        wait_for(
            Duration::from_secs(180),
            "height 4 activates the fifth",
            || homes.iter().all(|h| committed(h, 4)),
        );

        // The discriminating proof: kill an original member and the mesh
        // still decides — only member 4's vote makes the five-member
        // quorum reachable at all.
        let killed = Command::new("kill")
            .args(["-9", &nodes[0].child.id().to_string()])
            .status()
            .unwrap();
        assert!(killed.success());
        let _ = nodes[0].child.wait();
        fs::write(
            homes[1].join("intake/five.batch"),
            plan.batches[&5].encode(),
        )
        .unwrap();
        wait_for(
            Duration::from_secs(180),
            "height 5 on the rotated set",
            || homes[1..].iter().all(|h| committed(h, 5)),
        );

        for node in nodes.iter_mut().skip(1) {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        }
    }

    /// The composed soak: several evenings of real use compressed into
    /// one mesh. A scaffolded four-member set takes an intake drop, a
    /// duplicate drop racing on two members, an in-band eligible-set
    /// transition and a malformed drop; the operator then schedules a
    /// five-validator activation, members rolling-restart onto it while
    /// traffic flows, the joiner syncs the decided prefix, one member is
    /// SIGKILLed mid-window and recovers, and two originals die together
    /// to prove the rotated quorum both stalls and heals. Every fault
    /// resolves and the mesh converges on identical journals, identical
    /// materialized rooms and fully drained intake/pending state.
    #[test]
    fn live_mesh_soak_duplicate_churn_rotation_converges() {
        let _mesh = mesh();
        let temp = Temp::new();
        // 8 funded batches: one room per drop. 24 sources leave award
        // headroom for the full sequence plus the post-transition drops.
        let plan = fixture::plan(8, 8, 24);
        let base = port_base();
        let members: Vec<Member> = (0..5u8)
            .map(|i| Member {
                seed: [70 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let key = |m: &Member| hex(PrivateKey::from(m.seed).public_key().as_bytes());

        let validators_v1: String = members[..4]
            .iter()
            .map(|m| format!("1:{}:1", key(m)))
            .collect::<Vec<_>>()
            .join(",");
        let eligible: String = plan
            .genesis
            .eligible
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
            .join(",");
        let net = temp.path("network.json");
        rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            &format!(
                "{},{},{},{},{}",
                plan.genesis.policy.base_cost,
                plan.genesis.policy.window_seconds,
                plan.genesis.policy.max_in_window,
                plan.genesis.policy.support_epoch_seconds,
                plan.genesis.policy.max_lifetime_rooms,
            ),
            "--validators",
            &validators_v1,
            "--eligible",
            &eligible,
        ]);

        let mut homes = Vec::new();
        let mut socials = Vec::new();
        for (i, member) in members[..4].iter().enumerate() {
            let home = temp.path(&format!("home-{i}"));
            let peers = members[..4]
                .iter()
                .filter(|m| m.port != member.port)
                .map(|m| format!("127.0.0.1:{}", m.port))
                .collect::<Vec<_>>()
                .join(",");
            rooms_ok(&[
                "node-init",
                home.to_str().unwrap(),
                "--network",
                net.to_str().unwrap(),
                "--node-key",
                &hex(&member.seed),
                "--port",
                &member.port.to_string(),
                "--peers",
                &peers,
            ]);
            let social = temp.path(&format!("social-{i}"));
            seed_social(&social, &plan);
            homes.push(home);
            socials.push(social);
        }
        // A sequence number keeps each respawn's captured logs distinct.
        let mut seq = 0usize;
        let mut spawn = |temp: &Temp, i: usize, socials: &[PathBuf], homes: &[PathBuf]| {
            seq += 1;
            spawn_node(
                temp,
                &format!("soak-{i}-{seq}"),
                &socials[i],
                &homes[i],
                &homes[i].join("node.json"),
            )
        };
        let mut nodes: Vec<Node> = (0..4).map(|i| spawn(&temp, i, &socials, &homes)).collect();
        let sigint = |node: &mut Node| {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        };
        let sigkill = |node: &mut Node| {
            let killed = Command::new("kill")
                .args(["-9", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(killed.success());
            let _ = node.child.wait();
        };
        let all_committed = |homes: &[PathBuf], h: u64| homes.iter().all(|home| committed(home, h));

        // h1: an ordinary drop.
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(Duration::from_secs(150), "h1 set-wide", || {
            all_committed(&homes, 1)
        });

        // h2: the same batch lands in two members' intakes at once. Both
        // assemble the same body; value-id dedup must commit room-2 on
        // exactly one height - never twice.
        for i in [0usize, 2] {
            fs::write(homes[i].join("intake/dup.batch"), plan.batches[&2].encode()).unwrap();
        }
        wait_for(Duration::from_secs(150), "h2 set-wide", || {
            all_committed(&homes, 2)
        });

        // h3: the operator rotates the award-source set in-band. The new
        // set keeps every genesis source and adds one newcomer, so all
        // later fixture batches stay funded under the transition.
        let mut owners = eligible.clone();
        owners.push_str(&format!(",{}", hex(&[0xee; 32])));
        let updated = rooms_ok(&[
            "eligible",
            socials[0].to_str().unwrap(),
            homes[0].to_str().unwrap(),
            REALM_HEX,
            &owners,
        ]);
        assert_eq!(updated["owners"].as_u64(), Some(25));
        wait_for(Duration::from_secs(180), "h3 eligible transition", || {
            all_committed(&homes, 3)
        });

        // h4: a post-transition drop still funds (sources retained).
        fs::write(
            homes[1].join("intake/three.batch"),
            plan.batches[&3].encode(),
        )
        .unwrap();
        // A malformed drop racing the same window must reject, never
        // consume a height. A LATE duplicate - batch 2 re-dropped after
        // room-2 already committed - must fail re-prepare the same way.
        fs::write(homes[2].join("intake/junk.batch"), b"not a batch").unwrap();
        fs::write(
            homes[3].join("intake/late.batch"),
            plan.batches[&2].encode(),
        )
        .unwrap();
        wait_for(Duration::from_secs(150), "h4 set-wide", || {
            all_committed(&homes, 4)
        });
        wait_for(Duration::from_secs(90), "junk and late rejected", || {
            homes[2].join("intake/junk.rejected").exists()
                && homes[3].join("intake/late.rejected").exists()
        });

        // The operator schedules the rotation: five validators activate
        // at h7. Incumbents update live - committed=4 freezes the
        // decided prefix - then rolling-restart to load the schedule,
        // with h5 dropping mid-restart so member 0 rejoins through sync.
        let net_v2 = temp.path("network-v2.json");
        let ext = rooms_ok(&[
            "network-extend",
            net.to_str().unwrap(),
            net_v2.to_str().unwrap(),
            "--from",
            "7",
            "--validators",
            &members
                .iter()
                .map(|m| format!("{}:1", key(m)))
                .collect::<Vec<_>>()
                .join(","),
        ]);
        assert_eq!(ext["activation_from"].as_u64(), Some(7));
        for home in homes.iter() {
            let upd = rooms_ok(&[
                "node-update",
                home.to_str().unwrap(),
                "--network",
                net_v2.to_str().unwrap(),
            ]);
            assert_eq!(upd["committed"].as_u64(), Some(4));
        }

        sigint(&mut nodes[0]);
        fs::write(
            homes[1].join("intake/four.batch"),
            plan.batches[&4].encode(),
        )
        .unwrap();
        nodes[0] = spawn(&temp, 0, &socials, &homes);
        wait_for(
            Duration::from_secs(180),
            "h5 during member-0 restart",
            || all_committed(&homes, 5),
        );
        for (i, node) in nodes.iter_mut().enumerate().take(4).skip(1) {
            sigint(node);
            *node = spawn(&temp, i, &socials, &homes);
        }

        // The joiner scaffolds onto v2 and syncs the decided prefix.
        let home4 = temp.path("home-4");
        let peers4 = members[..4]
            .iter()
            .map(|m| format!("127.0.0.1:{}", m.port))
            .collect::<Vec<_>>()
            .join(",");
        let out = rooms_ok(&[
            "node-init",
            home4.to_str().unwrap(),
            "--network",
            net_v2.to_str().unwrap(),
            "--node-key",
            &hex(&members[4].seed),
            "--port",
            &members[4].port.to_string(),
            "--peers",
            &peers4,
        ]);
        assert_eq!(out["node_key_votes_from"].as_u64(), Some(7));
        let social4 = temp.path("social-4");
        seed_social(&social4, &plan);
        homes.push(home4);
        socials.push(social4);
        nodes.push(spawn(&temp, 4, &socials, &homes));

        // h6: still the four-member set; the joiner follows on sync.
        fs::write(
            homes[2].join("intake/five.batch"),
            plan.batches[&5].encode(),
        )
        .unwrap();
        wait_for(Duration::from_secs(180), "h6 with joiner synced", || {
            all_committed(&homes, 6)
        });

        // h7 is the activation: five-member quorum needs 4 votes. The
        // drop lands at member 1 the instant member 2 is SIGKILLed - the
        // survivors are exactly {0,1,3,4}, so the joiner's vote is what
        // carries the height.
        fs::write(homes[1].join("intake/six.batch"), plan.batches[&6].encode()).unwrap();
        sigkill(&mut nodes[2]);
        wait_for(
            Duration::from_secs(240),
            "h7 activates the fifth without member 2",
            || [0usize, 1, 3, 4].iter().all(|&i| committed(&homes[i], 7)),
        );

        // Member 2 replays its WAL, syncs the gap and rejoins for h8.
        nodes[2] = spawn(&temp, 2, &socials, &homes);
        fs::write(
            homes[3].join("intake/seven.batch"),
            plan.batches[&7].encode(),
        )
        .unwrap();
        wait_for(Duration::from_secs(180), "h8 after crash recovery", || {
            all_committed(&homes, 8)
        });

        // The rotated quorum is real: kill two originals and the three
        // survivors {2,3,4} cannot reach 4 votes - h9 must stall even
        // though member 2's intake holds the drop.
        sigkill(&mut nodes[0]);
        sigkill(&mut nodes[1]);
        fs::write(
            homes[2].join("intake/eight.batch"),
            plan.batches[&8].encode(),
        )
        .unwrap();
        thread::sleep(Duration::from_secs(30));
        assert!(
            ![2usize, 3, 4].iter().any(|&i| committed(&homes[i], 9)),
            "three of five must not reach the four-vote quorum"
        );

        // Heal: both originals return, the stalled drop commits, and the
        // full set converges on h9.
        nodes[0] = spawn(&temp, 0, &socials, &homes);
        nodes[1] = spawn(&temp, 1, &socials, &homes);
        wait_for(Duration::from_secs(300), "h9 after heal", || {
            all_committed(&homes, 9)
        });
        assert!(
            !homes.iter().any(|h| committed(h, 10)),
            "the duplicate must not have burned a second height"
        );

        for node in nodes.iter_mut() {
            sigint(node);
        }

        // Convergence audit: every member committed exactly h1..h9 with
        // identical committed content - the bundle's certificate field is
        // per-member evidence (any quorum subset is valid) so equality is
        // over every other field: frontier pins, batch, value, config,
        // control record, debit marker, height. The materialized
        // registries are identical, room-2 exists once, all intake drops
        // resolved and no pending body is left behind.
        fn bundle_fields(bytes: &[u8]) -> Vec<&[u8]> {
            let mut fields = Vec::new();
            let mut cur = &bytes[4..];
            while cur.len() >= 8 {
                let len = u64::from_le_bytes(cur[..8].try_into().unwrap()) as usize;
                cur = &cur[8..];
                fields.push(&cur[..len]);
                cur = &cur[len..];
            }
            fields
        }
        let mut reference: Option<Vec<serde_json::Value>> = None;
        let mut journal_reference: Option<Vec<Vec<Vec<u8>>>> = None;
        for (i, home) in homes.iter().enumerate() {
            assert!(committed(home, 9), "member {i} must hold h9");
            let journals: Vec<Vec<Vec<u8>>> = (1..=9u64)
                .map(|h| {
                    let id = fs::read(home.join(format!("app/journal/heights/{h:016x}")))
                        .unwrap_or_else(|_| panic!("member {i} missing height {h}"));
                    assert_eq!(id.len(), 32, "member {i} h{h} marker corrupt");
                    let bytes = fs::read(home.join(format!("app/journal/bundles/{}", hex(&id))))
                        .unwrap_or_else(|_| panic!("member {i} missing bundle for h{h}"));
                    let fields = bundle_fields(&bytes);
                    assert_eq!(fields.len(), 9, "member {i} h{h} bundle malformed");
                    assert!(
                        !fields[0].is_empty(),
                        "member {i} h{h} stored no commit certificate"
                    );
                    assert_eq!(
                        fields[8],
                        h.to_le_bytes(),
                        "member {i} h{h} bundle commits a different height"
                    );
                    fields[1..].iter().map(|f| f.to_vec()).collect()
                })
                .collect();
            if let Some(journal_reference) = &journal_reference {
                assert_eq!(
                    &journals, journal_reference,
                    "member {i} committed different content"
                );
            } else {
                journal_reference = Some(journals);
            }
            let listed = rooms_ok(&[
                "list",
                socials[i].to_str().unwrap(),
                home.join("app/rooms").to_str().unwrap(),
                REALM_HEX,
            ]);
            let mut rows = listed["rooms"].as_array().unwrap().clone();
            rows.sort_by_key(|r| r["slug"].as_str().unwrap_or_default().to_owned());
            if let Some(reference) = &reference {
                assert_eq!(&rows, reference, "member {i} diverged: {listed}");
            } else {
                let slugs: Vec<&str> = rows.iter().filter_map(|r| r["slug"].as_str()).collect();
                for n in 1..=8 {
                    let slug = format!("room-{n}");
                    assert_eq!(
                        slugs.iter().filter(|s| **s == slug).count(),
                        1,
                        "{slug} must exist exactly once: {listed}"
                    );
                }
                assert_eq!(rows.len(), 8, "exactly the eight rooms: {listed}");
                reference = Some(rows);
            }
            let pending = home.join("store/pending");
            let leftovers: Vec<_> = fs::read_dir(&pending)
                .map(|d| d.flatten().collect())
                .unwrap_or_default();
            assert!(
                leftovers.is_empty(),
                "member {i} has unresolved pending bodies: {leftovers:?}"
            );
            let intake_leftovers: Vec<_> = fs::read_dir(home.join("intake"))
                .unwrap()
                .flatten()
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_str().unwrap_or_default();
                    name.ends_with(".batch")
                        || name.ends_with(".body")
                        || name.ends_with(".eligible")
                })
                .collect();
            assert!(
                intake_leftovers.is_empty(),
                "member {i} has undrained intake drops: {intake_leftovers:?}"
            );
        }

        // The joiner's own replica independently materializes the full
        // history - the `rooms status` live-read path on the member that
        // synced rather than proposed the early heights.
        let replica = temp.path("replica-4");
        let status = rooms_ok(&[
            "status",
            socials[4].to_str().unwrap(),
            replica.to_str().unwrap(),
            REALM_HEX,
            homes[4].to_str().unwrap(),
            "--config",
            homes[4].join("node.json").to_str().unwrap(),
        ]);
        assert_eq!(status["height"].as_u64(), Some(9));
        assert_eq!(
            status["rooms"].as_array().unwrap().len(),
            8,
            "the joiner's replica must show all eight rooms: {status}"
        );
    }

    /// The power-outage scenario: every member dies at once while a drop
    /// is mid-flight. Whether the body was still in intake, queued under
    /// `store/pending`, or partially voted through the WAL, the rebooted
    /// mesh must resume, commit it once, and keep deciding - no lost
    /// submissions, no divergent state.
    #[test]
    fn live_mesh_full_restart_resumes_mid_flight() {
        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(3, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [80 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let mut homes = Vec::new();
        let mut socials = Vec::new();
        let mut nodes = Vec::new();
        for (i, member) in members.iter().enumerate() {
            let (social, home) = member_dirs(&temp, i, member, &members, &plan);
            homes.push(home.clone());
            socials.push(social.clone());
            nodes.push(spawn_member(&temp, i, &social, &home));
        }
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        wait_for(Duration::from_secs(150), "h1 set-wide", || {
            homes.iter().all(|h| committed(h, 1))
        });

        // The drop must be durably accepted before the kill: wait for
        // member 1's store/pending marker so the body is queued - or
        // already assembled into a value mid-vote - rather than still a
        // loose intake file. Then the whole mesh dies at once.
        fs::write(homes[1].join("intake/two.batch"), plan.batches[&2].encode()).unwrap();
        wait_for(
            Duration::from_secs(90),
            "member 1 persists the body",
            || {
                fs::read_dir(homes[1].join("store/pending"))
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            },
        );
        for node in nodes.iter_mut() {
            let killed = Command::new("kill")
                .args(["-9", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(killed.success());
        }
        for node in nodes.iter_mut() {
            let _ = node.child.wait();
        }
        for (i, node) in nodes.iter_mut().enumerate() {
            *node = spawn_member(&temp, i, &socials[i], &homes[i]);
        }
        wait_for(
            Duration::from_secs(240),
            "h2 after full-mesh restart",
            || homes.iter().all(|h| committed(h, 2)),
        );

        // And the mesh keeps deciding normally afterwards.
        fs::write(
            homes[2].join("intake/three.batch"),
            plan.batches[&3].encode(),
        )
        .unwrap();
        wait_for(Duration::from_secs(180), "h3 post-restart", || {
            homes.iter().all(|h| committed(h, 3))
        });

        for node in nodes.iter_mut() {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        }

        // Every member materialized the same three rooms and left no
        // unresolved pending body behind.
        let mut reference: Option<Vec<serde_json::Value>> = None;
        for (i, home) in homes.iter().enumerate() {
            let listed = rooms_ok(&[
                "list",
                socials[i].to_str().unwrap(),
                home.join("app/rooms").to_str().unwrap(),
                REALM_HEX,
            ]);
            let mut rows = listed["rooms"].as_array().unwrap().clone();
            rows.sort_by_key(|r| r["slug"].as_str().unwrap_or_default().to_owned());
            if let Some(reference) = &reference {
                assert_eq!(&rows, reference, "member {i} diverged: {listed}");
            } else {
                assert_eq!(rows.len(), 3, "all three rooms materialized: {listed}");
                reference = Some(rows);
            }
            let leftovers: Vec<_> = fs::read_dir(home.join("store/pending"))
                .map(|d| d.flatten().collect())
                .unwrap_or_default();
            assert!(
                leftovers.is_empty(),
                "member {i} has unresolved pending bodies: {leftovers:?}"
            );
        }
    }

    /// A tailcat subprocess bound to the test — killed on drop.
    struct Tailcat {
        child: Child,
    }
    impl Drop for Tailcat {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Spawn `tailcat <args>` with captured output; `addr_file` sets
    /// TAILCAT_ADDR_FILE so a server publishes its `tc` address for the
    /// forwards to consume.
    fn tailcat(temp: &Temp, tag: &str, args: &[String], addr_file: Option<&Path>) -> Tailcat {
        let mut command = Command::new("tailcat");
        command.args(["--key=new"]).args(args);
        if let Some(path) = addr_file {
            command.env("TAILCAT_ADDR_FILE", path);
        }
        let child = command
            .stdout(Stdio::from(
                fs::File::create(temp.path(&format!("{tag}.stdout"))).unwrap(),
            ))
            .stderr(Stdio::from(
                fs::File::create(temp.path(&format!("{tag}.stderr"))).unwrap(),
            ))
            .spawn()
            .expect("tailcat must be installed to run this test");
        Tailcat { child }
    }

    /// The friends-on-different-networks path: a four-member mesh where
    /// every peer link runs through a real `tailcat` tunnel — each member
    /// serves its node port over WireGuard/DERP and reaches the others
    /// through local `tailcat forward` ports listed as its peers. This
    /// exercises magicsock NAT traversal and the DERP relay that the
    /// 768-byte/20 ms proposal pacing was qualified against. It needs
    /// outbound DERP access and the tailcat binary, so it only runs under
    /// `VHALLA_TAILCAT=1` — CI has neither.
    #[test]
    fn live_mesh_decides_over_tailcat_tunnels() {
        if std::env::var_os("VHALLA_TAILCAT").is_none() {
            eprintln!("skipping: set VHALLA_TAILCAT=1 to run the tailcat-tunnel mesh");
            return;
        }
        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(2, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [70 + i; 32],
                port: base + i as usize,
            })
            .collect();

        // Each member publishes its node port through a tailcat server
        // and collects the `tc` address peers will dial.
        let mut tc_addrs = Vec::new();
        let mut serves = Vec::new();
        for (i, member) in members.iter().enumerate() {
            let addr_file = temp.path(&format!("tc-{i}.addr"));
            serves.push(tailcat(
                &temp,
                &format!("serve-{i}"),
                &["serve".to_string(), member.port.to_string()],
                Some(&addr_file),
            ));
            tc_addrs.push(addr_file);
        }
        wait_for(Duration::from_secs(60), "tailcat addresses", || {
            tc_addrs
                .iter()
                .all(|f| fs::read_to_string(f).is_ok_and(|s| s.starts_with("tc")))
        });
        let tc_addrs: Vec<String> = tc_addrs
            .iter()
            .map(|f| fs::read_to_string(f).unwrap().trim().to_string())
            .collect();

        // Member j reaches member i through `tailcat forward tc_i
        // fwd(j,i):port_i` and lists the local forward port as the peer.
        // Forward ports are namespaced per member so every binding is
        // distinct on this one machine; on separate machines each member
        // could use the same small range.
        let fwd_base = port_base() + 4000;
        let fwd_port = |j: usize, i: usize| fwd_base + j * 10 + i;
        let mut forwards = Vec::new();
        for j in 0..members.len() {
            for i in 0..members.len() {
                if i == j {
                    continue;
                }
                forwards.push(tailcat(
                    &temp,
                    &format!("fwd-{j}-{i}"),
                    &[
                        "forward".to_string(),
                        tc_addrs[i].clone(),
                        format!("{}:{}", fwd_port(j, i), members[i].port),
                    ],
                    None,
                ));
            }
        }

        // Scaffold the shared params and member configs with the real
        // commands; each member's peer list is its forward ports.
        let key = |m: &Member| hex(PrivateKey::from(m.seed).public_key().as_bytes());
        let validators: String = members
            .iter()
            .map(|m| format!("1:{}:1", key(m)))
            .collect::<Vec<_>>()
            .join(",");
        let eligible: String = plan
            .genesis
            .eligible
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
            .join(",");
        let net = temp.path("network.json");
        rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            &format!(
                "{},{},{},{},{}",
                plan.genesis.policy.base_cost,
                plan.genesis.policy.window_seconds,
                plan.genesis.policy.max_in_window,
                plan.genesis.policy.support_epoch_seconds,
                plan.genesis.policy.max_lifetime_rooms,
            ),
            "--validators",
            &validators,
            "--eligible",
            &eligible,
        ]);
        let mut homes = Vec::new();
        let mut nodes = Vec::new();
        for (j, member) in members.iter().enumerate() {
            let home = temp.path(&format!("home-{j}"));
            let peers = (0..members.len())
                .filter(|i| *i != j)
                .map(|i| format!("127.0.0.1:{}", fwd_port(j, i)))
                .collect::<Vec<_>>()
                .join(",");
            rooms_ok(&[
                "node-init",
                home.to_str().unwrap(),
                "--network",
                net.to_str().unwrap(),
                "--node-key",
                &hex(&member.seed),
                "--port",
                &member.port.to_string(),
                "--listen",
                "127.0.0.1",
                "--peers",
                &peers,
            ]);
            let social = temp.path(&format!("social-{j}"));
            seed_social(&social, &plan);
            nodes.push(spawn_node(
                &temp,
                &format!("tc-member-{j}"),
                &social,
                &home,
                &home.join("node.json"),
            ));
            homes.push(home);
        }

        // Two heights decide over the tunnels — the first proves
        // connectivity, the second proves it survives the parts
        // re-streaming a churned relay connection forces.
        for n in 1u64..=2 {
            fs::write(
                homes[0].join(format!("intake/h{n}.batch")),
                plan.batches[&n].encode(),
            )
            .unwrap();
            wait_for(
                Duration::from_secs(240),
                &format!("height {n} set-wide over tailcat"),
                || homes.iter().all(|h| committed(h, n)),
            );
        }

        for node in nodes.iter_mut() {
            let signaled = Command::new("kill")
                .args(["-INT", &node.child.id().to_string()])
                .status()
                .unwrap();
            assert!(signaled.success());
            assert!(node.child.wait().unwrap().success());
        }
    }

    /// The operator/member scaffolding flow end to end on real commands:
    /// `network-init` authors the shared params once, `node-init` merges
    /// each member's key and networking into a working node.json,
    /// `node-check` reports the same genesis fingerprint on every member,
    /// and the resulting configs boot a deciding mesh. This is the exact
    /// journey the README hands a group of friends.
    #[test]
    fn scaffolding_produces_a_working_mesh() {
        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(2, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [40 + i; 32],
                port: base + i as usize,
            })
            .collect();

        // Operator: one canonical shared-params file covering the
        // fixture's genesis so the plan's batches stay valid.
        let validators: String = members
            .iter()
            .map(|m| {
                format!(
                    "1:{}:1",
                    hex(PrivateKey::from(m.seed).public_key().as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let eligible: String = plan
            .genesis
            .eligible
            .iter()
            .map(|id| hex(id.as_bytes()))
            .collect::<Vec<_>>()
            .join(",");
        let limits = format!(
            "{},{},{},{},{},{},{}",
            plan.genesis.limits.records,
            plan.genesis.limits.control_reserve,
            plan.genesis.limits.data_per_owner,
            plan.genesis.limits.data_per_writer,
            plan.genesis.limits.control_per_owner,
            plan.genesis.limits.pending,
            plan.genesis.limits.pending_per_signer,
        );
        let net = temp.path("network.json");
        let init = rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            &format!(
                "{},{},{},{},{}",
                plan.genesis.policy.base_cost,
                plan.genesis.policy.window_seconds,
                plan.genesis.policy.max_in_window,
                plan.genesis.policy.support_epoch_seconds,
                plan.genesis.policy.max_lifetime_rooms,
            ),
            "--validators",
            &validators,
            "--eligible",
            &eligible,
            "--limits",
            &limits,
        ]);
        // 4 equal-power validators: quorum is 3, exactly one loss held.
        assert_eq!(init["quorum_power"].as_u64(), Some(3));
        assert_eq!(init["absent_power_tolerated"].as_u64(), Some(1));
        let genesis = field(&init, "genesis");
        // A second run refuses to overwrite — the operator's file is
        // written once and distributed.
        let rerun = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args(["rooms", "network-init", net.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(!rerun.status.success(), "network-init never overwrites");

        // Members: each merges the network file with their own key,
        // port and peers — never touching the shared fields by hand.
        let mut homes = Vec::new();
        let mut socials = Vec::new();
        for (i, member) in members.iter().enumerate() {
            let home = temp.path(&format!("home-{i}"));
            let peers = members
                .iter()
                .filter(|m| m.port != member.port)
                .map(|m| format!("127.0.0.1:{}", m.port))
                .collect::<Vec<_>>()
                .join(",");
            let out = rooms_ok(&[
                "node-init",
                home.to_str().unwrap(),
                "--network",
                net.to_str().unwrap(),
                "--node-key",
                &hex(&member.seed),
                "--port",
                &member.port.to_string(),
                "--peers",
                &peers,
            ]);
            assert_eq!(
                field(&out, "genesis"),
                genesis,
                "member {i} fingerprint must equal the network file's"
            );
            assert_eq!(out["node_key_votes_from"].as_u64(), Some(1));
            assert!(out["warnings"].as_array().unwrap().is_empty());
            assert!(home.join("intake").is_dir(), "node-init creates intake");
            assert!(home.join("node.json").is_file());
            // The scaffolded home is owner-private: it holds the validator
            // seed, and intake is the producer drop boundary.
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&home), 0o700, "node home is owner-private");
            assert_eq!(mode(&home.join("intake")), 0o700);
            assert_eq!(mode(&home.join("node.json")), 0o600);
            // Idempotency is refused: a second init never overwrites.
            let again = Command::new(env!("CARGO_BIN_EXE_vhalla"))
                .env("HRANESS_SUPPORT", "off")
                .args([
                    "rooms",
                    "node-init",
                    home.to_str().unwrap(),
                    "--network",
                    net.to_str().unwrap(),
                    "--port",
                    &member.port.to_string(),
                ])
                .output()
                .unwrap();
            assert!(!again.status.success(), "node-init never overwrites");
            let social = temp.path(&format!("social-{i}"));
            seed_social(&social, &plan);
            homes.push(home);
            socials.push(social);
        }

        // node-check on member 0: identical fingerprint, the seeded
        // archive root, quorum arithmetic and a clean bill.
        let check = rooms_ok(&[
            "node-check",
            socials[0].to_str().unwrap(),
            homes[0].to_str().unwrap(),
            REALM_HEX,
            "--config",
            homes[0].join("node.json").to_str().unwrap(),
        ]);
        assert_eq!(field(&check, "genesis"), genesis);
        assert_eq!(field(&check, "archive").len(), 64);
        assert_eq!(check["node_key_votes_from"].as_u64(), Some(1));
        let sets = check["validator_sets"].as_array().unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0]["validators"].as_u64(), Some(4));
        assert_eq!(sets[0]["quorum_power"].as_u64(), Some(3));
        assert!(check["warnings"].as_array().unwrap().is_empty());

        // A tampered shared field must move the fingerprint — the whole
        // point of comparing it across members before boot.
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fs::read(homes[1].join("node.json")).unwrap()).unwrap();
        tampered["policy"]["base_cost"] = serde_json::json!(99);
        let bad = temp.path("node-bad.json");
        fs::write(&bad, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
        let bad_check = rooms_ok(&[
            "node-check",
            socials[1].to_str().unwrap(),
            homes[1].to_str().unwrap(),
            REALM_HEX,
            "--config",
            bad.to_str().unwrap(),
        ]);
        assert_ne!(
            field(&bad_check, "genesis"),
            genesis,
            "a divergent policy must change the genesis fingerprint"
        );

        // A config realm that disagrees with the REALM argument fails
        // closed — the file pins the realm it was scaffolded with.
        let wrong_realm = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node-check",
                socials[2].to_str().unwrap(),
                homes[2].to_str().unwrap(),
                "00000000000000000000000000000099",
                "--config",
                homes[2].join("node.json").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!wrong_realm.status.success());
        assert!(String::from_utf8_lossy(&wrong_realm.stderr).contains("realm"));

        // The scaffolded configs actually decide: four real subprocesses
        // mesh over loopback and commit the intake drop.
        let mut nodes = Vec::new();
        for (i, home) in homes.iter().enumerate() {
            nodes.push(spawn_node(
                &temp,
                &format!("scaf-{i}"),
                &socials[i],
                home,
                &home.join("node.json"),
            ));
        }
        fs::write(homes[0].join("intake/one.batch"), plan.batches[&1].encode()).unwrap();
        for home in &homes {
            wait_for(Duration::from_secs(150), "scaffolded mesh decides", || {
                committed(home, 1)
            });
        }
    }

    /// `node-init` without `--node-key` generates a fresh seed and
    /// reports it as a non-voter until the operator lists its public key.
    #[test]
    fn node_init_without_a_key_scaffolds_a_follower() {
        let temp = Temp::new();
        let plan = fixture::plan(1, 8, 16);
        let validator = PrivateKey::from([77; 32]);
        let net = temp.path("network.json");
        rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            "1,86400,8,86400,16",
            "--validators",
            &format!("1:{}:1", hex(validator.public_key().as_bytes())),
        ]);
        let home = temp.path("home");
        let out = rooms_ok(&[
            "node-init",
            home.to_str().unwrap(),
            "--network",
            net.to_str().unwrap(),
            "--port",
            "7400",
        ]);
        assert_eq!(out["node_key_generated"].as_bool(), Some(true));
        assert!(out["node_key_votes_from"].is_null());
        let warnings = out["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("never votes")),
            "a fresh key must warn it does not vote: {out}"
        );
        // The generated key round-trips: the config parses and the
        // reported public key is the seed's real public key.
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(home.join("node.json")).unwrap()).unwrap();
        let seed: [u8; 32] = unhex(config["node_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            hex(PrivateKey::from(seed).public_key().as_bytes()),
            field(&out, "public_key")
        );
    }

    /// The rotation commands on real invocations: `network-extend` copies
    /// shared fields verbatim and appends one future activation,
    /// `node-update` merges it into a member's existing config while
    /// refusing to touch decided-height sets or genesis fields.
    #[test]
    fn network_extend_and_node_update_rotate_the_schedule() {
        let temp = Temp::new();
        let plan = fixture::plan(1, 8, 16);
        let keys: Vec<String> = (0..4u8)
            .map(|i| hex(PrivateKey::from([90 + i; 32]).public_key().as_bytes()))
            .collect();
        let v1 = format!("1:{}:1,1:{}:1,1:{}:1", keys[0], keys[1], keys[2]);
        let net = temp.path("network.json");
        let init = rooms_ok(&[
            "network-init",
            net.to_str().unwrap(),
            "--realm",
            REALM_HEX,
            "--directory",
            &hex(plan.genesis.directory.as_bytes()),
            "--policy",
            "1,86400,8,86400,16",
            "--validators",
            &v1,
        ]);
        let genesis_v1 = field(&init, "genesis");

        // The operator extends: one complete replacement set of four at
        // height 50. Shared fields copy verbatim — only validators grow.
        let v2 = temp.path("network-v2.json");
        let ext = rooms_ok(&[
            "network-extend",
            net.to_str().unwrap(),
            v2.to_str().unwrap(),
            "--from",
            "50",
            "--validators",
            &format!("{}:1,{}:1,{}:1,{}:1", keys[0], keys[1], keys[2], keys[3]),
        ]);
        assert_eq!(ext["activation_from"].as_u64(), Some(50));
        assert_eq!(ext["validators"].as_u64(), Some(4));
        assert_eq!(ext["quorum_power"].as_u64(), Some(3));
        let genesis_v2 = field(&ext, "genesis");
        assert_ne!(
            genesis_v1, genesis_v2,
            "a changed schedule changes the fingerprint"
        );
        // The new file carries every shared field unchanged plus the
        // appended activation — and never overwrites.
        let net_v2: serde_json::Value = serde_json::from_slice(&fs::read(&v2).unwrap()).unwrap();
        assert_eq!(net_v2["validators"].as_array().unwrap().len(), 7);
        let rerun = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "network-extend",
                net.to_str().unwrap(),
                v2.to_str().unwrap(),
                "--from",
                "60",
                "--validators",
                &format!("{}:1", keys[0]),
            ])
            .output()
            .unwrap();
        assert!(!rerun.status.success(), "network-extend never overwrites");

        // Heights start at 1 — a zero activation can never take effect.
        let zero = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "network-extend",
                net.to_str().unwrap(),
                temp.path("network-v3.json").to_str().unwrap(),
                "--from",
                "0",
                "--validators",
                &format!("{}:1", keys[0]),
            ])
            .output()
            .unwrap();
        assert!(!zero.status.success(), "activation heights start at 1");
        assert!(String::from_utf8_lossy(&zero.stderr).contains("start at 1"));

        // A member joins the extended set: node-init on v1, node-update
        // to v2. Local fields survive; the schedule gains the activation.
        // The seed is keys[0]'s — a validator — so votes_from stays set.
        let home = temp.path("home");
        let seed = [90u8; 32];
        rooms_ok(&[
            "node-init",
            home.to_str().unwrap(),
            "--network",
            net.to_str().unwrap(),
            "--node-key",
            &hex(&seed),
            "--port",
            "7401",
            "--peers",
            "10.0.0.9:7000",
        ]);
        let upd = rooms_ok(&[
            "node-update",
            home.to_str().unwrap(),
            "--network",
            v2.to_str().unwrap(),
        ]);
        assert_eq!(upd["committed"].as_u64(), Some(0));
        // Nothing has committed, so both activations are still scheduled.
        let scheduled = upd["scheduled"].as_array().unwrap();
        assert_eq!(scheduled.len(), 2);
        assert_eq!(scheduled[1]["from"].as_u64(), Some(50));
        assert_eq!(field(&upd, "genesis"), genesis_v2);
        let node: serde_json::Value =
            serde_json::from_slice(&fs::read(home.join("node.json")).unwrap()).unwrap();
        assert_eq!(node["node_key"].as_str().unwrap(), hex(&seed));
        assert_eq!(node["port"].as_u64(), Some(7401));
        assert_eq!(node["peers"][0].as_str().unwrap(), "10.0.0.9:7000");
        assert_eq!(node["validators"].as_array().unwrap().len(), 7);
        assert_eq!(upd["node_key_votes_from"].as_u64(), Some(1));
        // The rewrite keeps the seed file owner-private — the atomic
        // rename replaces the inode, so the mode must be restated.
        assert_eq!(
            fs::metadata(home.join("node.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // A shared-field change is a different network, not an update.
        let mut drifted = net_v2.clone();
        drifted["policy"]["base_cost"] = serde_json::json!(9);
        let bad = temp.path("network-drifted.json");
        fs::write(&bad, serde_json::to_vec_pretty(&drifted).unwrap()).unwrap();
        let drift = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node-update",
                home.to_str().unwrap(),
                "--network",
                bad.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!drift.status.success());
        assert!(String::from_utf8_lossy(&drift.stderr).contains("genesis field"));

        // Once height 1 has committed, its activation is frozen: a file
        // that reschedules it must be refused. The journal marker names
        // are `{height:016x}` — an empty file is enough for the bound.
        fs::create_dir_all(home.join("app/journal/heights")).unwrap();
        fs::write(home.join("app/journal/heights/0000000000000001"), []).unwrap();
        let mut rewrote = net_v2.clone();
        rewrote["validators"] = serde_json::json!([
            {"from": 1, "key": keys[0], "power": 2},
            {"from": 50, "key": keys[0], "power": 1},
        ]);
        let bad = temp.path("network-rewrote.json");
        fs::write(&bad, serde_json::to_vec_pretty(&rewrote).unwrap()).unwrap();
        let rewrite = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env("HRANESS_SUPPORT", "off")
            .args([
                "rooms",
                "node-update",
                home.to_str().unwrap(),
                "--network",
                bad.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!rewrite.status.success());
        assert!(
            String::from_utf8_lossy(&rewrite.stderr).contains("decided height"),
            "frozen activations must refuse change: {}",
            String::from_utf8_lossy(&rewrite.stderr)
        );

        // The honest update still lands: frozen prefix intact, future
        // activation adopted, and the committed bound reported.
        let upd = rooms_ok(&[
            "node-update",
            home.to_str().unwrap(),
            "--network",
            v2.to_str().unwrap(),
        ]);
        assert_eq!(upd["committed"].as_u64(), Some(1));
    }

    /// A test-controlled byte pipe on one directed edge: listens on an
    /// ephemeral port and forwards to `target_port`. `up == false` drops
    /// live connections and closes new ones on accept — a real mid-flight
    /// link failure; `up == true` resumes forwarding, so libp2p's
    /// persistent-peer re-dial re-establishes the edge without a restart.
    struct Link {
        up: Arc<AtomicBool>,
        port: usize,
    }

    fn spawn_link(target_port: usize) -> Link {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port() as usize;
        let up = Arc::new(AtomicBool::new(true));
        let flag = up.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut inbound) = stream else { continue };
                if !flag.load(Ordering::Relaxed) {
                    continue; // partitioned: refuse the dial outright
                }
                let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target_port as u16)) else {
                    continue;
                };
                for s in [&inbound, &outbound] {
                    s.set_read_timeout(Some(Duration::from_millis(200)))
                        .unwrap();
                }
                let mut ret_in = inbound.try_clone().unwrap();
                let mut ret_out = outbound.try_clone().unwrap();
                let (f1, f2) = (flag.clone(), flag.clone());
                thread::spawn(move || pump(&mut inbound, &mut outbound, &f1));
                thread::spawn(move || pump(&mut ret_out, &mut ret_in, &f2));
            }
        });
        Link { up, port }
    }

    /// Forward bytes until the peer closes or the link drops; the read
    /// timeout lets a severed link notice `up` even when no data flows.
    fn pump(from: &mut TcpStream, to: &mut TcpStream, up: &AtomicBool) {
        let mut buf = [0u8; 8192];
        loop {
            if !up.load(Ordering::Relaxed) {
                return;
            }
            match from.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    if to.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => return,
            }
        }
    }

    /// Flip every edge incident to `member` in both directions: `false`
    /// severs (the node keeps running, voting into the void), `true`
    /// heals (persistent-peer re-dial resumes the flows).
    fn set_member_isolated(links: &BTreeMap<(usize, usize), Link>, member: usize, up: bool) {
        for (&(i, j), link) in links {
            if (i == member) != (j == member) {
                link.up.store(up, Ordering::Relaxed);
            }
        }
    }

    /// Read one journaled (certificate, batch) pair out of a node home's
    /// own `app/journal` store — the real `VC2` bytes a separate process
    /// wrote, not a fixture.
    fn read_decided(
        home: &Path,
        height: u64,
    ) -> (
        vhalla_rooms_consensus::CommitCertificate,
        vhalla_rooms_consensus::Batch,
    ) {
        // Pure reads only: `recover` is writer-side boot recovery that drops
        // residue markers, and a live writer can publish a height marker
        // before its pin lands — calling it here could erase a live marker.
        // The marker is written after the bundle syncs, so marker ⇒ bundle.
        let journal =
            vhalla_journal::Journal::new(home.join("app/journal"), vhalla_journal::FsStore);
        let id = journal.at_height(height).unwrap().unwrap();
        let bundle = journal.bundle(id).unwrap().unwrap();
        let batch = vhalla_rooms_consensus::Batch::decode(bundle.field(3).unwrap()).unwrap();
        (
            vhalla_rooms_consensus::CommitCertificate {
                bytes: bundle.field(0).unwrap().to_vec(),
                height,
                value_commitment: batch.value_id(),
            },
            batch,
        )
    }

    /// A structurally valid fabricated quorum session for lane-decision
    /// tests: one open slot, one real-key player, `Authority::Quorum` over a
    /// tag-derived scheme. Game semantics are out of scope for the transport
    /// boundary; the full session drive stays with the in-process suite.
    fn quorum_game_fixture(
        tag: &str,
    ) -> (
        vhalla_game_platonik::manifest::GameManifest,
        vhalla_game_platonik::wire::SessionOpen,
        [u8; 32],
    ) {
        use vhalla_core::{Epoch, RealmId, RoomId};
        use vhalla_game_platonik::ids::RulesetId;
        use vhalla_game_platonik::manifest::{
            GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
            VerificationAllowance,
        };
        use vhalla_game_platonik::session::seed_commitment;
        use vhalla_game_platonik::wire::{Authority, Player, SessionOpen};
        use vhalla_witness::hash::{ManifestHash, ProgramHash};
        use vhalla_witness::manifest::WorkContract;
        use vhalla_witness::platform::WorkAllowance;

        let scheme = ProgramHash::of(format!("vhalla/test/{tag}/scheme/v1").as_bytes()).0;
        let world = ManifestHash::of(format!("vhalla/test/{tag}/world/v1").as_bytes());
        let host_salt = ProgramHash::of(format!("vhalla/test/{tag}/host-salt/v1").as_bytes()).0;
        let manifest = GameManifest {
            ruleset: RulesetId::V1,
            world,
            slots: vec![GameSlot {
                cell: 3,
                role: SlotRole::Open { fallback: None },
            }],
            contract: WorkContract {
                useful_floor: 0,
                total_ceiling: 1_000,
                require_passed: true,
            },
            loading_work: vec![1],
            artifacts: Vec::new(),
            limits: SessionLimits {
                max_events: 64,
                max_segments: 4,
                replay: WorkAllowance { max_total: 1_000 },
                verification: VerificationAllowance {
                    max_replays: 4,
                    max_work: 4_000,
                    max_event_bytes: 1_024,
                    max_artifact_bytes: 1_024,
                },
                missing_member: MissingMember::Pause,
                kind: SessionKind::Live,
            },
            publisher: ProgramHash::of(format!("vhalla/test/{tag}/publisher/v1").as_bytes()).0,
        };
        let open = SessionOpen {
            realm: RealmId(3),
            room: RoomId(4),
            manifest: manifest.hash(),
            ruleset: RulesetId::V1,
            seed_commitment: seed_commitment(&host_salt, world),
            authority: Authority::Quorum { scheme },
            players: vec![Player {
                key: *PrivateKey::from([71; 32]).public_key().as_bytes(),
                slots: vec![3],
            }],
            epoch: Epoch(0),
            nonce: ProgramHash::of(format!("vhalla/test/{tag}/nonce/v1").as_bytes()).0,
        };
        (manifest, open, scheme)
    }

    /// The certificate verify hook over the set every member config carries.
    fn game_verify(members: &[Member]) -> impl Fn(&[u8], u64, &[u8; 32]) -> bool {
        use vhalla_rooms_node::cert::verify_canonical_certificate;
        use vhalla_rooms_node::{RoomValidator, RoomValidatorSet, RoomValueId};

        let set = RoomValidatorSet::new(
            members
                .iter()
                .map(|m| RoomValidator::new(PrivateKey::from(m.seed).public_key(), 1))
                .collect(),
        );
        move |bytes, height, value| {
            verify_canonical_certificate(bytes, height, &RoomValueId(*value), &set)
        }
    }

    /// A `.body` intake drop carrying one game-commitment lane at `height`.
    fn drop_game_body(
        home: &Path,
        name: &str,
        time: u64,
        lane: vhalla_rooms_consensus::GameCommitment,
    ) {
        let body = vhalla_rooms_consensus::BatchBody {
            time,
            evidence: Vec::new(),
            records: Vec::new(),
            games: vec![lane],
            eligible: None,
        };
        fs::write(home.join(format!("intake/{name}.body")), body.encode()).unwrap();
    }

    /// An actor-authored event record and its game lane at `sequence` — the
    /// quorum actor is unforgeable, so the record carries the enforced zero
    /// signature.
    fn actor_event_lane(
        session: &vhalla_game_platonik::session::Session,
        scheme: &[u8; 32],
        sequence: u64,
    ) -> (
        vhalla_game_platonik::record::GameRecord,
        vhalla_rooms_consensus::GameCommitment,
    ) {
        use vhalla_core::{Epoch, Sequence};
        use vhalla_game_platonik::quorum::commitment;
        use vhalla_game_platonik::record::{GameRecord, RecordKind};
        use vhalla_game_platonik::session::quorum_actor;
        use vhalla_game_platonik::wire::{encode_game_event, EventBody, GameEvent};

        let actor = quorum_actor(scheme);
        let event = GameEvent {
            session: session.key(),
            epoch: Epoch(0),
            author: actor,
            sequence: Sequence(sequence),
            parents: Vec::new(),
            body: EventBody::BindClose {
                commits: Vec::new(),
            },
        };
        let record = GameRecord::unsigned(
            RecordKind::Event,
            session.key(),
            actor,
            encode_game_event(&event),
        )
        .unwrap();
        let lane = commitment(session, &record).unwrap();
        (record, lane)
    }

    /// Two real `rooms node` subprocesses mesh over loopback while `.body`
    /// drops carry game-commitment lanes: the decided values journal `VC2`
    /// certificates that verify under the committed two-key set, the
    /// `SessionOpen` commitment read back cross-process opens a quorum
    /// session, and a record commitment decided at the next height mints a
    /// `prove` proof. Remote qualification ends at open + prove — the
    /// full session drive (binds, seals, settlement, attestation) is the
    /// in-process suite's job.
    #[test]
    fn remote_intake_decides_game_lanes_and_opens_a_quorum_session() {
        use vhalla_core::RealmId;
        use vhalla_game_platonik::quorum::{open as quorum_open, open_commitment, prove};
        use vhalla_rooms_consensus::GameCommitmentKind;

        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(2, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..2u8)
            .map(|i| Member {
                seed: [60 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let (socials, homes): (Vec<_>, Vec<_>) = (0..2)
            .map(|i| member_dirs(&temp, i, &members[i], &members, &plan))
            .unzip();
        let nodes: Vec<Node> = (0..2)
            .map(|i| spawn_member(&temp, i, &socials[i], &homes[i]))
            .collect();

        // The session the lane will decide: `open.key()` fixes the session
        // identity before any certificate exists, so every lane value is
        // computable up front or once the session opens. `verify` is the
        // certificate hook a consumer runs over the committed set.
        let (manifest, open, scheme) = quorum_game_fixture("remote-game");
        let verify = game_verify(&members);

        // Height 1: the SessionOpen commitment drops into member 0's
        // intake in the native `.body` producer format and decides on
        // both processes' journals.
        drop_game_body(
            &homes[0],
            "h1",
            plan.batches[&1].time,
            open_commitment(&open),
        );
        for home in &homes {
            wait_for(Duration::from_secs(150), "h1 game lane to decide", || {
                committed(home, 1)
            });
        }
        let (c1, b1) = read_decided(&homes[0], 1);
        assert!(verify(&c1.bytes, 1, &c1.value_commitment));
        assert_eq!(b1.games, vec![open_commitment(&open)]);
        let session = quorum_open(
            manifest.clone(),
            open.clone(),
            RealmId(3),
            &c1,
            &b1,
            0,
            &verify,
        )
        .unwrap();
        // The same evidence at the wrong lane position cannot open.
        assert!(quorum_open(manifest, open, RealmId(3), &c1, &b1, 1, &verify).is_err());

        // Height 2: an actor-authored event record's commitment — the
        // quorum actor is unforgeable, so the record carries the enforced
        // zero signature — drops into member 1's intake and decides.
        let (record, lane) = actor_event_lane(&session, &scheme, 1);
        assert_eq!(lane.kind, GameCommitmentKind::Event);
        drop_game_body(&homes[1], "h2", plan.batches[&2].time, lane);
        for home in &homes {
            wait_for(Duration::from_secs(150), "h2 game lane to decide", || {
                committed(home, 2)
            });
        }

        // Member 1's own journal serves h2: cert bytes written by a
        // separate process, verified under the same committed set, and
        // the record's commitment at lane position 0 mints a proof.
        let (c2, b2) = read_decided(&homes[1], 2);
        assert!(verify(&c2.bytes, 2, &c2.value_commitment));
        assert_eq!(b2.games, vec![lane]);
        let _proof = prove(&session, &record, &c2, &b2, 0, &verify).unwrap();
        drop(nodes);
    }

    /// A real link partition over TCP: every directed edge between members
    /// runs through a test pipe that severs mid-stream. Member 3 is
    /// partitioned while {0,1,2} — exactly quorum of the four-member set —
    /// decide a game-commitment lane; on heal the still-running member
    /// re-dials, syncs the decided value, and its journal serves a
    /// certificate the quorum session consumes. This is the boundary the
    /// in-process suite cannot express: static persistent peers never
    /// model a link dying under live traffic.
    #[test]
    fn remote_game_lanes_cross_a_healed_link_partition() {
        use vhalla_core::RealmId;
        use vhalla_game_platonik::quorum::{open as quorum_open, open_commitment, prove};
        use vhalla_rooms_consensus::GameCommitmentKind;

        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(2, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [80 + i; 32],
                port: base + i as usize,
            })
            .collect();

        // One pipe per directed edge: member i's `peers` entry for j is
        // links[(i,j)], forwarding to j's real listener. Severing every
        // edge incident to member 3 isolates it in both directions while
        // it keeps running.
        let mut links = BTreeMap::new();
        for i in 0..members.len() {
            for (j, target) in members.iter().enumerate() {
                if i != j {
                    links.insert((i, j), spawn_link(target.port));
                }
            }
        }

        let (socials, homes): (Vec<_>, Vec<_>) = (0..members.len())
            .map(|i| member_dirs(&temp, i, &members[i], &members, &plan))
            .unzip();
        for (i, member) in members.iter().enumerate() {
            write_proxied_mesh_config(
                &temp.path(&format!("node-{i}.json")),
                i,
                member,
                &members,
                &links,
                &plan,
            );
        }
        let nodes: Vec<Node> = (0..members.len())
            .map(|i| spawn_member(&temp, i, &socials[i], &homes[i]))
            .collect();

        // The session the lane decides: identical in shape to the remote
        // intake test's — the transport boundary is what differs.
        let (manifest, open, scheme) = quorum_game_fixture("partition-game");
        let verify = game_verify(&members);

        // Height 1 with the whole mesh linked: the SessionOpen commitment
        // decides under all four votes.
        drop_game_body(
            &homes[0],
            "h1",
            plan.batches[&1].time,
            open_commitment(&open),
        );
        for home in &homes {
            wait_for(Duration::from_secs(150), "h1 game lane to decide", || {
                committed(home, 1)
            });
        }

        // Partition member 3: sever every edge incident to it in both
        // directions. The node keeps running — it just cannot reach the
        // mesh, which is the case a kill -9 cannot express.
        set_member_isolated(&links, 3, false);
        thread::sleep(Duration::from_secs(1)); // let live pumps notice

        // `commitment` needs the opened session, which exists once h1's
        // certificate is consumed — the session opens from member 0's
        // journaled evidence before the h2 lane is even computed.
        let (c1, b1) = read_decided(&homes[0], 1);
        assert!(verify(&c1.bytes, 1, &c1.value_commitment));
        assert_eq!(b1.games, vec![open_commitment(&open)]);
        let session = quorum_open(
            manifest.clone(),
            open.clone(),
            RealmId(3),
            &c1,
            &b1,
            0,
            &verify,
        )
        .unwrap();
        assert!(quorum_open(manifest, open, RealmId(3), &c1, &b1, 1, &verify).is_err());

        // Height 2 decided by exactly-quorum {0,1,2}: an actor-authored
        // event commitment drops into member 1's intake.
        let (record, lane) = actor_event_lane(&session, &scheme, 1);
        assert_eq!(lane.kind, GameCommitmentKind::Event);
        drop_game_body(&homes[1], "h2", plan.batches[&2].time, lane);
        for home in homes.iter().take(3) {
            wait_for(
                Duration::from_secs(150),
                "h2 game lane to decide under partition",
                || committed(home, 2),
            );
        }
        // The partitioned member must not have h2 — it is alive and voting
        // into the void, not slow or crashed.
        assert!(
            !committed(&homes[3], 2),
            "partitioned member received h2: the links did not isolate it"
        );

        // Heal: every incident edge resumes; persistent-peer re-dial plus
        // value sync carry the decided h2 to member 3 without a restart.
        set_member_isolated(&links, 3, true);
        wait_for(
            Duration::from_secs(150),
            "partitioned member to sync h2 after heal",
            || committed(&homes[3], 2),
        );

        // Member 3's own journal — evidence received purely over the
        // healed partition — verifies under the committed set, and the
        // record's commitment at lane position 0 mints a proof.
        let (c2, b2) = read_decided(&homes[3], 2);
        assert!(verify(&c2.bytes, 2, &c2.value_commitment));
        assert_eq!(b2.games, vec![lane]);
        let _proof = prove(&session, &record, &c2, &b2, 0, &verify).unwrap();
        drop(nodes);
    }

    /// Multi-round resupply under churn: member 3 accumulates a
    /// three-height decided-value deficit while exactly-quorum {0,1,2}
    /// keeps deciding game lanes, then catches every missed height up over
    /// the healed link without a restart — and member 1 survives the same
    /// partition/resync cycle on the height that follows. Resupply is
    /// exercised across repeated cycles and members, not once.
    #[test]
    fn remote_partitioned_members_resync_decided_lanes_under_churn() {
        use vhalla_core::RealmId;
        use vhalla_game_platonik::quorum::{open as quorum_open, open_commitment, prove};

        let _mesh = mesh();
        let temp = Temp::new();
        let plan = fixture::plan(5, 8, 16);
        let base = port_base();
        let members: Vec<Member> = (0..4u8)
            .map(|i| Member {
                seed: [90 + i; 32],
                port: base + i as usize,
            })
            .collect();
        let mut links = BTreeMap::new();
        for i in 0..members.len() {
            for (j, target) in members.iter().enumerate() {
                if i != j {
                    links.insert((i, j), spawn_link(target.port));
                }
            }
        }
        let (socials, homes): (Vec<_>, Vec<_>) = (0..members.len())
            .map(|i| member_dirs(&temp, i, &members[i], &members, &plan))
            .unzip();
        for (i, member) in members.iter().enumerate() {
            write_proxied_mesh_config(
                &temp.path(&format!("node-{i}.json")),
                i,
                member,
                &members,
                &links,
                &plan,
            );
        }
        let nodes: Vec<Node> = (0..members.len())
            .map(|i| spawn_member(&temp, i, &socials[i], &homes[i]))
            .collect();

        let (manifest, open, scheme) = quorum_game_fixture("churn-game");
        let verify = game_verify(&members);

        // h1 under the whole mesh: the SessionOpen commitment decides
        // under all four votes and the session opens from the journaled
        // evidence.
        drop_game_body(
            &homes[0],
            "h1",
            plan.batches[&1].time,
            open_commitment(&open),
        );
        for home in &homes {
            wait_for(Duration::from_secs(150), "h1 game lane to decide", || {
                committed(home, 1)
            });
        }
        let (c1, b1) = read_decided(&homes[0], 1);
        assert!(verify(&c1.bytes, 1, &c1.value_commitment));
        let session = quorum_open(
            manifest.clone(),
            open.clone(),
            RealmId(3),
            &c1,
            &b1,
            0,
            &verify,
        )
        .unwrap();

        // Member 3 isolated: exactly-quorum {0,1,2} decides h2–h4 while it
        // keeps running and voting into the void — a three-height deficit
        // accumulated under sustained decision, not a single gap.
        set_member_isolated(&links, 3, false);
        thread::sleep(Duration::from_secs(1));
        let mut records = Vec::new();
        for h in 2..=4u64 {
            let (record, lane) = actor_event_lane(&session, &scheme, h - 1);
            drop_game_body(
                &homes[h as usize - 2],
                &format!("h{h}"),
                plan.batches[&h].time,
                lane,
            );
            for home in homes.iter().take(3) {
                wait_for(
                    Duration::from_secs(150),
                    "game lane to decide under partition",
                    || committed(home, h),
                );
            }
            assert!(
                !committed(&homes[3], h),
                "partitioned member received h{h}: the links did not isolate it"
            );
            records.push(record);
        }

        // Heal: member 3 resyncs all three missed heights without a
        // restart, and each resynced journal bundle verifies under the
        // committed set — the middle deficit height's cert mints a proof.
        set_member_isolated(&links, 3, true);
        wait_for(
            Duration::from_secs(150),
            "member 3 to resync the decided heights after heal",
            || committed(&homes[3], 4),
        );
        for h in 2..=4u64 {
            let (cert, batch) = read_decided(&homes[3], h);
            assert!(verify(&cert.bytes, h, &cert.value_commitment));
            assert_eq!(batch.games.len(), 1);
        }
        let (c3, b3) = read_decided(&homes[3], 3);
        let _proof = prove(&session, &records[1], &c3, &b3, 0, &verify).unwrap();

        // Second churn cycle, different member: partition member 1, let
        // {0,2,3} decide h5, then heal — member 1 resyncs and its own
        // journal serves the certificate the proof consumes.
        set_member_isolated(&links, 1, false);
        thread::sleep(Duration::from_secs(1));
        let (record5, lane5) = actor_event_lane(&session, &scheme, 4);
        drop_game_body(&homes[2], "h5", plan.batches[&5].time, lane5);
        for i in [0usize, 2, 3] {
            wait_for(
                Duration::from_secs(150),
                "h5 game lane to decide under the second partition",
                || committed(&homes[i], 5),
            );
        }
        assert!(
            !committed(&homes[1], 5),
            "partitioned member received h5: the links did not isolate it"
        );
        set_member_isolated(&links, 1, true);
        wait_for(
            Duration::from_secs(150),
            "member 1 to resync h5 after heal",
            || committed(&homes[1], 5),
        );
        let (c5, b5) = read_decided(&homes[1], 5);
        assert!(verify(&c5.bytes, 5, &c5.value_commitment));
        assert_eq!(b5.games, vec![lane5]);
        let _proof = prove(&session, &record5, &c5, &b5, 0, &verify).unwrap();
        drop(nodes);
    }

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

        // `rooms status` is the live-mesh read: the node still runs and
        // still holds its `app/rooms` writer lock, yet the replica sync
        // reports height, the room listing and marker resolution in one
        // object.
        let status = rooms_ok(&[
            "status",
            net.to_str().unwrap(),
            replica_store.to_str().unwrap(),
            REALM_HEX,
            home.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ]);
        assert_eq!(status["height"].as_u64(), Some(1));
        assert!(
            status["rooms"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["slug"].as_str() == Some("first-room")),
            "status must list the committed room live: {status}"
        );
        let status_marker = status["pending"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["marker"].as_str() == Some(marker.as_str()))
            .expect("status must resolve the same marker");
        assert_eq!(status_marker["state"].as_str(), Some("committed"));
    }
}
