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
}
