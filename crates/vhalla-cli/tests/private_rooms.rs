//! Local-only maintained custody/CLI journeys. No listener, relay or user state.
#![cfg(all(unix, feature = "experimental-private"))]
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{symlink, DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
    now: u64,
    owner: String,
    member: String,
}
impl Fixture {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let root = std::env::temp_dir().join(format!(
            "vhalla-private-cli-{}-{}-{}",
            std::process::id(),
            time.as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let key = |name: &str| {
            let id = vhalla_identity::Identity::create_new(root.join(name)).unwrap();
            id.public_key().iter().map(|v| format!("{v:02x}")).collect()
        };
        let owner = key("owner-key");
        let member = key("member-key");
        Self {
            root,
            now: time.as_secs(),
            owner,
            member,
        }
    }
    fn path(&self, name: &str) -> String {
        self.root.join(name).to_str().unwrap().to_owned()
    }
    fn write(&self, name: &str, raw: &[u8]) {
        fs::write(self.root.join(name), raw).unwrap();
        fs::set_permissions(self.root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn validity(&self) -> Vec<(&'static str, String)> {
        vec![
            ("not-before", (self.now - 30).to_string()),
            ("expires", (self.now + 3600).to_string()),
        ]
    }
    fn run(
        &self,
        command: &str,
        identity: &str,
        store: Option<&str>,
        options: &[(&str, String)],
        input: Option<&[u8]>,
    ) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        cmd.args(["private", command]).arg(self.root.join(identity));
        if let Some(store) = store {
            cmd.arg(self.root.join(store));
        }
        for (flag, value) in options {
            cmd.arg(format!("--{flag}")).arg(value);
        }
        let mut child = cmd
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
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("private CLI bounded local command exceeded deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        child.wait_with_output().unwrap()
    }
    fn ok(&self, cmd: &str, identity: &str, store: Option<&str>, options: &[(&str, String)]) {
        let result = self.run(cmd, identity, store, options, None);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&result.stdout),
            "private local operation completed; no network delivery performed\n"
        );
    }
    fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }
    fn inspect(&self, identity: &str, store: &str, name: &str) -> Value {
        self.ok(
            "inspect",
            identity,
            Some(store),
            &[("out", self.path(name))],
        );
        self.json(name)
    }
    fn snapshot(&self, store: &str) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(self.root.join(store))
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    fn join(&self) {
        self.ok("create", "owner-key", Some("owner-room"), &self.validity());
        let mut flags = self.validity();
        flags.extend([
            ("recipient", self.member.clone()),
            ("operation", op(1)),
            ("out", self.path("offer")),
        ]);
        self.ok("offer", "owner-key", Some("owner-room"), &flags);
        self.ok(
            "offer-inspect",
            "member-key",
            None,
            &[
                ("offer", self.path("offer")),
                ("owner", self.owner.clone()),
                ("out", self.path("offer-metadata")),
            ],
        );
        let inspected = self.json("offer-metadata");
        let mut flags = self.validity();
        flags.extend([
            ("offer", self.path("offer")),
            ("owner", self.owner.clone()),
            ("room", inspected["room"].as_str().unwrap().into()),
            ("anchor", inspected["anchor"].as_str().unwrap().into()),
        ]);
        self.ok("import", "member-key", Some("member-room"), &flags);
        self.ok(
            "request",
            "member-key",
            Some("member-room"),
            &[
                ("offer", self.path("offer")),
                ("operation", op(1)),
                ("out", self.path("request")),
            ],
        );
        let mut flags = self.validity();
        flags.extend([
            ("request", self.path("request")),
            ("operation", op(2)),
            ("out", self.path("response")),
        ]);
        self.ok("accept", "owner-key", Some("owner-room"), &flags);
        self.ok(
            "join",
            "member-key",
            Some("member-room"),
            &[("response", self.path("response"))],
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn op(n: u64) -> String {
    format!("{n:032x}")
}
fn send_options(
    f: &Fixture,
    state: &Value,
    operation: u64,
    output: &str,
) -> Vec<(&'static str, String)> {
    vec![
        ("text", f.path("text")),
        ("operation", op(operation)),
        (
            "epoch",
            state["status"]["epoch"].as_u64().unwrap().to_string(),
        ),
        ("roster", state["status"]["roster"].as_str().unwrap().into()),
        ("out", f.path(output)),
    ]
}

#[test]
fn private_cli_complete_confidential_exchange_exact_retry_removal_and_renewal() {
    let f = Fixture::new();
    f.join();
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    let member = f.inspect("member-key", "member-room", "member-inspect");
    assert_eq!(owner["recipients"].as_array().unwrap().len(), 2);
    assert_eq!(member["recipients"], owner["recipients"]);
    f.write("text", b"inert private coordination\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message"),
    );
    let stable = f.snapshot("owner-room");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message-copy"),
    );
    assert_eq!(
        fs::read(f.root.join("message")).unwrap(),
        fs::read(f.root.join("message-copy")).unwrap()
    );
    assert_eq!(f.snapshot("owner-room"), stable);
    f.ok(
        "receive",
        "member-key",
        Some("member-room"),
        &[("message", f.path("message")), ("out", f.path("received"))],
    );
    assert_eq!(
        fs::read(f.root.join("received")).unwrap(),
        b"inert private coordination\n"
    );
    f.ok(
        "outbox",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", "0".into()),
            ("limit", "16".into()),
            ("out", f.path("outbox")),
        ],
    );
    let outbox = f.json("outbox");
    assert_eq!(outbox["records"][0]["kind"], "ContactOffer");
    assert!(outbox["records"][0]["artifact_bytes"].is_null());
    let refused = f.run(
        "export",
        "owner-key",
        Some("owner-room"),
        &[("sequence", "1".into()), ("out", f.path("must-not-exist"))],
        None,
    );
    assert!(!refused.status.success());
    assert!(!f.root.join("must-not-exist").exists());
    f.ok(
        "export",
        "owner-key",
        Some("owner-room"),
        &[("sequence", "3".into()), ("out", f.path("exported"))],
    );
    assert_eq!(
        fs::read(f.root.join("exported")).unwrap(),
        fs::read(f.root.join("message")).unwrap()
    );
    f.ok(
        "control-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", "0".into()),
            ("parent", "none".into()),
            ("out", f.path("addition-control")),
        ],
    );
    assert!(!fs::read(f.root.join("addition-control"))
        .unwrap()
        .is_empty());
    f.ok(
        "remove",
        "owner-key",
        Some("owner-room"),
        &[
            (
                "device",
                member["status"]["device"].as_str().unwrap().into(),
            ),
            ("operation", op(4)),
            ("out", f.path("removal")),
        ],
    );
    f.ok(
        "apply",
        "member-key",
        Some("member-room"),
        &[("control", f.path("removal"))],
    );
    let removed = f.inspect("member-key", "member-room", "removed-inspect");
    assert_eq!(removed["status"]["phase"], "Removed");
    f.ok(
        "renew",
        "owner-key",
        Some("owner-room"),
        &[
            ("operation", op(5)),
            ("not-before", (f.now - 10).to_string()),
            ("expires", (f.now + 7200).to_string()),
            ("out", f.path("renewal")),
        ],
    );
    let now = f.inspect("owner-key", "owner-room", "renewed-inspect");
    assert_eq!(now["status"]["epoch"], 3);
    for name in [
        "offer",
        "received",
        "owner-inspect",
        "request",
        "response",
        "message",
    ] {
        assert_eq!(
            fs::metadata(f.root.join(name)).unwrap().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn private_cli_output_failure_preserves_commit_and_stale_recipients_refuse_before_text() {
    let f = Fixture::new();
    f.join();
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    let member = f.inspect("member-key", "member-room", "member-inspect");
    f.write("text", b"never print this secret body");
    f.write("occupied", b"keep original bytes");
    let result = f.run(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "occupied"),
        None,
    );
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("never print this secret body"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("NEW output path"));
    assert_eq!(
        fs::read(f.root.join("occupied")).unwrap(),
        b"keep original bytes"
    );
    let committed = f.snapshot("owner-room");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "recovered"),
    );
    assert_eq!(f.snapshot("owner-room"), committed);
    f.ok(
        "remove",
        "owner-key",
        Some("owner-room"),
        &[
            (
                "device",
                member["status"]["device"].as_str().unwrap().into(),
            ),
            ("operation", op(4)),
            ("out", f.path("removal")),
        ],
    );
    fs::remove_file(f.root.join("text")).unwrap();
    let before = f.snapshot("owner-room");
    let result = f.run(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 5, "blocked"),
        None,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("recipients changed"));
    assert_eq!(f.snapshot("owner-room"), before);
    assert!(!f.root.join("blocked").exists());
    f.ok(
        "export",
        "owner-key",
        Some("owner-room"),
        &[
            ("sequence", "3".into()),
            ("out", f.path("old-exact-cipher")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("old-exact-cipher")).unwrap(),
        fs::read(f.root.join("recovered")).unwrap()
    );
}

#[test]
fn private_cli_bounds_pins_paths_and_partial_namespace_never_reset_or_leak() {
    let f = Fixture::new();
    f.ok("create", "owner-key", Some("owner-room"), &f.validity());
    let before = f.snapshot("owner-room");
    assert!(!f
        .run(
            "create",
            "owner-key",
            Some("owner-room"),
            &f.validity(),
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("owner-room"), before);
    assert!(!f
        .run(
            "inspect",
            "member-key",
            Some("owner-room"),
            &[("out", f.path("wrong-account"))],
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("owner-room"), before);
    assert!(!f.root.join("wrong-account").exists());
    let marker = f.root.join("owner-room/FORMAT");
    let exact = fs::read(&marker).unwrap();
    fs::write(&marker, &exact[..15]).unwrap();
    let partial = f.snapshot("owner-room");
    assert!(!f
        .run(
            "inspect",
            "owner-key",
            Some("owner-room"),
            &[("out", f.path("partial"))],
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("owner-room"), partial);
    fs::write(&marker, exact).unwrap();
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    f.write("text", &vec![b'x'; 4097]);
    let before = f.snapshot("owner-room");
    assert!(!f
        .run(
            "send",
            "owner-key",
            Some("owner-room"),
            &send_options(&f, &owner, 1, "large"),
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("owner-room"), before);
    f.write("text", b"private text");
    fs::set_permissions(f.root.join("text"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!f
        .run(
            "send",
            "owner-key",
            Some("owner-room"),
            &send_options(&f, &owner, 1, "public-mode"),
            None
        )
        .status
        .success());
    fs::remove_file(f.root.join("text")).unwrap();
    f.write("original-text", b"private text");
    symlink(f.root.join("original-text"), f.root.join("text")).unwrap();
    assert!(!f
        .run(
            "send",
            "owner-key",
            Some("owner-room"),
            &send_options(&f, &owner, 1, "linked"),
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("owner-room"), before);
    let mut options = send_options(&f, &owner, 1, "pipe-message");
    options[0].1 = "-".into();
    let result = f.run(
        "send",
        "owner-key",
        Some("owner-room"),
        &options,
        Some(b"private pipe input"),
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("private pipe input"));
}

#[test]
fn private_cli_complete_locator_without_image_never_recreates_lost_device() {
    use vhalla_private_kernel::protocol::Validity;
    use vhalla_private_native::{
        client::RoomCreation,
        private_rooms::{Context, Limits, NativePrivateStore},
    };
    let f = Fixture::new();
    let identity = vhalla_identity::Identity::open(f.root.join("owner-key")).unwrap();
    let draft =
        RoomCreation::owner(identity, Validity::new(f.now - 30, f.now + 3600).unwrap()).unwrap();
    let selected = draft.context();
    let hint = Context::new(
        *selected.scope.room.as_bytes(),
        *selected.scope.anchor.as_bytes(),
        *selected.account.as_bytes(),
        *selected.device.as_bytes(),
    )
    .unwrap();
    let store = NativePrivateStore::create_new(
        f.root.join("unfinished"),
        hint,
        Limits {
            max_records: 1000,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    drop(store);
    drop(draft);
    let before = f.snapshot("unfinished");
    assert!(!f
        .run(
            "inspect",
            "owner-key",
            Some("unfinished"),
            &[("out", f.path("not-authenticated"))],
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("unfinished"), before);
    assert!(!f
        .run(
            "create",
            "owner-key",
            Some("unfinished"),
            &f.validity(),
            None
        )
        .status
        .success());
    assert_eq!(f.snapshot("unfinished"), before);
    assert!(!f.root.join("not-authenticated").exists());
}

#[path = "private_rooms/archive.rs"]
mod archive;
