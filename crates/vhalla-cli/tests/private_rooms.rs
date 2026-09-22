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
            "{cmd} {identity} {store:?}: {}",
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

#[test]
fn private_cli_relay_mailbox_is_opaque_durable_and_never_member_acceptance() {
    let f = Fixture::new();
    f.join();
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    f.write("text", b"opaque relay ciphertext\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message"),
    );
    let namespace = "ab".repeat(32);
    f.ok(
        "relay-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("sequence", "3".into()),
            ("out", f.path("item")),
        ],
    );
    let mailbox = f.path("mailbox");
    f.ok(
        "relay-mailbox",
        &mailbox,
        None,
        &[("namespace", namespace.clone()), ("max-items", "8".into())],
    );
    // A mailbox is created once; an existing path and a foreign namespace refuse.
    assert!(!f
        .run(
            "relay-mailbox",
            &mailbox,
            None,
            &[("namespace", namespace.clone())],
            None
        )
        .status
        .success());
    let foreign = "cd".repeat(32);
    assert!(!f
        .run(
            "relay-page",
            &mailbox,
            None,
            &[
                ("namespace", foreign.clone()),
                ("after", "0".into()),
                ("limit", "8".into()),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    assert!(!f.root.join("must-not-exist").exists());
    let put = |out: &str| {
        f.ok(
            "relay-put",
            &mailbox,
            None,
            &[
                ("namespace", namespace.clone()),
                ("relay", f.path("item")),
                ("out", f.path(out)),
            ],
        );
        f.json(out)
    };
    let receipt = put("receipt");
    assert_eq!(receipt["position"], 1);
    assert_eq!(receipt["duplicate"], false);
    // An exact retry is idempotent at the same mailbox position; the receipt
    // never claims member acceptance.
    assert_eq!(put("receipt-retry")["duplicate"], true);
    assert_eq!(put("receipt-retry-2")["position"], 1);
    f.ok(
        "relay-page",
        &mailbox,
        None,
        &[
            ("namespace", namespace.clone()),
            ("after", "0".into()),
            ("limit", "8".into()),
            ("out", f.path("page")),
        ],
    );
    let page = f.json("page");
    assert_eq!(page["head"], 1);
    assert_eq!(page["next"], Value::Null);
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["position"], 1);
    // The item still carries its sender-local outbox sequence as metadata.
    assert_eq!(records[0]["sequence"], 3);
    assert_eq!(records[0]["kind"], "Application");
    assert!(records[0]["digest"].as_str().unwrap().len() == 64);
    // The durable mailbox survives across processes; get returns canonical bytes.
    f.ok(
        "relay-get",
        &mailbox,
        None,
        &[
            ("namespace", namespace.clone()),
            ("position", "1".into()),
            ("out", f.path("item-copy")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("item")).unwrap(),
        fs::read(f.root.join("item-copy")).unwrap()
    );
    assert!(!f
        .run(
            "relay-get",
            &mailbox,
            None,
            &[
                ("namespace", namespace.clone()),
                ("position", "2".into()),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    f.ok(
        "relay-apply",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace),
            ("relay", f.path("item-copy")),
            ("out", f.path("applied")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("applied")).unwrap(),
        b"opaque relay ciphertext\n"
    );
}

/// A running relay service must be torn down even when a journey panics.
struct Server(std::process::Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `relay-serve` on an ephemeral loopback port and read its one ready
/// line. A failed start ends the line early and the assertion rejects it.
fn serve(f: &Fixture, mailbox: &str, namespace: &str, tokenfile: &str) -> (Server, String) {
    use std::io::{BufRead, BufReader};
    let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(["private", "relay-serve"])
        .arg(f.root.join(mailbox))
        .args([
            "--namespace",
            namespace,
            "--token",
            &f.path(tokenfile),
            "--listen",
            "127.0.0.1:0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .trim()
        .strip_prefix("relay-serve ")
        .unwrap_or_else(|| panic!("relay-serve did not report a listener: {line:?}"))
        .to_owned();
    (Server(child), addr)
}

#[test]
fn private_cli_relay_socket_adapter_delivers_canonical_items() {
    let f = Fixture::new();
    f.join();
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    f.write("text", b"delivered over the socket adapter\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message"),
    );
    let namespace = "ef".repeat(32);
    f.ok(
        "relay-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("sequence", "3".into()),
            ("out", f.path("item")),
        ],
    );
    f.ok(
        "relay-mailbox",
        &f.path("mailbox"),
        None,
        &[("namespace", namespace.clone()), ("max-items", "8".into())],
    );
    // The mailbox admission secret is a 0600 file, never an argv value.
    f.write("token", "11".repeat(32).as_bytes());
    f.write("wrong-token", "22".repeat(32).as_bytes());
    let (server, addr) = serve(&f, "mailbox", &namespace, "token");
    let submit = |out: &str| {
        f.ok(
            "relay-submit",
            &f.path("item"),
            None,
            &[
                ("addr", addr.clone()),
                ("token", f.path("token")),
                ("out", f.path(out)),
            ],
        );
        f.json(out)
    };
    let receipt = submit("receipt");
    // The mailbox assigns its own position; the item's sender sequence is 3.
    assert_eq!(receipt["position"], 1);
    assert_eq!(receipt["duplicate"], false);
    // An exact retry is idempotent over the socket.
    assert_eq!(submit("receipt-retry")["duplicate"], true);
    // A wrong token is refused and writes no receipt.
    assert!(!f
        .run(
            "relay-submit",
            &f.path("item"),
            None,
            &[
                ("addr", addr.clone()),
                ("token", f.path("wrong-token")),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    assert!(!f.root.join("must-not-exist").exists());
    // Catch-up pulls the retained item through the socket into a private dir.
    f.ok(
        "relay-scan",
        &f.path("catchup"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("scan")),
        ],
    );
    let scan = f.json("scan");
    assert_eq!(scan["scanned"], 1);
    assert_eq!(scan["cursor"], 1);
    assert_eq!(scan["head"], 1);
    let delivered = f.root.join("catchup/items/0000000000000001.vhrelay");
    assert_eq!(
        fs::read(&delivered).unwrap(),
        fs::read(f.root.join("item")).unwrap()
    );
    // An unchanged mailbox rescans to zero new items.
    f.ok(
        "relay-scan",
        &f.path("catchup"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("scan-again")),
        ],
    );
    assert_eq!(f.json("scan-again")["scanned"], 0);
    // Offline periods refuse, then the durable cursor resumes exactly.
    drop(server);
    assert!(!f
        .run(
            "relay-scan",
            &f.path("catchup"),
            None,
            &[
                ("addr", addr),
                ("token", f.path("token")),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    assert!(!f.root.join("must-not-exist").exists());
    // The same durable mailbox reopens under a fresh service process.
    let (_server, addr) = serve(&f, "mailbox", &namespace, "token");
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect-2");
    f.write("text", b"second socket delivery\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 4, "message-2"),
    );
    f.ok(
        "relay-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("sequence", "4".into()),
            ("out", f.path("item-2")),
        ],
    );
    f.ok(
        "relay-submit",
        &f.path("item-2"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("receipt-2")),
        ],
    );
    f.ok(
        "relay-scan",
        &f.path("catchup"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("scan-resumed")),
        ],
    );
    let resumed = f.json("scan-resumed");
    assert_eq!(resumed["scanned"], 1);
    assert_eq!(resumed["cursor"], 2);
    // The delivered ciphertext applies into the member room unchanged.
    f.ok(
        "relay-apply",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("relay", delivered.to_str().unwrap().into()),
            ("out", f.path("applied")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("applied")).unwrap(),
        b"delivered over the socket adapter\n"
    );
    let second = f.root.join("catchup/items/0000000000000002.vhrelay");
    f.ok(
        "relay-apply",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("relay", second.to_str().unwrap().into()),
            ("out", f.path("applied-2")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("applied-2")).unwrap(),
        b"second socket delivery\n"
    );
    // A member replies through the same mailbox: its sender-local sequence
    // overlaps the owner's, so only mailbox-assigned positions keep the stream
    // distinct. relay-push submits the member's whole outbox prefix; relay-pull
    // scans and applies every applicable item for the owner — including the
    // member's reply at position 3 — while own-echo items refuse cleanly.
    let member = f.inspect("member-key", "member-room", "member-inspect");
    f.write("text", b"member reply over the same mailbox\n");
    f.ok(
        "send",
        "member-key",
        Some("member-room"),
        &send_options(&f, &member, 5, "member-item"),
    );
    f.ok(
        "relay-push",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("member-push")),
        ],
    );
    // The member's whole outbox prefix — its earlier contact request plus the
    // reply — submits in sender order at positions 3 and 4, sharing the mailbox
    // with the owner's overlapping sender-local sequences without collision.
    let pushed = f.json("member-push");
    assert_eq!(pushed["submitted"], 2);
    let positions: Vec<u64> = pushed["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["position"].as_u64().unwrap())
        .collect();
    assert_eq!(positions, vec![3, 4]);
    f.ok(
        "relay-pull",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("dir", f.path("owner-catchup")),
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("owner-pull")),
        ],
    );
    let pulled = f.json("owner-pull");
    assert_eq!(pulled["scanned"], 4);
    // The owner's own two items echo back and refuse deterministically; the
    // member's contact request waits for its dedicated explicit command; the
    // reply is the only newly accepted item.
    assert_eq!(
        pulled["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![4]
    );
    assert_eq!(pulled["refused"].as_array().unwrap().len(), 2);
    assert_eq!(
        pulled["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![3]
    );
    // The skipped contact request routes to its dedicated command through
    // relay-unwrap: the staged item verifies and yields the exact request
    // envelope bytes the accept path consumed earlier.
    f.ok(
        "relay-unwrap",
        &f.path("owner-catchup/items/0000000000000003.vhrelay"),
        None,
        &[("out", f.path("unwrapped-request"))],
    );
    assert_eq!(
        fs::read(f.root.join("unwrapped-request")).unwrap(),
        fs::read(f.root.join("request")).unwrap()
    );
    // The accepted reply is durable in the owner's inbox.
    f.ok(
        "inbox",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", "0".into()),
            ("limit", "8".into()),
            ("out", f.path("owner-inbox")),
        ],
    );
    let inbox = f.json("owner-inbox");
    assert!(inbox["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["body_utf8"] == "member reply over the same mailbox\n"));
    // Out-of-order healing: two owner renewals chain controls 5 then 6. The
    // mailbox gets 6 before 5; the member's pull refuses the orphan, then a
    // later pull applies both once the missing parent exists. Each renewal
    // must strictly extend the credential expiry.
    let before = f.inspect("member-key", "member-room", "member-before-heal");
    let epoch_before = before["status"]["epoch"].as_u64().unwrap();
    for (operation, expires, out) in [
        (op(6), f.now + 7200, "renewal-5"),
        (op(7), f.now + 10800, "renewal-6"),
    ] {
        f.ok(
            "renew",
            "owner-key",
            Some("owner-room"),
            &[
                ("operation", operation),
                ("not-before", (f.now - 10).to_string()),
                ("expires", expires.to_string()),
                ("out", f.path(out)),
            ],
        );
    }
    for (sequence, out) in [("6", "item-6"), ("5", "item-5")] {
        f.ok(
            "relay-export",
            "owner-key",
            Some("owner-room"),
            &[
                ("namespace", namespace.clone()),
                ("sequence", sequence.into()),
                ("out", f.path(out)),
            ],
        );
    }
    f.ok(
        "relay-submit",
        &f.path("item-6"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("receipt-6")),
        ],
    );
    assert_eq!(f.json("receipt-6")["position"], 5);
    f.ok(
        "relay-pull",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("dir", f.path("member-heal")),
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("member-pull-1")),
        ],
    );
    let first = f.json("member-pull-1");
    // The member accepts the owner's messages, refuses its own echo and the
    // orphaned control whose parent has not arrived, and skips its own
    // contact-request envelope pending its dedicated command.
    assert_eq!(first["skipped"].as_array().unwrap().len(), 1);
    assert!(first["refused"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_u64() == Some(5)));
    f.ok(
        "relay-submit",
        &f.path("item-5"),
        None,
        &[
            ("addr", addr.clone()),
            ("token", f.path("token")),
            ("out", f.path("receipt-5")),
        ],
    );
    assert_eq!(f.json("receipt-5")["position"], 6);
    f.ok(
        "relay-pull",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace),
            ("dir", f.path("member-heal")),
            ("addr", addr),
            ("token", f.path("token")),
            ("out", f.path("member-pull-2")),
        ],
    );
    let healed = f.json("member-pull-2");
    // Position 5 heals once its parent is retained; position 6 applies right
    // behind it in the same pass.
    let healed_accepted: Vec<u64> = healed["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert!(healed_accepted.contains(&5));
    assert!(healed_accepted.contains(&6));
    let member = f.inspect("member-key", "member-room", "member-healed");
    assert_eq!(member["status"]["epoch"], epoch_before + 2);
}

#[test]
fn private_cli_relay_directory_transport_delivers_bidirectionally() {
    let f = Fixture::new();
    f.join();
    let namespace = "cd".repeat(32);
    // A durable mailbox directory is an interchangeable transport: no
    // listener, no token; filesystem custody gates the same positions.
    f.ok(
        "relay-mailbox",
        &f.path("mailbox"),
        None,
        &[("namespace", namespace.clone())],
    );
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect");
    f.write("text", b"owner message through a directory\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message"),
    );
    f.ok(
        "relay-push",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("mailbox", f.path("mailbox")),
            ("out", f.path("push")),
        ],
    );
    let pushed = f.json("push");
    // Offer issuance stays secret; the contact response and message retain.
    assert_eq!(pushed["skipped_secret"], 1);
    assert_eq!(pushed["submitted"], 2);
    // The member pulls through the same directory without a listener.
    f.ok(
        "relay-pull",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("dir", f.path("member-catchup")),
            ("mailbox", f.path("mailbox")),
            ("out", f.path("member-pull")),
        ],
    );
    let pull = f.json("member-pull");
    assert_eq!(pull["scanned"], 2);
    // The owner's message is durable in the member inbox.
    f.ok(
        "inbox",
        "member-key",
        Some("member-room"),
        &[
            ("after", "0".into()),
            ("limit", "8".into()),
            ("out", f.path("member-inbox")),
        ],
    );
    assert!(f.json("member-inbox")["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["body_utf8"] == "owner message through a directory\n"));
    // Member replies through the same mailbox directory. The deterministic
    // test operation IDs share one space across devices, so the reply uses an
    // operation number no relayed item already claimed.
    let member = f.inspect("member-key", "member-room", "member-inspect-2");
    f.write("text", b"member reply through a directory\n");
    f.ok(
        "send",
        "member-key",
        Some("member-room"),
        &send_options(&f, &member, 4, "member-message"),
    );
    f.ok(
        "relay-push",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            ("mailbox", f.path("mailbox")),
            ("out", f.path("member-push")),
        ],
    );
    // The owner pull applies the member reply; its own items refuse.
    f.ok(
        "relay-pull",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("dir", f.path("owner-catchup")),
            ("mailbox", f.path("mailbox")),
            ("out", f.path("owner-pull")),
        ],
    );
    let pulled = f.json("owner-pull");
    assert_eq!(pulled["scanned"], 4);
    let accepted: Vec<u64> = pulled["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert!(accepted.contains(&4));
    let owner = f.inspect("owner-key", "owner-room", "owner-inbox");
    f.ok(
        "inbox",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", "0".into()),
            ("limit", "8".into()),
            ("out", f.path("owner-inbox-list")),
        ],
    );
    assert!(f.json("owner-inbox-list")["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["body_utf8"] == "member reply through a directory\n"));
    let _ = owner;
    // The low-level submit/scan pair runs on the directory transport too:
    // a second owner message exported by sequence, retained through
    // relay-submit --mailbox, staged through relay-scan --mailbox, then
    // applied through the authenticated item path.
    let owner = f.inspect("owner-key", "owner-room", "owner-inspect-2");
    f.write("text", b"second directory message\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 5, "message-2"),
    );
    f.ok(
        "relay-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("namespace", namespace.clone()),
            ("sequence", "4".into()),
            ("out", f.path("item-4")),
        ],
    );
    f.ok(
        "relay-submit",
        &f.path("item-4"),
        None,
        &[("mailbox", f.path("mailbox")), ("out", f.path("receipt-4"))],
    );
    assert_eq!(f.json("receipt-4")["position"], 5);
    f.ok(
        "relay-scan",
        &f.path("member-catchup-2"),
        None,
        &[
            ("mailbox", f.path("mailbox")),
            ("namespace", namespace.clone()),
            ("out", f.path("scan-2")),
        ],
    );
    let scanned = f.json("scan-2");
    assert_eq!(scanned["scanned"], 5);
    assert_eq!(scanned["cursor"], 5);
    f.ok(
        "relay-apply",
        "member-key",
        Some("member-room"),
        &[
            ("namespace", namespace.clone()),
            (
                "relay",
                f.path("member-catchup-2/items/0000000000000005.vhrelay"),
            ),
            ("out", f.path("applied-4")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("applied-4")).unwrap(),
        b"second directory message\n"
    );
}

#[test]
fn private_cli_relay_transport_flag_conflicts_refuse() {
    let f = Fixture::new();
    f.join();
    let namespace = "cd".repeat(32);
    f.ok(
        "relay-mailbox",
        &f.path("mailbox"),
        None,
        &[("namespace", namespace.clone())],
    );
    f.write("token", "11".repeat(32).as_bytes());
    // Both transports at once, or a partial socket pair, must refuse before
    // any custody or mailbox write.
    for extra in [
        vec![
            ("addr", "127.0.0.1:9".into()),
            ("token", f.path("token")),
            ("mailbox", f.path("mailbox")),
        ],
        vec![("addr", "127.0.0.1:9".into())],
        vec![("token", f.path("token"))],
        vec![],
    ] {
        let mut flags = vec![
            ("namespace", namespace.clone()),
            ("dir", f.path("cursor")),
            ("out", f.path("must-not-exist")),
        ];
        flags.extend(extra.iter().cloned());
        assert!(
            !f.run("relay-pull", "owner-key", Some("owner-room"), &flags, None)
                .status
                .success(),
            "transport flags {extra:?} must refuse"
        );
        assert!(!f.root.join("must-not-exist").exists());
    }
}

#[test]
fn private_cli_same_account_fresh_device_rejoins_under_new_enrollment() {
    let f = Fixture::new();
    f.ok("create", "owner-key", Some("owner-room"), &f.validity());
    // A message committed before the fresh device exists must not reach it.
    let owner = f.inspect("owner-key", "owner-room", "owner-early");
    f.write("text", b"committed before the fresh device joined\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "early-message"),
    );
    // Restore the SAME account onto fresh custody — a lost-device stand-in.
    // The mnemonic stays in process memory; only the restored key directory
    // persists. The public key must reproduce exactly.
    let phrase = vhalla_identity::Identity::open(f.root.join("owner-key"))
        .unwrap()
        .backup();
    let restored = vhalla_identity::Identity::restore(&phrase, f.root.join("fresh-key")).unwrap();
    assert_eq!(
        restored
            .public_key()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>(),
        f.owner
    );
    drop(phrase);
    drop(restored);
    // The owner issues a confidential offer addressed to its own account. The
    // offer still travels an independently confidential channel; the kernel
    // binds it to the exact recipient account, never to the old device.
    let mut flags = f.validity();
    flags.extend([
        ("recipient", f.owner.clone()),
        ("operation", op(11)),
        ("out", f.path("self-offer")),
    ]);
    f.ok("offer", "owner-key", Some("owner-room"), &flags);
    f.ok(
        "offer-inspect",
        "fresh-key",
        None,
        &[
            ("offer", f.path("self-offer")),
            ("owner", f.owner.clone()),
            ("out", f.path("self-meta")),
        ],
    );
    let meta = f.json("self-meta");
    assert_eq!(meta["recipient"].as_str().unwrap(), f.owner);
    let mut flags = f.validity();
    flags.extend([
        ("offer", f.path("self-offer")),
        ("owner", f.owner.clone()),
        ("room", meta["room"].as_str().unwrap().into()),
        ("anchor", meta["anchor"].as_str().unwrap().into()),
    ]);
    f.ok("import", "fresh-key", Some("fresh-room"), &flags);
    f.ok(
        "request",
        "fresh-key",
        Some("fresh-room"),
        &[
            ("offer", f.path("self-offer")),
            ("operation", op(1)),
            ("out", f.path("fresh-request")),
        ],
    );
    let mut flags = f.validity();
    flags.extend([
        ("request", f.path("fresh-request")),
        ("operation", op(12)),
        ("out", f.path("fresh-response")),
    ]);
    f.ok("accept", "owner-key", Some("owner-room"), &flags);
    f.ok(
        "join",
        "fresh-key",
        Some("fresh-room"),
        &[("response", f.path("fresh-response"))],
    );
    // Two distinct devices now share one account; the fresh device is a new
    // member at its joining checkpoint, never a clone of the owner ratchet.
    let owner = f.inspect("owner-key", "owner-room", "owner-after");
    let fresh = f.inspect("fresh-key", "fresh-room", "fresh-inspect");
    assert_eq!(owner["status"]["members"].as_u64().unwrap(), 2);
    assert_eq!(fresh["status"]["members"].as_u64().unwrap(), 2);
    assert_eq!(owner["status"]["account"], fresh["status"]["account"]);
    assert_ne!(owner["status"]["device"], fresh["status"]["device"]);
    assert_eq!(owner["recipients"], fresh["recipients"]);
    assert!(owner["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["account"].as_str().unwrap() == f.owner));
    assert_eq!(fresh["status"]["inbox_head"].as_u64().unwrap(), 0);
    assert!(!f
        .run(
            "receive",
            "fresh-key",
            Some("fresh-room"),
            &[
                ("message", f.path("early-message")),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    assert!(!f.root.join("must-not-exist").exists());
    // Post-join traffic flows in both directions between the same account's
    // two devices, and retained retries return identical ciphertext.
    let owner = f.inspect("owner-key", "owner-room", "owner-send");
    f.write("text", b"owner to fresh device\n");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 13, "to-fresh"),
    );
    f.ok(
        "receive",
        "fresh-key",
        Some("fresh-room"),
        &[
            ("message", f.path("to-fresh")),
            ("out", f.path("fresh-received")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("fresh-received")).unwrap(),
        b"owner to fresh device\n"
    );
    let fresh = f.inspect("fresh-key", "fresh-room", "fresh-send");
    f.write("text", b"fresh device to owner\n");
    f.ok(
        "send",
        "fresh-key",
        Some("fresh-room"),
        &send_options(&f, &fresh, 2, "to-owner"),
    );
    f.ok(
        "send",
        "fresh-key",
        Some("fresh-room"),
        &send_options(&f, &fresh, 2, "to-owner-copy"),
    );
    assert_eq!(
        fs::read(f.root.join("to-owner")).unwrap(),
        fs::read(f.root.join("to-owner-copy")).unwrap()
    );
    f.ok(
        "receive",
        "owner-key",
        Some("owner-room"),
        &[
            ("message", f.path("to-owner")),
            ("out", f.path("owner-received")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("owner-received")).unwrap(),
        b"fresh device to owner\n"
    );
    // Account-authorized succession: the owner hands authority to the
    // already-enrolled fresh device through one predecessor-signed control.
    // The account-signed grant pins the exact roster enrollment, sequence and
    // validity window.
    let fresh = f.inspect("fresh-key", "fresh-room", "fresh-pre-succeed");
    let owner = f.inspect("owner-key", "owner-room", "owner-pre-succeed");
    let head_sequence = owner["status"]["control_sequence"].as_u64().unwrap();
    let head_id = owner["status"]["control_id"].as_str().unwrap().to_string();
    let mut flags = f.validity();
    flags.extend([
        ("device", fresh["status"]["device"].as_str().unwrap().into()),
        ("operation", op(14)),
        ("out", f.path("succession")),
    ]);
    f.ok("succeed", "owner-key", Some("owner-room"), &flags);
    // The predecessor demotes locally at commit. A re-run cannot rebuild the
    // signed grant — it pinned the pre-handoff floor — so the command refuses
    // rather than minting a second handoff; the committed envelope stays
    // recoverable through the retained-control export cursor.
    let demoted = f.inspect("owner-key", "owner-room", "owner-demoted");
    assert_eq!(demoted["status"]["phase"], "MemberJoined");
    assert_eq!(demoted["status"]["members"].as_u64().unwrap(), 2);
    assert_eq!(demoted["successions"].as_array().unwrap().len(), 1);
    f.ok(
        "control-export",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", head_sequence.to_string()),
            ("parent", head_id.clone()),
            ("out", f.path("succession-exported")),
        ],
    );
    assert_eq!(
        fs::read(f.root.join("succession")).unwrap(),
        fs::read(f.root.join("succession-exported")).unwrap()
    );
    assert!(!f
        .run("succeed", "owner-key", Some("owner-room"), &flags, None)
        .status
        .success());
    f.ok(
        "apply",
        "fresh-key",
        Some("fresh-room"),
        &[("control", f.path("succession"))],
    );
    let promoted = f.inspect("fresh-key", "fresh-room", "fresh-promoted");
    assert_eq!(promoted["status"]["phase"], "OwnerJoined");
    assert_eq!(promoted["status"]["members"].as_u64().unwrap(), 2);
    assert_eq!(promoted["successions"].as_array().unwrap().len(), 1);
    // The new owner issues controls the demoted predecessor applies in order;
    // the predecessor cannot regain owner operations.
    f.ok(
        "renew",
        "fresh-key",
        Some("fresh-room"),
        &[
            ("operation", op(3)),
            ("not-before", (f.now - 10).to_string()),
            ("expires", (f.now + 7200).to_string()),
            ("out", f.path("successor-renewal")),
        ],
    );
    f.ok(
        "apply",
        "owner-key",
        Some("owner-room"),
        &[("control", f.path("successor-renewal"))],
    );
    assert!(!f
        .run(
            "renew",
            "owner-key",
            Some("owner-room"),
            &[
                ("operation", op(15)),
                ("not-before", (f.now - 10).to_string()),
                ("expires", (f.now + 7200).to_string()),
                ("out", f.path("must-not-exist")),
            ],
            None
        )
        .status
        .success());
    assert!(!f.root.join("must-not-exist").exists());
    for name in [
        "self-offer",
        "fresh-request",
        "fresh-response",
        "to-fresh",
        "succession",
    ] {
        assert_eq!(
            fs::metadata(f.root.join(name)).unwrap().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn private_cli_signed_control_observe_detects_fork_and_preserves_evidence() {
    let f = Fixture::new();
    f.join();
    // Exact floor cursor for the proof exports that follow.
    let head = f.inspect("owner-key", "owner-room", "head-inspect");
    let sequence = head["status"]["control_sequence"].as_u64().unwrap();
    let parent = head["status"]["control_id"].as_str().unwrap().to_string();
    // Clone owner custody before renewal: two divergent signed continuations
    // under one owner key are the definition of an owner fork.
    let forked = f.root.join("owner-fork");
    fs::DirBuilder::new().mode(0o700).create(&forked).unwrap();
    for entry in fs::read_dir(f.root.join("owner-room")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), forked.join(entry.file_name())).unwrap();
    }
    // The real owner renews; the member applies the encrypted envelope.
    let mut flags = vec![
        ("not-before", (f.now - 10).to_string()),
        ("expires", (f.now + 7200).to_string()),
    ];
    flags.extend([("operation", op(4)), ("out", f.path("renewal"))]);
    f.ok("renew", "owner-key", Some("owner-room"), &flags);
    f.ok(
        "control-proof",
        "owner-key",
        Some("owner-room"),
        &[
            ("after", sequence.to_string()),
            ("parent", parent.clone()),
            ("out", f.path("renewal-proof")),
        ],
    );
    // A valid control the member has not yet accepted is unknown history,
    // never quarantine.
    f.ok(
        "observe",
        "member-key",
        Some("member-room"),
        &[
            ("control", f.path("renewal-proof")),
            ("out", f.path("unknown-verdict")),
        ],
    );
    assert_eq!(f.json("unknown-verdict")["verdict"], "unknown-history");
    f.ok(
        "apply",
        "member-key",
        Some("member-room"),
        &[("control", f.path("renewal"))],
    );
    // The already-accepted signed control is retained history.
    f.ok(
        "observe",
        "member-key",
        Some("member-room"),
        &[
            ("control", f.path("renewal-proof")),
            ("out", f.path("retained-verdict")),
        ],
    );
    assert_eq!(f.json("retained-verdict")["verdict"], "retained");
    // The copied custody renews differently at the same sequence: an authentic
    // owner-signed conflict.
    let mut flags = vec![
        ("not-before", (f.now - 5).to_string()),
        ("expires", (f.now + 9999).to_string()),
    ];
    flags.extend([("operation", op(5)), ("out", f.path("fork-renewal"))]);
    f.ok("renew", "owner-key", Some("owner-fork"), &flags);
    f.ok(
        "control-proof",
        "owner-key",
        Some("owner-fork"),
        &[
            ("after", sequence.to_string()),
            ("parent", parent),
            ("out", f.path("fork-proof")),
        ],
    );
    assert_ne!(
        fs::read(f.root.join("renewal-proof")).unwrap(),
        fs::read(f.root.join("fork-proof")).unwrap()
    );
    f.ok(
        "observe",
        "member-key",
        Some("member-room"),
        &[
            ("control", f.path("fork-proof")),
            ("out", f.path("fork-verdict")),
        ],
    );
    assert_eq!(
        f.json("fork-verdict")["verdict"],
        "conflicting-fork-quarantined"
    );
    // The retained proof pins both sides of the contradiction.
    f.ok(
        "fork-evidence",
        "member-key",
        Some("member-room"),
        &[("out", f.path("evidence"))],
    );
    let evidence = f.json("evidence");
    assert_eq!(
        evidence["accepted_sequence"].as_u64().unwrap(),
        sequence + 1
    );
    assert_ne!(
        evidence["accepted_control"],
        evidence["conflicting_control"]
    );
    assert_eq!(evidence["accepted_from_checkpoint"], false);
    // Quarantine refuses new sends before text is read; retained history stays.
    f.write("text", b"never after fork\n");
    let refused = f.run(
        "send",
        "member-key",
        Some("member-room"),
        &[
            ("text", f.path("text")),
            ("operation", op(6)),
            ("epoch", "1".into()),
            ("roster", "0".repeat(64)),
            ("out", f.path("must-not-exist")),
        ],
        None,
    );
    assert!(!refused.status.success());
    assert!(!f.root.join("must-not-exist").exists());
    f.ok(
        "inbox",
        "member-key",
        Some("member-room"),
        &[
            ("after", "0".into()),
            ("limit", "16".into()),
            ("out", f.path("quarantined-inbox")),
        ],
    );
    // A clean member reports no proof rather than fabricating any.
    assert!(!f
        .run(
            "fork-evidence",
            "owner-key",
            Some("owner-room"),
            &[("out", f.path("no-evidence"))],
            None
        )
        .status
        .success());
    assert!(!f.root.join("no-evidence").exists());
}

#[path = "private_rooms/archive.rs"]
mod archive;
