//! Local host initialization and real TLS subprocess lifecycle. Never installs a LaunchAgent.
#![cfg(all(unix, feature = "experimental-private"))]
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use vhalla_private_kernel::{OperationId, OutboxKind};
use vhalla_private_native::relay::{
    net::{NetError, RelayToken},
    tls::TlsRelay,
    RelayItem, RelayNamespace,
};
struct Fixture {
    root: PathBuf,
    addr: SocketAddr,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vhalla-local-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        Self { root, addr }
    }
    fn home(&self) -> PathBuf {
        self.root.join("host & retained")
    }
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command.args(["private-host", action]).arg(self.home());
        command
    }
    fn init(&self) -> Output {
        let mut command = self.command("init");
        command.args([
            "--listen",
            &self.addr.to_string(),
            "--tls-name",
            "local-host.test.invalid",
        ]);
        run(command)
    }
    fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.home().join(name)).unwrap()).unwrap()
    }
    fn token(&self, n: usize) -> [u8; 32] {
        unhex(
            std::str::from_utf8(&fs::read(self.home().join(format!("client-{n}.token"))).unwrap())
                .unwrap(),
        )
    }
    fn namespace(&self) -> RelayNamespace {
        RelayNamespace::from_bytes(unhex(
            self.json("connection.json")["namespace"].as_str().unwrap(),
        ))
        .unwrap()
    }
    fn client(&self, n: usize) -> TlsRelay {
        TlsRelay::new(
            self.addr,
            "local-host.test.invalid",
            fs::read(self.home().join("ca.der")).unwrap(),
            RelayToken::from_bytes(self.token(n)).unwrap(),
            self.namespace(),
        )
        .unwrap()
    }
    fn serve(&self) -> Server {
        let mut child = self
            .command("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = send.send(result);
        });
        let line = receive
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        if line.is_empty() {
            let output = child.wait_with_output().unwrap();
            panic!("serve: {}", String::from_utf8_lossy(&output.stderr));
        }
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["status"], "listening");
        assert_eq!(ready["listen"], self.addr.to_string());
        Server(child)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Server(Child);
impl Server {
    fn stop(&mut self) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.0.id().try_into().unwrap()).unwrap(),
            rustix::process::Signal::TERM,
        )
        .unwrap();
        wait(&mut self.0);
        assert!(self.0.try_wait().unwrap().unwrap().success());
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child exceeded fixed deadline");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn run(mut command: Command) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait(&mut child);
    child.wait_with_output().unwrap()
}
fn ok(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn unhex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    let mut out = [0; N];
    for (index, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}

#[test]
fn new_host_is_private_random_bounded_and_does_not_publish_credentials() {
    let f = Fixture::new();
    let initialized = f.init();
    ok(&initialized);
    assert_eq!(fs::metadata(f.home()).unwrap().mode() & 0o7777, 0o700);
    for name in [
        "config.json",
        "complete",
        "ca.der",
        "ca-key.der",
        "server.der",
        "server-key.der",
        "client-1.token",
        "client-2.token",
        "connection.json",
        "launch-agent.plist",
    ] {
        let meta = fs::symlink_metadata(f.home().join(name)).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }
    let config = f.json("config.json");
    assert_eq!(
        config["certificate_expires_at"].as_i64().unwrap() - config["created_at"].as_i64().unwrap(),
        365 * 86400
    );
    assert_eq!(
        config["authority_expires_at"].as_i64().unwrap() - config["created_at"].as_i64().unwrap(),
        5 * 365 * 86400
    );
    assert_ne!(f.token(1), f.token(2));
    let public = fs::read(f.home().join("connection.json")).unwrap();
    for n in [1, 2] {
        let token = fs::read(f.home().join(format!("client-{n}.token"))).unwrap();
        assert!(!public.windows(token.len()).any(|v| v == token));
        assert!(!initialized.stdout.windows(token.len()).any(|v| v == token));
        assert!(!initialized.stderr.windows(token.len()).any(|v| v == token));
    }
    let plist = fs::read_to_string(f.home().join("launch-agent.plist")).unwrap();
    assert!(plist.contains("host &amp; retained"));
    assert!(!plist.contains("client-1.token"));
    assert!(plist.contains("<key>ThrottleInterval</key><integer>30</integer>"));
    let second = Fixture::new();
    ok(&second.init());
    assert_ne!(f.namespace(), second.namespace());
    assert_ne!(f.token(1), second.token(1));
    let status = run(f.command("status"));
    ok(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["status"], "configured");
    assert_eq!(status["certificate_expired"], false);
}

#[test]
fn tls_host_restarts_with_exact_retention_and_graceful_custody_release() {
    let f = Fixture::new();
    ok(&f.init());
    let mut server = f.serve();
    let item = RelayItem::new(
        f.namespace(),
        1,
        OperationId::from_bytes([3; 16]).unwrap(),
        OutboxKind::Application,
        b"synthetic opaque committed ciphertext",
    )
    .unwrap();
    let first = f.client(1).submit(&item).unwrap();
    assert_eq!(first.position, 1);
    assert!(!first.duplicate);
    let page = f.client(2).page(0, 1).unwrap();
    assert_eq!(page.head, 1);
    assert_eq!(page.records[0].item, item);
    // Status never opens the mailbox writer and remains usable while it is held.
    ok(&run(f.command("status")));
    let duplicate_process = run(f.command("serve"));
    assert!(!duplicate_process.status.success());
    let wrong = TlsRelay::new(
        f.addr,
        "local-host.test.invalid",
        fs::read(f.home().join("ca.der")).unwrap(),
        RelayToken::from_bytes([5; 32]).unwrap(),
        f.namespace(),
    )
    .unwrap();
    assert!(matches!(wrong.page(0, 1), Err(NetError::Denied)));
    server.stop();
    assert!(std::net::TcpStream::connect(f.addr).is_err());
    let mut restarted = f.serve();
    let duplicate = f.client(1).submit(&item).unwrap();
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.position, first.position);
    assert_eq!(duplicate.digest, first.digest);
    assert_eq!(f.client(2).page(0, 1).unwrap().records[0].item, item);
    restarted.stop();
}

#[test]
fn partial_existing_foreign_and_mutated_homes_refuse_without_repair() {
    let partial = Fixture::new();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(partial.home())
        .unwrap();
    fs::write(partial.home().join("retained"), b"preserve partial setup").unwrap();
    assert!(!partial.init().status.success());
    assert_eq!(
        fs::read(partial.home().join("retained")).unwrap(),
        b"preserve partial setup"
    );
    assert!(!partial.home().join("config.json").exists());
    let f = Fixture::new();
    ok(&f.init());
    let config = fs::read(f.home().join("config.json")).unwrap();
    assert!(!f.init().status.success());
    assert_eq!(fs::read(f.home().join("config.json")).unwrap(), config);
    fs::set_permissions(
        f.home().join("config.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(!run(f.command("status")).status.success());
    fs::set_permissions(
        f.home().join("config.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut changed = config.clone();
    changed.push(b' ');
    fs::write(f.home().join("config.json"), &changed).unwrap();
    assert!(!run(f.command("serve")).status.success());
    assert_eq!(fs::read(f.home().join("config.json")).unwrap(), changed);
    fs::write(f.home().join("config.json"), config).unwrap();
    let target = f.home().join("client-1.token");
    let retained = fs::read(&target).unwrap();
    fs::rename(&target, f.home().join("retained-token")).unwrap();
    std::os::unix::fs::symlink(f.home().join("retained-token"), &target).unwrap();
    assert!(!run(f.command("status")).status.success());
    assert_eq!(fs::read(f.home().join("retained-token")).unwrap(), retained);
    let invalid = Fixture::new();
    let mut command = invalid.command("init");
    command.args(["--listen", "0.0.0.0:9473"]);
    assert!(!run(command).status.success());
    assert!(!invalid.home().exists());
}

#[test]
fn add_credential_and_rotate_extend_the_sealed_home_without_rebinding_members() {
    let f = Fixture::new();
    ok(&f.init());
    let ca = fs::read(f.home().join("ca.der")).unwrap();
    let tokens: Vec<Vec<u8>> = (1..=2)
        .map(|n| fs::read(f.home().join(format!("client-{n}.token"))).unwrap())
        .collect();
    let added = run(f.command("add-credential"));
    ok(&added);
    let added: Value = serde_json::from_slice(&added.stdout).unwrap();
    assert_eq!(added["status"], "credential_added");
    assert_eq!(added["credential_index"], 3);
    let minted = f.home().join("client-3.token");
    assert_eq!(fs::metadata(&minted).unwrap().mode() & 0o7777, 0o600);
    assert_ne!(f.token(3), f.token(1));
    assert_ne!(f.token(3), f.token(2));
    let config = f.json("config.json");
    assert_eq!(config["credential_ids"].as_array().unwrap().len(), 3);
    // The minted credential is admitted live under the unchanged namespace.
    let mut server = f.serve();
    let item = RelayItem::new(
        f.namespace(),
        7,
        OperationId::from_bytes([9; 16]).unwrap(),
        OutboxKind::Application,
        b"credential enrollment evidence",
    )
    .unwrap();
    assert_eq!(f.client(1).submit(&item).unwrap().position, 1);
    assert_eq!(f.client(3).page(0, 1).unwrap().records[0].item, item);
    server.stop();
    // Rotation keeps CA, listener, tokens and the old mailbox; only the
    // opaque namespace and mailbox selection advance.
    let rotated = run(f.command("rotate"));
    ok(&rotated);
    let rotated: Value = serde_json::from_slice(&rotated.stdout).unwrap();
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(rotated["mailbox"], "mailbox-2");
    let connection = f.json("connection.json");
    let previous = connection["previous_namespace"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(connection["mailbox"], "mailbox-2");
    assert_ne!(connection["namespace"], previous);
    assert_eq!(fs::read(f.home().join("ca.der")).unwrap(), ca);
    for (n, token) in tokens.iter().enumerate() {
        assert_eq!(
            fs::read(f.home().join(format!("client-{}.token", n + 1))).unwrap(),
            *token
        );
    }
    assert!(f.home().join("mailbox").is_dir());
    assert!(f.home().join("mailbox-2").is_dir());
    // Repeating the command is explicit and monotone: it never reuses or
    // rewrites an earlier mailbox.
    let again = run(f.command("rotate"));
    ok(&again);
    let again: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again["mailbox"], "mailbox-3");
    // The retained tokens still authenticate under the rotated namespace and
    // the fresh mailbox starts empty; the stale namespace is not admitted.
    let mut server = f.serve();
    let page = f.client(1).page(0, 1).unwrap();
    assert_eq!(page.head, 0);
    assert!(page.records.is_empty());
    let stale = TlsRelay::new(
        f.addr,
        "local-host.test.invalid",
        fs::read(f.home().join("ca.der")).unwrap(),
        RelayToken::from_bytes(f.token(1)).unwrap(),
        RelayNamespace::from_bytes(unhex(&previous)).unwrap(),
    )
    .unwrap();
    assert!(stale.page(0, 1).is_err());
    server.stop();
    // A torn sealed mutation recovers to the last sealed snapshot instead of
    // refusing the home or completing half of it.
    let before = fs::read(f.home().join("config.json")).unwrap();
    let before_complete = fs::read(f.home().join("complete")).unwrap();
    for (name, bytes) in [
        ("config.json.seal-backup", before.as_slice()),
        ("seal.pending", b"files".as_slice()),
    ] {
        let path = f.home().join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(f.home().join("config.json"), b"torn").unwrap();
    let recovered = run(f.command("add-credential"));
    ok(&recovered);
    let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["credential_index"], 4);
    assert!(!f.home().join("seal.pending").exists());
    assert!(!f.home().join("config.json.seal-backup").exists());
    assert_eq!(
        f.json("config.json")["credential_ids"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let status = run(f.command("status"));
    ok(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["credentials"], 4);
    assert_eq!(status["mailbox"], "mailbox-3");
    let _ = (before, before_complete);
}

#[test]
fn renew_reissues_the_leaf_under_the_retained_ca_without_rebinding() {
    let f = Fixture::new();
    // A deliberately short-lived leaf exercises the status warning window.
    let mut init = f.command("init");
    init.args([
        "--listen",
        &f.addr.to_string(),
        "--tls-name",
        "local-host.test.invalid",
        "--leaf-days",
        "1",
    ]);
    ok(&run(init));
    let ca = fs::read(f.home().join("ca.der")).unwrap();
    let leaf = fs::read(f.home().join("server.der")).unwrap();
    let leaf_key = fs::read(f.home().join("server-key.der")).unwrap();
    let tokens: Vec<Vec<u8>> = (1..=2)
        .map(|n| fs::read(f.home().join(format!("client-{n}.token"))).unwrap())
        .collect();
    let status = run(f.command("status"));
    ok(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["certificate_expired"], false);
    assert_eq!(status["certificate_expiring"], true);
    let renewed = run(f.command("renew"));
    ok(&renewed);
    let renewed: Value = serde_json::from_slice(&renewed.stdout).unwrap();
    assert_eq!(renewed["status"], "renewed");
    // Only the leaf pair and the published expiry advanced; the CA, tokens,
    // namespace and binding are byte-identical.
    assert_ne!(fs::read(f.home().join("server.der")).unwrap(), leaf);
    assert_ne!(fs::read(f.home().join("server-key.der")).unwrap(), leaf_key);
    assert_eq!(fs::read(f.home().join("ca.der")).unwrap(), ca);
    assert_eq!(
        f.json("connection.json")["certificate_expires_at"],
        renewed["certificate_expires_at"]
    );
    assert_eq!(
        f.json("config.json")["namespace"],
        f.json("connection.json")["namespace"]
    );
    for (n, token) in tokens.iter().enumerate() {
        assert_eq!(
            fs::read(f.home().join(format!("client-{}.token", n + 1))).unwrap(),
            *token
        );
    }
    for name in [
        "server.der",
        "server-key.der",
        "connection.json",
        "config.json",
    ] {
        let meta = fs::symlink_metadata(f.home().join(name)).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }
    // The renewed leaf chains to the retained CA: a real serve admits the
    // unchanged credentials, and the leaf lifetime stayed one day.
    let mut server = f.serve();
    assert_eq!(f.client(1).page(0, 1).unwrap().head, 0);
    server.stop();
    let after = run(f.command("status"));
    ok(&after);
    let after: Value = serde_json::from_slice(&after.stdout).unwrap();
    assert_eq!(after["certificate_expiring"], true);
    let span = renewed["certificate_expires_at"].as_i64().unwrap()
        - f.json("config.json")["created_at"].as_i64().unwrap();
    assert!((86_000..=172_800).contains(&span));
    // Without the retained CA private key renewal refuses and changes nothing.
    let g = Fixture::new();
    ok(&g.init());
    let moved = g.home().join("retained-ca-key");
    fs::rename(g.home().join("ca-key.der"), &moved).unwrap();
    let leaf_before = fs::read(g.home().join("server.der")).unwrap();
    assert!(!run(g.command("renew")).status.success());
    assert_eq!(fs::read(g.home().join("server.der")).unwrap(), leaf_before);
    assert!(moved.exists());
}

#[test]
fn tailcat_template_uses_only_saved_private_key_and_exact_one_port_without_activation() {
    let f = Fixture::new();
    ok(&f.init());
    let key = f.home().join("tailcat.private.json");
    let secret = b"synthetic saved-key fixture; template generation never executes Tailcat";
    fs::write(&key, secret).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let out = f.home().join("tailcat-agent.plist");
    let command = || {
        let mut command = f.command("tailcat-plist");
        command
            .arg("--binary")
            .arg(env!("CARGO_BIN_EXE_vhalla"))
            .arg("--key")
            .arg(&key)
            .arg("--out")
            .arg(&out);
        command
    };
    let generated = run(command());
    ok(&generated);
    let report: Value = serde_json::from_slice(&generated.stdout).unwrap();
    assert_eq!(report["installed"], false);
    let plist = fs::read(&out).unwrap();
    let text = std::str::from_utf8(&plist).unwrap();
    assert!(text.contains("--key="));
    assert!(text.contains("tailcat.private.json"));
    assert!(text.contains(&format!(
        "<string>serve</string><string>{}</string>",
        f.addr.port()
    )));
    assert!(!text.contains(&format!("{}:{}", f.addr.port(), f.addr)));
    assert!(!text.contains("--key=new"));
    assert!(!text.contains("exit-node"));
    assert!(!plist.windows(secret.len()).any(|b| b == secret));
    assert!(!generated.stdout.windows(secret.len()).any(|b| b == secret));
    assert_eq!(fs::metadata(&out).unwrap().mode() & 0o7777, 0o600);
    assert!(!run(command()).status.success());
    assert_eq!(fs::read(&out).unwrap(), plist);
    fs::remove_file(&out).unwrap();
    std::os::unix::fs::symlink(&key, &out).unwrap();
    assert!(!run(command()).status.success());
    assert_eq!(fs::read(&key).unwrap(), secret);
    fs::remove_file(&out).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!run(command()).status.success());
    assert!(!out.exists());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&key, f.home().join("retained-overlay-key")).unwrap();
    std::os::unix::fs::symlink(f.home().join("retained-overlay-key"), &key).unwrap();
    assert!(!run(command()).status.success());
    assert!(!out.exists());
}
