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
    home_name: &'static str,
}
impl Fixture {
    fn new() -> Self {
        Self::with_home("host & retained")
    }
    fn with_home(home_name: &'static str) -> Self {
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
        Self {
            root,
            addr,
            home_name,
        }
    }
    fn home(&self) -> PathBuf {
        self.root.join(self.home_name)
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
        assert_eq!(ready["listen"], self.json("config.json")["listen"]);
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
fn listener_selection_refuses_wildcards_and_misdirected_advertisements() {
    let lan = ["--listen", "192.0.2.10:9473", "--advertise"];
    let cases: &[&[&str]] = &[
        &["--listen", "0.0.0.0:9473"],
        &["--listen", "[::]:9473"],
        &["--listen", "224.0.0.1:9473"],
        &["--listen", "192.0.2.10:0"],
        &["--listen", "[fe80::1]:9473"],
        &["--advertise", "203.0.113.7:9473"],
        &[lan[0], lan[1], lan[2], "127.0.0.1:9473"],
        &[lan[0], lan[1], lan[2], "0.0.0.0:9473"],
        &[lan[0], lan[1], lan[2], "203.0.113.7:9473,203.0.113.7:9473"],
        &[lan[0], lan[1], lan[2], "203.0.113.7:9473,"],
        &[
            lan[0],
            lan[1],
            lan[2],
            "203.0.113.1:1,203.0.113.2:1,203.0.113.3:1,203.0.113.4:1,203.0.113.5:1",
        ],
    ];
    for flags in cases {
        let f = Fixture::new();
        let mut command = f.command("init");
        command.args(*flags);
        assert!(!run(command).status.success(), "{flags:?}");
        assert!(!f.home().exists(), "{flags:?}");
    }
}

#[test]
fn network_listener_records_the_addresses_clients_dial() {
    // Initialization binds nothing, so documentation addresses stand in for a
    // cloud server's private interface and the public address clients dial.
    let f = Fixture::new();
    let mut command = f.command("init");
    command.args([
        "--listen",
        "192.0.2.10:9473",
        "--advertise",
        "203.0.113.7:9473,[2001:db8::7]:9473",
        "--tls-name",
        "local-host.test.invalid",
    ]);
    let initialized = run(command);
    ok(&initialized);
    let dial = serde_json::json!(["203.0.113.7:9473", "[2001:db8::7]:9473"]);
    let printed: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(printed["addresses"], dial);
    assert_eq!(f.json("config.json")["listen"], "192.0.2.10:9473");
    assert_eq!(f.json("config.json")["advertise"], dial);
    assert_eq!(f.json("connection.json")["listen"], "192.0.2.10:9473");
    assert_eq!(f.json("connection.json")["addresses"], dial);
    let status = run(f.command("status"));
    ok(&status);
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["addresses"], dial);
    // A loopback host lists its listener and writes no advertise field.
    let local = Fixture::new();
    ok(&local.init());
    assert_eq!(
        local.json("connection.json")["addresses"],
        serde_json::json!([local.addr.to_string()])
    );
    assert!(local.json("config.json").get("advertise").is_none());
}

/// The routed source address of this host, found by connecting a UDP socket
/// (which sends nothing) toward a documentation address, provided the host
/// also accepts its own TCP connections on it.
#[cfg(target_os = "linux")]
fn routed_address() -> Option<std::net::IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let listener = TcpListener::bind((ip, 0)).ok()?;
    std::net::TcpStream::connect_timeout(&listener.local_addr().ok()?, Duration::from_secs(2))
        .ok()?;
    Some(ip)
}

#[cfg(target_os = "linux")]
#[test]
fn network_listener_serves_clients_that_dial_its_address() {
    let Some(ip) = routed_address() else {
        eprintln!("skipped: this host has no routed non-loopback IPv4 address");
        return;
    };
    let mut f = Fixture::new();
    let probe = TcpListener::bind((ip, 0)).unwrap();
    f.addr = probe.local_addr().unwrap();
    drop(probe);
    ok(&f.init());
    assert_eq!(
        f.json("connection.json")["addresses"],
        serde_json::json!([f.addr.to_string()])
    );
    let mut server = f.serve();
    let item = RelayItem::new(
        f.namespace(),
        1,
        OperationId::from_bytes([4; 16]).unwrap(),
        OutboxKind::Application,
        b"synthetic ciphertext over a network listener",
    )
    .unwrap();
    assert_eq!(f.client(1).submit(&item).unwrap().position, 1);
    assert_eq!(f.client(2).page(0, 1).unwrap().records[0].item, item);
    let probed = run({
        let mut command = f.command("status");
        command.arg("--probe");
        command
    });
    ok(&probed);
    let probed: Value = serde_json::from_slice(&probed.stdout).unwrap();
    assert_eq!(probed["probe"]["probed"], true);
    // The listener is the routed address only; loopback is not served.
    assert!(std::net::TcpStream::connect(("127.0.0.1", f.addr.port())).is_err());
    server.stop();
}

#[test]
fn add_credential_and_recovery_extend_the_sealed_home_without_rebinding_members() {
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
    assert_eq!(fs::read(f.home().join("ca.der")).unwrap(), ca);
    for (n, token) in tokens.iter().enumerate() {
        assert_eq!(
            fs::read(f.home().join(format!("client-{}.token", n + 1))).unwrap(),
            *token
        );
    }
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
    assert_eq!(status["mailbox"], "mailbox");
    let _ = (before, before_complete);
}

#[test]
fn rotation_refuses_without_mutation_even_when_empty_or_serving() {
    let f = Fixture::new();
    ok(&f.init());
    let before: std::collections::BTreeMap<_, _> = fs::read_dir(f.home())
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| (entry.file_name(), fs::read(entry.path()).unwrap()))
        .collect();
    let refused = run(f.command("rotate"));
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("pending or uncertain work"));
    assert!(!f.home().join("mailbox-2").exists());
    assert!(!f.home().join("maintenance.lock").exists());
    for (name, bytes) in &before {
        assert_eq!(fs::read(f.home().join(name)).unwrap(), *bytes);
    }
    let namespace = f.namespace();
    let mut server = f.serve();
    assert_eq!(f.client(1).page(0, 1).unwrap().head, 0);
    assert!(!run(f.command("rotate")).status.success());
    assert_eq!(f.namespace(), namespace);
    assert_eq!(f.client(1).page(0, 1).unwrap().head, 0);
    assert!(!f.home().join("mailbox-2").exists());
    server.stop();
}

#[test]
fn gateway_sigterm_drains_admitted_put_and_restart_reconciles_exact_retention() {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::Path;

    fn private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn gateway(config: &Path, origin: &str) -> Server {
        let mut server = Server(
            Command::new(env!("CARGO_BIN_EXE_vhalla"))
                .args(["private-gateway", "serve"])
                .arg(config)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = server.0.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = send.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
        });
        let line = receive
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(line.trim(), format!("private-gateway {origin}"));
        server
    }
    fn connect(addr: SocketAddr) -> TcpStream {
        let socket = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
    }
    fn response(socket: &mut TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).unwrap();
        assert!(bytes.starts_with(b"HTTP/1.1 200"));
        let body = bytes.windows(4).position(|p| p == b"\r\n\r\n").unwrap() + 4;
        bytes[body..].to_vec()
    }

    let f = Fixture::new();
    ok(&f.init());
    let mut host = f.serve();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("http://{addr}");
    let config = f.root.join("gateway.json");
    let token = f.root.join("browser.token");
    private(&token, "08".repeat(32).as_bytes());
    let assets = f.root.join("assets");
    fs::DirBuilder::new().mode(0o700).create(&assets).unwrap();
    let ui = b"synthetic gateway lifecycle fixture";
    fs::write(assets.join("index.html"), ui).unwrap();
    let digest: String = Sha256::digest(ui)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    fs::write(assets.join("artifact.json"), serde_json::to_vec(&serde_json::json!({
        "format":1,"purpose":"production","assets":{"index.html":{"bytes":ui.len(),"sha256":digest}}
    })).unwrap()).unwrap();
    private(
        &config,
        &serde_json::to_vec(&serde_json::json!({
            "format":1,"listen":addr,"namespace":f.json("connection.json")["namespace"],
            "browser_token_file":token,"assets_dir":assets,"initial_cursor":"0",
            "upstream":{"addr":f.addr,"tls_name":"local-host.test.invalid",
              "tls_ca_file":f.home().join("ca.der"),"token_file":f.home().join("client-1.token")}
        }))
        .unwrap(),
    );
    let selected = fs::read(&config).unwrap();
    let item = RelayItem::new(
        f.namespace(),
        1,
        OperationId::from_bytes([51; 16]).unwrap(),
        OutboxKind::Application,
        b"retained through real gateway process drain",
    )
    .unwrap();
    let encoded = item.encode().unwrap();
    // Canonical relay v1 frame: length, PUT tag, exact opaque item.
    let mut body = ((encoded.len() + 1) as u32).to_be_bytes().to_vec();
    body.push(1);
    body.extend(encoded);
    let header = format!("POST /private-relay/v1 HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\nAuthorization: Bearer {}\r\nX-Vhalla-Namespace: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        "08".repeat(32), f.json("connection.json")["namespace"].as_str().unwrap(), body.len());
    let mut service = gateway(&config, &origin);
    let mut put = connect(addr);
    put.write_all(header.as_bytes()).unwrap();
    put.write_all(&body[..body.len() - 1]).unwrap();
    // A later successful request proves the accept loop admitted the first
    // connection, whose missing final body byte prevents an upstream PUT.
    let mut probe = connect(addr);
    probe
        .write_all(format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .unwrap();
    assert_eq!(response(&mut probe), ui);
    assert_eq!(f.client(1).page(0, 1).unwrap().head, 0);
    let started = Instant::now();
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(service.0.id().try_into().unwrap()).unwrap(),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(
        service.0.try_wait().unwrap().is_none(),
        "admitted PUT was abandoned"
    );
    put.write_all(&body[body.len() - 1..]).unwrap();
    let retained = response(&mut put);
    let mut receipt = 42u32.to_be_bytes().to_vec();
    receipt.push(0); // Successful canonical retention status.
    receipt.extend(1u64.to_be_bytes());
    receipt.extend(item.digest());
    receipt.push(0); // First publication.
    assert_eq!(retained, receipt);
    wait(&mut service.0);
    assert!(service.0.try_wait().unwrap().unwrap().success());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(fs::read_to_string(f.root.join("events.log"))
        .unwrap()
        .contains("\"reason\":\"terminate\""));
    assert_eq!(f.client(1).page(0, 2).unwrap().records[0].item, item);
    host.stop();
    host = f.serve();
    service = gateway(&config, &origin);
    let mut retry = connect(addr);
    retry.write_all(header.as_bytes()).unwrap();
    retry.write_all(&body).unwrap();
    *receipt.last_mut().unwrap() = 1;
    assert_eq!(response(&mut retry), receipt);
    let page = f.client(1).page(0, 2).unwrap();
    assert_eq!(page.head, 1);
    assert_eq!(page.records[0].item, item);
    assert_eq!(fs::read(&config).unwrap(), selected);
    service.stop();
    host.stop();
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
fn revocation_and_replacement_activate_after_restart_without_changing_quota_identity() {
    let f = Fixture::new();
    ok(&f.init());
    let initial = f.json("config.json");
    let old_token = fs::read(f.home().join("client-1.token")).unwrap();
    let old_client = f.client(1);
    let mut server = f.serve();
    let item = RelayItem::new(
        f.namespace(),
        1,
        OperationId::from_bytes([71; 16]).unwrap(),
        OutboxKind::Application,
        b"retained before token revocation",
    )
    .unwrap();
    let first = old_client.submit(&item).unwrap();
    let mut revoke = f.command("revoke-credential");
    revoke.arg("1");
    let result = run(revoke);
    ok(&result);
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["restart_required"], true);
    assert_eq!(report["credential_id"], initial["credential_ids"][0]);
    assert_eq!(
        f.json("config.json")["credential_ids"],
        initial["credential_ids"]
    );
    assert_eq!(
        fs::read(f.home().join("client-1.token")).unwrap(),
        old_token
    );
    assert_eq!(
        old_client.page(0, 1).unwrap().head,
        first.position,
        "running service retains startup authority until drain"
    );
    server.stop();
    let mut server = f.serve();
    assert!(matches!(old_client.page(0, 1), Err(NetError::Denied)));
    assert_eq!(f.client(2).page(0, 1).unwrap().records[0].item, item);
    let mut probe = f.command("status");
    probe.arg("--probe");
    let probed = run(probe);
    ok(&probed);
    assert_eq!(
        serde_json::from_slice::<Value>(&probed.stdout).unwrap()["probe"]["probed"],
        true
    );
    let mut replace = f.command("replace-credential");
    replace.arg("1");
    let result = run(replace);
    ok(&result);
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["credential_generation"], 2);
    assert_eq!(report["credential_id"], initial["credential_ids"][0]);
    let new_client = f.client(1);
    assert!(
        matches!(new_client.page(0, 1), Err(NetError::Denied)),
        "replacement is not admitted before the selected restart"
    );
    server.stop();
    let mut server = f.serve();
    assert!(matches!(old_client.page(0, 1), Err(NetError::Denied)));
    let retained = new_client.submit(&item).unwrap();
    assert!(retained.duplicate);
    assert_eq!(retained.position, first.position);
    assert_eq!(retained.digest, first.digest);
    assert_eq!(
        f.json("config.json")["credential_ids"],
        initial["credential_ids"]
    );
    let history = f.home().join("client-1.generation-1.token");
    assert_eq!(fs::read(&history).unwrap(), old_token);
    assert_eq!(fs::metadata(history).unwrap().mode() & 0o7777, 0o600);
    assert!(!result
        .stdout
        .windows(old_token.len())
        .any(|bytes| bytes == old_token));
    server.stop();
}

#[test]
fn revoking_all_credentials_is_loadable_and_refuses_new_service_admission() {
    let f = Fixture::new();
    ok(&f.init());
    for index in [1, 2] {
        let mut revoke = f.command("revoke-credential");
        revoke.arg(index.to_string());
        ok(&run(revoke));
    }
    let before = fs::read(f.home().join("config.json")).unwrap();
    let mut repeated = f.command("revoke-credential");
    repeated.arg("2");
    ok(&run(repeated));
    assert_eq!(fs::read(f.home().join("config.json")).unwrap(), before);
    ok(&run(f.command("status")));
    let refused = run(f.command("serve"));
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("enrolled in mailbox directory \"mailbox\" are revoked"),
        "{stderr}"
    );
    assert!(
        stderr.contains("replace-credential HOME INDEX` for credential index 1 or 2"),
        "{stderr}"
    );
    let mut replacement = f.command("replace-credential");
    replacement.arg("2");
    ok(&run(replacement));
    let mut server = f.serve();
    assert_eq!(f.client(2).page(0, 1).unwrap().head, 0);
    server.stop();
}

#[test]
fn tailcat_template_uses_only_saved_private_key_and_exact_one_port_without_activation() {
    // The plist template XML-escapes its argv, so the hostile fixture home is
    // safe on macOS; systemd ExecStart splits on whitespace, so the unit path
    // refuses any home it could not name unambiguously and this test exercises
    // the custody matrix through a space-free home, then asserts that refusal.
    #[cfg(target_os = "linux")]
    let f = Fixture::with_home("host");
    #[cfg(not(target_os = "linux"))]
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
    #[cfg(target_os = "linux")]
    {
        assert!(text.contains(&format!("serve {}\n", f.addr.port())));
        assert!(text.contains("StandardOutput=null\n"));
        assert!(text.contains("WantedBy=default.target\n"));
    }
    #[cfg(not(target_os = "linux"))]
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
    #[cfg(target_os = "linux")]
    {
        let hostile = Fixture::new();
        ok(&hostile.init());
        let hostile_key = hostile.home().join("tailcat.private.json");
        fs::write(&hostile_key, secret).unwrap();
        fs::set_permissions(&hostile_key, fs::Permissions::from_mode(0o600)).unwrap();
        let mut refused = hostile.command("tailcat-plist");
        refused
            .arg("--binary")
            .arg(env!("CARGO_BIN_EXE_vhalla"))
            .arg("--key")
            .arg(&hostile_key)
            .arg("--out")
            .arg(hostile.home().join("tailcat.service"));
        assert!(!run(refused).status.success());
        assert!(!hostile.home().join("tailcat.service").exists());
    }
}

#[test]
fn drained_generation_retains_old_tls_retries_and_carries_spend_to_successor() {
    use sha2::{Digest, Sha256};
    use vhalla_private_kernel::{
        protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
        Context,
    };
    use vhalla_private_native::{
        client::generation::{
            controller_id, Accounting, BrowserSharedAccounting, ControllerPauseReceipt,
        },
        relay::{tls::Service, FileStore},
    };
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn private(path: &std::path::Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let f = Fixture::new();
    ok(&f.init());
    let old_namespace = f.namespace();
    let old_client = f.client(1);
    let item = RelayItem::new(
        old_namespace,
        1,
        OperationId::from_bytes([14; 16]).unwrap(),
        OutboxKind::Application,
        b"original retained ciphertext",
    )
    .unwrap();
    let mut server = f.serve();
    assert_eq!(old_client.submit(&item).unwrap().position, 1);
    server.stop();
    let store = FileStore::open(f.home().join("mailbox"), old_namespace).unwrap();
    let (head, items) = store.retained_head().unwrap();
    let before = Service::credential_spend(&store).unwrap();
    drop(store);
    let config = f.json("config.json");
    let receipts = f.root.join("drained-controllers");
    fs::DirBuilder::new().mode(0o700).create(&receipts).unwrap();
    let mut controllers = Vec::new();
    for (index, id) in config["credential_ids"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([1; 32]).unwrap(),
                anchor: AnchorId::from_bytes([2; 32]).unwrap(),
            },
            account: Key::from_bytes(
                ed25519_dalek::SigningKey::from_bytes(&[3 + index as u8; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
            device: Key::from_bytes(
                ed25519_dalek::SigningKey::from_bytes(&[5 + index as u8; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
        };
        let mut counters = BrowserSharedAccounting {
            attempts: 4,
            wire_bytes: 2048,
            retained: 1,
            received: head,
            refused_total: 0,
            total_byte_ceiling: 8192,
            total_attempt_ceiling: 64,
            commitment: [0; 32],
        };
        counters.commitment = counters.computed_commitment();
        let receipt = ControllerPauseReceipt {
            context,
            controller_id: controller_id(context, [9 + index as u8; 32]),
            original_profile_binding: [9 + index as u8; 32],
            transition: [7; 32],
            generation: 0,
            namespace: *old_namespace.as_bytes(),
            endpoint: [11; 32],
            profile_binding: [9 + index as u8; 32],
            terminal_head: head,
            items_commitment: items,
            outbox_head: 1,
            control_head: 0,
            image_commitment: [13; 32],
            accounting: Accounting::BrowserShared(counters),
            prior_ledger_commitment: [0; 32],
        };
        private(
            &receipts.join(format!("{}.receipt", hex(&receipt.controller_id))),
            &receipt.encode().unwrap(),
        );
        controllers.push(serde_json::json!({"credential_id":id,"room":hex(context.scope.room.as_bytes()),"anchor":hex(context.scope.anchor.as_bytes()),"account":hex(context.account.as_bytes()),"device":hex(context.device.as_bytes()),"controller_id":hex(&receipt.controller_id),"original_profile_binding":hex(&receipt.original_profile_binding),"profile_binding":hex(&receipt.profile_binding),"endpoint":hex(&receipt.endpoint),"receipt_commitment":hex(&receipt.commitment().unwrap())}));
    }
    let port = TcpListener::bind("127.0.0.1:0").unwrap();
    let next_address = port.local_addr().unwrap();
    drop(port);
    assert_ne!(next_address, f.addr);
    let successor = RelayNamespace::from_bytes([8; 32]).unwrap();
    let plan = serde_json::json!({"version":1,"complete_controller_inventory":true,"config_sha256":hex(&Sha256::digest(fs::read(f.home().join("config.json")).unwrap())),"transition":hex(&[7;32]),"generation":0,"predecessor":hex(old_namespace.as_bytes()),"successor":hex(successor.as_bytes()),"successor_address":next_address.to_string(),"expected_head":head,"items_commitment":hex(&items),"controllers":controllers,"allowances":[]});
    let plan_path = f.root.join("generation-plan.json");
    private(&plan_path, &serde_json::to_vec(&plan).unwrap());
    for action in ["generation-check", "generation-prepare"] {
        let mut command = f.command(action);
        command
            .arg("--plan")
            .arg(&plan_path)
            .arg("--receipts")
            .arg(&receipts);
        ok(&run(command));
    }
    let pending_refusal = || {
        let refused = run(f.command("serve"));
        assert!(!refused.status.success());
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(
            stderr.contains("generation transition is pending"),
            "{stderr}"
        );
    };
    pending_refusal();
    ok(&run(f.command("generation-fence")));
    pending_refusal();
    ok(&run(f.command("generation-cutover")));
    let next = FileStore::open(f.home().join("mailbox-2"), successor).unwrap();
    let carried = Service::credential_spend(&next).unwrap();
    assert_eq!(carried, before);
    drop(next);
    let new_client = TlsRelay::new(
        next_address,
        "local-host.test.invalid",
        fs::read(f.home().join("ca.der")).unwrap(),
        RelayToken::from_bytes(f.token(1)).unwrap(),
        successor,
    )
    .unwrap();
    let mut server = f.serve();
    assert_eq!(old_client.page(0, 4).unwrap().records[0].item, item);
    let receipt = old_client.submit(&item).unwrap();
    assert!(receipt.duplicate);
    assert_eq!(receipt.position, 1);
    let forbidden = RelayItem::new(
        old_namespace,
        2,
        OperationId::from_bytes([15; 16]).unwrap(),
        OutboxKind::Application,
        b"new old-generation write",
    )
    .unwrap();
    assert!(matches!(
        old_client.submit(&forbidden),
        Err(NetError::Capacity)
    ));
    let next_item = RelayItem::new(
        successor,
        2,
        OperationId::from_bytes([16; 16]).unwrap(),
        OutboxKind::Application,
        b"new successor ciphertext",
    )
    .unwrap();
    assert_eq!(new_client.submit(&next_item).unwrap().position, 1);
    assert_eq!(old_client.page(0, 4).unwrap().head, 1);
    server.stop();
    let old = FileStore::open(f.home().join("mailbox"), old_namespace).unwrap();
    assert_eq!(Service::credential_spend(&old).unwrap(), before);
    drop(old);
    let next = FileStore::open(f.home().join("mailbox-2"), successor).unwrap();
    let after = Service::credential_spend(&next).unwrap();
    let first_id = unhex::<16>(config["credential_ids"][0].as_str().unwrap());
    assert_eq!(
        after
            .iter()
            .find(|c| c.id() == first_id)
            .unwrap()
            .spent_items(),
        2
    );
    assert_eq!(
        after
            .iter()
            .find(|c| c.id() == first_id)
            .unwrap()
            .authorized_items(),
        2048
    );
    drop(next);
    ok(&run(f.command("generation-recover")));
    // Later enrollment belongs to the active generation only. Startup must
    // never try to enroll this ID into a permanently fenced predecessor.
    ok(&run(f.command("add-credential")));
    let third = TlsRelay::new(
        next_address,
        "local-host.test.invalid",
        fs::read(f.home().join("ca.der")).unwrap(),
        RelayToken::from_bytes(f.token(3)).unwrap(),
        successor,
    )
    .unwrap();
    let mut server = f.serve();
    assert_eq!(third.page(0, 4).unwrap().head, 1);
    assert_eq!(old_client.page(0, 4).unwrap().head, 1);
    server.stop();
    let old = FileStore::open(f.home().join("mailbox"), old_namespace).unwrap();
    assert_eq!(Service::credential_spend(&old).unwrap().len(), 2);
    let next = FileStore::open(f.home().join("mailbox-2"), successor).unwrap();
    assert_eq!(Service::credential_spend(&next).unwrap().len(), 3);
    drop(old);
    drop(next);
    for index in ["1", "2"] {
        let mut revoke = f.command("revoke-credential");
        revoke.arg(index);
        ok(&run(revoke));
    }
    let refused = run(f.command("serve"));
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("enrolled in mailbox directory \"mailbox\" are revoked"),
        "{stderr}"
    );
    assert!(stderr.contains("credential index 1 or 2"), "{stderr}");
    let mut replace = f.command("replace-credential");
    replace.arg("1");
    ok(&run(replace));
    let replaced = TlsRelay::new(
        f.addr,
        "local-host.test.invalid",
        fs::read(f.home().join("ca.der")).unwrap(),
        RelayToken::from_bytes(f.token(1)).unwrap(),
        old_namespace,
    )
    .unwrap();
    let mut server = f.serve();
    assert_eq!(replaced.page(0, 4).unwrap().records[0].item, item);
    assert!(matches!(old_client.page(0, 4), Err(NetError::Denied)));
    assert_eq!(third.page(0, 4).unwrap().head, 1);
    server.stop();
}
