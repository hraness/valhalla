//! Real subprocess coverage for the default private host and its saved identity.
#![cfg(all(unix, feature = "experimental-private"))]

use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    net::UdpSocket,
    os::unix::fs::{DirBuilderExt, MetadataExt},
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
    iroh::{IrohEndpoint, IrohRelay, DEFAULT_RELAY_URL},
    net::{NetError, RelayToken},
    RelayItem, RelayNamespace,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-iroh-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn home(&self) -> PathBuf {
        self.0.join("host")
    }
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command
            .env("HRANESS_SUPPORT", "off")
            .args(["private-host", action])
            .arg(self.home());
        command
    }
    fn json(&self, name: &str) -> Value {
        serde_json::from_slice(&fs::read(self.home().join(name)).unwrap()).unwrap()
    }
    fn token(&self, index: usize) -> [u8; 32] {
        let raw = fs::read_to_string(self.home().join(format!("client-{index}.token"))).unwrap();
        unhex(raw.trim_end())
    }
    fn namespace(&self) -> RelayNamespace {
        RelayNamespace::from_bytes(unhex(
            self.json("connection.json")["namespace"].as_str().unwrap(),
        ))
        .unwrap()
    }
    fn client(&self, token: [u8; 32]) -> IrohRelay {
        let endpoint: IrohEndpoint =
            serde_json::from_value(self.json("connection.json")["endpoint"].clone()).unwrap();
        IrohRelay::new(
            endpoint,
            RelayToken::from_bytes(token).unwrap(),
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
        let mut server = Server(child);
        let (send, recv) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            let _ = send.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
        });
        let line = recv
            .recv_timeout(Duration::from_secs(20))
            .expect("host readiness deadline")
            .unwrap();
        if line.is_empty() {
            server.0.kill().ok();
            server.0.wait().ok();
            panic!(
                "iroh host did not become ready; retained fixture {}",
                self.0.display()
            );
        }
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["status"], "listening");
        server
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !thread::panicking() {
            let _ = fs::remove_dir_all(&self.0);
        } else {
            eprintln!("retained iroh fixture: {}", self.0.display());
        }
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
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("subprocess exceeded deadline");
        }
        thread::sleep(Duration::from_millis(10));
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
fn unhex(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn default_host_saves_endpoint_identity_without_certificates() {
    let fixture = Fixture::new();
    let initialized = run(fixture.command("init"));
    ok(&initialized);
    let connection = fixture.json("connection.json");
    assert_eq!(connection["transport"], "iroh");
    assert_eq!(connection["endpoint"]["relay_url"], DEFAULT_RELAY_URL);
    assert!(connection["endpoint"]["addresses"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(connection.get("tls_name").is_none());
    assert!(connection.get("ca").is_none());
    for name in ["ca.der", "ca-key.der", "server.der", "server-key.der"] {
        assert!(!fixture.home().join(name).exists());
    }
    let key = fs::read(fixture.home().join("endpoint.key")).unwrap();
    assert_eq!(key.len(), 32);
    let metadata = fs::symlink_metadata(fixture.home().join("endpoint.key")).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(fs::metadata(fixture.home()).unwrap().mode() & 0o7777, 0o700);
    for token in [fixture.token(1), fixture.token(2)] {
        let encoded: String = token.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!connection.to_string().contains(&encoded));
        assert!(!String::from_utf8_lossy(&initialized.stdout).contains(&encoded));
    }
    ok(&run(fixture.command("status")));
    assert!(!run(fixture.command("renew")).status.success());
    assert!(!run(fixture.command("init")).status.success());
    assert_eq!(fs::read(fixture.home().join("endpoint.key")).unwrap(), key);
}

#[test]
fn direct_host_preserves_identity_items_and_credential_revocation_across_restart() {
    let fixture = Fixture::new();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let bind = socket.local_addr().unwrap();
    drop(socket);
    let mut init = fixture.command("init");
    init.args(["--iroh-bind", &bind.to_string(), "--relay-url", "none"]);
    ok(&run(init));
    let endpoint = fixture.json("connection.json")["endpoint"].clone();
    let old_token = fixture.token(1);
    let relay = fixture.client(old_token);
    let mut host = fixture.serve();
    let item = RelayItem::new(
        fixture.namespace(),
        1,
        OperationId::from_bytes([7; 16]).unwrap(),
        OutboxKind::Application,
        b"synthetic opaque ciphertext",
    )
    .unwrap();
    let receipt = relay.submit(&item).unwrap();
    assert_eq!(relay.page(0, 2).unwrap().records[0].item, item);
    let mut retry_receipt = receipt;
    retry_receipt.duplicate = true;
    assert_eq!(relay.submit(&item).unwrap(), retry_receipt);
    let mut probe = fixture.command("status");
    probe.arg("--probe");
    let probed = run(probe);
    ok(&probed);
    let report: Value = serde_json::from_slice(&probed.stdout).unwrap();
    assert_eq!(report["probe"]["probed"], true);
    host.stop();
    let mut replace = fixture.command("replace-credential");
    replace.arg("1");
    ok(&run(replace));
    assert_ne!(fixture.token(1), old_token);
    assert_eq!(fixture.json("connection.json")["endpoint"], endpoint);
    let replacement = fixture.client(fixture.token(1));
    let mut host = fixture.serve();
    assert!(matches!(relay.page(0, 1), Err(NetError::Denied)));
    assert_eq!(replacement.submit(&item).unwrap(), retry_receipt);
    assert_eq!(replacement.page(0, 2).unwrap().records.len(), 1);
    host.stop();
    let mut revoke = fixture.command("revoke-credential");
    revoke.arg("1");
    ok(&run(revoke));
    let mut host = fixture.serve();
    assert!(matches!(replacement.page(0, 1), Err(NetError::Denied)));
    let remaining = fixture.client(fixture.token(2));
    assert_eq!(remaining.page(0, 2).unwrap().records[0].item, item);
    host.stop();
}
