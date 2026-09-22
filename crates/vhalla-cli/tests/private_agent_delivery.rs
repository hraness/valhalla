//! Real TLS daemon and two independent stdio agent custodies; synthetic local data only.
#![cfg(all(unix, feature = "experimental-private"))]

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{protocol::Validity, Context, OperationId};
use vhalla_private_native::{
    client::{RoomCreation, RoomSession},
    private_rooms::Limits,
    relay::{delivery::DeliveryStore, net::RelayToken, tls::TlsRelay, RelayItem, RelayNamespace},
};

const NAME: &str = "agent-relay.integration.invalid";
const MODERN: &str = "2026-07-28";
const OWNER: usize = 0;
const MEMBER: usize = 1;

struct Fixture {
    path: PathBuf,
    contexts: [Context; 2],
    addr: SocketAddr,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-agent-delivery-{}-{}-{}",
            std::process::id(),
            stamp.as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let contexts = runtime().block_on(async {
            let valid = Validity::new(stamp.as_secs() - 1, stamp.as_secs() + 3600).unwrap();
            let limits = Limits {
                max_records: 128,
                max_record_bytes: 8 * 1024 * 1024,
            };
            let draft =
                RoomCreation::owner(Identity::create_new(path.join("0-id")).unwrap(), valid)
                    .unwrap();
            let owner_context = draft.context();
            let member = RoomCreation::member(
                Identity::create_new(path.join("1-id")).unwrap(),
                owner_context.scope,
                draft.anchor().clone(),
                draft.enrollment().clone(),
                valid,
            )
            .unwrap();
            let member_context = member.context();
            let mut owner = draft.commit(path.join("0-room"), limits).await.unwrap();
            let mut member = member.commit(path.join("1-room"), limits).await.unwrap();
            let request = member.key_package(op(1)).await.unwrap();
            let invitation = owner.invite(op(2), request.bytes(), valid).await.unwrap();
            member.join(invitation.bytes()).await.unwrap();
            [owner_context, member_context]
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let fixture = Self {
            path,
            contexts,
            addr,
        };
        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = issuer.self_signed(&issuer_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(vec![NAME.to_owned()]).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&key, &issuer, &issuer_key).unwrap();
        fixture.write("ca.der", issuer.der());
        fixture.write("leaf.der", leaf.der());
        fixture.write("key.der", &key.serialize_der());
        fixture.write("token", hex(&[7; 32]).as_bytes());
        fixture.write_json("disclosure.json", &json!({"host":"synthetic delivery integration", "provider":"none", "model":"fixture", "processing_policy":"local synthetic content only", "allow_cooperating_host":true}));
        fixture.write_json(
            "relay.json",
            &json!({
                "max_connections":8, "request_timeout_ms":2000, "window_ms":1000,
                "requests_per_window":128, "bytes_per_window":134217728,
                "credentials":[{"id":hex(&[8;16]), "namespace":hex(ns().as_bytes()),
                    "token_files":[fixture.p("token")], "put":true, "page":true,
                    "max_items":64, "max_bytes":8388608, "max_inflight":4,
                    "requests_per_window":64, "bytes_per_window":67108864}]
            }),
        );
        let mut command = fixture.command("relay-mailbox");
        command.arg(fixture.p("mailbox")).args([
            "--namespace",
            &hex(ns().as_bytes()),
            "--max-items",
            "128",
            "--max-bytes",
            "16777216",
        ]);
        success(command);
        let mut command = fixture.command("relay-tls-init");
        command
            .arg(fixture.p("mailbox"))
            .args(["--namespace", &hex(ns().as_bytes())]);
        success(command);
        for who in [OWNER, MEMBER] {
            fixture.write_json(&format!("{who}-delivery.json"), &fixture.profile(who));
            let mut command = fixture.room_command("delivery-init", who);
            command
                .arg("--config")
                .arg(fixture.p(&format!("{who}-delivery.json")));
            success(command);
        }
        fixture
    }
    fn p(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
    fn write(&self, name: &str, bytes: &[u8]) {
        fs::write(self.p(name), bytes).unwrap();
        fs::set_permissions(self.p(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn write_json(&self, name: &str, value: &Value) {
        self.write(name, &serde_json::to_vec(value).unwrap());
    }
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command.args(["private", action]);
        command
    }
    fn room_command(&self, action: &str, who: usize) -> Command {
        let mut command = self.command(action);
        command
            .arg(self.p(&format!("{who}-id")))
            .arg(self.p(&format!("{who}-room")));
        command
    }
    fn profile(&self, who: usize) -> Value {
        let c = self.contexts[who];
        json!({"version":1,
            "context":{"room":hex(c.scope.room.as_bytes()),"anchor":hex(c.scope.anchor.as_bytes()),"account":hex(c.account.as_bytes()),"device":hex(c.device.as_bytes())},
            "namespace":hex(ns().as_bytes()), "addr":self.addr.to_string(), "tls_name":NAME,
            "ca":self.p("ca.der"),"token":self.p("token"),"state":self.p(&format!("{who}-delivery")),
            "max_jobs":64,"max_bytes":8388608,"max_attempts":8,
            "initial_backoff_secs":5,"max_backoff_secs":30,"emit_acceptance":true})
    }
    fn grant(&self, who: usize, name: &str, through: u64) -> Value {
        let mut command = self.room_command("agent-grant", who);
        command
            .args([
                "--mode",
                "read-write",
                "--follow-inbox",
                "true",
                "--inbox-through",
                &through.to_string(),
                "--max-read-records",
                "512",
                "--max-read-bytes",
                "134217728",
            ])
            .arg("--disclosure")
            .arg(self.p("disclosure.json"))
            .arg("--receipt")
            .arg(self.p(&format!("{name}-claim.json")))
            .arg("--out")
            .arg(self.p(&format!("{name}-grant.json")));
        success(command);
        assert!(!self.p(&format!("{name}-claim.json")).exists());
        serde_json::from_slice(&fs::read(self.p(&format!("{name}-grant.json"))).unwrap()).unwrap()
    }
    fn host(&self, who: usize, grant: &str, profile: usize) -> Host {
        let mut command = self.room_command("agent-serve", who);
        command
            .arg("--grant")
            .arg(self.p(&format!("{grant}-grant.json")))
            .arg("--delivery")
            .arg(self.p(&format!("{profile}-delivery.json")));
        Host::spawn(command)
    }
    fn relay(&self) -> Host {
        let mut command = self.command("relay-tls-serve");
        command
            .arg(self.p("mailbox"))
            .args([
                "--namespace",
                &hex(ns().as_bytes()),
                "--listen",
                &self.addr.to_string(),
            ])
            .arg("--cert")
            .arg(self.p("leaf.der"))
            .arg("--key")
            .arg(self.p("key.der"))
            .arg("--config")
            .arg(self.p("relay.json"));
        let mut relay = Host::spawn(command);
        assert_eq!(
            relay.line().trim(),
            format!("relay-tls-serve {}", self.addr)
        );
        relay
    }
    fn client(&self) -> TlsRelay {
        TlsRelay::new(
            self.addr,
            NAME,
            fs::read(self.p("ca.der")).unwrap(),
            RelayToken::from_bytes([7; 32]).unwrap(),
            ns(),
        )
        .unwrap()
    }
    fn job(&self, who: usize, sequence: u64) -> vhalla_private_native::relay::delivery::JobStatus {
        let queue = DeliveryStore::open(
            self.p(&format!("{who}-delivery/jobs")),
            self.contexts[who],
            ns(),
            self.client().endpoint_id(),
        )
        .unwrap();
        queue
            .statuses(sequence - 1, 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }
    fn applied(&self, who: usize) -> Vec<Value> {
        fs::read_dir(self.p(&format!("{who}-delivery/applied")))
            .unwrap()
            .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
            .collect()
    }
    fn ciphertext(&self, who: usize, sequence: u64) -> Vec<u8> {
        runtime().block_on(async {
            let mut room = RoomSession::open(
                Identity::open(self.p(&format!("{who}-id"))).unwrap(),
                self.p(&format!("{who}-room")),
                self.contexts[who],
            )
            .await
            .unwrap();
            room.outbox(sequence - 1, 1).await.unwrap().records[0]
                .artifact()
                .unwrap()
                .bytes()
                .to_vec()
        })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Host {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<String>,
}
impl Host {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (send, responses) = mpsc::sync_channel(16);
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        assert!(line.len() <= 1024 * 1024 + 1);
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            child,
            input,
            responses,
        }
    }
    fn line(&mut self) -> String {
        match self.responses.recv_timeout(Duration::from_secs(12)) {
            Ok(line) => line,
            Err(error) => {
                let detail = if self.child.try_wait().unwrap().is_some() {
                    self.stderr()
                } else {
                    "child is still running".to_owned()
                };
                panic!("bounded child response: {error}: {detail}");
            }
        }
    }
    fn ask(&mut self, value: Value) -> Value {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
        serde_json::from_str(&self.line()).expect("stdout contains only MCP JSON")
    }
    fn call(&mut self, grant: &Value, name: &str, mut args: Value) -> Value {
        args["session"] = grant["grant_id"].clone();
        self.ask(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":MODERN,"io.modelcontextprotocol/clientCapabilities":{}},"name":name,"arguments":args}}))
    }
    fn queue(&mut self, grant: &Value, body: &str, operation: u8) -> u64 {
        let prepared = self.call(grant, "private_prepare", json!({"body":body}));
        let queued = self.call(grant, "private_queue", json!({"draft":prepared["result"]["structuredContent"]["draft"],"operation":hex(&[operation;16])}));
        let value = &queued["result"]["structuredContent"];
        assert_eq!(value["status"], "durable_local_only", "{queued}");
        assert!(
            value.get("relay").is_none(),
            "queue completion alone is not delivery evidence"
        );
        value["sequence"].as_str().unwrap().parse().unwrap()
    }
    fn outbox(&mut self, grant: &Value, sequence: u64) -> Value {
        let response = self.call(
            grant,
            "private_outbox_status",
            json!({"after":(sequence-1).to_string(),"limit":1}),
        );
        let record = response["result"]["structuredContent"]["records"][0].clone();
        assert!(record.is_object(), "{response}");
        record
    }
    fn await_outbox(
        &mut self,
        grant: &Value,
        sequence: u64,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let value = self.outbox(grant, sequence);
            if predicate(&value) {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "delivery state did not converge: {value}"
            );
            thread::sleep(Duration::from_millis(500));
        }
    }
    fn close(&mut self) {
        drop(self.input.take());
        wait_exit(&mut self.child);
        assert!(
            self.child.try_wait().unwrap().unwrap().success(),
            "{}",
            self.stderr()
        );
    }
    fn refused(&mut self) {
        wait_exit(&mut self.child);
        assert!(!self.child.try_wait().unwrap().unwrap().success());
        assert!(self
            .responses
            .recv_timeout(Duration::from_millis(100))
            .is_err());
    }
    fn stderr(&mut self) -> String {
        let mut text = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}
fn ns() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn op(n: u8) -> OperationId {
    OperationId::from_bytes([n; 16]).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn wait_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded child exit deadline");
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
    wait_exit(&mut child);
    child.wait_with_output().unwrap()
}
fn success(command: Command) {
    let out = run(command);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn tls_delivery_survives_offline_restart_and_distinguishes_retention_from_recipient_claim() {
    let f = Fixture::new();
    let first = f.grant(OWNER, "first", 16);
    let mut owner = f.host(OWNER, "first", OWNER);
    let sequence = owner.queue(&first, "synthetic first message", 10);
    let offline = owner.await_outbox(&first, sequence, |v| v["relay"]["state"] == "uncertain");
    assert_eq!(offline["relay"]["attempts"], 1);
    assert_eq!(offline["relay"]["uncertain"], true);
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        owner.outbox(&first, sequence)["relay"]["attempts"],
        1,
        "offline attempts must respect backoff"
    );
    owner.close();
    let retained_wire = f.ciphertext(OWNER, sequence);
    let before = f.job(OWNER, sequence);
    assert!(before.uncertain);
    let mut reused = f.host(OWNER, "first", OWNER);
    reused.refused();
    assert!(f.p("first-claim.json").exists());
    assert_eq!(
        f.job(OWNER, sequence),
        before,
        "old launch refusal must not advance durable attempts"
    );
    let _relay = f.relay();
    let second = f.grant(OWNER, "second", 16);
    let mut owner = f.host(OWNER, "second", OWNER);
    let retained = owner.await_outbox(&second, sequence, |v| v["relay"]["state"] == "retained");
    assert_eq!(retained["relay"]["uncertain"], false);
    assert_eq!(
        retained["member_acceptances"],
        json!([]),
        "relay retention is not member acceptance"
    );
    let later = owner.queue(
        &second,
        "synthetic later message beyond disclosure ceiling",
        11,
    );
    owner.await_outbox(&second, later, |v| v["relay"]["state"] == "retained");
    let member_grant = f.grant(MEMBER, "member", 1);
    let mut member = f.host(MEMBER, "member", MEMBER);
    let claim = owner.await_outbox(&second, sequence, |v| {
        v["member_acceptances"]
            .as_array()
            .is_some_and(|a| a.len() == 1)
    });
    assert_eq!(
        claim["member_acceptances"][0]["recipient"],
        hex(f.contexts[MEMBER].device.as_bytes())
    );
    assert_eq!(claim["member_acceptances"][0]["received_sequence"], "1");
    owner.await_outbox(&second, later, |v| {
        v["member_acceptances"]
            .as_array()
            .is_some_and(|a| a.len() == 1)
    });
    assert_eq!(
        member.call(&member_grant, "private_status", json!({}))["result"]["structuredContent"]
            ["inbox_head"],
        "2",
        "host delivery may retain later messages while the agent disclosure ceiling stays fixed"
    );
    let inbox = member.call(
        &member_grant,
        "private_inbox",
        json!({"after":"0","limit":8}),
    );
    assert_eq!(inbox["result"]["structuredContent"]["head"], "1");
    assert_eq!(
        inbox["result"]["structuredContent"]["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        inbox["result"]["structuredContent"]["records"][0]["text"],
        "synthetic first message"
    );
    assert!(!inbox.to_string().contains("synthetic later message"));
    let forbidden = member.call(
        &member_grant,
        "private_inbox",
        json!({"after":"2","limit":1}),
    );
    assert_eq!(
        forbidden["result"]["structuredContent"]["code"],
        "history_not_granted"
    );
    member.close();
    owner.close();
    assert_eq!(
        f.ciphertext(OWNER, sequence),
        retained_wire,
        "restart retransmits exact committed ciphertext"
    );
    assert_eq!(f.job(OWNER, sequence).id, before.id);
    assert!(f
        .applied(OWNER)
        .iter()
        .any(|v| v["state"] == "exact-local-outbox-echo"));
    assert!(f
        .applied(OWNER)
        .iter()
        .any(|v| v["state"] == "recipient-device-claim"));
    // A fresh explicit grant restores the signed claim from retained receive evidence.
    let third = f.grant(OWNER, "third", 16);
    let mut owner = f.host(OWNER, "third", OWNER);
    let restored = owner.await_outbox(&third, sequence, |v| {
        v["member_acceptances"]
            .as_array()
            .is_some_and(|a| a.len() == 1)
    });
    assert_eq!(restored["member_acceptances"], claim["member_acceptances"]);
    owner.close();
}

#[test]
fn foreign_delivery_profile_refuses_before_consuming_grant_or_mutating_queue() {
    let f = Fixture::new();
    let grant = f.grant(OWNER, "selected", 4);
    let binding = fs::read(f.p("0-delivery/binding")).unwrap();
    let mut wrong = f.host(OWNER, "selected", MEMBER);
    wrong.refused();
    assert!(
        !f.p("selected-claim.json").exists(),
        "profile admission must precede one-use grant claim"
    );
    assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
    let mut altered = f.profile(OWNER);
    altered["max_attempts"] = json!(9);
    f.write_json("0-delivery.json", &altered);
    let mut drifted = f.host(OWNER, "selected", OWNER);
    drifted.refused();
    assert!(
        !f.p("selected-claim.json").exists(),
        "retry policy drift must not consume the grant"
    );
    let mut shifted = f.profile(OWNER);
    shifted["initial_cursor"] = json!(1);
    f.write_json("0-delivery.json", &shifted);
    let mut drifted = f.host(OWNER, "selected", OWNER);
    drifted.refused();
    assert!(
        !f.p("selected-claim.json").exists(),
        "a new admission checkpoint cannot reinterpret retained custody"
    );
    assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
    f.write_json("0-delivery.json", &f.profile(OWNER));
    let mut right = f.host(OWNER, "selected", OWNER);
    let status = right.call(&grant, "private_status", json!({}));
    assert_eq!(status["result"]["structuredContent"]["status"], "live");
    right.close();
    assert!(f.p("selected-claim.json").exists());
    // Existing profile initialization is never interpreted as permission to reset it.
    let mut init = f.room_command("delivery-init", OWNER);
    init.arg("--config").arg(f.p("0-delivery.json"));
    assert!(!run(init).status.success());
    assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
}

#[test]
fn authenticated_removal_releases_stdio_custody_without_disclosing_more_agent_output() {
    let f = Fixture::new();
    let _relay = f.relay();
    let grant = f.grant(MEMBER, "removed", 4);
    let mut member = f.host(MEMBER, "removed", MEMBER);
    assert_eq!(
        member.call(&grant, "private_status", json!({}))["result"]["structuredContent"]["status"],
        "live"
    );
    let removal = runtime().block_on(async {
        let mut owner = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        owner
            .remove(op(12), f.contexts[MEMBER].device)
            .await
            .unwrap()
    });
    f.client()
        .submit(&RelayItem::from_artifact(ns(), &removal).unwrap())
        .unwrap();
    member.refused();
    assert!(f.p("removed-claim.json").exists());
    runtime().block_on(async {
        let room = RoomSession::open(
            Identity::open(f.p("1-id")).unwrap(),
            f.p("1-room"),
            f.contexts[MEMBER],
        )
        .await
        .unwrap();
        assert_eq!(
            room.status().unwrap().phase,
            vhalla_private_kernel::Phase::Removed
        );
    });
}
