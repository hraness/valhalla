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
use vhalla_private_kernel::{protocol::Validity, Context, OperationId, OutboxKind};
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
    max_jobs: usize,
    mailbox_polling: Option<&'static str>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_capacity(128, 128)
    }
    fn with_capacity(max_records: u64, mailbox_items: usize) -> Self {
        Self::with_queue_capacity(max_records, mailbox_items, 64)
    }
    fn with_queue_capacity(max_records: u64, mailbox_items: usize, max_jobs: usize) -> Self {
        Self::with_policy(max_records, mailbox_items, max_jobs, None)
    }
    fn with_policy(
        max_records: u64,
        mailbox_items: usize,
        max_jobs: usize,
        mailbox_polling: Option<&'static str>,
    ) -> Self {
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
                max_records,
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
            max_jobs,
            mailbox_polling,
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
                "requests_per_window":mailbox_items.max(128), "bytes_per_window":134217728,
                "credentials":[{"id":hex(&[8;16]), "namespace":hex(ns().as_bytes()),
                    "token_files":[fixture.p("token")], "put":true, "page":true,
                    "max_items":mailbox_items / 2, "max_bytes":8388608, "max_inflight":4,
                    "requests_per_window":(mailbox_items / 2).max(64), "bytes_per_window":67108864}]
            }),
        );
        let mut command = fixture.command("relay-mailbox");
        command.arg(fixture.p("mailbox")).args([
            "--namespace",
            &hex(ns().as_bytes()),
            "--max-items",
            &mailbox_items.to_string(),
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
        let mut profile = json!({"version":2,
            "context":{"room":hex(c.scope.room.as_bytes()),"anchor":hex(c.scope.anchor.as_bytes()),"account":hex(c.account.as_bytes()),"device":hex(c.device.as_bytes())},
            "namespace":hex(ns().as_bytes()), "addr":self.addr.to_string(), "tls_name":NAME,
            "ca":self.p("ca.der"),"token":self.p("token"),"state":self.p(&format!("{who}-delivery")),
            "max_jobs":self.max_jobs,"max_bytes":8388608,"max_attempts":8,
            "initial_backoff_secs":5,"max_backoff_secs":30,"emit_acceptance":true});
        if let Some(policy) = self.mailbox_polling {
            profile["mailbox_polling"] = json!(policy);
        }
        profile
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
    fn job(
        &self,
        who: usize,
        sequence: u64,
    ) -> (
        vhalla_private_native::relay::delivery::JobStatus,
        vhalla_private_native::relay::delivery::JobEvidence,
    ) {
        let queue = DeliveryStore::open(
            self.p(&format!("{who}-delivery/jobs")),
            self.contexts[who],
            ns(),
            self.client().endpoint_id(),
        )
        .unwrap();
        let status = queue
            .statuses(sequence - 1, 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let evidence = queue.evidence(status.id).unwrap();
        (status, evidence)
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
    fn driver_checkpoint(&self, who: usize) -> (u64, u64) {
        DeliveryStore::open(
            self.p(&format!("{who}-delivery/jobs")),
            self.contexts[who],
            ns(),
            self.client().endpoint_id(),
        )
        .unwrap()
        .driver_checkpoint()
        .unwrap()
    }
    fn control_job(
        &self,
        who: usize,
        sequence: u64,
    ) -> (
        vhalla_private_native::relay::delivery::JobStatus,
        vhalla_private_native::relay::delivery::JobEvidence,
    ) {
        let queue = DeliveryStore::open(
            self.p(&format!("{who}-delivery/controls")),
            self.contexts[who],
            ns(),
            self.client().endpoint_id(),
        )
        .unwrap();
        let status = queue.statuses(sequence - 1, 1).unwrap().remove(0);
        let evidence = queue.evidence(status.id).unwrap();
        (status, evidence)
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
        self.outbox_wait(grant, sequence, 0)
    }
    fn outbox_wait(&mut self, grant: &Value, sequence: u64, wait_for: u64) -> Value {
        let response = self.call(
            grant,
            "private_outbox_status",
            json!({"after":(sequence-1).to_string(),"limit":1,"wait_for":wait_for}),
        );
        let record = response["result"]["structuredContent"]["records"][0].clone();
        assert!(record.is_object(), "{response}");
        if wait_for > 0 {
            assert!(
                matches!(
                    response["result"]["structuredContent"]["wait"].as_str(),
                    Some("changed" | "timeout")
                ),
                "{response}"
            );
        }
        record
    }
    fn await_outbox(
        &mut self,
        grant: &Value,
        sequence: u64,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut value = self.outbox(grant, sequence);
        loop {
            if predicate(&value) {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "delivery state did not converge: {value}"
            );
            // Long-poll: the server answers as soon as delivery evidence changes.
            value = self.outbox_wait(grant, sequence, 3);
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
        // A refused launch may emit one bounded closing notice so a client sees
        // why the stream ended; it is never a data response and nothing more
        // may follow it.
        if let Ok(line) = self.responses.recv_timeout(Duration::from_millis(500)) {
            let notice: Value = serde_json::from_str(&line).expect("closing frame is MCP JSON");
            assert_eq!(notice["method"], "notifications/message", "{notice}");
            assert_eq!(notice["params"]["data"]["status"], "closed", "{notice}");
            assert!(self
                .responses
                .recv_timeout(Duration::from_millis(100))
                .is_err());
        }
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
    delivery_survives_offline_restart(None);
}

#[test]
fn interactive_polling_preserves_exact_delivery_restarts_and_grant_disclosure_limits() {
    delivery_survives_offline_restart(Some("interactive"));
}

fn delivery_survives_offline_restart(mailbox_polling: Option<&'static str>) {
    let f = Fixture::with_policy(128, 128, 64, mailbox_polling);
    let first = f.grant(OWNER, "first", 16);
    let mut owner = f.host(OWNER, "first", OWNER);
    let sequence = owner.queue(&first, "synthetic first message", 10);
    // The required owner control encounters the outage first. Applications
    // remain pending until that exact control has been retained by the relay.
    let offline = owner.await_outbox(&first, sequence, |v| v["relay"]["state"] == "pending");
    assert_eq!(offline["relay"]["attempts"], 0);
    assert_eq!(offline["relay"]["uncertain"], false);
    assert_eq!(offline["relay"]["last_error"], Value::Null);
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        owner.outbox(&first, sequence)["relay"]["attempts"],
        0,
        "offline attempts must respect backoff"
    );
    owner.close();
    let retained_wire = f.ciphertext(OWNER, sequence);
    let (before, before_evidence) = f.job(OWNER, sequence);
    assert!(!before.uncertain);
    assert_eq!(before.attempts, 0);
    assert_eq!(before_evidence.outages, 0);
    let (control, control_evidence) = f.control_job(OWNER, 1);
    assert!(control.uncertain);
    assert_eq!(
        control.last_error,
        Some(vhalla_private_native::relay::net::NetError::Connect)
    );
    assert_eq!(
        control.attempts, 0,
        "outages do not spend finite attempt authority"
    );
    assert_eq!(control_evidence.outages, 1);
    let mut reused = f.host(OWNER, "first", OWNER);
    reused.refused();
    assert!(f.p("first-claim.json").exists());
    assert_eq!(
        f.job(OWNER, sequence).0,
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
    assert_eq!(f.job(OWNER, sequence).0.id, before.id);
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
fn denied_tls_token_ends_grant_then_explicit_replacement_retries_exact_ciphertext() {
    use vhalla_private_native::relay::{delivery::JobState, net::NetError};

    let f = Fixture::new();
    let artifact = runtime().block_on(async {
        let mut room = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        let draft = room
            .prepare_message(b"synthetic credential replacement")
            .unwrap();
        room.send(op(13), &draft).await.unwrap()
    });
    let sequence = artifact.sequence();
    let exact_item = RelayItem::from_artifact(ns(), &artifact).unwrap();
    let _relay = f.relay();
    f.write("wrong-token", hex(&[6; 32]).as_bytes());
    let mut wrong_profile = f.profile(OWNER);
    wrong_profile["token"] = json!(f.p("wrong-token"));
    f.write_json("0-delivery.json", &wrong_profile);
    f.grant(OWNER, "denied", 4);
    let mut denied = f.host(OWNER, "denied", OWNER);
    denied.refused();
    assert!(f.p("denied-claim.json").exists());
    let (before, _) = f.job(OWNER, sequence);
    assert_eq!(before.id, exact_item.digest());
    assert_eq!(before.state, JobState::Pending);
    assert_eq!(before.attempts, 0, "required control is attempted first");
    assert_eq!(before.last_error, None);
    assert!(!before.uncertain);
    let (control, _) = f.control_job(OWNER, 1);
    assert_eq!(control.attempts, 1);
    assert_eq!(control.last_error, Some(NetError::Denied));
    assert_eq!(f.client().page(0, 8).unwrap().head, 0);
    assert_eq!(f.ciphertext(OWNER, sequence), artifact.bytes());

    // Correcting the credential alone cannot reuse the consumed launch grant.
    f.write_json("0-delivery.json", &f.profile(OWNER));
    let mut reused = f.host(OWNER, "denied", OWNER);
    reused.refused();
    assert_eq!(f.job(OWNER, sequence).0, before);
    let replacement = f.grant(OWNER, "replacement", 4);
    let mut owner = f.host(OWNER, "replacement", OWNER);
    let retained = owner.await_outbox(&replacement, sequence, |v| {
        v["relay"]["state"] == "retained"
    });
    assert_eq!(retained["relay"]["attempts"], 1);
    owner.close();
    assert_eq!(f.job(OWNER, sequence).0.id, before.id);
    assert_eq!(f.ciphertext(OWNER, sequence), artifact.bytes());
    let page = f.client().page(0, 8).unwrap();
    assert_eq!(page.head, 2);
    assert_eq!(page.records.len(), 2);
    assert_eq!(
        page.records[0].item.kind(),
        vhalla_private_native::relay::RelayKind::Control
    );
    assert_eq!(page.records[1].item, exact_item);
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
    for policy in [
        json!("interactive"),
        json!("unknown"),
        json!(1),
        Value::Null,
    ] {
        let mut changed = f.profile(OWNER);
        changed["mailbox_polling"] = policy;
        f.write_json("0-delivery.json", &changed);
        let mut drifted = f.host(OWNER, "selected", OWNER);
        drifted.refused();
        assert!(
            !f.p("selected-claim.json").exists(),
            "mailbox policy drift or malformed selection must precede the grant claim"
        );
        assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
    }
    let mut explicit_default = f.profile(OWNER);
    explicit_default["mailbox_polling"] = json!("adaptive");
    f.write_json("0-delivery.json", &explicit_default);
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
fn interactive_profile_cannot_silently_fall_back_to_adaptive() {
    let f = Fixture::with_policy(128, 128, 64, Some("interactive"));
    let grant = f.grant(OWNER, "selected", 4);
    let binding = fs::read(f.p("0-delivery/binding")).unwrap();
    assert_eq!(&binding[..10], b"VHDELHOST\x04");
    for selection in [Some("adaptive"), None] {
        let mut changed = f.profile(OWNER);
        if let Some(policy) = selection {
            changed["mailbox_polling"] = json!(policy);
        } else {
            changed.as_object_mut().unwrap().remove("mailbox_polling");
        }
        f.write_json("0-delivery.json", &changed);
        let mut refused = f.host(OWNER, "selected", OWNER);
        refused.refused();
        assert!(!f.p("selected-claim.json").exists());
        assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
    }
    f.write_json("0-delivery.json", &f.profile(OWNER));
    let mut selected = f.host(OWNER, "selected", OWNER);
    let status = selected.call(&grant, "private_status", json!({}));
    assert_eq!(status["result"]["structuredContent"]["status"], "live");
    selected.close();
}

#[test]
fn authenticated_removal_releases_stdio_custody_without_disclosing_more_agent_output() {
    let f = Fixture::new();
    let _relay = f.relay();
    let grant = f.grant(MEMBER, "removed", 4);
    let mut member = f.host(MEMBER, "removed", MEMBER);
    let probe = member.call(&grant, "private_status", json!({}));
    assert_eq!(
        probe["result"]["structuredContent"]["status"],
        "live",
        "{probe} stderr={}",
        member.stderr()
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

#[test]
fn malformed_retained_item_records_skip_marker_and_following_delivery_still_applies() {
    let f = Fixture::new();
    let artifact = runtime().block_on(async {
        let mut room = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        room.send(
            op(30),
            &room
                .prepare_message(b"real message behind a foreign item")
                .unwrap(),
        )
        .await
        .unwrap()
    });
    let _relay = f.relay();
    // Position 1 is undecryptable garbage no room member can ever process; the
    // real committed output lands right behind it at position 2.
    f.client()
        .submit(
            &RelayItem::new(
                ns(),
                1,
                op(98),
                OutboxKind::Application,
                b"this is not a valid MLS private-room artifact",
            )
            .unwrap(),
        )
        .unwrap();
    f.client()
        .submit(&RelayItem::from_artifact(ns(), &artifact).unwrap())
        .unwrap();
    let grant = f.grant(MEMBER, "unstuck", 8);
    let mut member = f.host(MEMBER, "unstuck", MEMBER);
    // The driver marks the foreign position terminally skipped instead of
    // wedging the contiguous applied watermark or ending the launch.
    let deadline = Instant::now() + Duration::from_secs(30);
    let markers = loop {
        let markers = f.applied(MEMBER);
        if markers
            .iter()
            .any(|v| v["state"] == "undecryptable-foreign-or-stale")
            && markers.iter().any(|v| v["state"] == "locally-received")
        {
            break markers;
        }
        if Instant::now() >= deadline {
            let detail = if member.child.try_wait().unwrap().is_some() {
                member.stderr()
            } else {
                "host still running".to_owned()
            };
            panic!("driver did not advance past the foreign item: {markers:?}\n{detail}");
        }
        thread::sleep(Duration::from_millis(300));
    };
    let skip = markers
        .iter()
        .find(|v| v["state"] == "undecryptable-foreign-or-stale")
        .unwrap();
    assert!(
        [
            "stale_epoch",
            "ratchet_gap_past",
            "foreign_scope",
            "authentication",
            "malformed_encoding",
            "unprocessable_mls",
            "bounds",
            "policy",
            "predates_control_floor",
        ]
        .contains(&skip["error"].as_str().unwrap()),
        "skip reasons stay inside the closed set: {skip}"
    );
    assert_eq!(skip["position"], "1");
    // The launch stays live and the valid message behind the skip is received.
    assert_eq!(
        member.call(&grant, "private_status", json!({}))["result"]["structuredContent"]["status"],
        "live"
    );
    let inbox = member.call(&grant, "private_inbox", json!({"after":"0","limit":4}));
    assert!(
        inbox["result"]["structuredContent"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["text"] == "real message behind a foreign item"),
        "{inbox}"
    );
    assert!(!inbox.to_string().contains("not a valid MLS"));
    // The member emitted a signed acceptance receipt for the received message:
    // it is a durable queue row (the member's own outbox sequence 2), and the
    // driver delivers it like any other job. Waiting for retention guarantees
    // the outgoing watermark covered the receipt before the launch ended.
    member.await_outbox(&grant, 2, |v| v["relay"]["state"] == "retained");
    member.close();
    // The durable checkpoint retains both watermarks across the launch end.
    let (outgoing, applied) = f.driver_checkpoint(MEMBER);
    assert!(applied >= 2, "applied watermark survived relaunch evidence");
    assert!(outgoing >= 2, "outgoing covered the emitted receipt");
    // The read-only journal reports the same durable state without a grant.
    let mut status = f.room_command("delivery-status", MEMBER);
    status
        .arg("--config")
        .arg(f.p("1-delivery.json"))
        .arg("--out")
        .arg(f.p("status.json"));
    success(status);
    let report: Value = serde_json::from_slice(&fs::read(f.p("status.json")).unwrap()).unwrap();
    assert_eq!(report["driver"]["applied"], applied.to_string());
    // The member's own outbox was scanned: the emitted acceptance receipt is
    // a durable queue row (its key package is a confidential offer, never a
    // relay job).
    assert_eq!(
        report["driver"]["outgoing"],
        outgoing.to_string(),
        "{report}"
    );
    let jobs = report["jobs"].as_array().unwrap();
    assert!(
        !jobs.is_empty(),
        "emitted receipt is a durable queue row: {report}"
    );
    assert!(jobs.iter().all(|j| matches!(
        j["state"].as_str(),
        Some("pending" | "uncertain" | "retained" | "stopped")
    )));
}

#[test]
fn third_member_control_unblocks_more_than_one_page_after_restart_and_explicit_regrant() {
    use vhalla_private_kernel::protocol::Key;
    use vhalla_private_native::relay::{delivery::JobState, RelayKind, MAX_RELAY_PAGE};

    let f = Fixture::with_capacity(1024, 512);
    let count = MAX_RELAY_PAGE + 1;
    let (expected_control, messages) = runtime().block_on(async {
        let mut owner = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        let before = owner.status().unwrap().control_floor;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = Validity::new(now - 1, now + 1800).unwrap();
        let identity = Identity::create_new(f.p("2-id")).unwrap();
        let recipient = Key::from_bytes(identity.public_key()).unwrap();
        let offer = owner
            .create_contact_offer(op(200), recipient, valid)
            .await
            .unwrap();
        let mut third = RoomCreation::from_contact(
            identity,
            offer.confidential_bytes(),
            f.contexts[OWNER].account,
            valid,
        )
        .unwrap()
        .commit(
            f.p("2-room"),
            Limits {
                max_records: 1024,
                max_record_bytes: 8 * 1024 * 1024,
            },
        )
        .await
        .unwrap();
        let request = third
            .contact_request(op(201), offer.confidential_bytes())
            .await
            .unwrap();
        let welcome = owner
            .accept_contact(op(202), request.bytes(), valid)
            .await
            .unwrap();
        third.join_contact(welcome.bytes()).await.unwrap();
        let page = owner.encrypted_controls(before, 1).await.unwrap();
        let control = RelayItem::from_control(ns(), &page.records[0]).unwrap();
        let mut messages = Vec::new();
        for i in 0..count {
            let draft = third
                .prepare_message(format!("third member exact message {i}").as_bytes())
                .unwrap();
            let artifact = third.send(op((i + 1) as u8), &draft).await.unwrap();
            messages.push(RelayItem::from_artifact(ns(), &artifact).unwrap());
        }
        (control, messages)
    });
    let _relay = f.relay();
    // Transport can reorder independent senders. All application bytes precede
    // their required control, including one beyond a complete native scan page.
    for item in &messages {
        f.client().submit(item).unwrap();
    }
    let first = f.grant(MEMBER, "deferred-first", 128);
    let mut member = f.host(MEMBER, "deferred-first", MEMBER);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let staged = fs::read_dir(f.p("1-delivery/scan/items")).unwrap().count();
        if staged >= count {
            break;
        }
        assert!(Instant::now() < deadline, "future-epoch page did not stage");
        assert_eq!(
            member.call(&first, "private_status", json!({}))["result"]["structuredContent"]
                ["status"],
            "live"
        );
        thread::sleep(Duration::from_millis(50));
    }
    member.close();
    assert!(
        f.applied(MEMBER).is_empty(),
        "future epochs must remain retryable"
    );
    assert_eq!(f.driver_checkpoint(MEMBER).1, 0);
    // Neither a contiguous filename nor a plausible marker beyond a deferred
    // gap may advance recovery. The second marker has the exact staged digest
    // but invents reception evidence that does not exist in kernel custody.
    for position in [1u64, 2] {
        let marker = if position == 1 {
            b"{}".to_vec()
        } else {
            serde_json::to_vec(&json!({"digest":hex(&messages[1].digest()), "position":"2", "state":"locally-received", "inbox_sequence":"1", "receipt_outbox_sequence":"1"})).unwrap()
        };
        let name = format!("1-delivery/applied/{position:016x}.json");
        f.write(&name, &marker);
        let grant_name = format!("corrupt-{position}");
        f.grant(MEMBER, &grant_name, 128);
        f.host(MEMBER, &grant_name, MEMBER).refused();
        assert_eq!(
            fs::read(f.p(&name)).unwrap(),
            marker,
            "refusal preserves corrupt evidence"
        );
        assert_eq!(f.driver_checkpoint(MEMBER).1, 0);
        fs::rename(
            f.p(&name),
            f.p(&format!("preserved-corrupt-{position}.json")),
        )
        .unwrap();
    }

    // A fresh grant still authorizes only the old roster. The owner's ordinary
    // configured host publishes its retained control without manual injection.
    f.grant(MEMBER, "before-admission", 128);
    let owner_grant = f.grant(OWNER, "publish-admission", 128);
    let mut owner = f.host(OWNER, "publish-admission", OWNER);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let page = f.client().page(count as u64, 8).unwrap();
        if page.records.iter().any(|r| r.item == expected_control) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "automatic admission control did not reach relay"
        );
        assert_eq!(
            owner.call(&owner_grant, "private_status", json!({}))["result"]["structuredContent"]
                ["status"],
            "live"
        );
        thread::sleep(Duration::from_millis(50));
    }
    owner.close();
    let mut member = f.host(MEMBER, "before-admission", MEMBER);
    member.refused();
    assert!(f
        .applied(MEMBER)
        .iter()
        .any(|v| v["state"] == "locally-applied-control"));
    assert!(
        !f.applied(MEMBER)
            .iter()
            .any(|v| v["state"] == "locally-received"),
        "changed roster must end the previous disclosure grant before plaintext release"
    );
    runtime().block_on(async {
        let room = RoomSession::open(
            Identity::open(f.p("1-id")).unwrap(),
            f.p("1-room"),
            f.contexts[MEMBER],
        )
        .await
        .unwrap();
        assert_eq!(room.status().unwrap().members, 3);
        assert_eq!(room.status().unwrap().inbox_head, 0);
    });
    let second = f.grant(MEMBER, "after-admission", 128);
    let mut member = f.host(MEMBER, "after-admission", MEMBER);
    // Receiving and signing each acceptance requires durable writes, while
    // relay publication shares the driver's two-second work window. Bound a
    // stalled driver separately from total throughput on a loaded CI host.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(120);
    let mut progress_deadline = started + Duration::from_secs(30);
    let mut received = 0;
    let mut progress = Vec::new();
    let mut last_status = Value::Null;
    loop {
        let markers = f.applied(MEMBER);
        let count_received = markers
            .iter()
            .filter(|v| v["state"] == "locally-received")
            .count();
        let now = Instant::now();
        assert!(
            (received..=count).contains(&count_received),
            "received markers regressed or exceeded the input: {received} -> {count_received}/{count}"
        );
        // Check both existing deadlines before new evidence can refresh the
        // progress clock or late completion can turn a timeout into success.
        assert!(
            now < deadline && now < progress_deadline,
            "deferred messages did not resume: {count_received}/{count}; elapsed_ms={}; \
             progress_ms_and_count={progress:?}; markers={}; staged={:?}; last_status={last_status}",
            now.duration_since(started).as_millis(),
            markers.len(),
            fs::read_dir(f.p("1-delivery/scan/items")).map(|entries| entries.count())
        );
        if count_received > received {
            received = count_received;
            progress_deadline = now + Duration::from_secs(30);
            // Strictly increasing counts bound this history to 65 entries.
            progress.push((now.duration_since(started).as_millis(), received));
        }
        if count_received == count {
            break;
        }
        let probe = member.call(&second, "private_status", json!({}));
        let status = &probe["result"]["structuredContent"];
        last_status = json!({
            "status": status["status"],
            "inbox_head": status["inbox_head"],
            "outbox_head": status["outbox_head"],
        });
        assert_eq!(
            status["status"], "live",
            "received={count_received}: {probe}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let inbox = member.call(&second, "private_inbox", json!({"after":"0","limit":1}));
    assert_eq!(
        inbox["result"]["structuredContent"]["records"][0]["text"],
        "third member exact message 0"
    );
    let status = member.call(&second, "private_status", json!({}));
    let final_outbox: u64 = status["result"]["structuredContent"]["outbox_head"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    member.await_outbox(&second, final_outbox, |v| v["relay"]["state"] == "retained");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let head = f.client().page(0, 1).unwrap().head;
        if f.applied(MEMBER).len() as u64 == head {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "inbound evidence did not drain before replay snapshot"
        );
        let probe = member.call(&second, "private_status", json!({}));
        assert_eq!(
            probe["result"]["structuredContent"]["status"], "live",
            "{probe}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    member.close();
    assert!(f.driver_checkpoint(MEMBER).1 >= count as u64);
    let controls = DeliveryStore::open(
        f.p("1-delivery/controls"),
        f.contexts[MEMBER],
        ns(),
        f.client().endpoint_id(),
    )
    .unwrap();
    let status = controls.job(expected_control.digest()).unwrap().unwrap();
    assert_eq!(status.state, JobState::Retained);
    assert_eq!(controls.driver_checkpoint().unwrap().0, 2);
    assert_eq!(expected_control.kind(), RelayKind::Control);
    assert_eq!(
        f.client().page(0, MAX_RELAY_PAGE).unwrap().records[0].item,
        messages[0],
        "exact deferred ciphertext is preserved"
    );
    let mut command = f.room_command("delivery-status", MEMBER);
    command
        .arg("--config")
        .arg(f.p("1-delivery.json"))
        .args(["--stream", "control"])
        .arg("--out")
        .arg(f.p("controls-status.json"));
    drop(controls);
    success(command);
    let report: Value =
        serde_json::from_slice(&fs::read(f.p("controls-status.json")).unwrap()).unwrap();
    assert_eq!(report["stream"], "control");
    assert_eq!(report["driver"]["outgoing"], "2");
    assert_eq!(report["jobs"][0]["digest"], hex(&expected_control.digest()));
    let before = runtime().block_on(async {
        let room = RoomSession::open(
            Identity::open(f.p("1-id")).unwrap(),
            f.p("1-room"),
            f.contexts[MEMBER],
        )
        .await
        .unwrap();
        (
            room.status().unwrap().inbox_head,
            room.status().unwrap().outbox_head,
        )
    });
    let saved_checkpoint = f.driver_checkpoint(MEMBER);
    // Each launch reauthenticates from the initial cursor in bounded windows.
    // Closing after a partial replay and reopening cannot decrease the saved
    // checkpoint or create another signed acceptance/ciphertext.
    for (name, rounds) in [("partial-marker-replay", 1), ("complete-marker-replay", 3)] {
        let grant = f.grant(MEMBER, name, 128);
        let mut member = f.host(MEMBER, name, MEMBER);
        for _ in 0..rounds {
            let status = member.call(&grant, "private_status", json!({}));
            assert_eq!(
                status["result"]["structuredContent"]["status"], "live",
                "{status}"
            );
        }
        member.close();
        assert!(f.driver_checkpoint(MEMBER).1 >= saved_checkpoint.1);
        runtime().block_on(async {
            let room = RoomSession::open(
                Identity::open(f.p("1-id")).unwrap(),
                f.p("1-room"),
                f.contexts[MEMBER],
            )
            .await
            .unwrap();
            assert_eq!(
                (
                    room.status().unwrap().inbox_head,
                    room.status().unwrap().outbox_head
                ),
                before
            );
        });
    }
}

#[test]
fn pending_old_epoch_application_precedes_own_control_and_new_epoch_at_one_job_capacity() {
    use vhalla_private_native::relay::RelayKind;
    let f = Fixture::with_queue_capacity(128, 128, 1);
    let (old, control, new) = runtime().block_on(async {
        let mut owner = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        let draft = owner
            .prepare_message(b"old epoch must remain decryptable")
            .unwrap();
        let old = owner.send(op(60), &draft).await.unwrap();
        let before = owner.status().unwrap().control_floor;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        owner
            .renew_owner(op(61), Validity::new(now - 1, now + 7200).unwrap())
            .await
            .unwrap();
        let control = owner
            .encrypted_controls(before, 1)
            .await
            .unwrap()
            .records
            .remove(0);
        let draft = owner
            .prepare_message(b"new epoch requires its control")
            .unwrap();
        let new = owner.send(op(62), &draft).await.unwrap();
        assert!(old.application_epoch().unwrap().unwrap() <= control.prior_epoch().unwrap());
        assert!(new.application_epoch().unwrap().unwrap() > control.prior_epoch().unwrap());
        (
            RelayItem::from_artifact(ns(), &old).unwrap(),
            RelayItem::from_control(ns(), &control).unwrap(),
            RelayItem::from_artifact(ns(), &new).unwrap(),
        )
    });
    let _relay = f.relay();
    let grant = f.grant(OWNER, "ordered", 16);
    let mut owner = f.host(OWNER, "ordered", OWNER);
    owner.await_outbox(&grant, new.sequence(), |v| {
        v["relay"]["state"] == "retained"
    });
    owner.close();
    let page = f.client().page(0, 16).unwrap();
    let position = |item: &RelayItem| {
        page.records
            .iter()
            .position(|record| record.item == *item)
            .unwrap()
    };
    assert!(position(&old) < position(&control));
    assert!(position(&control) < position(&new));
    assert_eq!(control.kind(), RelayKind::Control);
    assert_eq!(f.ciphertext(OWNER, old.sequence()), old.payload());
    assert_eq!(f.ciphertext(OWNER, new.sequence()), new.payload());
}

#[test]
fn acceptance_staging_cannot_leapfrog_a_bounded_outbox_backlog() {
    let f = Fixture::with_queue_capacity(256, 128, 1);
    let (pending, incoming) = runtime().block_on(async {
        let mut owner = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        let mut pending = Vec::new();
        // More than the driver's eight-attempt pass, with only one live job
        // allowed: the first apply pass runs while earlier output is unstaged.
        for n in 0..12 {
            let draft = owner
                .prepare_message(format!("pending {n}").as_bytes())
                .unwrap();
            let artifact = owner.send(op(80 + n), &draft).await.unwrap();
            pending.push(RelayItem::from_artifact(ns(), &artifact).unwrap());
        }
        drop(owner);
        let mut member = RoomSession::open(
            Identity::open(f.p("1-id")).unwrap(),
            f.p("1-room"),
            f.contexts[MEMBER],
        )
        .await
        .unwrap();
        let draft = member
            .prepare_message(b"accept after all older local output")
            .unwrap();
        let incoming = member.send(op(70), &draft).await.unwrap();
        (pending, RelayItem::from_artifact(ns(), &incoming).unwrap())
    });
    let _relay = f.relay();
    f.client().submit(&incoming).unwrap();
    let grant = f.grant(OWNER, "acceptance-order", 16);
    let mut owner = f.host(OWNER, "acceptance-order", OWNER);
    let receipt_sequence = pending.last().unwrap().sequence() + 1;
    // Waiting on an existing older record gives the first pass time to receive
    // and durably issue the acceptance; output custody remains sender-ordered.
    owner.await_outbox(&grant, pending.last().unwrap().sequence(), |v| {
        v["relay"]["state"] == "retained"
    });
    owner.await_outbox(&grant, receipt_sequence, |v| {
        v["relay"]["state"] == "retained"
    });
    owner.close();
    let receipt = runtime().block_on(async {
        let mut room = RoomSession::open(
            Identity::open(f.p("0-id")).unwrap(),
            f.p("0-room"),
            f.contexts[OWNER],
        )
        .await
        .unwrap();
        let page = room.outbox(receipt_sequence - 1, 1).await.unwrap();
        assert_eq!(
            page.head, receipt_sequence,
            "one exact acceptance was committed"
        );
        RelayItem::from_artifact(ns(), page.records[0].artifact().unwrap()).unwrap()
    });
    let page = f.client().page(0, 64).unwrap();
    let position = |item: &RelayItem| {
        page.records
            .iter()
            .position(|record| record.item == *item)
            .unwrap()
    };
    let positions: Vec<_> = pending.iter().map(position).collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(
        positions.last().unwrap() < &position(&receipt),
        "a newly issued acceptance leapfrogged an older committed application"
    );
}

#[test]
fn upgraded_legacy_tail_job_refuses_but_exact_enqueue_before_checkpoint_recovers() {
    for tail in [true, false] {
        let f = Fixture::with_queue_capacity(128, 128, 1);
        let (old, receipt) = runtime().block_on(async {
            let mut owner = RoomSession::open(
                Identity::open(f.p("0-id")).unwrap(),
                f.p("0-room"),
                f.contexts[OWNER],
            )
            .await
            .unwrap();
            let draft = owner
                .prepare_message(b"older unstaged application")
                .unwrap();
            let old = owner.send(op(95), &draft).await.unwrap();
            let mut member = RoomSession::open(
                Identity::open(f.p("1-id")).unwrap(),
                f.p("1-room"),
                f.contexts[MEMBER],
            )
            .await
            .unwrap();
            let draft = member.prepare_message(b"receipt predecessor").unwrap();
            let incoming = member.send(op(96), &draft).await.unwrap();
            owner.receive(incoming.bytes()).await.unwrap();
            let receipt = owner
                .issue_acceptance(op(97), incoming.bytes())
                .await
                .unwrap();
            (
                RelayItem::from_artifact(ns(), &old).unwrap(),
                RelayItem::from_artifact(ns(), &receipt).unwrap(),
            )
        });
        let selected = if tail { &receipt } else { &old };
        let before = {
            let mut queue = DeliveryStore::open(
                f.p("0-delivery/jobs"),
                f.contexts[OWNER],
                ns(),
                f.client().endpoint_id(),
            )
            .unwrap();
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let job = queue.enqueue(selected, time).unwrap();
            assert_eq!(queue.driver_checkpoint().unwrap(), (0, 0));
            job
        };
        let mut legacy = f.profile(OWNER);
        legacy["version"] = json!(1);
        f.write_json("0-delivery.json", &legacy);
        let mut upgrade = f.room_command("delivery-upgrade", OWNER);
        upgrade.arg("--config").arg(f.p("0-delivery.json"));
        success(upgrade);
        let _relay = f.relay();
        let grant = f.grant(OWNER, "precheckpoint", 8);
        let mut host = f.host(OWNER, "precheckpoint", OWNER);
        if tail {
            host.refused();
            assert_eq!(f.client().page(0, 8).unwrap().head, 0);
            let (after, _) = f.job(OWNER, receipt.sequence());
            assert_eq!(
                after, before,
                "refusal preserves exact attempts and retry state"
            );
            assert_eq!(f.ciphertext(OWNER, receipt.sequence()), receipt.payload());
        } else {
            host.await_outbox(&grant, receipt.sequence(), |v| {
                v["relay"]["state"] == "retained"
            });
            host.close();
            let page = f.client().page(0, 8).unwrap();
            let position = |item: &RelayItem| {
                page.records
                    .iter()
                    .position(|record| record.item == *item)
                    .unwrap()
            };
            assert!(position(&old) < position(&receipt));
        }
    }
}

#[test]
fn selected_control_upgrade_refuses_missing_evidence_and_v1_recovers_preselection() {
    let f = Fixture::new();
    let selected = fs::read(f.p("0-delivery.json")).unwrap();
    let marker = fs::read(f.p("0-delivery/controls.enabled")).unwrap();
    // Version 2 is already active. Preserve the exact artifacts outside their
    // selected names: upgrade must not recreate retry budgets or commitments.
    fs::rename(f.p("0-delivery/controls"), f.p("saved-controls")).unwrap();
    fs::rename(
        f.p("0-delivery/controls.enabled"),
        f.p("saved-controls.enabled"),
    )
    .unwrap();
    let upgrade = || {
        let mut command = f.room_command("delivery-upgrade", OWNER);
        command.arg("--config").arg(f.p("0-delivery.json"));
        command
    };
    assert!(!run(upgrade()).status.success());
    assert!(!f.p("0-delivery/controls").exists());
    assert!(!f.p("0-delivery/controls.enabled").exists());
    assert_eq!(fs::read(f.p("0-delivery.json")).unwrap(), selected);
    fs::rename(f.p("saved-controls"), f.p("0-delivery/controls")).unwrap();
    assert!(!run(upgrade()).status.success());
    assert!(!f.p("0-delivery/controls.enabled").exists());
    assert_eq!(fs::read(f.p("saved-controls.enabled")).unwrap(), marker);
    // An interrupted preselection migration may legitimately have its empty
    // additive queue present before the marker and final v2 config publish.
    let mut legacy = f.profile(OWNER);
    legacy["version"] = json!(1);
    f.write_json("0-delivery.json", &legacy);
    success(upgrade());
    assert_eq!(
        fs::read(f.p("0-delivery/controls.enabled")).unwrap(),
        marker
    );
    let activated: Value =
        serde_json::from_slice(&fs::read(f.p("0-delivery.json")).unwrap()).unwrap();
    assert_eq!(activated["version"], 2);
    success(upgrade());
}

#[test]
fn explicit_control_upgrade_versions_profile_and_preserves_legacy_queue_evidence() {
    let f = Fixture::new();
    let mut legacy = f.profile(OWNER);
    legacy["version"] = json!(1);
    f.write_json("0-delivery.json", &legacy);
    // Reproduce the predecessor shape in this empty synthetic fixture only.
    fs::remove_dir_all(f.p("0-delivery/controls")).unwrap();
    fs::remove_file(f.p("0-delivery/controls.enabled")).unwrap();
    let binding = fs::read(f.p("0-delivery/binding")).unwrap();
    let before = f.driver_checkpoint(OWNER);
    f.grant(OWNER, "legacy-refused", 4);
    f.host(OWNER, "legacy-refused", OWNER).refused();
    assert!(!f.p("legacy-refused-claim.json").exists());
    let mut command = f.room_command("delivery-status", OWNER);
    command
        .arg("--config")
        .arg(f.p("0-delivery.json"))
        .arg("--out")
        .arg(f.p("legacy-status.json"));
    success(command);
    for _ in 0..2 {
        let mut upgrade = f.room_command("delivery-upgrade", OWNER);
        upgrade.arg("--config").arg(f.p("0-delivery.json"));
        success(upgrade);
    }
    let selected: Value =
        serde_json::from_slice(&fs::read(f.p("0-delivery.json")).unwrap()).unwrap();
    assert_eq!(
        selected["version"], 2,
        "old Config::load accepts only v1 and refuses before transport"
    );
    assert_eq!(fs::read(f.p("0-delivery/binding")).unwrap(), binding);
    assert_eq!(f.driver_checkpoint(OWNER), before);
    let mut resume = f.room_command("delivery-resume", OWNER);
    resume
        .arg("--config")
        .arg(f.p("0-delivery.json"))
        .args(["--stream", "control"]);
    let out = run(resume);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_str(
        std::str::from_utf8(&out.stdout)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(report["stream"], "control");
    assert_eq!(report["resumed"], 0);
}
