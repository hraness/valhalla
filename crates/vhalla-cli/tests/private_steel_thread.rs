//! Two CLI agents exchange messages through the product local host. Every
//! step is a documented operator command; only synthetic state under one
//! temporary directory and ephemeral loopback ports are used.
#![cfg(all(unix, feature = "experimental-private"))]
use hegel::{generators as gs, HealthCheck, TestCase};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
        Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_private_kernel::{MemberAcceptance, OperationId, OutboxKind};
use vhalla_private_native::relay::{
    delivery::{DeliveryStore, JobState},
    net::{NetError, RelayToken},
    tls::TlsRelay,
    RelayItem, RelayNamespace,
};

const TLS_NAME: &str = "steel-thread.test.invalid";
const TOOLS: [&str; 5] = [
    "private_status",
    "private_inbox",
    "private_prepare",
    "private_queue",
    "private_outbox_status",
];
/// Live products bind these; the journey must never collide with them.
const RESERVED_PORTS: [u16; 3] = [9473, 8790, 19473];
const COMMAND_DEADLINE: Duration = Duration::from_secs(30);
const RESPONSE_DEADLINE: Duration = Duration::from_secs(15);
const CONVERGENCE: Duration = Duration::from_secs(30);

/// One admitted CLI agent: `a` owns the room, `b` is admitted through it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Who {
    A,
    B,
}
impl Who {
    fn dir(self) -> &'static str {
        match self {
            Who::A => "a",
            Who::B => "b",
        }
    }
    fn token(self) -> &'static str {
        match self {
            Who::A => "client-1.token",
            Who::B => "client-2.token",
        }
    }
    fn other(self) -> Who {
        match self {
            Who::A => Who::B,
            Who::B => Who::A,
        }
    }
}

struct Journey {
    root: PathBuf,
    addr: SocketAddr,
    now: u64,
    keys: [String; 2],
    evidence: Mutex<u64>,
    started: Instant,
}
impl Journey {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let root = std::env::temp_dir().join(format!(
            "vhalla-steel-thread-{}-{}-{}",
            std::process::id(),
            time.as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join("evidence"))
            .unwrap();
        let addr = loop {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            if !RESERVED_PORTS.contains(&addr.port()) {
                break addr;
            }
        };
        let journey = Self {
            root,
            addr,
            now: time.as_secs(),
            keys: [String::new(), String::new()],
            evidence: Mutex::new(0),
            started: Instant::now(),
        };
        for who in [Who::A, Who::B] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(journey.path(who.dir()))
                .unwrap();
        }
        journey
    }
    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    fn agent_path(&self, who: Who, name: &str) -> PathBuf {
        self.root.join(who.dir()).join(name)
    }
    fn text(&self, path: &Path) -> String {
        path.to_str().unwrap().to_owned()
    }
    fn write_private(&self, path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn json(&self, path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }
    /// Retain one JSON receipt per observed step; kept on failure only.
    fn record(&self, label: &str, value: &Value) {
        let mut counter = self.evidence.lock().unwrap();
        *counter += 1;
        let path = self.path(&format!("evidence/{:03}-{label}.json", *counter));
        fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
    fn vhalla(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command
            .env("HRANESS_SUPPORT", "off")
            .env("XDG_STATE_HOME", self.path("xdg-state"));
        command
    }
    fn validity(&self, seconds: u64) -> [(&'static str, String); 2] {
        [
            ("not-before", (self.now - 30).to_string()),
            ("expires", (self.now + seconds).to_string()),
        ]
    }
    /// `vhalla private COMMAND ID [STORE] --flag value ...` as documented.
    fn private(&self, command: &str, who: Who, store: bool, flags: &[(&str, String)]) -> Command {
        let mut cmd = self.vhalla();
        cmd.args(["private", command])
            .arg(self.agent_path(who, "account"));
        if store {
            cmd.arg(self.agent_path(who, "room"));
        }
        for (flag, value) in flags {
            cmd.arg(format!("--{flag}")).arg(value);
        }
        cmd
    }
    fn private_ok(&self, command: &str, who: Who, store: bool, flags: &[(&str, String)]) {
        let output = run(self.private(command, who, store, flags));
        assert!(
            output.status.success(),
            "private {command} for {}: {}",
            who.dir(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "private operation completed; consult the retained result for delivery status\n"
        );
    }

    // ----- Step 1: product host -----
    fn host_init(&self) {
        let mut command = self.vhalla();
        command
            .args(["private-host", "init"])
            .arg(self.path("host"))
            .args(["--listen", &self.addr.to_string(), "--tls-name", TLS_NAME])
            .arg("--executable")
            .arg(env!("CARGO_BIN_EXE_vhalla"));
        let output = run(command);
        assert!(
            output.status.success(),
            "private-host init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let initialized: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(initialized["status"], "initialized");
        self.record("host-init", &initialized);
        self.record(
            "host-connection",
            &self.json(&self.path("host/connection.json")),
        );
    }
    fn host_serve(&self) -> HostProcess {
        let mut command = self.vhalla();
        command
            .args(["private-host", "serve"])
            .arg(self.path("host"));
        let mut child = command
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
            .recv_timeout(RESPONSE_DEADLINE)
            .expect("private-host serve must print its readiness line within the deadline")
            .unwrap();
        if line.is_empty() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "private-host serve exited before listening: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let ready: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(ready["status"], "listening", "{ready}");
        assert_eq!(ready["listen"], self.addr.to_string());
        self.record("host-listening", &ready);
        HostProcess(child)
    }
    fn namespace(&self) -> RelayNamespace {
        RelayNamespace::from_bytes(unhex(
            self.json(&self.path("host/connection.json"))["namespace"]
                .as_str()
                .unwrap(),
        ))
        .unwrap()
    }
    fn relay_client(&self, token: [u8; 32]) -> TlsRelay {
        TlsRelay::new(
            self.addr,
            TLS_NAME,
            fs::read(self.path("host/ca.der")).unwrap(),
            RelayToken::from_bytes(token).unwrap(),
            self.namespace(),
        )
        .unwrap()
    }
    fn host_token(&self, who: Who) -> [u8; 32] {
        let raw = fs::read(self.path("host").join(who.token())).unwrap();
        unhex(std::str::from_utf8(&raw).unwrap().trim_end_matches('\n'))
    }

    // ----- Step 2: accounts and confidential admission -----
    fn identities(&mut self) {
        for (index, who) in [Who::A, Who::B].into_iter().enumerate() {
            let mut command = self.vhalla();
            command
                .args(["identity", "init"])
                .arg(self.agent_path(who, "account"));
            let output = run(command);
            assert!(
                output.status.success(),
                "identity init: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let shown = String::from_utf8(output.stdout).unwrap();
            let key = shown
                .trim()
                .strip_prefix("application-key ")
                .expect("identity init prints the public application key")
                .to_owned();
            assert_eq!(key.len(), 64);
            self.keys[index] = key;
        }
        assert_ne!(self.keys[0], self.keys[1]);
    }
    fn key(&self, who: Who) -> String {
        self.keys[usize::from(who == Who::B)].clone()
    }
    /// `docs/private-rooms.md` and the CLI README admission sequence, verbatim:
    /// create -> offer -> offer-inspect -> import -> request -> accept -> join.
    fn admit(&self) {
        let offer = self.text(&self.path("admission-offer.secret"));
        let review = self.path("admission-review.json");
        let request = self.text(&self.path("admission-request.cipher"));
        let response = self.text(&self.path("admission-response.cipher"));
        let mut flags = self.validity(7200).to_vec();
        self.private_ok("create", Who::A, true, &flags);
        flags = self.validity(3600).to_vec();
        flags.extend([
            ("recipient", self.key(Who::B)),
            ("operation", op(1)),
            ("out", offer.clone()),
        ]);
        self.private_ok("offer", Who::A, true, &flags);
        self.private_ok(
            "offer-inspect",
            Who::B,
            false,
            &[
                ("offer", offer.clone()),
                ("owner", self.key(Who::A)),
                ("out", self.text(&review)),
            ],
        );
        let reviewed = self.json(&review);
        assert_eq!(reviewed["kind"], "confidential-offer-metadata");
        self.record("admission-review", &reviewed);
        flags = self.validity(7200).to_vec();
        flags.extend([
            ("offer", offer.clone()),
            ("owner", self.key(Who::A)),
            ("room", reviewed["room"].as_str().unwrap().to_owned()),
            ("anchor", reviewed["anchor"].as_str().unwrap().to_owned()),
        ]);
        self.private_ok("import", Who::B, true, &flags);
        self.private_ok(
            "request",
            Who::B,
            true,
            &[
                ("offer", offer),
                ("operation", op(1)),
                ("out", request.clone()),
            ],
        );
        flags = self.validity(3600).to_vec();
        flags.extend([
            ("request", request),
            ("operation", op(2)),
            ("out", response.clone()),
        ]);
        self.private_ok("accept", Who::A, true, &flags);
        self.private_ok("join", Who::B, true, &[("response", response)]);
    }
    fn inspect(&self, who: Who) -> Value {
        let out = self.agent_path(who, "inspect.json");
        self.private_ok("inspect", who, true, &[("out", self.text(&out))]);
        let inspected = self.json(&out);
        self.record(&format!("inspect-{}", who.dir()), &inspected);
        inspected
    }
    fn device(&self, who: Who) -> String {
        self.json(&self.agent_path(who, "inspect.json"))["status"]["device"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    // ----- Step 3: per-device host credential and delivery profile -----
    /// The profile is the exact JSON shape from `docs/cli-agents.md`; no
    /// product command writes it today, so the test authors it the way an
    /// operator must.
    fn delivery_profile(&self, who: Who) {
        let context = &self.json(&self.agent_path(who, "inspect.json"))["status"];
        let ca = self.agent_path(who, "relay-ca.der");
        let token = self.agent_path(who, "relay-token.hex");
        self.write_private(&ca, &fs::read(self.path("host/ca.der")).unwrap());
        self.write_private(
            &token,
            &fs::read(self.path("host").join(who.token())).unwrap(),
        );
        let connection = self.json(&self.path("host/connection.json"));
        let profile = json!({
            "version": 1,
            "context": {
                "room": context["room"], "anchor": context["anchor"],
                "account": context["account"], "device": context["device"],
            },
            "namespace": connection["namespace"],
            "addr": connection["listen"],
            "tls_name": connection["tls_name"],
            "ca": ca, "token": token,
            "state": self.agent_path(who, "delivery-state"),
            "max_jobs": 1024, "max_bytes": 67108864, "max_attempts": 20,
            "initial_backoff_secs": 5, "max_backoff_secs": 300,
            "emit_acceptance": true, "initial_cursor": 0
        });
        assert_eq!(profile["addr"], self.addr.to_string());
        assert_eq!(profile["tls_name"], TLS_NAME);
        let path = self.agent_path(who, "delivery.json");
        self.write_private(&path, &serde_json::to_vec_pretty(&profile).unwrap());
        self.private_ok("delivery-init", who, true, &[("config", self.text(&path))]);
        assert!(self.agent_path(who, "delivery-state/binding").is_file());
    }
    fn delivery_job(
        &self,
        who: Who,
        sequence: u64,
    ) -> (
        vhalla_private_native::relay::delivery::JobStatus,
        vhalla_private_native::relay::delivery::JobEvidence,
    ) {
        let context = self.json(&self.agent_path(who, "inspect.json"))["status"].clone();
        let context = vhalla_private_kernel::Context {
            scope: vhalla_private_kernel::protocol::PrivateRoomScope {
                room: vhalla_private_kernel::protocol::RoomId::from_bytes(unhex(
                    context["room"].as_str().unwrap(),
                ))
                .unwrap(),
                anchor: vhalla_private_kernel::protocol::AnchorId::from_bytes(unhex(
                    context["anchor"].as_str().unwrap(),
                ))
                .unwrap(),
            },
            account: vhalla_private_kernel::protocol::Key::from_bytes(unhex(
                context["account"].as_str().unwrap(),
            ))
            .unwrap(),
            device: vhalla_private_kernel::protocol::Key::from_bytes(unhex(
                context["device"].as_str().unwrap(),
            ))
            .unwrap(),
        };
        let queue = DeliveryStore::open(
            self.agent_path(who, "delivery-state/jobs"),
            context,
            self.namespace(),
            self.relay_client(self.host_token(who)).endpoint_id(),
        )
        .unwrap();
        let job = queue
            .statuses(sequence - 1, 1)
            .unwrap()
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                panic!(
                    "{} outbox sequence {sequence} has no durable delivery job",
                    who.dir()
                )
            });
        let evidence = queue.evidence(job.id).unwrap();
        (job, evidence)
    }
    fn applied_states(&self, who: Who) -> Vec<String> {
        // Only committed markers; a `.pending` sibling may exist mid-publish.
        let mut states: Vec<String> = fs::read_dir(self.agent_path(who, "delivery-state/applied"))
            .unwrap()
            .filter_map(|entry| {
                let path = entry.unwrap().path();
                (path.extension() == Some(std::ffi::OsStr::new("json"))).then(|| {
                    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    value["state"].as_str().unwrap().to_owned()
                })
            })
            .collect();
        states.sort();
        states
    }

    // ----- Step 4: grants and MCP stdio agents -----
    fn disclosure(&self, who: Who) -> PathBuf {
        let path = self.agent_path(who, "disclosure.json");
        if !path.exists() {
            self.write_private(
                &path,
                &serde_json::to_vec(&json!({
                    "host": format!("synthetic steel-thread journey, agent {}", who.dir()),
                    "provider": "none", "model": "fixture",
                    "processing_policy": "local synthetic content only",
                    "allow_cooperating_host": true
                }))
                .unwrap(),
            );
        }
        path
    }
    /// One explicit one-use grant with a never-used claim path, as documented.
    fn grant(&self, who: Who, generation: u32) -> Value {
        let out = self.agent_path(who, &format!("grant-{generation:03}.json"));
        let claim = self.agent_path(who, &format!("claim-{generation:03}.json"));
        self.private_ok(
            "agent-grant",
            who,
            true,
            &[
                ("mode", "read-write".into()),
                ("disclosure", self.text(&self.disclosure(who))),
                ("receipt", self.text(&claim)),
                ("out", self.text(&out)),
                ("lifetime", "900".into()),
                ("follow-inbox", "true".into()),
                ("max-read-records", "512".into()),
            ],
        );
        assert!(!claim.exists(), "preparation must not consume the grant");
        self.json(&out)
    }
    fn agent(&self, who: Who, generation: u32) -> Agent<'_> {
        let grant = self.grant(who, generation);
        let mut command = self.private("agent-serve", who, true, &[]);
        command
            .arg("--grant")
            .arg(self.agent_path(who, &format!("grant-{generation:03}.json")))
            .arg("--delivery")
            .arg(self.agent_path(who, "delivery.json"));
        let mut agent = Agent::spawn(self, who, generation, grant, command);
        agent.initialize();
        assert!(
            self.agent_path(who, &format!("claim-{generation:03}.json"))
                .exists(),
            "tool exposure must follow the durable one-use claim"
        );
        agent
    }
    /// A consumed one-use grant refuses to serve again; its durable claim stays.
    /// Real stdio pipes are required to reach the grant check (the serve path
    /// refuses non-pipe descriptors before any grant work).
    fn refused_agent(&self, who: Who, generation: u32) {
        let mut command = self.private("agent-serve", who, true, &[]);
        command
            .arg("--grant")
            .arg(self.agent_path(who, &format!("grant-{generation:03}.json")))
            .arg("--delivery")
            .arg(self.agent_path(who, "delivery.json"));
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_exit(
            &mut child,
            "agent-serve on a consumed grant did not exit within the deadline",
        );
        let output = child.wait_with_output().unwrap();
        assert!(
            !output.status.success(),
            "consumed grant-{generation:03} must refuse to serve again"
        );
        assert!(
            output.stdout.is_empty(),
            "a refused launch must not expose tools: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            self.agent_path(who, &format!("claim-{generation:03}.json"))
                .is_file(),
            "the consumed claim stays retained for reconciliation"
        );
    }
}
impl Drop for Journey {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!(
                "steel-thread evidence retained at {} (elapsed {:?})",
                self.root.display(),
                self.started.elapsed()
            );
        } else {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct HostProcess(Child);
impl HostProcess {
    /// Operator stop: SIGTERM drains and releases mailbox custody with exit 0.
    fn stop(&mut self) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(self.0.id().try_into().unwrap()).unwrap(),
            rustix::process::Signal::TERM,
        )
        .unwrap();
        wait_exit(&mut self.0, "private-host serve did not exit after SIGTERM");
        assert!(self.0.try_wait().unwrap().unwrap().success());
    }
}
impl Drop for HostProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One `agent-serve --delivery` MCP stdio process under one grant.
struct Agent<'a> {
    journey: &'a Journey,
    who: Who,
    label: String,
    grant: Value,
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<String>,
    next_id: u64,
    inbox_cursor: u64,
    inbox: Vec<Value>,
    notices: Vec<Value>,
}
impl<'a> Agent<'a> {
    fn spawn(
        journey: &'a Journey,
        who: Who,
        generation: u32,
        grant: Value,
        mut command: Command,
    ) -> Self {
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
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            journey,
            who,
            label: format!("{}{generation}", who.dir()),
            grant,
            child,
            input: Some(input.unwrap()),
            responses,
            next_id: 1,
            inbox_cursor: 0,
            inbox: Vec::new(),
            notices: Vec::new(),
        }
    }
    fn line(&mut self, context: &str) -> String {
        match self.responses.recv_timeout(RESPONSE_DEADLINE) {
            Ok(line) => line,
            Err(error) => {
                let detail = if self.child.try_wait().unwrap().is_some() {
                    format!("process exited: {}", self.stderr())
                } else {
                    "process is still running".to_owned()
                };
                panic!(
                    "agent {} gave no MCP response to {context} within {RESPONSE_DEADLINE:?}: {error}; {detail}",
                    self.label
                );
            }
        }
    }
    fn send(&mut self, value: &Value) {
        let input = self.input.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
    }
    fn ask(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        loop {
            let frame: Value = serde_json::from_str(&self.line(method))
                .expect("agent stdout carries only MCP JSON lines");
            match frame.get("id") {
                Some(value) if *value == json!(id) => return frame,
                // Async session notices (for example the closing revocation
                // frame) carry no request id; retain them for diagnostics and
                // keep waiting for the actual response.
                None if frame.get("method").is_some() => self.notices.push(frame),
                _ => panic!("out-of-order or foreign MCP response: {frame}"),
            }
        }
    }
    /// The documented client handshake: initialize, initialized, tools/list.
    fn initialize(&mut self) {
        let initialized = self.ask(
            "initialize",
            json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"steel-thread journey","version":"1"}}),
        );
        assert_eq!(
            initialized["result"]["protocolVersion"], "2025-11-25",
            "{initialized}"
        );
        assert!(initialized["result"]["capabilities"]["tools"].is_object());
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        let listed = self.ask("tools/list", json!({}));
        let mut names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list: {listed}"))
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        let mut expected = TOOLS.to_vec();
        expected.sort_unstable();
        assert_eq!(names, expected, "exactly the five documented tools");
        for tool in listed["result"]["tools"].as_array().unwrap() {
            assert_eq!(
                tool["inputSchema"]["properties"]["session"]["const"],
                self.grant["grant_id"]
            );
        }
        self.journey
            .record(&format!("{}-tools", self.label), &listed);
        let status = self.call("private_status", json!({}));
        assert_eq!(status["status"], "live", "{status}");
        assert_eq!(status["session"], self.grant["grant_id"]);
        assert_eq!(status["context"]["device"], self.journey.device(self.who));
    }
    /// Returns the tool's structured content; refusals are the caller's problem.
    fn call(&mut self, name: &str, mut args: Value) -> Value {
        args["session"] = self.grant["grant_id"].clone();
        let response = self.ask("tools/call", json!({"name":name,"arguments":args}));
        let content = response["result"]["structuredContent"].clone();
        assert!(content.is_object(), "{name}: {response}");
        self.journey
            .record(&format!("{}-{name}", self.label), &content);
        content
    }
    fn queue(&mut self, body: &str, operation: u64) -> u64 {
        let prepared = self.call("private_prepare", json!({"body":body}));
        assert_eq!(prepared["status"], "prepared_exact_content", "{prepared}");
        let queued = self.call(
            "private_queue",
            json!({"draft":prepared["draft"],"operation":op(operation)}),
        );
        assert_eq!(queued["status"], "durable_local_only", "{queued}");
        assert!(
            queued.get("relay").is_none(),
            "queue completion is not delivery evidence"
        );
        queued["sequence"].as_str().unwrap().parse().unwrap()
    }
    fn outbox(&mut self, sequence: u64) -> Value {
        let page = self.call(
            "private_outbox_status",
            json!({"after":(sequence-1).to_string(),"limit":1}),
        );
        let record = page["records"][0].clone();
        assert!(record.is_object(), "{page}");
        assert_eq!(record["sequence"], sequence.to_string());
        record
    }
    fn await_outbox(
        &mut self,
        sequence: u64,
        what: &str,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        let deadline = Instant::now() + CONVERGENCE;
        loop {
            let record = self.outbox(sequence);
            if predicate(&record) {
                return record;
            }
            assert!(
                Instant::now() < deadline,
                "agent {} outbox sequence {sequence} did not reach {what} within {CONVERGENCE:?}: {record}",
                self.label
            );
            thread::sleep(Duration::from_millis(500));
        }
    }
    fn await_retained(&mut self, sequence: u64) -> Value {
        let record = self.await_outbox(sequence, "relay retention", |v| {
            v["relay"]["state"] == "retained"
        });
        assert_eq!(record["relay"]["uncertain"], false);
        record
    }
    fn await_acceptance(&mut self, sequence: u64) -> Value {
        let recipient = self.journey.device(self.who.other());
        let record = self.await_outbox(sequence, "recipient acceptance", |v| {
            v["member_acceptances"]
                .as_array()
                .is_some_and(|a| a.len() == 1)
        });
        assert_eq!(record["member_acceptances"][0]["recipient"], recipient);
        assert_eq!(record["relay"]["state"], "retained");
        record
    }
    /// Reads forward through the granted inbox with small pages so polling
    /// never spends more read credits than there are records.
    fn await_inbox_text(&mut self, text: &str) -> Value {
        let deadline = Instant::now() + CONVERGENCE;
        loop {
            let page = self.call(
                "private_inbox",
                json!({"after":self.inbox_cursor.to_string(),"limit":4}),
            );
            let records = page["records"]
                .as_array()
                .unwrap_or_else(|| panic!("{page}"))
                .clone();
            if let Some(last) = records.last() {
                self.inbox_cursor = last["sequence"].as_str().unwrap().parse().unwrap();
            }
            self.inbox.extend(records);
            if let Some(found) = self.inbox.iter().find(|r| r["text"] == text) {
                return found.clone();
            }
            assert!(
                Instant::now() < deadline,
                "agent {} inbox never showed {text:?} within {CONVERGENCE:?}; head {} after {} records",
                self.label,
                page["head"],
                self.inbox.len()
            );
            thread::sleep(Duration::from_millis(500));
        }
    }
    fn status(&mut self) -> Value {
        self.call("private_status", json!({}))
    }
    /// Records returned so far whose body is a device receipt. F5 repair:
    /// receipts are filtered from the agent-visible inbox and only surface
    /// through `member_acceptances`; this must stay empty.
    fn receipt_records(&self) -> Vec<&Value> {
        self.inbox
            .iter()
            .filter(|r| {
                r["body_hex"]
                    .as_str()
                    .and_then(unhex_vec)
                    .is_some_and(|body| MemberAcceptance::is_receipt(&body))
            })
            .collect()
    }
    fn remaining_read_records(&mut self) -> u64 {
        self.status()["remaining"]["read_records"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
    /// Client EOF ends the session with exit 0 and no further output.
    fn close(mut self) {
        drop(self.input.take());
        wait_exit(
            &mut self.child,
            &format!("agent {} did not exit after stdin EOF", self.label),
        );
        let status = self.child.try_wait().unwrap().unwrap();
        let label = self.label.clone();
        assert!(status.success(), "agent {label}: {}", self.stderr());
    }
    fn stderr(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut stderr) = self.child.stderr.take() {
            stderr.read_to_string(&mut text).unwrap();
        }
        text
    }
}
impl Drop for Agent<'_> {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn op(n: u64) -> String {
    format!("{n:032x}")
}
fn unhex_vec(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}
fn unhex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2, "expected {N} hex bytes");
    let mut out = [0; N];
    for (index, pair) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out
}
fn wait_exit(child: &mut Child, what: &str) {
    let deadline = Instant::now() + COMMAND_DEADLINE;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} within {COMMAND_DEADLINE:?}");
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
    wait_exit(&mut child, "bounded CLI command did not exit");
    child.wait_with_output().unwrap()
}

#[test]
fn two_agents_exchange_accept_survive_host_restart_and_refuse_wrong_token() {
    let mut journey = Journey::new();
    // 1. Product host on an ephemeral loopback port.
    journey.host_init();
    let mut host = journey.host_serve();
    // 2. Two accounts; B admitted into A's room through confidential admission.
    journey.identities();
    journey.admit();
    let a = journey.inspect(Who::A);
    let b = journey.inspect(Who::B);
    assert_eq!(a["status"]["phase"], "OwnerJoined", "{a}");
    assert_eq!(b["status"]["phase"], "MemberJoined", "{b}");
    assert_eq!(a["status"]["room"], b["status"]["room"]);
    assert_eq!(a["recipients"].as_array().unwrap().len(), 2);
    assert_eq!(b["recipients"], a["recipients"]);
    assert_ne!(a["status"]["device"], b["status"]["device"]);
    // 3. Distinct host credentials, delivery profiles and state directories.
    assert_ne!(journey.host_token(Who::A), journey.host_token(Who::B));
    journey.delivery_profile(Who::A);
    journey.delivery_profile(Who::B);
    // 4. Two MCP stdio agents under one-use grants; A -> B, then B -> A.
    let mut agent_a = journey.agent(Who::A, 1);
    let mut agent_b = journey.agent(Who::B, 1);
    let first = agent_a.queue("steel thread 1: A greets B", 0x10);
    agent_a.await_retained(first);
    let received = agent_b.await_inbox_text("steel thread 1: A greets B");
    assert_eq!(received["sender"], journey.device(Who::A));
    let accepted = agent_a.await_acceptance(first);
    assert_eq!(
        accepted["member_acceptances"][0]["received_sequence"],
        received["sequence"]
    );
    assert!(journey
        .applied_states(Who::B)
        .contains(&"locally-received".to_owned()));
    let reply = agent_b.queue("steel thread 2: B answers A", 0x20);
    agent_b.await_retained(reply);
    let answered = agent_a.await_inbox_text("steel thread 2: B answers A");
    assert_eq!(answered["sender"], journey.device(Who::B));
    let accepted = agent_b.await_acceptance(reply);
    assert_eq!(
        accepted["member_acceptances"][0]["received_sequence"],
        answered["sequence"]
    );
    // F5 repair: the recipient's signed device receipt is an application
    // record but never lands in the agent-visible inbox; it surfaces only
    // through private_outbox_status.member_acceptances (asserted above).
    assert_eq!(
        agent_a.receipt_records().len(),
        0,
        "receipts are filtered from the agent inbox"
    );
    // Relay-eligible kinds include the confidential admission artifacts, so the
    // mailbox also carries A's ContactInvitation and B's ContactRequest ahead
    // of the two messages and the two device receipts.
    let mailbox = journey.relay_client(journey.host_token(Who::A));
    assert_eq!(
        mailbox.page(0, 8).unwrap().head,
        6,
        "two admission artifacts, two messages and two device receipts"
    );
    // 5. Host outage: SIGTERM, queue while down, restart, fresh grants.
    host.stop();
    assert!(TcpStream::connect(journey.addr).is_err());
    let third = agent_a.queue("steel thread 3: queued while the host was down", 0x30);
    // A1/A11 semantics: an outage records uncertain outage evidence without
    // spending the finite attempt budget.
    let offline = agent_a.await_outbox(third, "an offline delivery attempt", |v| {
        v["relay"]["uncertain"] == true && v["relay"]["last_error"] == "connect"
    });
    assert_ne!(offline["relay"]["state"], "retained", "{offline}");
    assert_eq!(offline["relay"]["attempts"], 0, "{offline}");
    assert_eq!(offline["member_acceptances"], json!([]));
    let budget_a = agent_a.status()["remaining"].clone();
    let budget_b = agent_b.status()["remaining"].clone();
    // Review F9 documented expectation: every status-page poll above spent read
    // credits from the finite grant; the documented exchange stays far inside
    // the 512-record allowance.
    for remaining in [
        agent_a.remaining_read_records(),
        agent_b.remaining_read_records(),
    ] {
        assert!(remaining > 0, "the exchange must not exhaust the grant");
        assert!(
            remaining < 512,
            "status-page polling must charge read credits"
        );
    }
    agent_a.close();
    agent_b.close();
    let (durable, durable_evidence) = journey.delivery_job(Who::A, third);
    assert!(
        matches!(durable.state, JobState::Pending | JobState::Uncertain),
        "{durable:?}"
    );
    assert_eq!(durable.attempts, 0, "{durable:?}");
    assert_eq!(durable_evidence.outages, 1, "{durable_evidence:?}");
    assert_eq!(durable.position, None);
    let mut host = journey.host_serve();
    // The consumed one-use grants refuse to relaunch; fresh grants do.
    journey.refused_agent(Who::A, 1);
    journey.refused_agent(Who::B, 1);
    let mut agent_a = journey.agent(Who::A, 2);
    let mut agent_b = journey.agent(Who::B, 2);
    let delivered = agent_a.await_acceptance(third);
    assert_eq!(delivered["relay"]["position"], "7", "{delivered}");
    let after_restart = agent_b.await_inbox_text("steel thread 3: queued while the host was down");
    assert_eq!(
        delivered["member_acceptances"][0]["received_sequence"],
        after_restart["sequence"]
    );
    // F5 repair again: A's own device receipt for B's earlier reply stays out
    // of B's agent-visible inbox.
    assert_eq!(
        agent_b.receipt_records().len(),
        0,
        "receipts are filtered from the agent inbox"
    );
    // Earlier claims are restored from retained evidence, not re-delivered.
    agent_a.await_acceptance(first);
    agent_b.await_acceptance(reply);
    journey.record(
        "budgets",
        &json!({"before_restart":{"a":budget_a,"b":budget_b},"after_restart":{"a":agent_a.status()["remaining"],"b":agent_b.status()["remaining"]}}),
    );
    agent_a.close();
    agent_b.close();
    // The queue store is exclusively locked by a live driver; read the durable
    // job only after both relaunched agents have exited.
    let (retained_job, _) = journey.delivery_job(Who::A, third);
    assert_eq!(retained_job.id, durable.id, "restart retries the exact job");
    assert_eq!(retained_job.state, JobState::Retained, "{retained_job:?}");
    assert_eq!(retained_job.position, Some(7), "{retained_job:?}");
    assert!(journey
        .applied_states(Who::A)
        .contains(&"recipient-device-claim".to_owned()));
    // 6. A wrong host credential is refused and changes nothing.
    let before = mailbox.page(0, 8).unwrap();
    assert_eq!(
        before.head, 8,
        "two admission artifacts, three messages and three device receipts"
    );
    let wrong = journey.relay_client([0x5a; 32]);
    assert!(matches!(wrong.page(0, 1), Err(NetError::Denied)));
    let intruder = RelayItem::new(
        journey.namespace(),
        1,
        OperationId::from_bytes([0x5a; 16]).unwrap(),
        OutboxKind::Application,
        b"synthetic opaque bytes from an unauthorized client",
    )
    .unwrap();
    assert!(matches!(wrong.submit(&intruder), Err(NetError::Denied)));
    let after = mailbox.page(0, 8).unwrap();
    assert_eq!(after.head, before.head);
    assert_eq!(after.records.len(), before.records.len());
    assert!(after
        .records
        .iter()
        .zip(&before.records)
        .all(|(x, y)| x.item == y.item));
    host.stop();
    journey.record(
        "summary",
        &json!({"elapsed_ms":journey.started.elapsed().as_millis() as u64,"mailbox_head":after.head,"listen":journey.addr.to_string()}),
    );
    println!(
        "steel-thread journey completed in {:?}",
        journey.started.elapsed()
    );
}

/// Hegel variant of the steel-thread journey (lane F, Part 3): the same
/// product machinery under drawn interleavings of sends from either side,
/// host restarts, graceful and killed agent relaunches, and convergence.
/// The model's liveness invariant: once the host is up and both agents are
/// live, every queued message is retained, reaches exactly the other
/// member's inbox and yields exactly that member's signed acceptance on the
/// sender; receipts never appear in either agent-visible inbox.
///
/// The case count is lower than kernel Hegel tests because each case runs a
/// full product journey — host process, two `agent-serve` children, real
/// grants — end to end; the drawn interleaving is the coverage, not case
/// volume. Only TooSlow is suppressed: the multi-process setup legitimately
/// exceeds its budget.
#[hegel::test(test_cases = 4, suppress_health_check = [HealthCheck::TooSlow])]
fn hegel_two_agents_interleaved_restarts_relaunches_and_delivery(tc: TestCase) {
    let mut journey = Journey::new();
    journey.host_init();
    let mut host = Some(journey.host_serve());
    journey.identities();
    journey.admit();
    journey.inspect(Who::A);
    journey.inspect(Who::B);
    journey.delivery_profile(Who::A);
    journey.delivery_profile(Who::B);
    let mut generation = [1u32, 1u32];
    let mut agents = [
        Some(journey.agent(Who::A, generation[0])),
        Some(journey.agent(Who::B, generation[1])),
    ];
    let mut sent = 0u64;
    // (sender index, outbox sequence, body) queued but not yet converged.
    let mut pending: Vec<(usize, u64, String)> = Vec::new();
    let steps = tc.draw(gs::integers::<usize>().min_value(3).max_value(8));
    for _ in 0..steps {
        match tc.draw(gs::integers::<u8>().max_value(4)) {
            // Queue one message from a side; a dead sender relaunches first,
            // mirroring an operator restarting their agent under a new grant.
            side @ (0 | 1) => {
                let index = side as usize;
                let who = if index == 0 { Who::A } else { Who::B };
                if agents[index].is_none() {
                    generation[index] += 1;
                    agents[index] = Some(journey.agent(who, generation[index]));
                }
                sent += 1;
                let body = format!("hegel steel thread {sent} from {}", who.dir());
                // Admission consumed op(1)/op(2); committed operation IDs are
                // one-use, so message operations start at 0x10 like the
                // linear journey.
                let sequence = agents[index].as_mut().unwrap().queue(&body, 0x10 * sent);
                pending.push((index, sequence, body));
            }
            // Operator restart of the product host; queued and staged work
            // must survive the outage untouched.
            2 => {
                host.take().unwrap().stop();
                assert!(TcpStream::connect(journey.addr).is_err());
                host = Some(journey.host_serve());
            }
            // Relaunch each live agent, drawn per side as a graceful stdin
            // EOF or an abrupt kill; the consumed grant must stay refused
            // and a fresh grant resumes the exact same custody.
            3 => {
                for (index, who) in [Who::A, Who::B].into_iter().enumerate() {
                    let Some(agent) = agents[index].take() else {
                        continue;
                    };
                    if tc.draw(gs::booleans()) {
                        agent.close();
                    } else {
                        drop(agent);
                    }
                    journey.refused_agent(who, generation[index]);
                    generation[index] += 1;
                    agents[index] = Some(journey.agent(who, generation[index]));
                }
            }
            // Convergence point: with connectivity and live agents, every
            // queued message delivers and is accepted.
            _ => converge(&journey, &mut agents, &mut generation, &mut pending),
        }
    }
    converge(&journey, &mut agents, &mut generation, &mut pending);
    // F5 invariant under interleavings: signed device receipts surface only
    // through member_acceptances, never in the agent-visible inbox.
    for agent in agents.iter_mut().flatten() {
        assert!(agent.receipt_records().is_empty());
    }
    // The mailbox carries exactly the two admission artifacts plus one
    // message and one device receipt per send.
    let mailbox = journey.relay_client(journey.host_token(Who::A));
    assert_eq!(
        mailbox.page(0, 64).unwrap().head,
        2 + 2 * sent,
        "admission artifacts plus one message and receipt per send"
    );
}

/// Bring both agents live under fresh grants where needed and drain every
/// queued message end to end: retained relay delivery, the recipient's
/// inbox copy and the recipient's signed acceptance back on the sender.
fn converge<'a>(
    journey: &'a Journey,
    agents: &mut [Option<Agent<'a>>; 2],
    generation: &mut [u32; 2],
    pending: &mut Vec<(usize, u64, String)>,
) {
    for (index, who) in [Who::A, Who::B].into_iter().enumerate() {
        if agents[index].is_none() {
            generation[index] += 1;
            agents[index] = Some(journey.agent(who, generation[index]));
        }
    }
    for (sender, sequence, body) in pending.drain(..) {
        let accepted = agents[sender].as_mut().unwrap().await_acceptance(sequence);
        let received = agents[1 - sender].as_mut().unwrap().await_inbox_text(&body);
        assert_eq!(
            accepted["member_acceptances"][0]["received_sequence"], received["sequence"],
            "acceptance must name the recipient's exact inbox sequence"
        );
    }
}
