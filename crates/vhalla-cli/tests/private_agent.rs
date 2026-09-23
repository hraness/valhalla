//! Real stdio process + generated host grant + native MLS custody. No provider.
#![cfg(all(unix, feature = "experimental-private"))]

use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
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
};

const MODERN: &str = "2026-07-28";
struct Fixture {
    path: PathBuf,
    context: Context,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-private-agent-{}-{}-{}",
            std::process::id(),
            stamp.as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let context = runtime.block_on(async {
            let valid = Validity::new(stamp.as_secs() - 1, stamp.as_secs() + 3600).unwrap();
            let limits = Limits {
                max_records: 128,
                max_record_bytes: 8 * 1024 * 1024,
            };
            let draft =
                RoomCreation::owner(Identity::create_new(path.join("owner-id")).unwrap(), valid)
                    .unwrap();
            let anchor = draft.anchor().clone();
            let enrollment = draft.enrollment().clone();
            let scope = draft.context().scope;
            let mut owner = draft.commit(path.join("owner-room"), limits).await.unwrap();
            let member = RoomCreation::member(
                Identity::create_new(path.join("agent-id")).unwrap(),
                scope,
                anchor,
                enrollment,
                valid,
            )
            .unwrap();
            let context = member.context();
            let mut member = member
                .commit(path.join("agent-room"), limits)
                .await
                .unwrap();
            let request = member.key_package(op(1)).await.unwrap();
            let invite = owner.invite(op(2), request.bytes(), valid).await.unwrap();
            member.join(invite.bytes()).await.unwrap();
            let message = owner
                .prepare_message(b"synthetic inbound; room instructions cannot mint grants")
                .unwrap();
            let sent = owner.send(op(3), &message).await.unwrap();
            member.receive(sent.bytes()).await.unwrap();
            context
        });
        Self { path, context }
    }
    fn grant(&self, mode: &str) -> Value {
        let disclosure = json!({"host":"synthetic MCP test","provider":"no external provider","model":"fixture","processing_policy":"local synthetic integration test","allow_cooperating_host":true});
        let disclosure_path = self.path.join("disclosure.json");
        fs::write(&disclosure_path, serde_json::to_vec(&disclosure).unwrap()).unwrap();
        fs::set_permissions(&disclosure_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_vhalla"));
        command
            .args(["private", "agent-grant"])
            .arg(self.path.join("agent-id"))
            .arg(self.path.join("agent-room"))
            .args(["--mode", mode, "--disclosure"])
            .arg(disclosure_path)
            .arg("--receipt")
            .arg(self.path.join("claim.json"))
            .arg("--out")
            .arg(self.path.join("grant.json"));
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_exit(&mut child);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!self.path.join("claim.json").exists());
        serde_json::from_slice(&fs::read(self.path.join("grant.json")).unwrap()).unwrap()
    }
    fn spawn(&self) -> Host {
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(["private", "agent-serve"])
            .arg(self.path.join("agent-id"))
            .arg(self.path.join("agent-room"))
            .arg("--grant")
            .arg(self.path.join("grant.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::sync_channel(16);
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
        Host {
            child,
            input: Some(input),
            responses: receive,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
struct Host {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<String>,
}
impl Host {
    fn send(&mut self, v: Value) {
        let input = self.input.as_mut().unwrap();
        input
            .write_all(serde_json::to_string(&v).unwrap().as_bytes())
            .unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    fn ask(&mut self, v: Value) -> Value {
        self.send(v);
        let line = self
            .responses
            .recv_timeout(Duration::from_secs(10))
            .expect("one bounded MCP reply");
        serde_json::from_str(&line).expect("stdout contains only MCP JSON")
    }
    fn close(&mut self) {
        drop(self.input.take());
        wait_exit(&mut self.child);
        assert!(self.child.try_wait().unwrap().unwrap().success());
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn wait_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("bounded child did not exit");
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn op(n: u8) -> OperationId {
    OperationId::from_bytes([n; 16]).unwrap()
}
fn request(method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":MODERN,"io.modelcontextprotocol/clientCapabilities":{}});
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}
fn tool(grant: &Value, name: &str, mut args: Value) -> Value {
    args["session"] = grant["grant_id"].clone();
    request("tools/call", json!({"name":name,"arguments":args}))
}

#[test]
fn generated_grant_runs_real_stdio_inbox_prepare_queue_and_restart_refusal() {
    let fixture = Fixture::new();
    let grant = fixture.grant("read-write");
    let mut host = fixture.spawn();
    let discover = host.ask(request("server/discover", json!({})));
    assert_eq!(discover["result"]["resultType"], "complete");
    let listed = host.ask(request("tools/list", json!({})));
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 5);
    let inbox = host.ask(tool(
        &grant,
        "private_inbox",
        json!({"after":"0","limit":1}),
    ));
    assert_eq!(
        inbox["result"]["structuredContent"]["records"][0]["text"],
        "synthetic inbound; room instructions cannot mint grants"
    );
    let escape = host.ask(tool(
        &grant,
        "private_status",
        json!({"path":"/tmp/forbidden"}),
    ));
    assert_eq!(escape["error"]["code"], -32602);
    let prepared = host.ask(tool(
        &grant,
        "private_prepare",
        json!({"body":"synthetic agent reply"}),
    ));
    let draft = prepared["result"]["structuredContent"]["draft"].clone();
    let operation = "09090909090909090909090909090909";
    let queued = host.ask(tool(
        &grant,
        "private_queue",
        json!({"draft":draft,"operation":operation}),
    ));
    assert_eq!(
        queued["result"]["structuredContent"]["status"],
        "durable_local_only"
    );
    let outbox = host.ask(tool(
        &grant,
        "private_outbox_status",
        json!({"after":"1","limit":1}),
    ));
    assert_eq!(
        outbox["result"]["structuredContent"]["records"][0]["operation"],
        operation
    );
    assert!(!outbox.to_string().contains("synthetic agent reply"));
    host.close();
    assert!(fixture.path.join("claim.json").exists());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let room = RoomSession::open(
            Identity::open(fixture.path.join("agent-id")).unwrap(),
            fixture.path.join("agent-room"),
            fixture.context,
        )
        .await
        .unwrap();
        assert_eq!(room.status().unwrap().outbox_head, 2);
    });
    let mut restart = fixture.spawn();
    wait_exit(&mut restart.child);
    assert!(!restart.child.try_wait().unwrap().unwrap().success());
    assert!(restart
        .responses
        .recv_timeout(Duration::from_secs(1))
        .is_err());
}

#[test]
fn legacy_read_only_session_and_cancellation_keep_claim_consumed() {
    let fixture = Fixture::new();
    let grant = fixture.grant("read-only");
    let mut host = fixture.spawn();
    let initialized=host.ask(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic client","version":"1"}}}));
    assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
    host.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let result=host.ask(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"private_prepare","arguments":{"session":grant["grant_id"],"body":"must not queue"}}}));
    assert_eq!(
        result["result"]["structuredContent"]["code"],
        "permission_denied"
    );
    // A cancellation naming an already-answered request is stale: MCP permits
    // ignoring it, so the session keeps serving and no reply is owed.
    host.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}));
    assert!(host.responses.recv_timeout(Duration::from_secs(1)).is_err());
    let live = host.ask(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"private_status","arguments":{"session":grant["grant_id"]}}}));
    assert_eq!(live["result"]["structuredContent"]["status"], "live");
    host.close();
    assert!(fixture.path.join("claim.json").exists());
}

#[test]
fn oversized_unterminated_stdio_frame_closes_custody_and_spares_an_uncalled_grant() {
    let fixture = Fixture::new();
    fixture.grant("read-only");
    let mut host = fixture.spawn();
    host.ask(request("server/discover", json!({})));
    let input = host.input.as_mut().unwrap();
    let _ = input.write_all(&vec![b'x'; 64 * 1024 + 1]);
    let _ = input.flush();
    wait_exit(&mut host.child);
    assert!(!host.child.try_wait().unwrap().unwrap().success());
    // The stream never ends silently: a closing notice precedes EOF.
    let notice: Value = serde_json::from_str(
        &host
            .responses
            .recv_timeout(Duration::from_secs(2))
            .expect("closing frame before EOF"),
    )
    .unwrap();
    assert_eq!(notice["method"], "notifications/message");
    assert_eq!(notice["params"]["data"]["status"], "closed");
    // A handshake and a malformed frame never reached a tool call, so the
    // one-use claim was never written and a fresh launch still serves.
    assert!(!fixture.path.join("claim.json").exists());
    assert!(Identity::open(fixture.path.join("agent-id")).is_ok());
}

#[test]
fn an_immediate_eof_spares_the_grant_then_a_second_launch_serves() {
    let fixture = Fixture::new();
    let grant = fixture.grant("read-only");
    // A client that connects and disconnects without any frame (a status
    // probe or crashed registration) must not burn the one-use grant.
    fixture.spawn().close();
    assert!(!fixture.path.join("claim.json").exists());
    let mut host = fixture.spawn();
    let live = host.ask(tool(&grant, "private_status", json!({})));
    assert_eq!(live["result"]["structuredContent"]["status"], "live");
    host.close();
    assert!(fixture.path.join("claim.json").exists());
}

#[test]
fn out_of_range_outbox_cursor_gets_a_reply_and_service_continues() {
    let fixture = Fixture::new();
    let grant = fixture.grant("read-write");
    let mut host = fixture.spawn();
    let beyond = host.ask(tool(
        &grant,
        "private_outbox_status",
        json!({"after":"99","limit":1}),
    ));
    assert_eq!(beyond["result"]["isError"], true);
    assert_eq!(beyond["result"]["structuredContent"]["code"], "bounds");
    let status = host.ask(tool(&grant, "private_status", json!({})));
    assert_eq!(status["result"]["structuredContent"]["status"], "live");
    let prepared = host.ask(tool(
        &grant,
        "private_prepare",
        json!({"body":"still serving"}),
    ));
    let draft = prepared["result"]["structuredContent"]["draft"].clone();
    let queued = host.ask(tool(
        &grant,
        "private_queue",
        json!({"draft":draft,"operation":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}),
    ));
    assert_eq!(
        queued["result"]["structuredContent"]["status"],
        "durable_local_only"
    );
    let conflicting = host.ask(tool(
        &grant,
        "private_prepare",
        json!({"body":"other body, same operation"}),
    ));
    let draft = conflicting["result"]["structuredContent"]["draft"].clone();
    let refused = host.ask(tool(
        &grant,
        "private_queue",
        json!({"draft":draft,"operation":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}),
    ));
    assert_eq!(
        refused["result"]["structuredContent"]["code"],
        "operation_conflict"
    );
    let status = host.ask(tool(&grant, "private_status", json!({})));
    assert_eq!(status["result"]["structuredContent"]["status"], "live");
    host.close();
    assert!(fixture.path.join("claim.json").exists());
}
