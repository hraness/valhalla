#![cfg(all(unix, feature = "experimental-network"))]
//! Actual CLI processes, private application identities and fresh transport keys.
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const BIN: &str = env!("CARGO_BIN_EXE_vhalla");
const WAIT: Duration = Duration::from_secs(12);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("vhalla-chat-{:032x}", u128::from_be_bytes(nonce)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Process {
    child: Child,
    rx: Receiver<String>,
    readers: Vec<JoinHandle<()>>,
}
impl Process {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, rx) = mpsc::sync_channel(32);
        let streams: [Box<dyn Read + Send>; 2] = [
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        let readers = streams
            .into_iter()
            .map(|stream| {
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut line = Vec::new();
                        // The fixture cannot allocate an unbounded subprocess line.
                        match reader.by_ref().take(140_001).read_until(b'\n', &mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) if line.len() > 140_000 => break,
                            Ok(_) => {
                                if tx.try_send(String::from_utf8(line).unwrap()).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        Self { child, rx, readers }
    }
    fn line(&self, prefix: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let line = self
                .rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|e| panic!("waiting for {prefix}: {e}"));
            if line.starts_with(prefix) {
                return line.trim_end_matches('\n').into();
            }
        }
    }
    fn finish(mut self, expected: bool) -> String {
        let start = Instant::now();
        let mut output = String::new();
        loop {
            for line in self.rx.try_iter() {
                output.push_str(&line);
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                for reader in self.readers.drain(..) {
                    reader.join().unwrap();
                }
                for line in self.rx.try_iter() {
                    output.push_str(&line);
                }
                assert_eq!(status.success(), expected, "{output}");
                return output;
            }
            assert!(
                start.elapsed() < WAIT,
                "process exceeded deadline: {output}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
    }
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn init(path: &Path) -> String {
    let output = Process::spawn(&["identity", "init", self::path(path)]).finish(true);
    output
        .trim()
        .strip_prefix("application-key ")
        .unwrap()
        .to_string()
}
fn listener(path: &Path, peer: &str) -> (Process, String, String) {
    let process = Process::spawn(&["experimental", "listen", self::path(path), peer]);
    let line = process.line("route ");
    let mut parts = line.split_whitespace();
    assert_eq!(parts.next(), Some("route"));
    let address = parts.next().unwrap().to_string();
    let expiry = parts.next().unwrap().to_string();
    assert!(parts.next().is_none());
    (process, address, expiry)
}
fn send(path: &Path, peer: &str, address: &str, expiry: &str, text: &str, ok: bool) -> String {
    Process::spawn(&[
        "experimental",
        "send",
        self::path(path),
        peer,
        address,
        expiry,
        text,
    ])
    .finish(ok)
}

fn json_line(process: &Process, kind: &str) -> serde_json::Value {
    let line = process.line(&format!("{{\"v\":1,\"kind\":\"{kind}\""));
    assert!(line.len() <= 140_000);
    serde_json::from_str(&line).unwrap_or_else(|error| panic!("valid JSON event {line:?}: {error}"))
}

fn json_listener(path: &Path, peer: &str) -> (Process, String, String) {
    let process = Process::spawn(&["experimental", "--json", "listen", self::path(path), peer]);
    let event = json_line(&process, "ready");
    assert_eq!(event["v"], 1);
    (
        process,
        event["route"].as_str().unwrap().to_string(),
        event["expires_at"].as_u64().unwrap().to_string(),
    )
}

fn json_send(
    path: &Path,
    peer: &str,
    address: &str,
    expiry: &str,
    text: &str,
    ok: bool,
) -> serde_json::Value {
    let process = Process::spawn(&[
        "experimental",
        "--json",
        "send",
        self::path(path),
        peer,
        address,
        expiry,
        text,
    ]);
    let event = json_line(&process, "received");
    assert_eq!(event["v"], 1);
    let output = process.finish(ok);
    assert!(output.lines().all(|line| line.len() <= 140_000));
    event
}

#[test]
fn pinned_chat_survives_process_restart_and_strangers_cannot_join() {
    let tmp = Temp::new();
    let alice = tmp.0.join("alice");
    let bob = tmp.0.join("bob");
    let stranger = tmp.0.join("stranger");
    let alice_key = init(&alice);
    let bob_key = init(&bob);
    let stranger_key = init(&stranger);
    let (server, route, expiry) = listener(&bob, &alice_key);
    let wrong = send(&stranger, &bob_key, &route, &expiry, "intrusion", false);
    assert!(!wrong.contains("received peer="));
    assert!(server.line("rejected ").contains("Session(Context)"));
    server.line("peer-closed");
    let wrong = send(
        &alice,
        &stranger_key,
        &route,
        &expiry,
        "wrong recipient",
        false,
    );
    assert!(!wrong.contains("received peer="));
    server.line("rejected ");
    server.line("peer-closed");

    // Remote content must not emit terminal escapes or command-shaped output.
    let text = "hello\njoined session=fake\u{1b}]52;c;ZXZpbA==\u{7}";
    let first = send(&alice, &bob_key, &route, &expiry, text, true);
    assert!(first.starts_with(&format!("received peer={bob_key} session=")));
    let joined = server.line("joined ");
    let message = server.line("message ");
    let encoded: String = text.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert!(message.contains(&format!("peer={alice_key} ")));
    assert!(message.ends_with(&format!("body-hex={encoded}")));
    assert!(!message.contains('\u{1b}'));
    server.line("peer-closed");
    drop(server);

    let shown = Process::spawn(&["identity", "show", path(&bob)]).finish(true);
    assert_eq!(shown.trim(), format!("application-key {bob_key}"));
    let (server, next_route, next_expiry) = listener(&bob, &alice_key);
    assert_ne!(
        route.rsplit("/p2p/").next(),
        next_route.rsplit("/p2p/").next(),
        "fresh OS transport key required"
    );
    let second = send(
        &alice,
        &bob_key,
        &next_route,
        &next_expiry,
        "after restart",
        true,
    );
    assert!(second.starts_with(&format!("received peer={bob_key} session=")));
    assert_ne!(
        joined,
        server.line("joined "),
        "fresh application session required"
    );
    assert!(server
        .line("message ")
        .contains(&format!("peer={alice_key} ")));
    server.line("peer-closed");
}

#[test]
fn invited_send_redeems_once_and_cannot_replay_across_processes() {
    let tmp = Temp::new();
    let alice = tmp.0.join("alice");
    let bob = tmp.0.join("bob");
    let alice_key = init(&alice);
    let bob_key = init(&bob);
    let expiry_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;

    // Bob issues an owner-signed invitation naming Alice's application key.
    let issued = Process::spawn(&[
        "experimental",
        "invite",
        path(&bob),
        &alice_key,
        "0000000000000000000000000000004d",
        "0000000000000000000000000000004e",
        "1",
        &expiry_t.to_string(),
    ])
    .finish(true);
    let invitation = issued
        .trim()
        .strip_prefix("invitation ")
        .unwrap_or_else(|| panic!("invite output: {issued}"));
    assert_eq!(invitation.len(), 426, "canonical fixed-width invitation");

    // Bob listens on the invitation; Alice redeems it once.
    let server = Process::spawn(&[
        "experimental",
        "listen",
        path(&bob),
        "invitation",
        invitation,
    ]);
    let line = server.line("route ");
    let mut parts = line.split_whitespace();
    let (route, expiry) = (parts.nth(1).unwrap().to_string(), parts.next().unwrap());
    let sent = Process::spawn(&[
        "experimental",
        "send",
        path(&alice),
        "invitation",
        invitation,
        &bob_key,
        &route,
        expiry,
        "invited hello",
    ])
    .finish(true);
    assert!(sent.starts_with(&format!("received peer={bob_key}")));
    server.line("joined ");
    assert!(server
        .line("message ")
        .contains(&format!("peer={alice_key} ")));
    server.line("peer-closed");
    drop(server);

    // The durable spent record survives across processes.
    let spent_path = PathBuf::from(format!("{}.spent", path(&alice)));
    assert!(spent_path.exists(), "spend persisted beside the identity");

    // A second redemption is rejected before dialing — fresh process, same
    // identity, same invitation.
    let replay = Process::spawn(&[
        "experimental",
        "send",
        path(&alice),
        "invitation",
        invitation,
        &bob_key,
        &route,
        expiry,
        "replay",
    ])
    .finish(false);
    assert!(
        replay.contains("already spent"),
        "durable replay rejection: {replay}"
    );
}

#[test]
fn json_lines_preserve_hostile_bytes_and_bound_each_event() {
    let tmp = Temp::new();
    let alice = tmp.0.join("alice");
    let bob = tmp.0.join("bob");
    let alice_key = init(&alice);
    let bob_key = init(&bob);
    let (server, route, expiry) = json_listener(&bob, &alice_key);
    let text = "quote \" slash \\ newline\nemoji 🛡 and escape \u{1b}";
    let receipt = json_send(&alice, &bob_key, &route, &expiry, text, true);
    assert_eq!(receipt["kind"], "received");
    assert_eq!(receipt["peer"], bob_key);
    assert_eq!(receipt["frame_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(json_line(&server, "joined")["kind"], "joined");
    let message = json_line(&server, "message");
    let expected: String = text.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(message["peer"], alice_key);
    assert_eq!(message["body_hex"], expected);
    assert_eq!(json_line(&server, "peer_closed")["kind"], "peer_closed");
}

#[test]
fn listen_binds_a_named_host_and_the_route_is_dialable() {
    let tmp = Temp::new();
    let alice = tmp.0.join("alice");
    let bob = tmp.0.join("bob");
    let alice_key = init(&alice);
    let bob_key = init(&bob);

    // A non-default loopback exercises the optional listen host: the
    // route must advertise exactly what the peer will dial.
    let server = Process::spawn(&["experimental", "listen", path(&bob), &alice_key, "::1"]);
    let line = server.line("route ");
    let mut parts = line.split_whitespace();
    assert_eq!(parts.next(), Some("route"));
    let route = parts.next().unwrap().to_string();
    let expiry = parts.next().unwrap().to_string();
    assert!(parts.next().is_none());
    assert!(
        route.contains("::1"),
        "route must advertise the bound host: {route}"
    );

    let received = send(&alice, &bob_key, &route, &expiry, "across interfaces", true);
    assert!(received.starts_with(&format!("received peer={bob_key} session=")));
    assert!(server
        .line("message ")
        .contains(&format!("peer={alice_key} ")));
    server.line("peer-closed");
}
