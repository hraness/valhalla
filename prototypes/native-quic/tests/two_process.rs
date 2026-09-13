//! Runs real listener and sender binaries, not two in-memory swarms.
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_vhalla-quic-spike");

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn peer(seed: u8) -> String {
    let mut child = ChildGuard(
        Command::new(BIN)
            .args(["peer-id", &seed.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = wait_output(&mut child);
    assert!(output.0, "peer-id failed: {}", output.2);
    output.1.trim().into()
}

#[test]
fn real_processes_echo_and_reject_wrong_transport_identity() {
    let start = Instant::now();
    let client_peer = peer(2);
    let wrong_peer = peer(3);
    let mut listener = ChildGuard(
        Command::new(BIN)
            .args(["listen", "1", &client_peer])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let (tx, rx) = mpsc::sync_channel(16);
    let stdout = listener.0.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            if tx.try_send(line).is_err() {
                break;
            }
        }
    });
    let first = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let invitation = first.strip_prefix("INVITE ").expect("listener invitation");
    println!("listener_process={} {first}", listener.0.id());

    for size in [17, 64 * 1024] {
        let mut child = ChildGuard(
            Command::new(BIN)
                .args(["send", "2", invitation, &size.to_string()])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        println!("sender_process={} bytes={size}", child.0.id());
        let output = wait_output(&mut child);
        assert!(output.0, "sender: {}", output.2);
        assert!(
            output.1.contains(&format!("ECHO_OK bytes={size}")),
            "{}",
            output.1
        );
        print!("{}", output.1);
        loop {
            let line = rx
                .recv_timeout(Duration::from_secs(3))
                .expect("listener close evidence");
            println!("listener: {line}");
            if line.starts_with("PEER_CLOSED ") {
                break;
            }
        }
    }

    let (prefix, _) = invitation.rsplit_once("/p2p/").unwrap();
    let wrong = format!("{prefix}/p2p/{wrong_peer}");
    let mut child = ChildGuard(
        Command::new(BIN)
            .args(["send", "2", &wrong, "17"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let output = wait_output(&mut child);
    assert!(!output.0, "wrong peer succeeded");
    assert!(!output.1.contains("ECHO_OK"));
    assert!(
        output.2.contains("WRONG_PEER_REJECTED") || output.2.contains("peer identity mismatch"),
        "wrong-peer rejection must be identity-specific, not timeout: {}",
        output.2
    );
    println!("wrong_transport_peer={}", output.2.trim());
    drop(listener);
    reader.join().unwrap();
    println!("two_process_elapsed_ms={}", start.elapsed().as_millis());
}

fn wait_output(child: &mut ChildGuard) -> (bool, String, String) {
    use std::io::Read;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(12),
            "process deadline exceeded"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.success(), stdout, stderr)
}
