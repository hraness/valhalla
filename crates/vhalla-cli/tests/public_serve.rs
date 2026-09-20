//! Explicit serve activation, exact proof reads and clean restart continuation.
#![cfg(all(unix, feature = "experimental-public"))]
use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_core::RealmId;
use vhalla_public_client::{Bootstrap, CertifiedClient, Validator, ValidatorActivation};
use vhalla_public_protocol::{
    response::{hex, proof_from_hex, BundlePage, ReadKind, ReadRequest},
    PeerAdvertisement,
};
use vhalla_rooms::{registry::DirectoryPolicy, DirectoryId};
use vhalla_rooms_consensus::Genesis;
use vhalla_social::archive::{Archive, Limits};

struct Home {
    dir: PathBuf,
    pin: [u8; 32],
    network: [u8; 32],
    key: [u8; 32],
    frontier: [u8; 32],
}
impl Home {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-public-serve-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let key = vhalla_identity::Identity::create_new(dir.join("key")).unwrap();
        let public = key.public_key();
        drop(key);
        let realm = RealmId(77);
        let limits = Limits::default();
        let genesis = Genesis {
            directory: DirectoryId::from_bytes([8; 32]),
            realm,
            policy: DirectoryPolicy {
                base_cost: 1,
                window_seconds: 86400,
                max_in_window: 8,
                support_epoch_seconds: 86400,
                max_lifetime_rooms: 16,
            },
            eligible: vec![],
            limits,
            archive: Archive::new(realm, limits).unwrap(),
        };
        let bootstrap = Bootstrap::from_genesis(
            genesis,
            vec![ValidatorActivation {
                from: 1,
                validators: vec![Validator {
                    public_key: public,
                    power: 1,
                }],
            }],
        )
        .unwrap();
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        fs::write(dir.join("bootstrap"), bootstrap.encode()).unwrap();
        let frontier = CertifiedClient::new(bootstrap, pin)
            .unwrap()
            .frontier()
            .commitment();
        Self {
            dir,
            pin,
            network,
            key: public,
            frontier,
        }
    }
    fn args(&self, create: bool) -> Vec<OsString> {
        let mut args = vec![
            "public".into(),
            "serve".into(),
            self.dir.join("bootstrap").into(),
            hex(&self.pin).into(),
            self.dir.join("key").into(),
            self.dir.join("journal").into(),
            self.dir.join("peer-state").into(),
            "https://peer.vhalla.dev:443/vhalla/v1".into(),
            "https://app.vhalla.dev".into(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ];
        if create {
            args.push("--new-state".into());
        }
        args
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(home: &Home, create: bool) -> (Running, SocketAddr, u64) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(home.args(create))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, recv) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let mut guard = Running(child);
    let mut address = None;
    let mut sequence = None;
    loop {
        let line = recv
            .recv_timeout(Duration::from_secs(15))
            .unwrap_or_else(|e| {
                let _ = guard.0.kill();
                let mut stderr = String::new();
                guard
                    .0
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                panic!("serve startup failed: {e}: {stderr}")
            })
            .unwrap();
        if let Some(value) = line.strip_prefix("listen ") {
            address = Some(value.parse().unwrap());
        }
        if let Some(value) = line.strip_prefix("advertisement-sequence ") {
            sequence = Some(value.parse().unwrap());
        }
        if line.starts_with("transport ") {
            break;
        }
    }
    (guard, address.unwrap(), sequence.unwrap())
}
fn fetch(home: &Home, address: SocketAddr, kind: ReadKind, nonce: u8) -> Vec<u8> {
    let request = ReadRequest::new([nonce; 32], kind).unwrap();
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        socket,
        "GET {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nOrigin: https://app.vhalla.dev\r\n\r\n",
        request.target()
    )
    .unwrap();
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&raw[..split]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let body = &raw[split + 4..];
    let proof = headers
        .lines()
        .find_map(|v| v.strip_prefix("x-vhalla-proof: "))
        .unwrap();
    proof_from_hex(proof)
        .unwrap()
        .verify(home.network, home.key, &request, body)
        .unwrap();
    body.to_vec()
}
fn shutdown(mut running: Running) {
    assert!(Command::new("/bin/kill")
        .args(["-TERM", &running.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = running.0.try_wait().unwrap() {
            assert!(status.success(), "serve did not stop cleanly: {status}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "serve shutdown stalled"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
#[test]
fn serve_first_start_signed_reads_graceful_shutdown_and_monotone_restart() {
    let home = Home::new();
    let (running, address, sequence) = start(&home, true);
    assert!(address.ip().is_loopback());
    assert_eq!(sequence, 1);
    let ad = PeerAdvertisement::decode(&fetch(&home, address, ReadKind::Advertisement, 1)).unwrap();
    assert_eq!(ad.unverified_claims().sequence, 1);
    Bootstrap::decode(&fetch(&home, address, ReadKind::Bootstrap, 2), home.pin).unwrap();
    let kind = ReadKind::Bundles {
        after: 0,
        frontier: home.frontier,
        count: 32,
        bytes: 2 * 1024 * 1024,
    };
    let request = ReadRequest::new([3; 32], kind).unwrap();
    assert!(
        BundlePage::decode(&fetch(&home, address, kind, 3), &request)
            .unwrap()
            .bundles()
            .is_empty()
    );
    shutdown(running);
    let (running, address, sequence) = start(&home, false);
    assert_eq!(sequence, 2);
    let renewed =
        PeerAdvertisement::decode(&fetch(&home, address, ReadKind::Advertisement, 4)).unwrap();
    assert_eq!(renewed.unverified_claims().sequence, 2);
    shutdown(running);
    assert!(!home.dir.join("journal").exists());
}
#[test]
fn serve_refuses_implicit_state_creation_public_bind_and_duplicate_flags() {
    let home = Home::new();
    let mut public_bind = home.args(true);
    let index = public_bind.iter().position(|s| s == "127.0.0.1:0").unwrap();
    public_bind[index] = "0.0.0.0:9790".into();
    let mut duplicate = home.args(true);
    duplicate.push("--new-state".into());
    for args in [home.args(false), public_bind, duplicate] {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!home.dir.join("peer-state").exists());
    }
}
