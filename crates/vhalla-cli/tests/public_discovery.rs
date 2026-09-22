//! An explicit seedless discovery server serves signed challenges and reopens.
#![cfg(all(unix, feature = "experimental-public"))]
use sha2::{Digest, Sha256};
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
use vhalla_public_client::{Bootstrap, Validator, ValidatorActivation};
use vhalla_public_protocol::{
    discovery::{proof_from_hex, DiscoveryKind, DiscoveryRequest, RegistrationChallenge},
    response::hex,
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
}
impl Home {
    fn new() -> Self {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "vhalla-discovery-serve-{}-{}",
            std::process::id(),
            hex(&nonce)
        ));
        fs::create_dir(&dir).unwrap();
        let identity = vhalla_identity::Identity::create_new(dir.join("key")).unwrap();
        let key = identity.public_key();
        drop(identity);
        let realm = RealmId(77);
        let limits = Limits::default();
        let bootstrap = Bootstrap::from_genesis(
            Genesis {
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
            },
            vec![ValidatorActivation {
                from: 1,
                validators: vec![Validator {
                    public_key: key,
                    power: 1,
                }],
            }],
        )
        .unwrap();
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        fs::write(dir.join("bootstrap"), bootstrap.encode()).unwrap();
        Self {
            dir,
            pin,
            network,
            key,
        }
    }
    fn start(&self, new: bool) -> (Process, SocketAddr) {
        let mut args: Vec<OsString> = vec![
            "public".into(),
            "discovery-serve".into(),
            self.dir.join("bootstrap").into(),
            hex(&self.pin).into(),
            self.dir.join("key").into(),
            self.dir.join("journal").into(),
            self.dir.join("publisher").into(),
            "https://peer.vhalla.dev:443/vhalla/v1".into(),
            "https://app.vhalla.dev".into(),
            self.dir.join("discovery").into(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ];
        if new {
            args.extend(["--new-state".into(), "--new-discovery".into()]);
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                // Keep draining after startup receiver drops so the child
                // never receives a broken stdout pipe during later logging.
                let _ = tx.send(line.unwrap());
            }
        });
        let process = Process(child);
        loop {
            let line = rx
                .recv_timeout(Duration::from_secs(15))
                .expect("discovery startup");
            if let Some(address) = line.strip_prefix("listen ") {
                return (process, address.parse().unwrap());
            }
        }
    }
    fn advertisement(&self) -> PeerAdvertisement {
        PeerAdvertisement::decode(&fs::read(self.dir.join("publisher/advertisement")).unwrap())
            .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
struct Process(Child);
impl Process {
    fn stop(mut self) {
        assert!(Command::new("/bin/kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "discovery graceful shutdown"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn discovery_cli_seedless_startup_signed_challenge_and_restart() {
    let home = Home::new();
    let (process, address) = home.start(true);
    let original = home.advertisement();
    let request = DiscoveryRequest::new(
        [7; 32],
        DiscoveryKind::Challenge {
            publisher: home.key,
            advertisement: Sha256::digest(original.encode()).into(),
        },
    )
    .unwrap();
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nConnection: close\r\n\r\n",
                request.target()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    socket.take(16 * 1024).read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let at = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..at]).unwrap();
    let proof = headers
        .lines()
        .find_map(|line| line.strip_prefix("x-vhalla-proof: "))
        .unwrap()
        .trim();
    let body = &response[at + 4..];
    proof_from_hex(proof)
        .unwrap()
        .verify(home.network, home.key, request, body)
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    RegistrationChallenge::decode(body)
        .unwrap()
        .verify(home.network, home.key, request, now)
        .unwrap();
    assert_eq!(
        original.unverified_claims().capabilities,
        vhalla_public_protocol::Capabilities::READ
    );
    process.stop();
    let (process, _) = home.start(false);
    assert!(
        home.advertisement().unverified_claims().sequence > original.unverified_claims().sequence
    );
    process.stop();
    assert!(home.dir.join("discovery/registry").is_file());
}

#[test]
fn discovery_cli_internal_resolver_rejects_extra_or_private_routes_without_dialing() {
    for args in [
        vec!["public", "discovery-resolve"],
        vec![
            "public",
            "discovery-resolve",
            "https://127.0.0.1:443/vhalla/v1",
        ],
        vec![
            "public",
            "discovery-resolve",
            "https://seed.vhalla.dev:443/vhalla/v1",
            "extra",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_vhalla"))
            .env_clear()
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
