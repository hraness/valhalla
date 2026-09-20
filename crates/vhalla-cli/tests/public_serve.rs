//! Explicit serve activation, exact proof reads and clean restart continuation.
#![cfg(all(unix, feature = "experimental-public"))]
use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
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

static FIXTURE_SERIAL: AtomicU64 = AtomicU64::new(0);

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
            "vhalla-public-serve-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            FIXTURE_SERIAL.fetch_add(1, Ordering::Relaxed)
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
    start_args(home.args(create))
}
fn start_args(args: Vec<OsString>) -> (Running, SocketAddr, u64) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(args)
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
    assert_eq!(
        ad.unverified_claims().capabilities,
        vhalla_public_protocol::Capabilities::READ
    );
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

fn init_args(home: &Home) -> Vec<OsString> {
    vec![
        "public".into(),
        "activity-store-init".into(),
        home.dir.join("bootstrap").into(),
        hex(&home.pin).into(),
        hex(&[5; 32]).into(),
        home.dir.join("activity").into(),
        "100".into(),
        "1000000".into(),
    ]
}
fn invoke(args: Vec<OsString>) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vhalla"))
        .args(args)
        .output()
        .unwrap()
}
fn init_activity(home: &Home) {
    let output = invoke(init_args(home));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("local-storage-only-no-room-policy-grant")
    );
}
fn activity_args(home: &Home, create: bool) -> Vec<OsString> {
    let mut args = home.args(create);
    args.extend([
        "--activity-store".into(),
        hex(&[5; 32]).into(),
        home.dir.join("activity").into(),
        "100".into(),
        "1000000".into(),
    ]);
    args
}
fn publisher_files(home: &Home) -> std::collections::BTreeMap<OsString, Vec<u8>> {
    fs::read_dir(home.dir.join("peer-state"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), fs::read(entry.path()).unwrap())
        })
        .collect()
}
#[test]
fn activity_store_init_checks_pin_limits_scope_and_never_overwrites() {
    let home = Home::new();
    let mut wrong_pin = init_args(&home);
    wrong_pin[3] = hex(&[0; 32]).into();
    let mut zero = init_args(&home);
    zero[6] = "0".into();
    let mut padded = init_args(&home);
    padded[7] = "01000000".into();
    for args in [wrong_pin, zero, padded] {
        assert!(!invoke(args).status.success());
        assert!(!home.dir.join("activity").exists());
    }
    init_activity(&home);
    assert!(!home.dir.join("peer-state").exists());
    assert!(!home.dir.join("journal").exists());
    let before = fs::read(home.dir.join("activity/HEAD")).unwrap();
    assert!(!invoke(init_args(&home)).status.success());
    assert_eq!(fs::read(home.dir.join("activity/HEAD")).unwrap(), before);
    let scope = vhalla_room_activity::RoomScope {
        network: home.network,
        realm: RealmId(77),
        directory: DirectoryId::from_bytes([8; 32]),
        room: vhalla_rooms::RoomGenesisId::from_bytes([5; 32]),
    };
    let limits = vhalla_room_activity_store::Limits {
        max_events: 100,
        max_history_bytes: 1_000_000,
    };
    let store =
        vhalla_room_activity_store::Store::open(home.dir.join("activity"), scope, limits, None)
            .unwrap();
    assert_eq!(store.pin().count(), 0);
}
#[test]
fn serve_explicit_activity_mode_reopens_exactly_and_never_grants_room_policy() {
    use vhalla_public_protocol::{
        activity::{ActivityPage, ActivityRequest},
        Capabilities,
    };
    let home = Home::new();
    init_activity(&home);
    let (running, address, sequence) = start_args(activity_args(&home, true));
    assert_eq!(sequence, 1);
    let ad = PeerAdvertisement::decode(&fetch(&home, address, ReadKind::Advertisement, 1)).unwrap();
    assert!(ad
        .unverified_claims()
        .capabilities
        .contains(Capabilities::PUBLISH));
    let request = ActivityRequest::page([2; 32], [5; 32], 0, 16).unwrap();
    let raw = activity_http(&home, address, &request, None, 200);
    let page = ActivityPage::decode(&raw, &request).unwrap();
    assert_eq!(page.local_tip(), 0);
    assert!(page.entries().is_empty());
    // Storage selection and PUBLISH do not invent a room or posting policy.
    let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let event = vhalla_room_activity::UnsignedEvent::new(vhalla_room_activity::EventClaims {
        scope: vhalla_room_activity::RoomScope {
            network: home.network,
            realm: RealmId(77),
            directory: DirectoryId::from_bytes([8; 32]),
            room: vhalla_rooms::RoomGenesisId::from_bytes([5; 32]),
        },
        policy: vhalla_rooms::RoomRecordId::from_bytes([9; 32]),
        author: key.verifying_key().to_bytes(),
        sequence: 1,
        previous: vhalla_room_activity::EventId::ZERO,
        created_at: 123,
        content: vhalla_room_activity::Content::Text(
            vhalla_room_activity::Text::new("not authorized by PUBLISH").unwrap(),
        ),
    })
    .unwrap()
    .sign_with_key(&key)
    .unwrap()
    .encode();
    let post = ActivityRequest::post([3; 32], [5; 32], &event).unwrap();
    activity_http(&home, address, &post, Some(&event), 409);
    let after = ActivityRequest::page([8; 32], [5; 32], 0, 16).unwrap();
    let raw = activity_http(&home, address, &after, None, 200);
    let page = ActivityPage::decode(&raw, &after).unwrap();
    assert_eq!(page.local_tip(), 0);
    assert!(page.entries().is_empty());
    shutdown(running);
    let before = publisher_files(&home);
    assert!(!invoke(home.args(false)).status.success());
    let mut changed = activity_args(&home, false);
    let last = changed.len() - 1;
    changed[last] = "1000001".into();
    assert!(!invoke(changed).status.success());
    assert_eq!(publisher_files(&home), before);
    let (running, address, sequence) = start_args(activity_args(&home, false));
    assert_eq!(sequence, 2);
    let ad = PeerAdvertisement::decode(&fetch(&home, address, ReadKind::Advertisement, 4)).unwrap();
    assert!(ad
        .unverified_claims()
        .capabilities
        .contains(Capabilities::PUBLISH));
    shutdown(running);
}
fn activity_http(
    home: &Home,
    address: SocketAddr,
    request: &vhalla_public_protocol::activity::ActivityRequest,
    body: Option<&[u8]>,
    status: u16,
) -> Vec<u8> {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    if let Some(body) = body {
        write!(socket, "POST {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", request.target(), body.len()).unwrap();
        socket.write_all(body).unwrap();
    } else {
        write!(
            socket,
            "GET {} HTTP/1.1\r\nHost: peer.vhalla.dev\r\n\r\n",
            request.target()
        )
        .unwrap();
    }
    let mut raw = Vec::new();
    socket.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&raw[..split]).unwrap();
    assert!(
        headers.starts_with(&format!("HTTP/1.1 {status}")),
        "{headers}"
    );
    let body = &raw[split + 4..];
    if status == 200 {
        let proof = headers
            .lines()
            .find_map(|line| line.strip_prefix("x-vhalla-proof: "))
            .unwrap();
        vhalla_public_protocol::activity::proof_from_hex(proof)
            .unwrap()
            .verify(home.network, home.key, request, body)
            .unwrap();
    }
    body.to_vec()
}
#[test]
fn serve_activity_flags_are_bounded_and_missing_store_never_initializes_state() {
    let home = Home::new();
    let missing = activity_args(&home, true);
    assert!(!invoke(missing).status.success());
    assert!(!home.dir.join("activity").exists());
    assert!(!home.dir.join("peer-state").exists());
    init_activity(&home);
    let mut duplicate = activity_args(&home, true);
    duplicate.extend([
        "--activity-store".into(),
        hex(&[5; 32]).into(),
        home.dir.join("activity").into(),
        "100".into(),
        "1000000".into(),
    ]);
    let mut zero = activity_args(&home, true);
    let last = zero.len() - 1;
    zero[last] = "0".into();
    let mut overflow = activity_args(&home, true);
    let last = overflow.len() - 1;
    overflow[last] = "18446744073709551616".into();
    let mut too_many = home.args(true);
    for id in 1..=33 {
        too_many.extend([
            "--activity-store".into(),
            hex(&[id; 32]).into(),
            home.dir.join("activity").into(),
            "100".into(),
            "1000000".into(),
        ]);
    }
    for args in [duplicate, zero, overflow, too_many] {
        assert!(!invoke(args).status.success());
        assert!(!home.dir.join("peer-state").exists());
    }
}
