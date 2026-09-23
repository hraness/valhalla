use super::*;
use std::sync::atomic::AtomicUsize;
struct Fake {
    calls: AtomicUsize,
    fail: bool,
}
impl Upstream for Fake {
    fn exchange(&self, op: u8, body: &[u8], deadline: Instant) -> Result<Vec<u8>> {
        assert!(deadline > Instant::now());
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(NetError::Timeout);
        }
        if op == OP_PUT {
            let item = RelayItem::decode(body).unwrap();
            Ok(encode_receipt(super::super::RelayReceipt {
                position: 7,
                digest: item.digest(),
                duplicate: true,
            }))
        } else {
            Ok(vec![0; 11])
        }
    }
}
fn fixture(timeout: Duration, fail: bool) -> (Gateway, TcpListener, Arc<Fake>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fake = Arc::new(Fake {
        calls: AtomicUsize::new(0),
        fail,
    });
    let assets = Assets::new(BTreeMap::from([(
        "index.html".into(),
        b"verified UI".to_vec(),
    )]))
    .unwrap();
    let gateway = Gateway::configured(
        listener.local_addr().unwrap(),
        RelayNamespace::from_bytes([9; 32]).unwrap(),
        BrowserCapability::from_bytes([8; 32]).unwrap(),
        fake.clone(),
        assets,
        GatewayLimits {
            timeout,
            ..GatewayLimits::default()
        },
    )
    .unwrap();
    (gateway, listener, fake)
}
fn request(gateway: &Gateway, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {ENDPOINT} HTTP/1.1\r\nHost: {}\r\nOrigin: {}\r\nAuthorization: Bearer {}\r\nX-Vhalla-Namespace: {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        gateway.0.host,
        gateway.origin(),
        "08".repeat(32),
        "09".repeat(32),
        body.len()
    );
    [head.as_bytes(), body].concat()
}
fn exchange(gateway: Gateway, listener: TcpListener, raw: &[u8]) -> Vec<u8> {
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = handle(&gateway.0, stream);
    });
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.write_all(raw).unwrap();
    socket.shutdown(std::net::Shutdown::Write).unwrap();
    let mut response = Vec::new();
    if let Err(error) = socket.read_to_end(&mut response) {
        // Refusal may close with unread hostile request bytes. macOS can reset
        // that connection instead of delivering a complete HTTP error response.
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(!response.starts_with(b"HTTP/1.1 200"));
    }
    worker.join().unwrap();
    response
}
#[test]
fn unauthorized_or_malformed_requests_never_touch_upstream() {
    for change in 0..9 {
        let (gateway, listener, fake) = fixture(Duration::from_secs(1), false);
        let body = frame(OP_PAGE, &page_request(0, 1).unwrap());
        let raw = request(&gateway, &body);
        let split = raw.windows(4).position(|b| b == b"\r\n\r\n").unwrap();
        let mut header = String::from_utf8(raw[..split].to_vec()).unwrap();
        match change {
            0 => {
                header = header.replace(
                    &format!("Origin: {}", gateway.origin()),
                    "Origin: http://evil.test",
                )
            }
            1 => {
                header = header.replace(&format!("Host: {}", gateway.0.host), "Host: attacker.test")
            }
            2 => header = header.replace(&"08".repeat(32), &"07".repeat(32)),
            3 => header = header.replace(&"09".repeat(32), &"07".repeat(32)),
            4 => header.push_str("\r\nTransfer-Encoding: chunked"),
            5 => header.push_str("\r\nContent-Length: 0"),
            6 => header = header.replace(ENDPOINT, "http://evil.test/private-relay/v1"),
            7 => header = header.replace("Content-Length: 15", "Content-Length: 99999999"),
            _ => header = header.replace("POST", "OPTIONS"),
        }
        let response = exchange(
            gateway,
            listener,
            &[header.as_bytes(), b"\r\n\r\n", &body].concat(),
        );
        assert!(!response.starts_with(b"HTTP/1.1 200"), "change {change}");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn canonical_submit_receipt_and_unavailable_status_are_forwarded() {
    use vhalla_private_kernel::{OperationId, OutboxKind};
    for fail in [false, true] {
        let (gateway, listener, fake) = fixture(Duration::from_secs(1), fail);
        let item = RelayItem::new(
            gateway.0.namespace,
            1,
            OperationId::from_bytes([3; 16]).unwrap(),
            OutboxKind::Application,
            b"ciphertext",
        )
        .unwrap();
        let raw = request(&gateway, &frame(OP_PUT, &item.encode().unwrap()));
        let response = exchange(gateway, listener, &raw);
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let start = response.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
        let (status, body) = decode_frame(&response[start..], MAX_RESPONSE).unwrap();
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        if fail {
            assert_eq!(decode_status(status, body), Err(NetError::Unavailable));
        } else {
            assert_eq!(
                decode_receipt(&decode_status(status, body).unwrap(), &item)
                    .unwrap()
                    .position,
                7
            );
        }
    }
}
#[test]
fn static_allowlist_and_scope_malformed_body_never_dial() {
    for target in ["/", "/../config", "/?token=secret"] {
        let (gateway, listener, fake) = fixture(Duration::from_secs(1), false);
        let raw = format!("GET {target} HTTP/1.1\r\nHost: {}\r\n\r\n", gateway.0.host);
        let response = exchange(gateway, listener, raw.as_bytes());
        assert_eq!(response.starts_with(b"HTTP/1.1 200"), target == "/");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
    let (gateway, listener, fake) = fixture(Duration::from_secs(1), false);
    let raw = request(&gateway, &frame(OP_PAGE, &[0; 10]));
    assert!(exchange(gateway, listener, &raw).starts_with(b"HTTP/1.1 400"));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}
#[test]
fn absolute_deadline_closes_stalled_headers_and_shutdown_needs_no_client() {
    let (gateway, listener, fake) = fixture(Duration::from_millis(60), false);
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = handle(&gateway.0, stream);
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let start = Instant::now();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    worker.join().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    let (gateway, listener, _) = fixture(Duration::from_secs(1), false);
    let stop = Arc::new(AtomicBool::new(true));
    gateway.serve_until(listener, stop).unwrap();
}
#[test]
fn capabilities_redact_and_nonloopback_or_unbounded_policy_refuse() {
    assert!(!format!("{:?}", BrowserCapability::from_bytes([8; 32]).unwrap()).contains("08"));
    assert!(BrowserCapability::from_bytes([0; 32]).is_err());
    assert!(GatewayLimits {
        max_connections: 17,
        ..GatewayLimits::default()
    }
    .check()
    .is_err());
    let (gateway, _, fake) = fixture(Duration::from_secs(1), false);
    let assets = Assets::new(BTreeMap::from([("index.html".into(), vec![1])])).unwrap();
    assert!(Gateway::configured(
        "0.0.0.0:8000".parse().unwrap(),
        gateway.0.namespace,
        gateway.0.capability.clone(),
        fake,
        assets,
        GatewayLimits::default()
    )
    .is_err());
}

#[test]
fn constructor_refuses_shared_browser_and_upstream_capability_before_dial() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
    let upstream = TlsRelay::new(
        "127.0.0.1:1".parse().unwrap(),
        "localhost",
        certificate.cert.der().to_vec(),
        super::super::net::RelayToken::from_bytes([8; 32]).unwrap(),
        namespace,
    )
    .unwrap();
    let assets = Assets::new(BTreeMap::from([("index.html".into(), vec![1])])).unwrap();
    assert!(matches!(
        Gateway::new(
            "127.0.0.1:8000".parse().unwrap(),
            namespace,
            BrowserCapability::from_bytes([8; 32]).unwrap(),
            upstream,
            assets,
            GatewayLimits::default()
        ),
        Err(NetError::Denied)
    ));
}

#[test]
fn constructor_refuses_default_http_port_before_dial() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
    let upstream = TlsRelay::new(
        "127.0.0.1:1".parse().unwrap(),
        "localhost",
        certificate.cert.der().to_vec(),
        super::super::net::RelayToken::from_bytes([7; 32]).unwrap(),
        namespace,
    )
    .unwrap();
    let assets = Assets::new(BTreeMap::from([("index.html".into(), vec![1])])).unwrap();
    assert!(matches!(
        Gateway::new(
            "127.0.0.1:80".parse().unwrap(),
            namespace,
            BrowserCapability::from_bytes([8; 32]).unwrap(),
            upstream,
            assets,
            GatewayLimits::default()
        ),
        Err(NetError::Bounds)
    ));
}

#[test]
fn default_budget_admits_two_maximum_assets_then_refuses_more_work() {
    let (gateway, _, fake) = fixture(Duration::from_secs(1), false);
    assert!(admit(&gateway.0, 32 * 1024 * 1024, false).unwrap());
    assert!(admit(&gateway.0, 32 * 1024 * 1024, false).unwrap());
    assert!(!admit(&gateway.0, 1, false).unwrap());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

fn large_asset_fixture(timeout: Duration) -> (Gateway, TcpListener, Arc<Fake>, Vec<u8>) {
    let (mut gateway, listener, fake) = fixture(timeout, false);
    // Larger than the observed macOS send buffer, while inside the real asset
    // and window bounds. This must cross multiple TCP writes without truncation.
    let body = vec![0x5a; 8 * 1024 * 1024];
    Arc::get_mut(&mut gateway.0).unwrap().assets = Assets::new(BTreeMap::from([
        ("index.html".into(), b"verified UI".to_vec()),
        ("module.wasm".into(), body.clone()),
    ]))
    .unwrap();
    (gateway, listener, fake, body)
}

#[test]
fn actual_nonblocking_accept_serves_complete_large_asset_to_slow_reader() {
    let (gateway, listener, fake, body) = large_asset_fixture(Duration::from_secs(2));
    let address = listener.local_addr().unwrap();
    let request = format!("GET /module.wasm HTTP/1.1\r\nHost: {address}\r\n\r\n");
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, server_stop));
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.write_all(request.as_bytes()).unwrap();
    // Let the initial send buffer fill before draining the body, as happens
    // while the browser is loading and compiling its other assets.
    thread::sleep(Duration::from_millis(100));
    let mut response = Vec::new();
    let read = socket.read_to_end(&mut response);
    drop(socket);
    stop.store(true, Ordering::Release);
    let served = server.join().unwrap();
    read.unwrap();
    served.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    let header = std::str::from_utf8(&response[..split]).unwrap();
    assert!(header.contains(&format!("Content-Length: {}\r\n", body.len())));
    assert_eq!(&response[split..], body.as_slice());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn inherited_nonblocking_mode_is_cleared_before_large_response_on_every_platform() {
    let (gateway, listener, fake, body) = large_asset_fixture(Duration::from_secs(2));
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Linux does not inherit this mode from accept. Set it explicitly so
        // the production Mac failure also has a portable regression.
        stream.set_nonblocking(true).unwrap();
        handle(&gateway.0, stream)
    });
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .write_all(format!("GET /module.wasm HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    let mut response = Vec::new();
    let read = socket.read_to_end(&mut response);
    let served = server.join().unwrap();
    read.unwrap();
    served.unwrap();
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(&response[split..], body.as_slice());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn admission_refusals_answer_explicit_statuses_instead_of_dropping() {
    // 503 while every worker slot is occupied: hold one connection open past
    // accept so the next accepted socket is refused with a bounded response.
    let (mut gateway, listener, fake) = fixture(Duration::from_secs(2), false);
    Arc::get_mut(&mut gateway.0).unwrap().limits.max_connections = 1;
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, server_stop));
    let mut held = TcpStream::connect(address).unwrap();
    held.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let mut refused_503 = Vec::new();
    for _ in 0..50 {
        let mut extra = TcpStream::connect(address).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        refused_503.clear();
        if extra.read_to_end(&mut refused_503).is_ok() && refused_503.starts_with(b"HTTP/1.1 503") {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    stop.store(true, Ordering::Release);
    assert!(refused_503.starts_with(b"HTTP/1.1 503"));
    assert!(std::str::from_utf8(&refused_503)
        .unwrap()
        .contains("Connection: close"));
    drop(held);
    server.join().unwrap().unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    // 429 once the accepted-connection window budget is spent: a one-request
    // window admits the first connection and refuses the second.
    let (mut gateway, listener, fake) = fixture(Duration::from_secs(1), false);
    Arc::get_mut(&mut gateway.0).unwrap().limits.requests = 1;
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, server_stop));
    let mut first = TcpStream::connect(address).unwrap();
    first
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    first
        .write_all(format!("GET / HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = Vec::new();
    first.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let mut refused_429 = Vec::new();
    for _ in 0..50 {
        let mut extra = TcpStream::connect(address).unwrap();
        extra
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        refused_429.clear();
        if extra.read_to_end(&mut refused_429).is_ok() && refused_429.starts_with(b"HTTP/1.1 429") {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    stop.store(true, Ordering::Release);
    assert!(refused_429.starts_with(b"HTTP/1.1 429"));
    server.join().unwrap().unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    // The refusal writer itself emits a complete bounded close response.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    let helper = thread::spawn(move || {
        let (stream, _) = probe.accept().unwrap();
        refuse(stream, 403);
    });
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).unwrap();
    helper.join().unwrap();
    assert!(response.starts_with(b"HTTP/1.1 403"));
    assert!(std::str::from_utf8(&response)
        .unwrap()
        .ends_with("\r\n\r\ntemporarily unavailable"));
}

#[test]
fn stalled_large_asset_write_keeps_original_deadline_during_shutdown() {
    let (gateway, listener, fake, body) = large_asset_fixture(Duration::from_millis(100));
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, server_stop));
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .write_all(format!("GET /module.wasm HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .unwrap();
    // Confirm that the request was admitted, then leave the receive buffer
    // undrained. Shutdown must wait only for this request's existing deadline.
    let mut first = [0; 1];
    socket.read_exact(&mut first).unwrap();
    let started = Instant::now();
    stop.store(true, Ordering::Release);
    let served = server.join().unwrap();
    let elapsed = started.elapsed();
    let mut response = first.to_vec();
    socket.read_to_end(&mut response).unwrap();
    served.unwrap();
    assert!(elapsed < Duration::from_secs(1));
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    assert!(response.len() - split < body.len());
    assert_eq!(&response[split..], &body[..response.len() - split]);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}
