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

fn live_exchange(address: SocketAddr, raw: &[u8]) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.write_all(raw).unwrap();
    let mut response = Vec::new();
    if let Err(error) = socket.read_to_end(&mut response) {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(!response.starts_with(b"HTTP/1.1 200"));
    }
    response
}

fn finish_failed_gateway(server: thread::JoinHandle<Result<()>>, stop: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while !server.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let stopped_itself = server.is_finished();
    // Clean up even if a regression accidentally isolates uncertain state.
    stop.store(true, Ordering::Release);
    let result = server.join().unwrap();
    assert!(
        stopped_itself,
        "shared uncertainty must stop admission without an operator stop"
    );
    assert!(matches!(result, Err(NetError::Unavailable)));
}

#[test]
fn connection_local_panic_does_not_stop_legitimate_work_or_deadline_drain() {
    let (gateway, listener, upstream) = fixture(Duration::from_millis(200), false);
    let state = gateway.0.clone();
    let address = listener.local_addr().unwrap();
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let requests = AtomicUsize::new(0);
    let server = thread::spawn(move || {
        gateway.serve_with(
            listener,
            selected,
            move |state, stream, upstream_uncertain| {
                if requests.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("injected connection-local parser failure");
                }
                handle_tracked(state, stream, upstream_uncertain)
            },
        )
    });
    let failed = live_exchange(address, &raw);
    assert!(!failed.starts_with(b"HTTP/1.1 200"));
    let legitimate = live_exchange(address, &raw);
    assert!(legitimate.starts_with(b"HTTP/1.1 200"));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert!(!state.unhealthy.load(Ordering::Acquire));

    // Leave one admitted request incomplete. The same stop flag that the CLI
    // sets on SIGTERM/SIGINT drains it under its original request deadline.
    // This is core flag coverage, not an operating-system signal test.
    let mut stalled = TcpStream::connect(address).unwrap();
    stalled.write_all(b"GET / HTTP/1.1\r\n").unwrap();
    let wait_until = Instant::now() + Duration::from_secs(1);
    while state.budget.lock().unwrap().requests < 3 && Instant::now() < wait_until {
        thread::sleep(Duration::from_millis(5));
    }
    let admitted = state.budget.lock().unwrap().requests;
    let started = Instant::now();
    stop.store(true, Ordering::Release);
    let result = server.join().unwrap();
    assert_eq!(admitted, 3);
    assert!(started.elapsed() < Duration::from_secs(1));
    result.unwrap();
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn poisoned_shared_budget_stops_admission_and_preserves_failure() {
    let (gateway, listener, upstream) = fixture(Duration::from_millis(200), false);
    let state = gateway.0.clone();
    let address = listener.local_addr().unwrap();
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || {
        gateway.serve_with(listener, selected, |state, _stream, _upstream_uncertain| {
            let _budget = state.budget.lock().unwrap();
            panic!("injected shared-budget mutation failure");
        })
    });
    let failed = live_exchange(address, &raw);
    assert!(!failed.starts_with(b"HTTP/1.1 200"));
    finish_failed_gateway(server, &stop);
    assert!(state.budget.is_poisoned());
    assert!(state.unhealthy.load(Ordering::Acquire));
    assert!(matches!(admit(&state, 0, true), Err(NetError::Unavailable)));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn upstream_unwind_is_uncertain_even_when_gateway_budget_is_healthy() {
    struct PanickingUpstream;
    impl Upstream for PanickingUpstream {
        fn exchange(&self, _op: u8, _body: &[u8], _deadline: Instant) -> Result<Vec<u8>> {
            panic!("injected upstream state uncertainty");
        }
    }
    let (mut gateway, listener, _) = fixture(Duration::from_millis(200), false);
    Arc::get_mut(&mut gateway.0).unwrap().upstream = Arc::new(PanickingUpstream);
    let state = gateway.0.clone();
    let address = listener.local_addr().unwrap();
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, selected));
    assert!(!live_exchange(address, &raw).starts_with(b"HTTP/1.1 200"));
    finish_failed_gateway(server, &stop);
    assert!(!state.budget.is_poisoned());
    assert!(state.unhealthy.load(Ordering::Acquire));
    assert!(TcpStream::connect(address).is_err());
}

#[test]
fn unexpected_worker_unwind_outside_audited_boundary_stops_gateway() {
    struct FailingDrop;
    impl Drop for FailingDrop {
        fn drop(&mut self) {
            panic!("injected unexpected worker cleanup failure");
        }
    }
    let (gateway, listener, _) = fixture(Duration::from_millis(200), false);
    let address = listener.local_addr().unwrap();
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || {
        gateway.serve_with(
            listener,
            selected,
            |_state, _stream, _upstream_uncertain| {
                // The protected handler unwinds, then its opaque panic payload
                // itself panics during cleanup outside that audited boundary.
                std::panic::panic_any(FailingDrop);
            },
        )
    });
    assert!(!live_exchange(address, &raw).starts_with(b"HTTP/1.1 200"));
    finish_failed_gateway(server, &stop);
    assert!(TcpStream::connect(address).is_err());
}

fn browser_client(id: u8, secret: u8) -> BrowserClient {
    BrowserClient {
        id: [id; 16],
        capability: BrowserCapability::from_bytes([secret; 32]).unwrap(),
        expires_unix_secs: unix_now().unwrap() + 3600,
        revoked: false,
        max_inflight: 1,
        requests_per_window: 64,
        bytes_per_window: 1024 * 1024,
    }
}
fn https_fixture(
    timeout: Duration,
    clients: Vec<BrowserClient>,
) -> (Gateway, TcpListener, Arc<Fake>, Arc<rustls::ClientConfig>) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let issuer_key = KeyPair::generate().unwrap();
    let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    issuer.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let issuer = issuer.self_signed(&issuer_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf =
        CertificateParams::new(vec!["gateway.test".into(), "other.gateway.test".into()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf.signed_by(&key, &issuer, &issuer_key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let fake = Arc::new(Fake {
        calls: AtomicUsize::new(0),
        fail: false,
    });
    let settings = HttpsSettings {
        origin: HttpsOrigin::parse(&format!("https://gateway.test:{}", address.port())).unwrap(),
        certificate_chain: vec![leaf.der().to_vec()],
        private_key: key.serialize_der(),
        clients,
    };
    let gateway = Gateway::configured_https(
        address,
        RelayNamespace::from_bytes([9; 32]).unwrap(),
        settings,
        fake.clone(),
        Assets::new(BTreeMap::from([(
            "index.html".into(),
            b"verified UI".to_vec(),
        )]))
        .unwrap(),
        GatewayLimits {
            timeout,
            ..GatewayLimits::default()
        },
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    (gateway, listener, fake, Arc::new(client))
}
fn https_socket(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> StreamOwned<rustls::ClientConnection, TcpStream> {
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    StreamOwned::new(
        rustls::ClientConnection::new(
            config,
            rustls::pki_types::ServerName::try_from("gateway.test").unwrap(),
        )
        .unwrap(),
        socket,
    )
}
fn https_read(socket: &mut StreamOwned<rustls::ClientConnection, TcpStream>) -> Vec<u8> {
    let mut response = Vec::new();
    if let Err(error) = socket.read_to_end(&mut response) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "{error}"
        );
        assert!(
            !response.starts_with(b"HTTP/1.1 200"),
            "successful responses must finish TLS cleanly"
        );
    }
    response
}
fn https_exchange(
    gateway: Gateway,
    listener: TcpListener,
    config: Arc<rustls::ClientConfig>,
    raw: &[u8],
) -> Vec<u8> {
    let address = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let _ = handle(&gateway.0, socket);
    });
    let mut socket = https_socket(address, config);
    socket.write_all(raw).unwrap();
    socket.flush().unwrap();
    let response = https_read(&mut socket);
    worker.join().unwrap();
    response
}
#[test]
fn https_serves_verified_assets_and_authenticated_same_origin_relay_frames() {
    for asset in [false, true] {
        let (gateway, listener, fake, config) =
            https_fixture(Duration::from_secs(2), vec![browser_client(1, 8)]);
        let raw = if asset {
            format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", gateway.0.host).into_bytes()
        } else {
            request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()))
        };
        let response = https_exchange(gateway, listener, config, &raw);
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert_eq!(fake.calls.load(Ordering::SeqCst), usize::from(!asset));
        if asset {
            assert!(response.ends_with(b"verified UI"));
        }
    }
}
#[test]
fn https_wrong_host_origin_capability_namespace_and_proxy_headers_never_dial() {
    for change in 0..7 {
        let (gateway, listener, fake, config) =
            https_fixture(Duration::from_secs(2), vec![browser_client(1, 8)]);
        let body = frame(OP_PAGE, &page_request(0, 1).unwrap());
        let raw = request(&gateway, &body);
        let split = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
        let mut header = String::from_utf8(raw[..split].to_vec()).unwrap();
        match change {
            0 => {
                header = header.replace(&format!("Host: {}", gateway.0.host), "Host: attacker.test")
            }
            1 => {
                header = header.replace(
                    &format!("Origin: {}", gateway.origin()),
                    "Origin: https://attacker.test",
                )
            }
            2 => header = header.replace(&"08".repeat(32), &"07".repeat(32)),
            3 => header = header.replace(&"09".repeat(32), &"07".repeat(32)),
            4 => header.push_str("\r\nForwarded: proto=https;host=gateway.test"),
            5 => header.push_str("\r\nX-Forwarded-Proto: https"),
            _ => header = header.replace(&format!("Origin: {}\r\n", gateway.origin()), ""),
        }
        let response = https_exchange(
            gateway,
            listener,
            config,
            &[header.as_bytes(), b"\r\n\r\n", &body].concat(),
        );
        assert!(response.starts_with(b"HTTP/1.1 403"), "change {change}");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn https_plaintext_missing_alpn_and_untrusted_certificate_never_reach_http_or_upstream() {
    for mode in 0..3 {
        let (gateway, listener, fake, config) =
            https_fixture(Duration::from_millis(200), vec![browser_client(1, 8)]);
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle(&gateway.0, socket)
        });
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if mode == 0 {
            socket
                .write_all(b"GET / HTTP/1.1\r\nHost: gateway.test\r\n\r\n")
                .unwrap();
            let mut response = Vec::new();
            let _ = socket.read_to_end(&mut response);
            assert!(!response.windows(5).any(|part| part == b"HTTP/"));
        } else {
            let mut config = (*config).clone();
            if mode == 1 {
                config.alpn_protocols.clear();
            } else {
                config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
            let mut tls = StreamOwned::new(
                rustls::ClientConnection::new(
                    Arc::new(config),
                    rustls::pki_types::ServerName::try_from("gateway.test").unwrap(),
                )
                .unwrap(),
                socket,
            );
            let sent = tls.write_all(b"GET / HTTP/1.1\r\nHost: gateway.test\r\n\r\n");
            let mut response = Vec::new();
            let read = tls.read_to_end(&mut response);
            assert!(sent.is_err() || read.is_err() || response.is_empty());
            assert!(!response.starts_with(b"HTTP/1.1 200"));
        }
        assert!(worker.join().unwrap().is_err());
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn https_stalled_handshake_has_one_absolute_deadline_and_drains() {
    let (gateway, listener, fake, _) =
        https_fixture(Duration::from_millis(80), vec![browser_client(1, 8)]);
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let state = gateway.0.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, selected));
    let _held = TcpStream::connect(address).unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while state.budget.lock().unwrap().requests == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(state.budget.lock().unwrap().requests, 1);
    let start = Instant::now();
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert!(TcpStream::connect(address).is_err());
}
#[test]
fn hosted_client_expiry_revocation_and_rate_limits_are_independent() {
    let mut revoked = browser_client(1, 8);
    revoked.revoked = true;
    let mut expired = browser_client(2, 7);
    expired.expires_unix_secs = 0;
    let mut limited = browser_client(3, 6);
    limited.requests_per_window = 1;
    let (gateway, _, _, _) = https_fixture(
        Duration::from_secs(2),
        vec![revoked, expired, limited, browser_client(4, 5)],
    );
    for key in [8, 7] {
        let token = format!("{key:02x}").repeat(32);
        assert!(matches!(
            authorize(&gateway.0, Some(&format!("Bearer {token}"))).unwrap(),
            Authorized::Denied
        ));
    }
    let limited = format!("Bearer {}", "06".repeat(32));
    let Authorized::Allowed(Some(first)) = authorize(&gateway.0, Some(&limited)).unwrap() else {
        panic!("valid client refused")
    };
    assert!(matches!(
        authorize(&gateway.0, Some(&limited)).unwrap(),
        Authorized::Busy
    ));
    drop(first);
    assert!(matches!(
        authorize(&gateway.0, Some(&limited)).unwrap(),
        Authorized::Busy
    ));
    assert!(matches!(
        authorize(&gateway.0, Some(&format!("Bearer {}", "05".repeat(32)))).unwrap(),
        Authorized::Allowed(Some(_))
    ));
}
#[test]
fn https_rechecks_expiry_after_slow_body_before_upstream_and_keeps_charges() {
    let (gateway, listener, fake, config) =
        https_fixture(Duration::from_secs(2), vec![browser_client(1, 8)]);
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let split = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
    let address = listener.local_addr().unwrap();
    let state = gateway.0.clone();
    let worker = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        handle(&gateway.0, socket)
    });
    let mut socket = https_socket(address, config);
    socket.write_all(&raw[..split]).unwrap();
    socket.flush().unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        let mut clients = state.hosted.as_ref().unwrap().clients.lock().unwrap();
        if clients[0].inflight == 1 {
            clients[0].expires = Some(Instant::now());
            break;
        }
        drop(clients);
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(2));
    }
    socket.write_all(&raw[split..]).unwrap();
    socket.flush().unwrap();
    assert!(https_read(&mut socket).starts_with(b"HTTP/1.1 403"));
    worker.join().unwrap().unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    let clients = state.hosted.as_ref().unwrap().clients.lock().unwrap();
    assert!(clients[0].disabled);
    assert_eq!(clients[0].budget.requests, 1);
    assert!(clients[0].budget.bytes > 0);
    assert_eq!(clients[0].inflight, 0);
}
#[test]
fn https_shutdown_drains_admitted_body_without_reissuing_or_renewing_authority() {
    let (gateway, listener, fake, config) =
        https_fixture(Duration::from_secs(2), vec![browser_client(1, 8)]);
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let split = raw.len() - 1;
    let address = listener.local_addr().unwrap();
    let state = gateway.0.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, selected));
    let mut socket = https_socket(address, config);
    socket.write_all(&raw[..split]).unwrap();
    socket.flush().unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while state.hosted.as_ref().unwrap().clients.lock().unwrap()[0].inflight == 0 {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(2));
    }
    stop.store(true, Ordering::Release);
    socket.write_all(&raw[split..]).unwrap();
    socket.flush().unwrap();
    assert!(https_read(&mut socket).starts_with(b"HTTP/1.1 200"));
    server.join().unwrap().unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert!(TcpStream::connect(address).is_err());
    let clients = state.hosted.as_ref().unwrap().clients.lock().unwrap();
    assert_eq!(clients[0].inflight, 0);
    assert_eq!(clients[0].budget.requests, 1);
}

#[test]
fn https_authenticated_request_and_byte_budgets_refuse_before_another_upstream_effect() {
    let mut first = browser_client(1, 8);
    first.requests_per_window = 1;
    let mut second = browser_client(2, 6);
    second.bytes_per_window = 31;
    let (gateway, listener, fake, config) = https_fixture(
        Duration::from_secs(2),
        vec![first, second, browser_client(3, 5)],
    );
    let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, selected));
    for (key, status) in [(8, 200), (8, 429), (6, 200), (6, 429), (5, 200)] {
        let token = format!("{key:02x}").repeat(32);
        let bytes = String::from_utf8(raw[..raw.len() - 15].to_vec())
            .unwrap()
            .replace(&"08".repeat(32), &token)
            .into_bytes();
        let request = [bytes, raw[raw.len() - 15..].to_vec()].concat();
        let mut socket = https_socket(address, config.clone());
        socket.write_all(&request).unwrap();
        socket.flush().unwrap();
        let response = https_read(&mut socket);
        assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
    }
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn https_wrong_or_missing_sni_refuses_even_a_trusted_certificate_and_exact_http_host() {
    for missing in [false, true] {
        let (gateway, listener, fake, config) =
            https_fixture(Duration::from_secs(2), vec![browser_client(1, 8)]);
        let raw = request(&gateway, &frame(OP_PAGE, &page_request(0, 1).unwrap()));
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            handle(&gateway.0, socket)
        });
        let mut config = (*config).clone();
        config.enable_sni = !missing;
        let name = if missing {
            "gateway.test"
        } else {
            "other.gateway.test"
        };
        let mut socket = https_socket(address, Arc::new(config.clone()));
        socket.conn = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from(name).unwrap(),
        )
        .unwrap();
        // The synthetic certificate covers both names. Verification stays on;
        // the server's exact SNI check must refuse before any HTTP response.
        while socket.conn.is_handshaking() {
            socket.conn.complete_io(&mut socket.sock).unwrap();
        }
        let _ = socket.write_all(&raw);
        let _ = socket.flush();
        assert!(https_read(&mut socket).is_empty());
        assert_eq!(worker.join().unwrap(), Err(NetError::Scope));
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn hosted_inflight_release_restores_only_that_clients_concurrency_slot() {
    let (gateway, _, _, _) = https_fixture(
        Duration::from_secs(2),
        vec![browser_client(1, 8), browser_client(2, 7)],
    );
    let first = format!("Bearer {}", "08".repeat(32));
    let second = format!("Bearer {}", "07".repeat(32));
    let Authorized::Allowed(Some(held)) = authorize(&gateway.0, Some(&first)).unwrap() else {
        panic!("first client refused")
    };
    assert!(matches!(
        authorize(&gateway.0, Some(&first)).unwrap(),
        Authorized::Busy
    ));
    let Authorized::Allowed(Some(other)) = authorize(&gateway.0, Some(&second)).unwrap() else {
        panic!("another client's slot was affected")
    };
    drop(held);
    let Authorized::Allowed(Some(recovered)) = authorize(&gateway.0, Some(&first)).unwrap() else {
        panic!("released slot was not reusable")
    };
    assert!(matches!(
        authorize(&gateway.0, Some(&second)).unwrap(),
        Authorized::Busy
    ));
    drop(recovered);
    drop(other);
    let clients = gateway.0.hosted.as_ref().unwrap().clients.lock().unwrap();
    assert_eq!((clients[0].inflight, clients[1].inflight), (0, 0));
    assert_eq!(
        (clients[0].budget.requests, clients[1].budget.requests),
        (2, 1)
    );
}

#[test]
fn https_reply_budget_refusal_after_put_has_no_receipt_and_preserves_request_charge() {
    use vhalla_private_kernel::{OperationId, OutboxKind};
    let item = RelayItem::new(
        RelayNamespace::from_bytes([9; 32]).unwrap(),
        1,
        OperationId::from_bytes([3; 16]).unwrap(),
        OutboxKind::Application,
        b"ciphertext",
    )
    .unwrap();
    let body = frame(OP_PUT, &item.encode().unwrap());
    let mut limited = browser_client(1, 8);
    limited.bytes_per_window = body.len();
    let (gateway, listener, fake, config) =
        https_fixture(Duration::from_secs(2), vec![limited, browser_client(2, 7)]);
    let raw = request(&gateway, &body);
    let split = raw.len() - body.len();
    let state = gateway.0.clone();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let selected = stop.clone();
    let server = thread::spawn(move || gateway.serve_until(listener, selected));
    for (key, status, calls) in [(8, 429, 1), (8, 429, 1), (7, 200, 2)] {
        let token = format!("{key:02x}").repeat(32);
        let header = String::from_utf8(raw[..split].to_vec())
            .unwrap()
            .replace(&"08".repeat(32), &token);
        let request = [header.as_bytes(), &body].concat();
        let mut socket = https_socket(address, config.clone());
        socket.write_all(&request).unwrap();
        socket.flush().unwrap();
        let response = https_read(&mut socket);
        assert!(response.starts_with(format!("HTTP/1.1 {status}").as_bytes()));
        let start = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
        if status == 429 {
            assert_eq!(&response[start..], b"temporarily unavailable");
        } else {
            let (status, bytes) = decode_frame(&response[start..], MAX_RESPONSE).unwrap();
            assert_eq!(
                decode_receipt(&decode_status(status, bytes).unwrap(), &item)
                    .unwrap()
                    .position,
                7
            );
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), calls);
        let clients = state.hosted.as_ref().unwrap().clients.lock().unwrap();
        assert_eq!(clients[0].budget.bytes, body.len());
        assert_eq!(clients[0].inflight, 0);
    }
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    let clients = state.hosted.as_ref().unwrap().clients.lock().unwrap();
    assert_eq!(clients[0].budget.requests, 2);
    assert_eq!(clients[1].budget.requests, 1);
}
