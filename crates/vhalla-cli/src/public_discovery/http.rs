//! System curl transport for explicitly selected public routes only.
//! No shell, temporary files, redirects, inherited proxy/configuration or keys.
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use vhalla_public_protocol::{
    activity::{
        ActivityKind, ActivityRequest, MAX_ACTIVITY_PAGE_BYTES, MAX_ACTIVITY_PROOF_BYTES,
        RECEIPT_BYTES,
    },
    discovery::{DiscoveryKind, DiscoveryRequest, MAX_REGISTRATION_BYTES},
    response::{ReadKind, ReadRequest, MAX_RESPONSE_PROOF_BYTES},
    Endpoint, MAX_ADVERTISEMENT_BYTES,
};
use vhalla_room_activity::SignedEvent;

#[path = "dns.rs"]
mod dns;

pub(super) fn resolve_child(args: &[std::ffi::OsString]) -> Result<(), String> {
    dns::child(args)
}

const CURL: &str = "/usr/bin/curl";
const MAX_HEADERS: usize = 8192;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(18);

fn command() -> Command {
    let mut command = Command::new(CURL);
    // --disable MUST be first: suppress ~/.curlrc and every implicit option.
    command.env_clear().arg("--disable");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn run(
    mut command: Command,
    body: Option<&[u8]>,
    limit: usize,
    duration: Duration,
    cancel: &AtomicBool,
    operation: &str,
) -> Result<Vec<u8>, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err(format!("{operation} request cancelled"));
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("{operation} subprocess unavailable: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("curl stdin unavailable")?;
    let input = body.unwrap_or_default().to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let stdout = child.stdout.take().ok_or("curl stdout unavailable")?;
    let oversized = Arc::new(AtomicBool::new(false));
    let overflow = oversized.clone();
    let reader = std::thread::spawn(move || {
        let mut raw = Vec::new();
        let result = stdout.take(limit as u64 + 1).read_to_end(&mut raw);
        if raw.len() > limit {
            overflow.store(true, Ordering::Relaxed);
        }
        result.map(|_| raw)
    });
    let deadline = Instant::now() + duration;
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err(format!("{operation} request cancelled"));
        }
        if oversized.load(Ordering::Relaxed) {
            break Err(format!("{operation} response exceeded byte limit"));
        }
        if Instant::now() >= deadline {
            break Err(format!("{operation} command deadline exceeded"));
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(status)) => {
                break Err(format!(
                    "{operation} request failed ({status}); no authenticated receipt"
                ))
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => break Err(format!("{operation} process check: {error}")),
        }
    };
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    let wrote = writer.join().map_err(|_| "curl input worker failed")?;
    let raw = reader
        .join()
        .map_err(|_| "curl output worker failed")?
        .map_err(|e| format!("curl output: {e}"))?;
    result?;
    wrote.map_err(|e| format!("curl request input: {e}"))?;
    if raw.len() > limit {
        return Err("curl response exceeded byte limit".into());
    }
    Ok(raw)
}

pub(in crate::public_network) fn preflight() -> Result<(), String> {
    let mut command = command();
    command.arg("--version");
    let raw = run(
        command,
        None,
        8192,
        Duration::from_secs(3),
        &AtomicBool::new(false),
        "curl",
    )?;
    let text = std::str::from_utf8(&raw).map_err(|_| "invalid system curl version output")?;
    // Multiple pinned addresses in --resolve require curl >=7.59.0.
    let version = text.split_ascii_whitespace().nth(1).and_then(|s| {
        s.split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .ok()
    });
    if !text.starts_with("curl ")
        || !version.is_some_and(|v| v.len() == 3 && (v[0], v[1], v[2]) >= (7, 59, 0))
        || !text.lines().any(|line| {
            line.strip_prefix("Protocols:")
                .is_some_and(|line| line.split_ascii_whitespace().any(|p| p == "https"))
        })
    {
        return Err(
            "/usr/bin/curl >=7.59.0 with HTTPS support is required for selected public peer requests"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn exchange(
    endpoint: &Endpoint,
    target: &str,
    body: Option<&[u8]>,
    max_body: usize,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, String), String> {
    // Advertisement refresh uses the canonical base `/vhalla/v1?nonce=...`;
    // all other routes are accepted only through their exact typed decoders.
    let valid = if let Some(body) = body {
        body.len() <= MAX_REGISTRATION_BYTES
            && DiscoveryRequest::parse_target(target).is_ok_and(|request| {
                matches!(request.kind(), DiscoveryKind::Register { .. })
                    && request.check_body(body).is_ok()
            })
    } else {
        ReadRequest::parse_target(target).is_ok()
            || DiscoveryRequest::parse_target(target)
                .is_ok_and(|request| !matches!(request.kind(), DiscoveryKind::Register { .. }))
    };
    if !valid {
        return Err("invalid bounded discovery transport request".into());
    }
    exchange_bounded(endpoint, target, body, max_body, 1024, cancel)
}

/// Transport only: the caller must authenticate the returned proof against its
/// independently pinned network, full peer key and exact request before using
/// the body. A successful HTTP response is not a saved delivery receipt.
pub(in crate::public_network) fn exchange_activity(
    endpoint: &Endpoint,
    request: &ActivityRequest,
    body: Option<&[u8]>,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, String), String> {
    let max_body = match (request.kind(), body) {
        (ActivityKind::Post { .. }, Some(body)) => {
            request
                .check_body(body)
                .map_err(|_| "activity POST differs from the exact bounded request body")?;
            let event = SignedEvent::decode(body)
                .and_then(SignedEvent::verify)
                .map_err(|_| {
                    "activity POST requires one canonical strictly verified signed event"
                })?;
            if event.claims().scope.room.as_bytes() != &request.room() {
                return Err("activity POST room differs from its signed event".into());
            }
            RECEIPT_BYTES
        }
        (ActivityKind::Page { .. }, None) => MAX_ACTIVITY_PAGE_BYTES,
        _ => return Err("activity POST requires a body and activity Page forbids one".into()),
    };
    // Construct the route from its immutable typed request; no arbitrary target
    // or caller-selected response ceiling enters the common curl path.
    exchange_bounded(
        endpoint,
        &request.target(),
        body,
        max_body,
        MAX_ACTIVITY_PROOF_BYTES * 2,
        cancel,
    )
}

/// Canonical selected-author continuity transport only. This never installs a
/// receipt; callers verify the exact peer/request/body and publish it durably.
pub(in crate::public_network) fn exchange_continuity(
    endpoint: &Endpoint,
    request: &vhalla_public_protocol::continuity::Request,
    body: Option<&[u8]>,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, String), String> {
    let bound = continuity_bound(request, body)?;
    exchange_bounded(
        endpoint,
        &request.target(),
        body,
        bound,
        vhalla_public_protocol::continuity::MAX_PROOF_BYTES * 2,
        cancel,
    )
}
fn continuity_bound(
    request: &vhalla_public_protocol::continuity::Request,
    body: Option<&[u8]>,
) -> Result<usize, String> {
    use vhalla_public_protocol::continuity::{Kind, MAX_REPLY_BYTES};
    match (request.kind(), body) {
        (Kind::Stage { .. } | Kind::Commit { .. }, Some(raw)) => {
            request.check_body(raw).map_err(|_| "continuity body differs from exact typed request")?;
        }
        (Kind::Status { .. } | Kind::Evidence { .. }, None) => (),
        _ => return Err("continuity mutations require exact bodies; author reads forbid bodies; room feed is outside this controller".into()),
    }
    Ok(MAX_REPLY_BYTES)
}
#[cfg(test)]
#[path = "http_continuity_tests.rs"]
mod continuity_tests;

/// Refresh only a typed advertisement request at the selected route.
/// The caller must verify the full pinned peer and retain its newer floor.
pub(in crate::public_network) fn exchange_advertisement(
    endpoint: &Endpoint,
    request: &ReadRequest,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, String), String> {
    if request.kind() != ReadKind::Advertisement {
        return Err("selected-peer refresh requires an advertisement request".into());
    }
    exchange_bounded(
        endpoint,
        &request.target(),
        None,
        MAX_ADVERTISEMENT_BYTES,
        MAX_RESPONSE_PROOF_BYTES * 2,
        cancel,
    )
}

fn exchange_bounded(
    endpoint: &Endpoint,
    target: &str,
    body: Option<&[u8]>,
    max_body: usize,
    max_proof: usize,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, String), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("curl request cancelled".into());
    }
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let addresses = dns::resolve(endpoint, cancel, COMMAND_TIMEOUT)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("selected-seed request deadline exceeded".into());
    }
    let command = request_command(
        endpoint,
        target,
        body.is_some(),
        max_body,
        &addresses,
        remaining,
    )?;
    let raw = run(
        command,
        body,
        MAX_HEADERS + max_body,
        deadline.saturating_duration_since(Instant::now()),
        cancel,
        "curl",
    )?;
    parse_response_with_limit(&raw, max_body, max_proof)
}

fn request_command(
    endpoint: &Endpoint,
    target: &str,
    has_body: bool,
    max_body: usize,
    addresses: &[std::net::IpAddr],
    remaining: Duration,
) -> Result<Command, String> {
    let origin = endpoint
        .as_str()
        .strip_suffix("/vhalla/v1")
        .ok_or("invalid selected seed route")?;
    let url = format!("{origin}{target}");
    let mut command = command();
    dns::pin(&mut command, endpoint, addresses)?;
    command.args([
        "--silent",
        "--globoff",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-redirs",
        "0",
        "--proxy",
        "",
        "--noproxy",
        "*",
        "--http1.1",
        "--connect-timeout",
        "5",
        "--max-time",
    ]);
    command.arg(format!(
        "{:.3}",
        remaining
            .min(Duration::from_secs(15))
            .as_secs_f64()
            .max(0.001)
    ));
    command.args(["--include", "--max-filesize"]);
    command.arg(max_body.to_string());
    command.args([
        "--header",
        "Accept: application/octet-stream",
        "--header",
        "Expect:",
    ]);
    if has_body {
        command.args([
            "--request",
            "POST",
            "--header",
            "Content-Type: application/octet-stream",
            "--data-binary",
            "@-",
        ]);
    } else {
        command.args(["--request", "GET"]);
    }
    command.arg("--url").arg(url);
    Ok(command)
}

#[cfg(test)]
fn parse_response(raw: &[u8], max_body: usize) -> Result<(Vec<u8>, String), String> {
    parse_response_with_limit(raw, max_body, 1024)
}

fn parse_response_with_limit(
    raw: &[u8],
    max_body: usize,
    max_proof: usize,
) -> Result<(Vec<u8>, String), String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing bounded HTTP headers")?;
    if split + 4 > MAX_HEADERS || raw.len() - split - 4 > max_body {
        return Err("HTTP header/body limit exceeded".into());
    }
    let headers = std::str::from_utf8(&raw[..split]).map_err(|_| "HTTP headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or("missing HTTP status")?;
    let mut fields = status.split_ascii_whitespace();
    if fields.next() != Some("HTTP/1.1") || fields.next() != Some("200") {
        return Err("selected seed did not return HTTP/1.1 200; no authenticated receipt".into());
    }
    let mut proof = None;
    let mut content = None;
    let mut length = None;
    let mut transfer = None;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err("folded HTTP header refused".into());
        }
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-vhalla-proof") {
            if proof.replace(value).is_some() {
                return Err("duplicate proof header".into());
            }
        } else if name.eq_ignore_ascii_case("content-type") {
            if content.replace(value).is_some() {
                return Err("duplicate content type".into());
            }
        } else if name.eq_ignore_ascii_case("content-length") {
            if length.replace(value).is_some() {
                return Err("duplicate content length".into());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer.replace(value).is_some() {
                return Err("duplicate transfer encoding".into());
            }
        } else if name.eq_ignore_ascii_case("content-encoding") {
            return Err("encoded response refused".into());
        }
    }
    if content != Some("application/octet-stream") {
        return Err("unexpected response content type".into());
    }
    let body = &raw[split + 4..];
    if let Some(length) = length {
        let count = length
            .parse::<usize>()
            .map_err(|_| "invalid content length")?;
        if count.to_string() != length || count != body.len() || transfer.is_some() {
            return Err("response length mismatch".into());
        }
    }
    // curl removes chunk framing; the independent decoded body bound above still
    // applies even with an absent/false Content-Length or chunked transport.
    if transfer.is_some_and(|encoding| encoding != "chunked") {
        return Err("unsupported transfer encoding".into());
    }
    let proof = proof.ok_or("missing signed response proof")?;
    if proof.len() > max_proof || proof.is_empty() {
        return Err("response proof header exceeds limit".into());
    }
    Ok((body.to_vec(), proof.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activity_frame() -> Vec<u8> {
        use vhalla_core::RealmId;
        use vhalla_room_activity::{Content, EventClaims, EventId, RoomScope, Text, UnsignedEvent};
        use vhalla_rooms::{DirectoryId, RoomGenesisId, RoomRecordId};
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        UnsignedEvent::new(EventClaims {
            scope: RoomScope {
                network: [7; 32],
                realm: RealmId(77),
                directory: DirectoryId::from_bytes([5; 32]),
                room: RoomGenesisId::from_bytes([8; 32]),
            },
            policy: RoomRecordId::from_bytes([9; 32]),
            author: key.verifying_key().to_bytes(),
            sequence: 1,
            previous: EventId::ZERO,
            created_at: 1234,
            content: Content::Text(Text::new("retained native outbox event").unwrap()),
        })
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .encode()
    }

    #[test]
    fn activity_http_typed_post_and_page_reach_cancellation_without_network() {
        let endpoint = Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap();
        let raw = activity_frame();
        let post = ActivityRequest::post([1; 32], [8; 32], &raw).unwrap();
        let page = ActivityRequest::page([2; 32], [8; 32], 19, 16).unwrap();
        let cancel = AtomicBool::new(true);
        for (request, body) in [(&post, Some(raw.as_slice())), (&page, None)] {
            assert_eq!(
                exchange_activity(&endpoint, request, body, &cancel).unwrap_err(),
                "curl request cancelled"
            );
            // Adding activity did not broaden the existing discovery allowlist.
            assert_eq!(
                exchange(&endpoint, &request.target(), body, 4096, &cancel).unwrap_err(),
                "invalid bounded discovery transport request"
            );
        }
        assert!(exchange_activity(&endpoint, &post, None, &cancel).is_err());
        for body in [b"".as_slice(), raw.as_slice()] {
            assert_eq!(
                exchange_activity(&endpoint, &page, Some(body), &cancel).unwrap_err(),
                "activity POST requires a body and activity Page forbids one"
            );
        }
    }

    #[test]
    fn activity_http_rejects_changed_malformed_or_foreign_room_signed_bodies() {
        let endpoint = Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap();
        let raw = activity_frame();
        let post = ActivityRequest::post([1; 32], [8; 32], &raw).unwrap();
        let cancel = AtomicBool::new(true);
        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut trailing = raw.clone();
        trailing.push(0);
        for malformed in [tampered, trailing, raw[..raw.len() - 1].to_vec()] {
            assert_eq!(
                exchange_activity(&endpoint, &post, Some(&malformed), &cancel).unwrap_err(),
                "activity POST differs from the exact bounded request body"
            );
            // Recommitting malformed bytes does not bypass canonical/signature
            // checks merely because the POST's body hash now matches.
            let request = ActivityRequest::post([3; 32], [8; 32], &malformed).unwrap();
            assert_eq!(
                exchange_activity(&endpoint, &request, Some(&malformed), &cancel).unwrap_err(),
                "activity POST requires one canonical strictly verified signed event"
            );
        }
        let oversized = vec![0; vhalla_room_activity::MAX_EVENT_BYTES + 1];
        assert_eq!(
            exchange_activity(&endpoint, &post, Some(&oversized), &cancel).unwrap_err(),
            "activity POST differs from the exact bounded request body"
        );
        let foreign = ActivityRequest::post([4; 32], [99; 32], &raw).unwrap();
        assert_eq!(
            exchange_activity(&endpoint, &foreign, Some(&raw), &cancel).unwrap_err(),
            "activity POST room differs from its signed event"
        );
    }

    #[test]
    fn activity_http_response_proof_and_body_have_protocol_specific_ceilings() {
        let proof_limit = MAX_ACTIVITY_PROOF_BYTES * 2;
        fn response(proof: &str, body: &[u8]) -> Vec<u8> {
            let mut raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Vhalla-Proof: {proof}\r\n\r\n"
            )
            .into_bytes();
            raw.extend_from_slice(body);
            raw
        }
        // The transport bounds headers only; strict proof verification remains
        // mandatory in the controller before interpreting these untrusted bytes.
        let proof = "a".repeat(proof_limit);
        let body = vec![0; RECEIPT_BYTES];
        let raw = response(&proof, &body);
        assert_eq!(
            parse_response_with_limit(&raw, RECEIPT_BYTES, proof_limit).unwrap(),
            (body, proof)
        );
        assert!(parse_response_with_limit(
            &response(&"a".repeat(proof_limit + 1), b""),
            RECEIPT_BYTES,
            proof_limit
        )
        .is_err());
        assert!(parse_response_with_limit(
            &response("ab", &[0; RECEIPT_BYTES + 1]),
            RECEIPT_BYTES,
            proof_limit
        )
        .is_err());
        assert!(parse_response_with_limit(
            &response("ab", &vec![0; MAX_ACTIVITY_PAGE_BYTES + 1]),
            MAX_ACTIVITY_PAGE_BYTES,
            proof_limit
        )
        .is_err());
    }

    #[test]
    fn discovery_http_accepts_canonical_base_refresh_before_starting_transport() {
        use vhalla_public_protocol::response::ReadKind;
        let endpoint = Endpoint::parse("https://seed.vhalla.dev:443/vhalla/v1").unwrap();
        let request = ReadRequest::new([7; 32], ReadKind::Advertisement).unwrap();
        let cancelled = AtomicBool::new(true);
        // The actual exchange gate must accept the base route, then reach the
        // cancellation boundary without starting curl or dialing any host.
        assert_eq!(
            exchange(&endpoint, &request.target(), None, 4096, &cancelled).unwrap_err(),
            "curl request cancelled"
        );
        for target in [
            request.target().replace("/vhalla/v1?", "/vhalla/v1/?"),
            request.target().replace("nonce=", "other="),
        ] {
            assert_eq!(
                exchange(&endpoint, &target, None, 4096, &cancelled).unwrap_err(),
                "invalid bounded discovery transport request"
            );
        }
        assert_eq!(
            exchange(
                &endpoint,
                &request.target(),
                Some(b"body"),
                4096,
                &cancelled
            )
            .unwrap_err(),
            "invalid bounded discovery transport request"
        );
    }
    #[test]
    fn discovery_http_response_bounds_apply_without_content_length() {
        let base = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nX-Vhalla-Proof: ab\r\n\r\nabc";
        assert_eq!(
            parse_response(base, 3).unwrap(),
            (b"abc".to_vec(), "ab".into())
        );
        assert!(parse_response(base, 2).is_err());
        let mut huge = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        huge.extend_from_slice(&vec![b'x'; MAX_HEADERS]);
        huge.extend_from_slice(b"\r\n\r\n");
        assert!(parse_response(&huge, 3).is_err());
    }
    #[test]
    fn discovery_http_ambiguous_or_redirected_replies_are_refused() {
        for header in [
            "Content-Length: 03\r\n",
            "Content-Length: 2\r\n",
            "Content-Length: 3\r\nContent-Length: 3\r\n",
            "Content-Encoding: gzip\r\n",
            "X-Vhalla-Proof: cd\r\n",
            " bad: folded\r\n",
        ] {
            let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Vhalla-Proof: ab\r\n{header}\r\nabc");
            assert!(parse_response(raw.as_bytes(), 3).is_err(), "{header}");
        }
        assert!(parse_response(
            b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example\r\n\r\n",
            20
        )
        .is_err());
        let command = command();
        assert_eq!(command.get_program(), CURL);
        assert_eq!(command.get_args().next().unwrap(), "--disable");
    }
    #[test]
    fn discovery_system_curl_preflight_is_bounded_and_cancel_is_immediate() {
        preflight().unwrap();
        let mut command = command();
        command.arg("--version");
        assert!(run(
            command,
            None,
            8192,
            Duration::from_secs(1),
            &AtomicBool::new(true),
            "curl",
        )
        .is_err());
    }

    #[test]
    fn discovery_http_pinned_argv_preserves_tls_hostname_and_one_deadline() {
        use vhalla_public_protocol::response::ReadKind;
        let endpoint = Endpoint::parse("https://seed.vhalla.dev:8443/vhalla/v1").unwrap();
        let request = ReadRequest::new([9; 32], ReadKind::Advertisement).unwrap();
        let command = request_command(
            &endpoint,
            &request.target(),
            false,
            4096,
            &["8.8.8.8".parse().unwrap()],
            Duration::from_millis(2500),
        )
        .unwrap();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(args[0], "--disable");
        for pair in [
            ["--resolve", "seed.vhalla.dev:8443:8.8.8.8"],
            ["--proto", "=https"],
            ["--max-redirs", "0"],
            ["--proxy", ""],
            ["--noproxy", "*"],
            ["--max-time", "2.500"],
        ] {
            assert!(args.windows(2).any(|actual| actual == pair));
        }
        assert_eq!(args[args.len() - 2], "--url");
        assert_eq!(
            args[args.len() - 1],
            format!("https://seed.vhalla.dev:8443{}", request.target())
        );
        assert!(!args.iter().any(|arg| [
            "--insecure",
            "-k",
            "--location",
            "--connect-to",
            "--alt-svc",
            "--retry"
        ]
        .contains(arg)));
        assert_eq!(command.get_envs().count(), 0);
    }

    #[test]
    fn discovery_resolver_custody_deadline_and_cancellation_reap_before_return() {
        // A deterministic blocking child with no DNS or socket calls exercises
        // the same supervisor that contains a stuck system resolver. run kills,
        // waits and joins both pipe workers before returning an error.
        fn sleeper() -> Command {
            let mut command = Command::new("/bin/sleep");
            command
                .env_clear()
                .arg("5")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            command
        }
        let started = Instant::now();
        let error = run(
            sleeper(),
            None,
            640,
            Duration::from_millis(50),
            &AtomicBool::new(false),
            "DNS resolver",
        )
        .unwrap_err();
        assert_eq!(error, "DNS resolver command deadline exceeded");
        assert!(started.elapsed() < Duration::from_secs(2));
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            worker_cancel.store(true, Ordering::Relaxed);
        });
        let error = run(
            sleeper(),
            None,
            640,
            Duration::from_secs(2),
            &cancel,
            "DNS resolver",
        )
        .unwrap_err();
        setter.join().unwrap();
        assert_eq!(error, "DNS resolver request cancelled");
        // Overflow also terminates its child without retaining a reader worker.
        let mut command = Command::new("/usr/bin/printf");
        command
            .env_clear()
            .arg("oversized")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        assert!(run(
            command,
            None,
            2,
            Duration::from_secs(1),
            &AtomicBool::new(false),
            "DNS resolver"
        )
        .is_err());
    }
}
