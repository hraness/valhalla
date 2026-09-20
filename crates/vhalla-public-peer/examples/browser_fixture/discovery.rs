//! Bounded real-HTTP discovery seeding for the local, freshly generated fixture.
//! All socket addresses and Host values are fixed test routes, never network hints.
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_public_peer::ManagedPeer;
use vhalla_public_protocol::discovery::{
    proof_from_hex, DiscoveryKind, DiscoveryRequest, PeerPage, RegistrationChallenge,
    RegistrationReceipt, MAX_PEER_PAGE_BYTES, MAX_REGISTRATION_BYTES, MAX_SOLVE_ATTEMPTS,
    REGISTRATION_CHALLENGE_BYTES, REGISTRATION_RECEIPT_BYTES,
};

fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(debug)
}
fn nonce() -> Result<[u8; 32], String> {
    let mut raw = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(debug)?;
    if raw == [0; 32] {
        return Err("zero fixture request nonce".into());
    }
    Ok(raw)
}

fn exchange(
    receiver: &ManagedPeer,
    route: usize,
    request: DiscoveryRequest,
    body: Option<&[u8]>,
    bound: usize,
) -> Result<Vec<u8>, String> {
    let (address, host) = match route {
        0 => ("127.0.0.1:9781", "peer-a.vhalla.dev:443"),
        1 => ("127.0.0.1:9782", "peer-b.vhalla.dev:443"),
        _ => return Err("fixture route outside fixed loopback pair".into()),
    };
    if body.is_some_and(|b| b.len() > MAX_REGISTRATION_BYTES) {
        return Err("fixture request too large".into());
    }
    let address: SocketAddr = address.parse().map_err(debug)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(debug)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(debug)?;
    let method = if body.is_some() { "POST" } else { "GET" };
    let mut header = format!(
        "{method} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n",
        request.target()
    );
    if let Some(body) = body {
        header.push_str(&format!(
            "Content-Type: application/octet-stream\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes()).map_err(debug)?;
    if let Some(body) = body {
        stream.write_all(body).map_err(debug)?;
    }
    let maximum = 8192 + bound;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut raw = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("fixture HTTP response deadline")?;
        stream.set_read_timeout(Some(remaining)).map_err(debug)?;
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).map_err(debug)?;
        if count == 0 {
            break;
        }
        if raw.len() + count > maximum {
            return Err("fixture HTTP response exceeds fixed bound".into());
        }
        raw.extend_from_slice(&chunk[..count]);
    }
    let end = raw
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("fixture response missing headers")?;
    if end + 4 > 8192 || raw.len() - end - 4 > bound {
        return Err("fixture response header/body bound".into());
    }
    let headers = std::str::from_utf8(&raw[..end]).map_err(debug)?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err("fixture discovery request was refused".into());
    }
    let mut proof = None;
    let mut length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("fixture malformed header")?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "x-vhalla-proof" if proof.is_none() => proof = Some(value),
            "content-length" if length.is_none() => {
                length = Some(value.parse::<usize>().map_err(debug)?);
            }
            "content-type" if content_type.is_none() => content_type = Some(value),
            "x-vhalla-proof" | "content-length" | "content-type" | "transfer-encoding"
            | "content-encoding" => return Err("fixture ambiguous response framing".into()),
            _ => {}
        }
    }
    let body = &raw[end + 4..];
    if length != Some(body.len()) || content_type != Some("application/octet-stream") {
        return Err("fixture response framing mismatch".into());
    }
    proof_from_hex(proof.ok_or("fixture discovery proof missing")?)
        .and_then(|proof| {
            proof.verify(
                receiver.network_id(),
                receiver.application_key(),
                request,
                body,
            )
        })
        .map_err(debug)?;
    Ok(body.to_vec())
}

/// Register one locally generated READ peer to the other through the actual
/// listener, then read the listing and require the exact signed descriptor.
pub fn register(
    publisher: &ManagedPeer,
    receiver: &ManagedPeer,
    receiver_route: usize,
) -> Result<(), String> {
    if publisher.network_id() != receiver.network_id() {
        return Err("fixture discovery network mismatch".into());
    }
    let advertisement = publisher.current_public_advertisement().map_err(debug)?;
    let request = DiscoveryRequest::new(
        nonce()?,
        DiscoveryKind::Challenge {
            publisher: publisher.application_key(),
            advertisement: Sha256::digest(advertisement.encode()).into(),
        },
    )
    .map_err(debug)?;
    let raw = exchange(
        receiver,
        receiver_route,
        request,
        None,
        REGISTRATION_CHALLENGE_BYTES,
    )?;
    let challenge = RegistrationChallenge::decode(&raw).map_err(debug)?;
    let verified = challenge
        .verify(
            receiver.network_id(),
            receiver.application_key(),
            request,
            now()?,
        )
        .map_err(debug)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut offset = 0;
    let work = loop {
        if offset >= MAX_SOLVE_ATTEMPTS
            || Instant::now() >= deadline
            || now()? >= challenge.expires_at()
        {
            return Err("fixture discovery work/time budget exhausted".into());
        }
        let count = 8192.min(MAX_SOLVE_ATTEMPTS - offset);
        if let Some(work) = verified.solve_range(offset, count).map_err(debug)? {
            break work;
        }
        offset += count;
    };
    let registration = publisher
        .sign_discovery_registration(verified, work)
        .map_err(debug)?;
    if registration.advertisement() != &advertisement {
        return Err("fixture advertisement changed while solving".into());
    }
    let raw = registration.encode();
    let request = DiscoveryRequest::new(
        nonce()?,
        DiscoveryKind::Register {
            registration: Sha256::digest(&raw).into(),
        },
    )
    .map_err(debug)?;
    let receipt = exchange(
        receiver,
        receiver_route,
        request,
        Some(&raw),
        REGISTRATION_RECEIPT_BYTES,
    )?;
    RegistrationReceipt::decode(&receipt)
        .and_then(|receipt| {
            receipt.check(
                receiver.network_id(),
                receiver.application_key(),
                &advertisement,
            )
        })
        .map_err(debug)?;
    let request = DiscoveryRequest::new(
        nonce()?,
        DiscoveryKind::List {
            generation: 0,
            after: [0; 32],
            count: 16,
        },
    )
    .map_err(debug)?;
    let page = PeerPage::decode(&exchange(
        receiver,
        receiver_route,
        request,
        None,
        MAX_PEER_PAGE_BYTES,
    )?)
    .map_err(debug)?;
    page.check_request(receiver.network_id(), request)
        .map_err(debug)?;
    if page.has_more() || page.advertisements() != [advertisement] {
        return Err("fixture discovery listing does not contain exact other peer".into());
    }
    Ok(())
}
