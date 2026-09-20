//! Explicit one-peer activity delivery and authenticated, non-admitted page export.
//! Existing finalized signed bytes are retried unchanged; this path never opens a key.
//! Peer statements are not independent room-policy or global-delivery evidence.
use super::{preserved, write_new};
use crate::public_network::{bytes, discovery::http, hex, hex32};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File},
    os::unix::fs::DirBuilderExt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_browser_storage::{
    history::HistoryScope,
    native::{
        peers::{NativePeerSession, PeerSelection},
        NativeOutbox,
    },
    outbox::{delivery::DeliveryHead, AuthorScope},
};
use vhalla_public_client::{Bootstrap, CertifiedClient, MAX_BOOTSTRAP_BYTES};
use vhalla_public_protocol::{
    activity::{self, ActivityPage, ActivityRequest, ActivityResponseProof},
    response::{self, ReadKind, ReadRequest},
    Capabilities, Endpoint, Scheme, VerificationPolicy, MAX_ADVERTISEMENT_BYTES,
    MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
};
use vhalla_room_activity::RoomScope;
use vhalla_rooms::RoomGenesisId;

pub(super) const HELP: &str = "vhalla public activity peer-add BOOTSTRAP PIN64 NEW_PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT AD_FILE\nvhalla public activity send BOOTSTRAP PIN64 OUTBOX ROOM64 AUTHOR64 PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT\nvhalla public activity read BOOTSTRAP PIN64 ROOM64 PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT AFTER_CURSOR NEW_EXPORT_DIR\npeer-add explicitly saves one fresh signed READ peer without dialing. send attempts at most 3 retained posts to that exact peer, persisting its receipts before reporting confirmation. read exports at most 16 full-scope signed frames plus the exact request/proof/page into a new directory; AFTER_CURSOR is explicit and peer-local. JSON reports continuation; received pages are not independently admitted room history. No key use, endpoint discovery/failover, PUBLISH startup, or author-floor reset occurs. Keep peer state to preserve signed advertisement and clock floors; no route/key migration is implemented.";
const SEND_LIMIT: usize = 3;
const PAGE_LIMIT: u8 = 16;

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "clock precedes Unix epoch".into())
}
fn nonce() -> Result<[u8; 32], String> {
    for _ in 0..2 {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| "secure nonce source unavailable")?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err("secure nonce source returned zero twice".into())
}
fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("activity operation cancelled; preserve retained state".into())
    } else {
        Ok(())
    }
}
fn endpoint(raw: &str) -> Result<Endpoint, String> {
    let value = Endpoint::parse(raw).map_err(|e| format!("explicit peer endpoint: {e:?}"))?;
    if value.scheme() != Scheme::Https {
        return Err("activity transport requires an exact public HTTPS endpoint".into());
    }
    Ok(value)
}
fn scope(client: &CertifiedClient, room: [u8; 32]) -> RoomScope {
    RoomScope {
        network: client.network_id(),
        realm: client.registry().realm(),
        directory: client.registry().directory(),
        room: RoomGenesisId::from_bytes(room),
    }
}
fn policy(network: [u8; 32], at: u64) -> VerificationPolicy {
    VerificationPolicy {
        network,
        now: at,
        max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
        max_ttl_seconds: MAX_TTL_SECONDS,
    }
}

trait Transport {
    fn advertisement(
        &mut self,
        route: &Endpoint,
        request: &ReadRequest,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String>;
    fn activity(
        &mut self,
        route: &Endpoint,
        request: &ActivityRequest,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String>;
}
struct Curl;
impl Transport for Curl {
    fn advertisement(
        &mut self,
        route: &Endpoint,
        request: &ReadRequest,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        http::exchange_advertisement(route, request, cancel)
    }
    fn activity(
        &mut self,
        route: &Endpoint,
        request: &ActivityRequest,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        http::exchange_activity(route, request, body, cancel)
    }
}

fn usable(selection: &PeerSelection, at: u64, publish: bool) -> Result<(), String> {
    if at < selection.clock_floor() {
        return Err("clock regressed below retained peer state".into());
    }
    let verified = selection
        .advertisement()
        .verify(&policy(selection.scope().network(), at), None)
        .map_err(|e| format!("selected advertisement is not fresh: {e:?}"))?;
    if verified.claims().application_key != selection.peer()
        || !verified.claims().endpoints.contains(selection.endpoint())
        || !verified.claims().capabilities.contains(Capabilities::READ)
        || (publish
            && !verified
                .claims()
                .capabilities
                .contains(Capabilities::PUBLISH))
    {
        return Err("retained fresh peer evidence does not authorize this exact route/service; newer evidence is preserved and no alternate endpoint was selected".into());
    }
    Ok(())
}

fn refresh(
    session: &mut NativePeerSession,
    transport: &mut impl Transport,
    clock: &impl Fn() -> Result<u64, String>,
    publish: bool,
    cancel: &AtomicBool,
) -> Result<PeerSelection, String> {
    cancelled(cancel)?;
    let selected = session.selection().map_err(preserved)?;
    let selected = session
        .checkpoint_clock(&selected, clock()?)
        .map_err(preserved)?;
    let request = ReadRequest::new(nonce()?, ReadKind::Advertisement)
        .map_err(|e| format!("refresh request: {e:?}"))?;
    // The immutable explicitly selected route may request renewal after expiry;
    // it cannot post/read activity until fresh evidence is durably retained.
    let (body, proof) = transport.advertisement(selected.endpoint(), &request, cancel)?;
    cancelled(cancel)?;
    response::proof_from_hex(&proof)
        .and_then(|proof| {
            proof.verify(selected.scope().network(), selected.peer(), &request, &body)
        })
        .map_err(|e| format!("selected peer refresh proof: {e:?}"))?;
    let at = clock()?;
    let observed = session.observe(&selected, &body, at).map_err(preserved)?;
    // Preserve a signed withdrawal before refusing use. Never forget a greater
    // sequence merely because its capabilities or selected route are unusable.
    usable(&observed, at, publish)?;
    Ok(observed)
}

fn activity_reply(
    transport: &mut impl Transport,
    selected: &PeerSelection,
    request: &ActivityRequest,
    body: Option<&[u8]>,
    cancel: &AtomicBool,
) -> Result<(Vec<u8>, ActivityResponseProof), String> {
    cancelled(cancel)?;
    let (raw, proof) = transport.activity(selected.endpoint(), request, body, cancel)?;
    cancelled(cancel)?;
    let proof = activity::proof_from_hex(&proof)
        .map_err(|e| format!("activity response framing: {e:?}"))?;
    proof
        .verify(selected.scope().network(), selected.peer(), request, &raw)
        .map_err(|e| format!("activity response proof: {e:?}"))?;
    Ok((raw, proof))
}

struct SendOutcome {
    report: Value,
    error: Option<String>,
}
fn send(
    session: &mut NativePeerSession,
    outbox: &mut NativeOutbox,
    room: RoomScope,
    transport: &mut impl Transport,
    clock: &impl Fn() -> Result<u64, String>,
    cancel: &AtomicBool,
) -> Result<SendOutcome, String> {
    let selected = session.selection().map_err(preserved)?;
    let peer = selected.peer();
    let local = outbox.head().map_err(preserved)?;
    if local.scope() != AuthorScope::new(room, local.scope().author())
        || room.network != selected.scope().network()
    {
        return Err("outbox and selected peer differ from the full requested room scope".into());
    }
    let mut prior = outbox.load_delivery(peer).map_err(preserved)?;
    let start = prior.map_or(0, DeliveryHead::sequence);
    let mut confirmed = Vec::new();
    let outcome = (|| {
        if start >= local.sequence() {
            return Ok(());
        }
        let mut selected = refresh(session, transport, clock, true, cancel)?;
        let page = outbox.read_page(start, SEND_LIMIT).map_err(preserved)?;
        for event in page.events {
            cancelled(cancel)?;
            let at = clock()?;
            selected = session.checkpoint_clock(&selected, at).map_err(preserved)?;
            usable(&selected, at, true)?;
            let raw = event.encode();
            let request = ActivityRequest::post(nonce()?, *room.room.as_bytes(), &raw)
                .map_err(|e| format!("retained event request: {e:?}"))?;
            let (body, proof) = activity_reply(transport, &selected, &request, Some(&raw), cancel)?;
            let next = outbox
                .record_delivery(peer, prior.as_ref(), &request, &proof, &body)
                .map_err(preserved)?;
            confirmed.push(json!({"sequence":next.sequence().to_string(), "eventId":hex(next.event_id().as_bytes()), "peerCursor":next.local_cursor().to_string()}));
            prior = Some(next);
        }
        Ok(())
    })();
    let through = prior.map_or(0, DeliveryHead::sequence);
    let status = if outcome.is_err() {
        "attempt-stopped"
    } else if local.sequence() == 0 {
        "nothing-to-send"
    } else if start >= local.sequence() {
        "already-acknowledged"
    } else {
        "peer-receipts-retained"
    };
    Ok(SendOutcome {
        report: json!({"format":"vhalla-activity-send/1", "network":hex(&room.network), "bootstrapPin":hex(&selected.scope().bootstrap_pin()),
            "realm":format!("{:032x}", room.realm.0), "directory":hex(room.directory.as_bytes()), "room":hex(room.room.as_bytes()),
            "author":hex(&local.scope().author()), "peer":hex(&peer), "endpoint":selected.endpoint().as_str(),
            "authorHead":local.sequence().to_string(), "peerAcknowledgedThrough":through.to_string(),
            "remaining":local.sequence().saturating_sub(through).to_string(), "maxPostsPerCall":SEND_LIMIT,
            "confirmed":confirmed, "status":status, "needsReopen":session.needs_reopen() || outbox.needs_reopen(),
            "deliveryScope":"one-peer-local-retention", "globalDelivery":"not-established"}),
        error: outcome.err(),
    })
}

fn require_new(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("export destination already exists; never overwrites".into()),
        Err(e) => Err(format!("export destination: {e}")),
    }
}
fn export_page(
    path: &Path,
    room: RoomScope,
    selected: &PeerSelection,
    request: &ActivityRequest,
    raw: &[u8],
    proof: &ActivityResponseProof,
    page: &ActivityPage,
) -> Result<Value, String> {
    let activity::ActivityKind::Page { after, .. } = request.kind() else {
        return Err("page export requires page request".into());
    };
    require_new(path)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("create new page export: {e}"))?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|e| format!("page export parent sync: {e}; preserve partial export"))?;
    write_new(&path.join("request.txt"), request.target().as_bytes())?;
    write_new(&path.join("response.vhproof"), &proof.encode())?;
    write_new(&path.join("response.vhactivity-page"), raw)?;
    let mut records = Vec::new();
    for entry in page.entries() {
        let event = entry.event();
        let name = format!(
            "{:020}-{}.vhactivity",
            entry.cursor(),
            hex(event.id().as_bytes())
        );
        write_new(&path.join(&name), &event.encode())?;
        records.push(json!({"file":name, "peerCursor":entry.cursor().to_string(), "author":hex(&event.claims().author),
            "sequence":event.claims().sequence.to_string(), "eventId":hex(event.id().as_bytes())}));
    }
    let next = page.entries().last().map_or(after, |e| e.cursor());
    let manifest = json!({"format":"vhalla-activity-page-export/1", "network":hex(&room.network),
        "bootstrapPin":hex(&selected.scope().bootstrap_pin()), "realm":format!("{:032x}", room.realm.0),
        "directory":hex(room.directory.as_bytes()), "room":hex(room.room.as_bytes()), "peer":hex(&selected.peer()),
        "endpoint":selected.endpoint().as_str(), "after":after.to_string(), "nextAfter":next.to_string(),
        "peerReportedTip":page.local_tip().to_string(), "peerObservedHeight":page.observed_height().to_string(),
        "peerObservedFrontier":hex(&page.observed_frontier()), "responseSha256":hex(&Sha256::digest(raw)),
        "request":"request.txt", "proof":"response.vhproof", "page":"response.vhactivity-page", "records":records,
        "coverage":"bounded-one-peer-page", "authorSignatures":"verified", "peerResponse":"verified",
        "roomPolicyAdmission":"not-independently-verified", "authorContinuity":"not-independently-verified"});
    write_new(
        &path.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )?;
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("page export sync uncertain: {e}; preserve partial export"))?;
    Ok(manifest)
}

fn read(
    session: &mut NativePeerSession,
    room: RoomScope,
    after: u64,
    path: &Path,
    transport: &mut impl Transport,
    clock: &impl Fn() -> Result<u64, String>,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    require_new(path)?;
    if room.network != session.selection().map_err(preserved)?.scope().network() {
        return Err("requested room network differs from selected peer state".into());
    }
    let selected = refresh(session, transport, clock, false, cancel)?;
    let at = clock()?;
    let selected = session.checkpoint_clock(&selected, at).map_err(preserved)?;
    usable(&selected, at, false)?;
    let request = ActivityRequest::page(nonce()?, *room.room.as_bytes(), after, PAGE_LIMIT)
        .map_err(|e| format!("activity page request: {e:?}"))?;
    let (raw, proof) = activity_reply(transport, &selected, &request, None, cancel)?;
    let page = ActivityPage::decode(&raw, &request)
        .map_err(|e| format!("activity page framing/signatures: {e:?}"))?;
    if page
        .entries()
        .iter()
        .any(|e| e.event().claims().scope != room)
    {
        return Err("received activity differs from the full network/realm/directory/room scope; no export created".into());
    }
    export_page(path, room, &selected, &request, &raw, &proof, &page)
}

fn run_inner(args: &[OsString], cancel: &AtomicBool) -> Result<(), String> {
    let arg = |i: usize| args[i].to_str().ok_or("arguments must be UTF-8");
    let command = arg(2)?;
    let pin = hex32(arg(4)?)?;
    let bootstrap = Bootstrap::decode(&bytes(Path::new(&args[3]), MAX_BOOTSTRAP_BYTES)?, pin)
        .map_err(|e| format!("independently pinned bootstrap: {e:?}"))?;
    let client =
        CertifiedClient::new(bootstrap, pin).map_err(|e| format!("network genesis: {e:?}"))?;
    let history = HistoryScope::new(client.network_id(), pin);
    if command == "peer-add" {
        let peer = hex32(arg(6)?)?;
        let route = endpoint(arg(7)?)?;
        let raw = bytes(Path::new(&args[8]), MAX_ADVERTISEMENT_BYTES)?;
        let session =
            NativePeerSession::create_new(Path::new(&args[5]), history, peer, route, &raw, now()?)
                .map_err(preserved)?;
        let selected = session.selection().map_err(preserved)?;
        println!(
            "{}",
            json!({"format":"vhalla-peer-selection/1", "network":hex(&history.network()), "bootstrapPin":hex(&pin),
            "peer":hex(&peer), "endpoint":selected.endpoint().as_str(), "sequence":selected.advertisement().unverified_claims().sequence.to_string(),
            "status":"selected-and-retained-no-dial"})
        );
        return Ok(());
    }
    http::preflight()?;
    let (room_index, state_index, peer_index, route_index) = if command == "send" {
        (6, 8, 9, 10)
    } else {
        (5, 6, 7, 8)
    };
    let room = scope(&client, hex32(arg(room_index)?)?);
    let peer = hex32(arg(peer_index)?)?;
    let route = endpoint(arg(route_index)?)?;
    // Peer-session then outbox is the fixed cooperating lock acquisition order.
    let mut session = NativePeerSession::open(Path::new(&args[state_index]), history, peer, &route)
        .map_err(preserved)?;
    if command == "send" {
        let author = hex32(arg(7)?)?;
        let mut outbox =
            NativeOutbox::open(Path::new(&args[5]), AuthorScope::new(room, author), history)
                .map_err(preserved)?;
        let outcome = send(&mut session, &mut outbox, room, &mut Curl, &now, cancel)?;
        println!("{}", outcome.report);
        if let Some(error) = outcome.error {
            return Err(error);
        }
    } else {
        let raw_after = arg(9)?;
        let after: u64 = raw_after.parse().map_err(|_| "invalid peer-local cursor")?;
        if after.to_string() != raw_after {
            return Err("peer-local cursor must be canonical unsigned decimal".into());
        }
        let manifest = read(
            &mut session,
            room,
            after,
            Path::new(&args[10]),
            &mut Curl,
            &now,
            cancel,
        )?;
        println!("{}", manifest);
    }
    Ok(())
}

pub(super) fn run(args: &[OsString]) -> Result<(), String> {
    let command = args.get(2).and_then(|a| a.to_str()).ok_or(HELP)?;
    let count = match command {
        "peer-add" => 9,
        "send" | "read" => 11,
        _ => return Err(HELP.into()),
    };
    if args.len() != count {
        return Err(HELP.into());
    }
    if command == "peer-add" {
        return run_inner(args, &AtomicBool::new(false));
    }
    let args = args.to_vec();
    supervised(Duration::from_secs(90), move |cancel| {
        run_inner(&args, &cancel)
    })
}

// Cancellation is owned until the blocking transport has returned and reaped its
// subprocesses. Do not detach a send or acknowledge an unfinished local receipt.
fn supervised(
    timeout: Duration,
    work: impl FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    let cancel = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("signal runtime: {e}"))?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| format!("SIGTERM: {e}"))?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| format!("SIGINT: {e}"))?;
        let worker_cancel = cancel.clone();
        let mut job = tokio::task::spawn_blocking(move || work(worker_cancel));
        let stopped = tokio::select! {
            result = &mut job => return result.map_err(|e| format!("activity worker: {e}"))?,
            _ = term.recv() => "SIGTERM received",
            _ = interrupt.recv() => "SIGINT received",
            _ = tokio::time::sleep(timeout) => "activity operation deadline exceeded",
        };
        cancel.store(true, Ordering::Relaxed);
        // Drain the owned blocking transport; no detached retry continues.
        let _ = job
            .await
            .map_err(|e| format!("activity worker shutdown: {e}"))?;
        Err(format!("{stopped}; preserve state and reopen before retry"))
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

#[cfg(test)]
#[path = "network/tests.rs"]
mod tests;
