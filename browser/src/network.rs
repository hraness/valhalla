//! Pinned network selection, incremental certified replay and explicit peer use.
use crate::transport;
#[path = "network/activity.rs"]
mod activity;
#[path = "network/discovery.rs"]
mod discovery;
#[path = "network/puzzles.rs"]
mod puzzles;
#[path = "network/recovery.rs"]
mod recovery;
use js_sys::Uint8Array;
use std::{
    cell::RefCell,
    future::{poll_fn, Future},
    rc::Rc,
    task::{Poll, Waker},
};
use vhalla_browser_storage::{
    browser::history::IndexedHistory,
    browser::IndexedStorage,
    history::{HistoryFrontier, HistoryHead, HistoryRecord, HistoryScope},
    Image, Namespace, Slot,
};
use vhalla_public_client::{Bootstrap, CertifiedClient, MAX_BOOTSTRAP_BYTES};
use vhalla_public_protocol::response::{hex, BundlePage, ReadKind};
use vhalla_public_protocol::{
    Capabilities, PeerAdvertisement, Scheme, VerificationPolicy, MAX_ADVERTISEMENT_BYTES,
    MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
};
use vhalla_rooms_consensus::Frontier;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{Document, Event, HtmlButtonElement, HtmlInputElement};

const PROFILE: [u8; 32] = *b"vhalla-browser-local-profile-v01";
const MAX_PEERS: usize = 16;
const REPLAY_PER_ACTION: usize = 256;
const READS_PER_ACTION: usize = 8;
type App = Rc<RefCell<State>>;
struct Session {
    client: CertifiedClient,
    history: IndexedHistory,
    head: HistoryHead,
    recovery_target: HistoryHead,
}
struct State {
    document: Document,
    selection: Option<IndexedStorage>,
    saved: Option<Image>,
    session: Option<Session>,
    peers: Vec<Vec<u8>>,
    candidates: Vec<Vec<u8>>,
    clock_floor: u64,
    busy: bool,
    failed: bool,
    next_peer: usize,
    feed: Option<activity::FeedPosition>,
}
fn status(app: &App, text: &str) {
    app.borrow()
        .document
        .get_element_by_id("network-status")
        .unwrap()
        .set_text_content(Some(text));
}
fn field(app: &App, id: &str) -> HtmlInputElement {
    app.borrow()
        .document
        .get_element_by_id(id)
        .unwrap()
        .unchecked_into()
}
fn policy(network: [u8; 32], now: u64) -> VerificationPolicy {
    VerificationPolicy {
        network,
        now,
        max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
        max_ttl_seconds: MAX_TTL_SECONDS,
    }
}
fn now(floor: u64) -> Result<u64, String> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 || millis / 1000.0 > u64::MAX as f64 {
        return Err("This device's clock is unavailable.".into());
    }
    let current = (millis / 1000.0) as u64;
    if current < floor {
        return Err("This device's clock moved backwards. Correct it before connecting.".into());
    }
    Ok(current)
}
fn pin(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("Enter the full 64-character lowercase network fingerprint from an independent trusted source.".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| "Invalid fingerprint")?;
    }
    Ok(out)
}
fn frontier(f: Frontier) -> HistoryFrontier {
    HistoryFrontier {
        height: f.height,
        value: f.value,
        registry: f.registry,
        social: f.social,
        control: f.control,
        time: f.time,
    }
}
fn manifest(scope: HistoryScope, clock: u64, peers: &[Vec<u8>]) -> Result<Image, String> {
    let mut header = Vec::with_capacity(72);
    header.extend_from_slice(&scope.network());
    header.extend_from_slice(&scope.bootstrap_pin());
    header.extend_from_slice(&clock.to_be_bytes());
    let mut records = vec![header.as_slice()];
    records.extend(peers.iter().map(Vec::as_slice));
    Image::new(Slot::Checkpoint, &records)
        .map_err(|_| "Network selection exceeds its storage limit.".into())
}
async fn save_selection(
    app: &App,
    scope: HistoryScope,
    peers: &[Vec<u8>],
    clock: u64,
) -> Result<(), String> {
    if clock < app.borrow().clock_floor {
        return Err("Device clock regressed during publication.".into());
    }
    let image = manifest(scope, clock, peers)?;
    let (mut storage, previous) = {
        let mut s = app.borrow_mut();
        let previous = s.saved.clone();
        (
            s.selection.take().ok_or("Local storage is unavailable.")?,
            previous,
        )
    };
    let result = storage.compare_exchange(previous.as_ref(), &image).await;
    app.borrow_mut().selection = Some(storage);
    if result.is_err() {
        app.borrow_mut().failed = true;
        return Err("Network selection changed in another tab or storage failed. Reload to reconcile before continuing.".into());
    }
    let mut s = app.borrow_mut();
    s.saved = Some(image);
    s.clock_floor = clock;
    Ok(())
}
fn render(app: &App) {
    let s = app.borrow();
    let available = !s.busy && !s.failed && s.selection.is_some();
    let ready = s
        .session
        .as_ref()
        .is_some_and(|v| v.head == v.recovery_target);
    for (id, enabled) in [
        ("join-network", available),
        ("add-peer", available && ready),
        ("sync-network", available && ready && !s.peers.is_empty()),
        (
            "recover-network",
            available && s.session.is_some() && !ready,
        ),
    ] {
        s.document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!enabled);
    }
    for id in ["network-file", "network-pin", "peer-file"] {
        s.document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlInputElement>()
            .set_disabled(!available);
    }
    activity::render(app, s.session.as_ref(), available);
    discovery::render(app, available, ready);
    let badge = s.document.get_element_by_id("network-state").unwrap();
    badge.set_text_content(Some(if s.failed {
        "Reload required"
    } else if s.busy {
        "Verifying"
    } else if ready {
        "Verified locally"
    } else {
        "Not connected"
    }));
    let summary = s.document.get_element_by_id("network-summary").unwrap();
    let rooms = s.document.get_element_by_id("room-list").unwrap();
    rooms.set_text_content(None);
    if let Some(session) = &s.session {
        summary.set_text_content(Some(&format!(
            "Network {} · certified height {} · {} selected peers",
            hex(&session.client.network_id()),
            session.client.frontier().height,
            s.peers.len()
        )));
        if ready {
            if let Ok(found) = session.client.registry().search("", 32, 4096) {
                if found.rooms.is_empty() {
                    rooms.set_text_content(Some(
                        "No public rooms are visible in the verified directory yet.",
                    ));
                }
                for room in found.rooms {
                    let item = s.document.create_element("article").unwrap();
                    item.set_class_name("room-card");
                    let title = s.document.create_element("h3").unwrap();
                    title.set_text_content(Some(room.slug().as_str()));
                    let description = s.document.create_element("p").unwrap();
                    description.set_text_content(Some(room.description().as_str()));
                    let state = s.document.create_element("small").unwrap();
                    let open = room.public_activity_policy().is_some_and(|p| {
                        room.allows_public_activity(&session.client.network_id(), p.record)
                    });
                    state.set_text_content(Some(if open {
                        "Public activity enabled"
                    } else {
                        "Public activity closed"
                    }));
                    let _ = item.append_child(&title);
                    let _ = item.append_child(&description);
                    let _ = item.append_child(&state);
                    let _ = rooms.append_child(&item);
                }
                if found.partial {
                    let text = s.document.create_element("p").unwrap();
                    text.set_text_content(Some("Showing the first 32 matching rooms."));
                    let _ = rooms.append_child(&text);
                }
            }
        }
    } else {
        summary.set_text_content(Some(
            "Choose a network invitation and verify its fingerprint before connecting.",
        ));
    }
}
async fn file(input: HtmlInputElement, max: usize) -> Result<Vec<u8>, String> {
    let file = input
        .files()
        .and_then(|f| f.get(0))
        .ok_or("Choose a file first.")?;
    if !file.size().is_finite() || file.size() < 1.0 || file.size() > max as f64 {
        return Err("The selected file has an unsupported size.".into());
    }
    let result = JsFuture::from(file.array_buffer())
        .await
        .map_err(|_| "The selected file could not be read.")?;
    let array = Uint8Array::new(&result);
    if array.length() as usize > max {
        return Err("The selected file exceeds its limit.".into());
    }
    Ok(array.to_vec())
}
async fn recover(session: &mut Session) -> Result<bool, String> {
    let target = session.recovery_target.frontier().height;
    let mut count = 0;
    while session.head.frontier().height < target && count < REPLAY_PER_ACTION {
        let start = session
            .head
            .frontier()
            .height
            .checked_add(1)
            .ok_or("History height overflow.")?;
        let page = session
            .history
            .read_page(start, 16, 2 * 1024 * 1024)
            .await
            .map_err(|_| {
                "Saved history is incomplete or unavailable. Preserve storage and reload."
            })?;
        if page.head.frontier().height < target || page.records.is_empty() {
            return Err(
                "Saved history regressed or is incomplete. Preserve storage before recovery."
                    .into(),
            );
        }
        for record in page.records {
            if record.head().frontier().height > target {
                break;
            }
            if record.base() != session.head {
                return Err("Saved history does not extend the retained frontier.".into());
            }
            let candidate = session
                .client
                .prepare(session.client.network_id(), record.bundle_bytes())
                .map_err(|_| "Saved history failed certificate or application verification.")?;
            if record.head().frontier() != frontier(candidate.next_frontier())
                || record.head().bundle_id() != candidate.bundle_id()
            {
                return Err("Saved history metadata does not match its certified evidence.".into());
            }
            session
                .client
                .commit_after_persist(candidate)
                .map_err(|_| "Saved history has a stale verification basis.")?;
            session.head = record.head();
            count += 1;
        }
    }
    if session.head.frontier().height == target && session.head != session.recovery_target {
        return Err("Saved history does not match its published head.".into());
    }
    Ok(session.head.frontier().height == target)
}
async fn open_session(raw: &[u8], expected: [u8; 32], create: bool) -> Result<Session, String> {
    let bootstrap = Bootstrap::decode(raw, expected)
        .map_err(|_| "Network invitation or fingerprint is invalid.")?;
    let scope = HistoryScope::new(bootstrap.network_id(), expected);
    let client =
        CertifiedClient::new(bootstrap, expected).map_err(|_| "Network genesis is invalid.")?;
    let genesis = HistoryHead::new(scope, frontier(client.frontier()), [0; 32])
        .map_err(|_| "Unsupported genesis.")?;
    let mut history = IndexedHistory::open(Namespace::new(PROFILE), scope)
        .await
        .map_err(|_| "Could not open saved network history.")?;
    let stored = history
        .load_bootstrap()
        .await
        .map_err(|_| "Could not read saved bootstrap.")?;
    match stored {
        Some(bytes) if bytes == raw => {}
        Some(_) => {
            return Err("Saved network bootstrap differs. Preserve storage and reload.".into());
        }
        None if create => history
            .initialize(raw, &genesis)
            .await
            .map_err(|_| "Could not atomically save network genesis.")?,
        None => {
            return Err(
                "Saved network bootstrap is missing. Preserve storage before recovery.".into(),
            );
        }
    }
    let target = history
        .load_head()
        .await
        .map_err(|_| "Could not read saved history head.")?
        .ok_or("Saved history head is missing.")?;
    Ok(Session {
        client,
        history,
        head: genesis,
        recovery_target: target,
    })
}
async fn join(app: &App, raw: Vec<u8>, expected: [u8; 32]) -> Result<(), String> {
    // Preserve the profile's trust root and selected peer sequence floors.
    if app
        .borrow()
        .session
        .as_ref()
        .is_some_and(|session| session.head.scope().bootstrap_pin() != expected)
    {
        return Err("This profile is pinned to a different network configuration. Use a separate browser profile; configuration migration is not yet available.".into());
    }
    let mut session = open_session(&raw, expected, true).await?;
    let complete = recover(&mut session).await?;
    let clock = now(app.borrow().clock_floor)?;
    let peers = app.borrow().peers.clone();
    save_selection(app, session.head.scope(), &peers, clock).await?;
    let mut state = app.borrow_mut();
    state.session = Some(session);
    state.peers = peers;
    drop(state);
    status(
        app,
        if complete {
            "Network fingerprint verified and genesis saved. Add a peer invitation to retrieve certified rooms."
        } else {
            "Saved history is being reverified. Continue recovery before connecting."
        },
    );
    Ok(())
}
async fn add_peer(app: &App, raw: Vec<u8>) -> Result<(), String> {
    let (scope, mut peers, floor) = {
        let s = app.borrow();
        (
            s.session
                .as_ref()
                .ok_or("Select a network first.")?
                .head
                .scope(),
            s.peers.clone(),
            s.clock_floor,
        )
    };
    let clock = now(floor)?;
    let ad = PeerAdvertisement::decode(&raw).map_err(|_| "Peer invitation is malformed.")?;
    let key = ad.unverified_claims().application_key;
    let existing = peers.iter().position(|bytes| {
        PeerAdvertisement::decode(bytes).is_ok_and(|p| p.unverified_claims().application_key == key)
    });
    let old = existing
        .map(|index| {
            PeerAdvertisement::decode(&peers[index])
                .unwrap()
                .restore_sequence_anchor(scope.network())
        })
        .transpose()
        .map_err(|_| "Saved peer evidence is invalid.")?;
    let same = existing.is_some_and(|i| peers[i] == raw);
    let verified = ad
        .verify(
            &policy(scope.network(), clock),
            if same { None } else { old.as_ref() },
        )
        .map_err(|_| "Peer invitation is expired, rolled back, or belongs to another network.")?;
    if !verified.claims().capabilities.contains(Capabilities::READ)
        || !verified
            .claims()
            .endpoints
            .iter()
            .any(|e| e.scheme() == Scheme::Https)
    {
        return Err("This peer does not advertise an HTTPS read service.".into());
    }
    if let Some(i) = existing {
        peers[i] = raw;
    } else {
        if peers.len() >= MAX_PEERS {
            return Err("This device has reached its selected-peer limit.".into());
        }
        peers.push(raw);
    }
    save_selection(app, scope, &peers, clock).await?;
    app.borrow_mut().peers = peers;
    status(
        app,
        "Peer invitation verified and saved. Sync retrieves signed evidence without sharing your identity.",
    );
    Ok(())
}
async fn sync(app: &App, session: &mut Session) -> Result<(), String> {
    let mut budget = READS_PER_ACTION;
    let (mut peers, start, floor) = {
        let s = app.borrow();
        (s.peers.clone(), s.next_peer, s.clock_floor)
    };
    now(floor)?;
    if peers.is_empty() {
        return Err("Add a peer invitation first.".into());
    }
    'peers: for offset in 0..peers.len() {
        let index = (start + offset) % peers.len();
        app.borrow_mut().next_peer = (index + 1) % peers.len();
        let old = PeerAdvertisement::decode(&peers[index])
            .map_err(|_| "Saved peer invitation is corrupt.")?;
        let anchor = old
            .restore_sequence_anchor(session.client.network_id())
            .map_err(|_| "Saved peer signature is invalid.")?;
        let key = *anchor.application_key();
        for endpoint in &old.unverified_claims().endpoints {
            if endpoint.scheme() != Scheme::Https {
                continue;
            }
            if budget == 0 {
                return Err("Selected peers were unavailable within this attempt's budget. Retry to continue with another peer.".into());
            }
            budget -= 1;
            status(
                app,
                "Contacting a selected peer and verifying fresh route evidence…",
            );
            let request = transport::request(ReadKind::Advertisement)
                .map_err(|_| "Browser randomness is unavailable.")?;
            // This route was explicitly selected by the local user. Expired
            // evidence is used only to request renewal from that exact key/URL.
            let Ok(raw) =
                transport::read(endpoint, session.client.network_id(), key, &request).await
            else {
                continue;
            };
            let Ok(ad) = PeerAdvertisement::decode(&raw) else {
                continue;
            };
            let same = raw == peers[index];
            let current_anchor = PeerAdvertisement::decode(&peers[index])
                .map_err(|_| "Saved peer evidence is malformed.")?
                .restore_sequence_anchor(session.client.network_id())
                .map_err(|_| "Saved peer signature is invalid.")?;
            let Ok(verified) = ad.verify(
                &policy(session.client.network_id(), now(app.borrow().clock_floor)?),
                if same { None } else { Some(&current_anchor) },
            ) else {
                continue;
            };
            if verified.claims().endpoints != old.unverified_claims().endpoints
                || !verified.claims().capabilities.contains(Capabilities::READ)
            {
                continue;
            }
            let mut renewed = peers.clone();
            renewed[index] = raw;
            let clock = now(app.borrow().clock_floor)?;
            save_selection(app, session.head.scope(), &renewed, clock).await?;
            peers = renewed;
            app.borrow_mut().peers = peers.clone();
            while budget > 0 {
                budget -= 1;
                let base = session.client.frontier();
                status(
                    app,
                    &format!("Verifying room history after height {}…", base.height),
                );
                let request = transport::request(ReadKind::Bundles {
                    after: base.height,
                    frontier: base.commitment(),
                    count: 16,
                    bytes: 2 * 1024 * 1024,
                })
                .map_err(|_| "Could not create a fresh request.")?;
                let Ok(raw) =
                    transport::read(endpoint, session.client.network_id(), key, &request).await
                else {
                    break;
                };
                let Ok(page) = BundlePage::decode(&raw, &request) else {
                    break;
                };
                for bytes in page.bundles() {
                    let Ok(candidate) = session.client.prepare(session.client.network_id(), bytes)
                    else {
                        status(
                            app,
                            "A peer supplied invalid certified history. Trying another selected peer…",
                        );
                        continue 'peers;
                    };
                    let next = HistoryHead::new(
                        session.head.scope(),
                        frontier(candidate.next_frontier()),
                        candidate.bundle_id(),
                    )
                    .map_err(|_| "Unsupported history frontier.")?;
                    let record = HistoryRecord::new(session.head, next, candidate.bundle_bytes())
                        .map_err(|_| "History exceeds per-record bounds.")?;
                    if session
                        .history
                        .append(&session.head, &record)
                        .await
                        .is_err()
                    {
                        app.borrow_mut().failed = true;
                        return Err("History publication changed or failed. Reload to reconcile persisted evidence before continuing.".into());
                    }
                    if session.client.commit_after_persist(candidate).is_err() {
                        app.borrow_mut().failed = true;
                        return Err("Verified candidate became stale after persistence. Reload to reconcile.".into());
                    }
                    session.head = next;
                    session.recovery_target = next;
                }
                if session.client.frontier().height == page.observed_height() {
                    if session.client.frontier().commitment() != page.observed_frontier() {
                        status(
                            app,
                            "A peer's observed head conflicts with its evidence. Trying another selected peer…",
                        );
                        continue 'peers;
                    }
                    status(
                        app,
                        &format!(
                            "Certified through height {} and saved locally. This matches the selected peer's observed head; it is not a claim of global freshness.",
                            page.observed_height()
                        ),
                    );
                    return Ok(());
                }
                if page.bundles().is_empty() {
                    break;
                }
            }
        }
    }
    Err("No selected peer supplied a complete matching view in this attempt. Previously verified history remains saved; retry to continue catch-up or try another peer.".into())
}
fn bind(app: &App, id: &str, action: fn(App)) {
    let app = app.clone();
    let document = app.borrow().document.clone();
    let callback = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
        event.prevent_default();
        {
            let mut s = app.borrow_mut();
            if s.busy || s.failed {
                return;
            }
            s.busy = true;
        }
        render(&app);
        action(app.clone());
    });
    document
        .get_element_by_id(id)
        .unwrap()
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .unwrap();
    callback.forget();
}
fn finish(app: &App, result: Result<(), String>) {
    if let Err(message) = result {
        status(app, &message);
    }
    app.borrow_mut().busy = false;
    render(app);
}
// One operation owns every in-flight future. Deadline cancellation drops IDB
// guards and Fetch attempts; any uncertain publication requires reopen/replay.
fn launch(app: App, future: impl Future<Output = ()> + 'static) {
    spawn_local(async move {
        let Some(window) = web_sys::window() else {
            return;
        };
        let Some(clock) = window.performance() else {
            app.borrow_mut().failed = true;
            finish(&app, Err("Browser timing support is unavailable.".into()));
            return;
        };
        let deadline = clock.now() + 180_000.0;
        let waker: Rc<RefCell<Option<Waker>>> = Rc::new(RefCell::new(None));
        let wake = waker.clone();
        let callback = Closure::<dyn FnMut()>::new(move || {
            if let Some(waker) = wake.borrow_mut().take() {
                waker.wake();
            }
        });
        let Ok(timer) = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            180_000,
        ) else {
            app.borrow_mut().failed = true;
            finish(&app, Err("Browser timing support is unavailable.".into()));
            return;
        };
        let mut future = Box::pin(future);
        let completed = poll_fn(|cx| {
            if clock.now() >= deadline {
                return Poll::Ready(false);
            }
            *waker.borrow_mut() = Some(cx.waker().clone());
            match future.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(true),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        window.clear_timeout_with_handle(timer);
        drop(future);
        drop(callback);
        if !completed {
            app.borrow_mut().failed = true;
            finish(
                &app,
                Err(
                    "The operation timed out. Reload to reconcile saved state before retrying."
                        .into(),
                ),
            );
        }
    });
}
pub fn start() {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let app = Rc::new(RefCell::new(State {
        document,
        selection: None,
        saved: None,
        session: None,
        peers: Vec::new(),
        candidates: Vec::new(),
        clock_floor: 0,
        busy: true,
        failed: false,
        next_peer: 0,
        feed: None,
    }));
    bind(&app, "join-network", |app| {
        let expected = pin(&field(&app, "network-pin").value());
        let input = field(&app, "network-file");
        launch(app.clone(), async move {
            let result = async {
                let expected = expected?;
                let raw = file(input, MAX_BOOTSTRAP_BYTES).await?;
                join(&app, raw, expected).await
            }
            .await;
            finish(&app, result);
        });
    });
    bind(&app, "add-peer", |app| {
        let input = field(&app, "peer-file");
        launch(app.clone(), async move {
            let result = async {
                let raw = file(input, MAX_ADVERTISEMENT_BYTES).await?;
                add_peer(&app, raw).await
            }
            .await;
            finish(&app, result);
        });
    });
    bind(&app, "recover-network", |app| {
        launch(app.clone(), async move {
            let mut session = app.borrow_mut().session.take().unwrap();
            let result = recover(&mut session).await.map(|complete| {
                status(
                    &app,
                    if complete {
                        "Saved certified history verified. You can now sync with selected peers."
                    } else {
                        "Recovery progressed. Continue to verify the remaining saved history."
                    },
                )
            });
            if result.is_err() {
                app.borrow_mut().failed = true;
            }
            app.borrow_mut().session = Some(session);
            finish(&app, result);
        });
    });
    bind(&app, "sync-network", |app| {
        launch(app.clone(), async move {
            let mut session = app.borrow_mut().session.take().unwrap();
            let result = sync(&app, &mut session).await;
            app.borrow_mut().session = Some(session);
            finish(&app, result);
        });
    });
    activity::bind_actions(&app);
    discovery::bind_actions(&app);
    puzzles::bind_actions(&app);
    render(&app);
    launch(app.clone(), async move {
        let result=async {
            let mut storage=IndexedStorage::open(Namespace::new(PROFILE)).await.map_err(|_|"Could not open network selection storage.")?;
            let saved=storage.load(Slot::Checkpoint).await.map_err(|_|"Could not load saved network selection.")?;
            app.borrow_mut().selection=Some(storage);app.borrow_mut().saved=saved.clone();
            let Some(image)=saved else {status(&app,"Choose a network invitation to begin.");return Ok(());};
            let records:Vec<_>=image.records().collect();
            if records.is_empty()||records.len()>MAX_PEERS+1||records[0].len()!=72 {return Err("Saved network selection is malformed. Preserve storage before recovery.".into());}
            let network:[u8;32]=records[0][..32].try_into().unwrap();let expected:[u8;32]=records[0][32..64].try_into().unwrap();let clock=u64::from_be_bytes(records[0][64..72].try_into().unwrap());
            let scope=HistoryScope::new(network,expected);
            let mut history=IndexedHistory::open(Namespace::new(PROFILE),scope).await.map_err(|_|"Could not open saved network history.")?;
            let raw=history.load_bootstrap().await.map_err(|_|"Could not read saved network bootstrap.")?.ok_or("Saved network bootstrap is missing.")?;drop(history);
            let mut session=open_session(&raw,expected,false).await?;
            if session.client.network_id()!=network {return Err("Saved network identity does not match its fingerprint.".into());}
            let mut peers=Vec::new();
            for raw in &records[1..] {let ad=PeerAdvertisement::decode(raw).map_err(|_|"Saved peer evidence is malformed.")?;ad.restore_sequence_anchor(network).map_err(|_|"Saved peer evidence has an invalid signature.")?;peers.push(raw.to_vec());}
            let complete=recover(&mut session).await?;
            let mut state=app.borrow_mut();state.session=Some(session);state.peers=peers;state.clock_floor=clock;drop(state);
            status(&app,if complete {"Saved network history verified. Sync to check selected peers for newer certified rooms."} else {"Continue recovery to verify the remaining saved history."});Ok(())
        }.await;
        if result.is_err() {
            app.borrow_mut().failed = true;
        }
        finish(&app, result);
    });
}
