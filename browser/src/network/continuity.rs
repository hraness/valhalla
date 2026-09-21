//! Fixed-target continuity transfer to one explicitly selected peer route.
//!
//! A durable attempt reservation always precedes each network exchange and the
//! authenticated original reply is retained before the next step. No signing,
//! author reset, v1 receipt conversion or automatic target growth happens here.
use super::*;
use crate::ui;
use vhalla_browser_storage::{
    browser::outbox::IndexedOutbox,
    outbox::{
        continuity::{ContinuityJob, Limits, SessionScope, Snapshot},
        AuthorScope, MAX_OUTBOX_PAGE_BYTES,
    },
};
use vhalla_public_protocol::continuity as wire;
use vhalla_room_activity::{RoomScope, UnsignedEvent, VerifiedEvent};
use web_sys::HtmlSelectElement;

/// Continuity exchanges per explicit step, matching the native supervisor.
const EXCHANGES: usize = 3;
/// The serving peer's staged-ancestor budget: 4,096 staged plus 32 inline. A
/// farther selected target advances through ordered intermediate admissions of
/// exact signed local events, never beyond this bound per admission.
const MAX_ANCESTORS: u64 = 4096 + 32;

/// The per-admission ancestor bound. Local qualification may only narrow this
/// bound through page storage so a real browser journey exercises ordered
/// intermediate admissions without fabricating a 4,129-event history; it can
/// never exceed the serving peer's staged-ancestor budget.
fn admission_bound() -> u64 {
    #[cfg(feature = "local-qualification")]
    {
        let stored = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("vhalla-continuity-bound").ok().flatten());
        if let Some(value) = stored.and_then(|raw| raw.parse::<u64>().ok()) {
            return value.min(MAX_ANCESTORS);
        }
    }
    MAX_ANCESTORS
}
/// Permanent receipt quotas for the browser surface; immutable once created.
const RECEIPT_LIMITS: Limits = Limits {
    max_records: 4096,
    max_bytes: 256 * 1024 * 1024,
};

fn status(app: &App, text: &str) {
    app.borrow()
        .document
        .get_element_by_id("continuity-status")
        .unwrap()
        .set_text_content(Some(text));
}
fn report_text(app: &App, text: &str) {
    app.borrow()
        .document
        .get_element_by_id("continuity-report")
        .unwrap()
        .set_text_content(Some(text));
}
fn peer_select(app: &App) -> HtmlSelectElement {
    app.borrow()
        .document
        .get_element_by_id("continuity-peer")
        .unwrap()
        .unchecked_into()
}
fn peer_index(app: &App) -> Result<usize, String> {
    let value = peer_select(app).value();
    if value.is_empty() {
        return Err("Select a serving peer for this continuity session.".into());
    }
    value
        .parse()
        .map_err(|_| "Select a serving peer for this continuity session.".into())
}

/// Reconstruct the exact session destination from the retained peer list. The
/// first advertised HTTPS route is stable: fresh evidence must repeat identical
/// endpoints, so it cannot silently move a retained session's route.
fn session_scope(app: &App, session: &Session) -> Result<(SessionScope, RoomScope), String> {
    let room = activity::scope(app, session)?;
    let author = AuthorScope::new(room, ui::activity_author()?);
    let index = peer_index(app)?;
    let raw = app
        .borrow()
        .peers
        .get(index)
        .cloned()
        .ok_or("Select a serving peer for this continuity session.")?;
    let ad = PeerAdvertisement::decode(&raw).map_err(|_| "Saved peer evidence is invalid.")?;
    let key = *ad
        .restore_sequence_anchor(session.client.network_id())
        .map_err(|_| "Saved peer signature is invalid.")?
        .application_key();
    let endpoint = ad
        .unverified_claims()
        .endpoints
        .iter()
        .find(|e| e.scheme() == Scheme::Https)
        .cloned()
        .ok_or("This peer does not advertise an HTTPS route.")?;
    let scope = SessionScope::new(author, session.head.scope(), key, endpoint)
        .map_err(|_| "The selected room, author and peer do not form a valid continuity scope.")?;
    Ok((scope, room))
}

async fn outbox() -> Result<IndexedOutbox, String> {
    IndexedOutbox::open(Namespace::new(PROFILE))
        .await
        .map_err(|_| "Could not open the local activity outbox.".into())
}

struct Driver<'a> {
    app: &'a App,
    session: &'a Session,
    storage: IndexedOutbox,
    scope: SessionScope,
    room: RoomScope,
    peer_index: usize,
}
impl Driver<'_> {
    fn floor(&self) -> wire::Observed {
        wire::Observed {
            height: self.session.client.frontier().height,
            frontier: self.session.client.frontier().commitment(),
        }
    }
    fn permit(&self, event: &VerifiedEvent) -> Result<(), String> {
        super::activity::permit(
            self.session,
            &UnsignedEvent::new(event.claims().clone())
                .map_err(|_| "The selected terminal is not a valid public event.")?,
        )
    }
    fn context(&self, state: &Snapshot) -> Result<wire::RequestContext, String> {
        Ok(wire::RequestContext {
            scope: self.room.into(),
            nonce: transport::nonce().map_err(|_| "Browser randomness is unavailable.")?,
            operation: state
                .job()
                .ok_or("No selected continuity job.")?
                .operation(),
            floor: self.floor(),
        })
    }
    fn request(&self, state: &Snapshot, kind: wire::Kind) -> Result<wire::Request, String> {
        wire::Request::new(
            self.context(state)?,
            wire::Selection::Author(self.scope.author().author()),
            kind,
        )
        .map_err(|_| "The continuity request exceeds protocol bounds.".into())
    }
    /// Re-verify the retained peer evidence locally for each exchange: fresh
    /// advertisement, this session's exact pinned route, and the capability
    /// this exchange needs. No failover or alternate route is ever selected.
    fn usable(&self, publish: bool) -> Result<(), String> {
        let raw = self
            .app
            .borrow()
            .peers
            .get(self.peer_index)
            .cloned()
            .ok_or("The session's peer is no longer selected.")?;
        let ad = PeerAdvertisement::decode(&raw).map_err(|_| "Saved peer evidence is invalid.")?;
        let clock = now(self.app.borrow().clock_floor)?;
        let verified = ad
            .verify(&policy(self.session.client.network_id(), clock), None)
            .map_err(|_| "Retained peer evidence is not fresh; sync or retry.")?;
        if verified.claims().application_key != self.scope.peer()
            || !verified.claims().endpoints.contains(self.scope.endpoint())
            || !verified.claims().capabilities.contains(Capabilities::READ)
            || (publish
                && !verified
                    .claims()
                    .capabilities
                    .contains(Capabilities::PUBLISH))
        {
            return Err("Retained fresh peer evidence does not authorize this session's exact route/service; newer evidence is preserved and no alternate route was selected.".into());
        }
        Ok(())
    }
    async fn event(&mut self, sequence: u64) -> Result<VerifiedEvent, String> {
        let author = self.scope.author();
        let head = self
            .storage
            .load_head(author)
            .await
            .map_err(|_| "Could not read the local author floor.")?
            .ok_or("No saved author state for this room.")?;
        if sequence > head.sequence()
            && self
                .storage
                .load_pending(author)
                .await
                .map_err(|_| "Could not check the saved draft state.")?
                .is_some()
        {
            return Err("The selected position is an unsigned held draft: use ordinary resume only if its exact policy still permits; nothing was signed or replaced here.".into());
        }
        if sequence == 0 || sequence > head.sequence() {
            return Err("The terminal position is not in the existing signed outbox; never infer or initialize an author.".into());
        }
        self.storage
            .read_page(author, sequence, 1, MAX_OUTBOX_PAGE_BYTES)
            .await
            .map_err(|_| "Could not verify the retained signed outbox.")?
            .events
            .into_iter()
            .next()
            .ok_or_else(|| "The exact local source frame is missing.".into())
    }
    async fn position(&mut self, sequence: u64) -> Result<wire::Position, String> {
        if sequence == 0 {
            Ok(wire::Position::EMPTY)
        } else {
            Ok(wire::Position::of(&self.event(sequence).await?))
        }
    }
    async fn exact_position(&mut self, p: wire::Position) -> Result<(), String> {
        if self.position(p.sequence()).await? != p {
            return Err("The peer position differs from the exact local signed source.".into());
        }
        Ok(())
    }
    /// Inclusive local source pages: `after` is an exclusive sequence cursor.
    async fn range(&mut self, after: u64, count: usize) -> Result<Vec<VerifiedEvent>, String> {
        if count > 32 {
            return Err("Continuity source page exceeds 32.".into());
        }
        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            let page = self
                .storage
                .read_page(
                    self.scope.author(),
                    after + 1 + out.len() as u64,
                    (count - out.len()).min(16),
                    MAX_OUTBOX_PAGE_BYTES,
                )
                .await
                .map_err(|_| "Could not verify the retained signed outbox.")?;
            if page.events.is_empty() {
                return Err("The local continuity source prefix is incomplete.".into());
            }
            out.extend(page.events);
        }
        Ok(out)
    }
    async fn exchange(
        &mut self,
        state: &mut Snapshot,
        request: wire::Request,
        body: &[u8],
        publish: bool,
    ) -> Result<wire::Reply, String> {
        let candidate = state.prepare_attempt(request, body).map_err(|_| {
            "The prepared attempt does not match this session's exact retained state."
        })?;
        *state = self.storage.publish_continuity(candidate).await.map_err(|_| {
            self.app.borrow_mut().failed = true;
            "The durable attempt reservation changed or failed. Reload to reconcile before continuing."
        })?;
        self.usable(publish)?;
        let (bytes, proof) = transport::continuity(
            self.scope.endpoint(),
            self.scope.peer(),
            &request,
            matches!(
                request.kind(),
                wire::Kind::Stage { .. } | wire::Kind::Commit { .. }
            )
            .then_some(body),
        )
        .await
        .map_err(|_| "The selected peer could not complete a valid continuity exchange. The exact request remains retained; retry the same session to continue.")?;
        let reply = proof
            .verify(self.scope.peer(), &request, &bytes)
            .map_err(|_| "The peer's signed continuity proof is invalid.".to_string())?
            .reply()
            .clone();
        match &reply {
            wire::Reply::Status(s) => {
                self.exact_position(s.published).await?;
                if let Some(ticket) = s.stage {
                    self.exact_position(ticket.tail()).await?;
                }
            }
            wire::Reply::Staged(s) => self.exact_position(s.ticket.tail()).await?,
            wire::Reply::Evidence(p) => self.exact_position(p.tip).await?,
            wire::Reply::Committed(_) => (),
            wire::Reply::Feed(_) => {
                return Err("A room feed cannot install author continuity receipts.".into())
            }
        }
        let candidate = state
            .prepare_response(&proof, &bytes)
            .map_err(|_| "The verified reply does not match the retained attempt.")?;
        *state = self.storage.publish_continuity(candidate).await.map_err(|_| {
            self.app.borrow_mut().failed = true;
            "The peer replied, but its exact evidence could not be retained. Reload to reconcile before continuing."
        })?;
        Ok(reply)
    }
    async fn current_role(&mut self, state: &Snapshot) -> Result<bool, String> {
        let Some(reference) = state.retention().record() else {
            return Ok(false);
        };
        let record = self
            .storage
            .continuity_record(self.scope.clone(), state.limits(), reference.index())
            .await
            .map_err(|_| "Could not read the retained continuity evidence.")?
            .ok_or("Retained continuity evidence is missing.")?;
        if record.reference() != reference {
            return Err("The retained evidence reference changed.".into());
        }
        Ok(
            matches!(record.reply(), wire::Reply::Evidence(p) if p.entries.last().is_some_and(|e|
                e.role == wire::EvidenceRole::CurrentAdmission
                    && wire::Position::of(&e.event) == state.retention().position())),
        )
    }
    async fn load(&mut self) -> Result<Snapshot, String> {
        self.storage
            .load_continuity(self.scope.clone(), RECEIPT_LIMITS)
            .await
            .map_err(|_| {
                "No continuity receipt session exists for this author/peer/route; start one first."
                    .into()
            })
    }
    async fn step(&mut self) -> Result<(Snapshot, usize, Option<String>), String> {
        let mut state = self.load().await?;
        let job = state
            .job()
            .ok_or("Select a fixed terminal sequence first.")?;
        let terminal = self.event(job.terminal().sequence()).await?;
        if wire::Position::of(&terminal) != job.terminal()
            || ContinuityJob::new(job.operation(), &terminal)
                .map(|candidate| candidate.frame_hash() != job.frame_hash())
                .unwrap_or(true)
        {
            return Err("The selected terminal's local source changed.".into());
        }
        if state.complete() {
            return Ok((state, 0, None));
        }
        // Refresh the session's exact peer once per step. The per-exchange
        // usable() check still requires the retained fresh evidence to list
        // this session's pinned route; no other advertised route is dialed.
        let mut budget = READS_PER_ACTION;
        let (peer, _) =
            activity::fresh_peer(self.app, self.session, self.peer_index, false, &mut budget)
                .await?;
        if peer != self.scope.peer() {
            return Err("The refreshed peer identity differs from this session's pinned peer; no alternate route was selected.".into());
        }
        let mut exchanges = 0usize;
        let result: Result<(), String> = async {
            let request = self.request(
                &state,
                wire::Kind::Status {
                    minimum: state.retention().position(),
                },
            )?;
            exchanges += 1;
            let wire::Reply::Status(mut remote) =
                self.exchange(&mut state, request, &[], false).await?
            else {
                return Err("The status reply has the wrong role.".into());
            };
            if remote.published.sequence() > job.terminal().sequence() {
                return Err("The peer already published beyond this fixed target; explicitly select a later retained terminal.".into());
            }
            while exchanges < EXCHANGES && !state.complete() {
                let at = now(self.app.borrow().clock_floor)?;
                if remote.published.sequence() > state.retention().position().sequence() {
                    self.usable(false)?;
                    let count = (remote.published.sequence()
                        - state.retention().position().sequence())
                    .min(32) as u8;
                    let request = self.request(
                        &state,
                        wire::Kind::Evidence {
                            after: state.retention().position(),
                            count,
                        },
                    )?;
                    exchanges += 1;
                    let wire::Reply::Evidence(page) =
                        self.exchange(&mut state, request, &[], false).await?
                    else {
                        return Err("The evidence reply has the wrong role.".into());
                    };
                    // Another publication may have happened since Status. Never
                    // adopt its position as retention; the next exact page proves it.
                    if page.tip.sequence() > job.terminal().sequence() {
                        return Err("The peer advanced beyond the fixed target; preserve evidence and explicitly select a later terminal.".into());
                    }
                    remote.published = page.tip;
                    remote.observed = page.observed;
                    remote.stage = None;
                    continue;
                }
                if remote.published != state.retention().position() {
                    return Err("The peer's published base differs from the retained evidence.".into());
                }
                let reconcile = state.retention().position() == job.terminal();
                let (base, stage, phase) = if reconcile {
                    if !self.current_role(&state).await? {
                        return Err("The selected target is immutable historical-only evidence; select a later admitted terminal.".into());
                    }
                    (
                        self.position(job.terminal().sequence() - 1).await?,
                        None,
                        terminal.clone(),
                    )
                } else {
                    if remote.observed.height > self.floor().height {
                        return Err("The peer reports a newer checkpoint; sync certified history before fresh work.".into());
                    }
                    self.permit(&terminal).map_err(|e| format!("The fixed terminal is not current-policy permitted; preserve it and any held draft: {e}"))?;
                    // One admission is bounded by the peer's staged-ancestor
                    // budget; a farther selected target advances through ordered
                    // intermediate admissions of exact signed local events.
                    let phase_seq = job
                        .terminal()
                        .sequence()
                        .min(remote.published.sequence().saturating_add(admission_bound() + 1));
                    let phase = if phase_seq == job.terminal().sequence() {
                        terminal.clone()
                    } else {
                        let phase = self.event(phase_seq).await?;
                        self.permit(&phase).map_err(|e| format!("The intermediate terminal is not current-policy permitted; preserve evidence and any held draft: {e}"))?;
                        phase
                    };
                    if remote.stage.is_some_and(|s| s.expires_at() <= at) {
                        return Err("The temporary stage expired; preserve the source and retry Status after peer maintenance.".into());
                    }
                    (remote.published, remote.stage, phase)
                };
                self.usable(true)?;
                let tail = stage.map_or(base, |s| s.tail());
                if tail.sequence() >= wire::Position::of(&phase).sequence() {
                    return Err("The temporary stage reaches the current admission terminal; no implicit target substitution.".into());
                }
                let remaining = wire::Position::of(&phase).sequence() - tail.sequence() - 1;
                let (request, body) = if remaining > 32 {
                    let body = wire::Body::stage(self.range(tail.sequence(), 32).await?)
                        .map_err(|_| "Could not form a fixed stage body.")?;
                    let request = wire::Request::stage(
                        self.context(&state)?,
                        self.scope.author().author(),
                        base,
                        stage,
                        &body,
                    )
                    .map_err(|_| "Could not form a stage request.")?;
                    (request, body.encode())
                } else {
                    let body = wire::Body::commit(
                        self.range(tail.sequence(), remaining as usize).await?,
                        phase.clone(),
                    )
                    .map_err(|_| "Could not form a commit body.")?;
                    let request = wire::Request::commit(
                        self.context(&state)?,
                        self.scope.author().author(),
                        base,
                        stage,
                        &body,
                    )
                    .map_err(|_| "Could not form a commit request.")?;
                    (request, body.encode())
                };
                // Recheck after local frame loading, immediately before the
                // mutation reservation and network exchange.
                if !reconcile {
                    self.permit(&phase)?;
                }
                exchanges += 1;
                match self.exchange(&mut state, request, &body, true).await? {
                    wire::Reply::Staged(ack) => {
                        remote.stage = Some(ack.ticket);
                        remote.observed = ack.observed;
                    }
                    wire::Reply::Committed(receipt) => {
                        remote.published = wire::Position::of(&receipt.event);
                        remote.stage = None;
                        remote.observed = receipt.observed;
                    }
                    _ => return Err("The mutation reply has the wrong role.".into()),
                }
            }
            Ok(())
        }
        .await;
        let error = result.err();
        Ok((state, exchanges, error))
    }
}

fn describe(app: &App, room: RoomScope, state: &Snapshot, line: &str, exchanges: usize) {
    let scope = state.scope();
    let mut lines = vec![format!(
        "status: {line}\nroom: {}\nauthor: {}…\npeer: {}…\nendpoint: {}",
        hex(room.room.as_bytes()),
        &hex(&scope.author().author())[..12],
        &hex(&scope.peer())[..12],
        scope.endpoint().as_str()
    )];
    if let Some(job) = state.job() {
        lines.push(format!(
            "fixed target: sequence {} · event {}\nretained through: {}\nrecords: {} · generation {}",
            job.terminal().sequence(),
            hex(job.terminal().event_id().as_bytes()),
            state.retention().position().sequence(),
            state.record_count(),
            state.generation()
        ));
    }
    lines.push(format!(
        "exchanges this step: {exchanges}/{EXCHANGES}\ncomplete: {}\nThis peer's receipts attest only to that peer's retention; they are not global delivery, and an unsigned held draft is never touched.",
        state.complete()
    ));
    report_text(app, &lines.join("\n"));
}

/// Create the explicit new receipt session; an existing exact prefix refuses.
async fn begin(app: &App, session: &Session) -> Result<(), String> {
    let (scope, room) = session_scope(app, session)?;
    let mut storage = outbox().await?;
    if storage
        .load_head(scope.author())
        .await
        .map_err(|_| "Could not read the local author floor.")?
        .is_none_or(|head| head.sequence() == 0)
    {
        return Err("There are no signed posts to transfer for this room.".into());
    }
    let state = storage
        .create_continuity(scope, RECEIPT_LIMITS)
        .await
        .map_err(|_| {
            "A continuity receipt session already exists for this exact author/peer/route, or the local source is missing; select a terminal on the existing session."
        })?;
    describe(app, room, &state, "receipt-session-created-no-dial", 0);
    status(
        app,
        "New continuity receipt session created. No request was sent; choose the fixed terminal sequence next.",
    );
    Ok(())
}

/// Select or re-select the fixed terminal; only strictly later terminals replace.
async fn select_terminal(app: &App, session: &Session) -> Result<(), String> {
    let (scope, room) = session_scope(app, session)?;
    let raw = field(app, "continuity-terminal").value();
    let terminal_seq: u64 = raw
        .parse()
        .ok()
        .filter(|_| raw.bytes().all(|b| b.is_ascii_digit()))
        .ok_or("Enter the exact author sequence to retain through, as an unsigned decimal.")?;
    let mut driver = Driver {
        app,
        session,
        storage: outbox().await?,
        scope,
        peer_index: peer_index(app)?,
        room,
    };
    let state = driver.load().await?;
    let terminal = driver.event(terminal_seq).await?;
    let job = match state.job().filter(|job| {
        job.terminal() == wire::Position::of(&terminal)
            && ContinuityJob::new(job.operation(), &terminal)
                .is_ok_and(|candidate| candidate.frame_hash() == job.frame_hash())
    }) {
        Some(job) => job,
        None => {
            let mut operation = [0; 16];
            web_sys::window()
                .ok_or("This browser context is unavailable.")?
                .crypto()
                .map_err(|_| "Browser randomness is unavailable.")?
                .get_random_values_with_u8_array(&mut operation)
                .map_err(|_| "Browser randomness is unavailable.")?;
            if operation == [0; 16] {
                return Err("Browser randomness returned an unusable operation id.".into());
            }
            ContinuityJob::new(operation, &terminal)
                .map_err(|_| "The selected terminal cannot form a continuity job.")?
        }
    };
    let state = driver
        .storage
        .publish_continuity(state.prepare_job(job).map_err(|_| {
            "Only a byte-identical retry or a strictly later retained terminal replaces the current selection."
        })?)
        .await
        .map_err(|_| {
            app.borrow_mut().failed = true;
            "The terminal selection could not be retained. Reload to reconcile before continuing."
        })?;
    describe(app, room, &state, "fixed-terminal-selected-no-dial", 0);
    status(
        app,
        "Fixed terminal retained locally. Nothing was sent; run a continuity step to exchange with the selected peer.",
    );
    Ok(())
}

async fn status_local(app: &App, session: &Session) -> Result<(), String> {
    let (scope, room) = session_scope(app, session)?;
    let mut driver = Driver {
        app,
        session,
        storage: outbox().await?,
        scope,
        peer_index: 0,
        room,
    };
    let state = driver.load().await?;
    describe(app, room, &state, "local-receipt-status-no-dial", 0);
    status(
        app,
        "Local continuity receipt state; no peer request was sent.",
    );
    Ok(())
}

async fn run_step(app: &App, session: &Session) -> Result<(), String> {
    let (scope, room) = session_scope(app, session)?;
    let mut driver = Driver {
        app,
        session,
        storage: outbox().await?,
        scope,
        peer_index: peer_index(app)?,
        room,
    };
    let (state, exchanges, error) = driver.step().await?;
    let line = if error.is_some() {
        "attempt-stopped"
    } else if state.complete() {
        "one-peer-retention-complete"
    } else {
        "more"
    };
    describe(app, room, &state, line, exchanges);
    match error {
        None if state.complete() => status(
            app,
            "The selected peer retains the exact terminal and its contiguous evidence. This is that peer's receipt only, not global delivery.",
        ),
        None => status(
            app,
            "Continuity step retained new evidence. Run the step again until the fixed target completes.",
        ),
        Some(error) => return Err(error),
    }
    Ok(())
}

pub(super) fn render(app: &App, session: Option<&Session>, available: bool, room_selected: bool) {
    let ready = session.is_some_and(|s| s.head == s.recovery_target);
    let select = peer_select(app);
    let previous = select.value();
    select.set_text_content(None);
    if let (true, Some(session)) = (ready, session) {
        for (i, raw) in app.borrow().peers.iter().enumerate() {
            let label = PeerAdvertisement::decode(raw)
                .ok()
                .and_then(|ad| ad.restore_sequence_anchor(session.client.network_id()).ok())
                .map(|anchor| {
                    let key = hex(anchor.application_key());
                    format!("Peer {}…{}", &key[..8], &key[56..])
                })
                .unwrap_or_else(|| format!("Peer {}", i + 1));
            let option = app.borrow().document.create_element("option").unwrap();
            let _ = option.set_attribute("value", &i.to_string());
            option.set_text_content(Some(&label));
            let _ = select.append_child(&option);
        }
    }
    if !previous.is_empty() {
        select.set_value(&previous);
    }
    let enabled =
        available && ready && room_selected && ui::activity_author().is_ok() && select.length() > 0;
    select.set_disabled(!enabled);
    field(app, "continuity-terminal").set_disabled(!enabled);
    for id in [
        "continuity-begin",
        "continuity-select",
        "continuity-step",
        "continuity-status-button",
    ] {
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!enabled);
    }
}

pub(super) fn bind_actions(app: &App) {
    for (id, operation) in [
        ("continuity-begin", 0usize),
        ("continuity-select", 1),
        ("continuity-step", 2),
        ("continuity-status-button", 3),
    ] {
        let app = app.clone();
        let document = app.borrow().document.clone();
        let callback = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            {
                let mut state = app.borrow_mut();
                if state.busy
                    || state.failed
                    || !state
                        .session
                        .as_ref()
                        .is_some_and(|s| s.head == s.recovery_target)
                {
                    return;
                }
                state.busy = true;
            }
            super::render(&app);
            let app = app.clone();
            launch(app.clone(), async move {
                let session = app.borrow_mut().session.take().unwrap();
                let result = match operation {
                    0 => begin(&app, &session).await,
                    1 => select_terminal(&app, &session).await,
                    2 => run_step(&app, &session).await,
                    _ => status_local(&app, &session).await,
                };
                app.borrow_mut().session = Some(session);
                if let Err(error) = result {
                    status(&app, &error);
                }
                finish(&app, Ok(()));
            });
        });
        document
            .get_element_by_id(id)
            .unwrap()
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .unwrap();
        callback.forget();
    }
}
