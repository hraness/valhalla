//! Fixed-target continuity transfer. No identity/signing or v1 receipt conversion.
use super::*;
use crate::public_network::activity::Context;
use vhalla_browser_storage::{
    native::continuity::NativeContinuity,
    outbox::continuity::{ContinuityJob, Limits, SessionScope, Snapshot},
};
use vhalla_public_protocol::continuity as wire;
use vhalla_room_activity::{UnsignedEvent, VerifiedEvent};

pub(in crate::public_network::activity) const HELP: &str = "vhalla public activity continuity-init|continuity-select BOOTSTRAP PIN64 OUTBOX ROOM64 AUTHOR64 PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT RECEIPTS MAX_RECORDS MAX_BYTES TERMINAL_SEQUENCE\nvhalla public activity continuity-status BOOTSTRAP PIN64 OUTBOX ROOM64 AUTHOR64 PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT RECEIPTS MAX_RECORDS MAX_BYTES\nvhalla public activity continuity-step BOOTSTRAP PIN64 OUTBOX ROOM64 AUTHOR64 PEER_STATE PEER64 EXACT_HTTPS_ENDPOINT RECEIPTS MAX_RECORDS MAX_BYTES JOURNAL [--replay-profile PROFILE]\ninit exclusively creates receipt custody; select opens it and explicitly selects a retained signed terminal (same exact selection resumes, only later selections replace it). status is local. step refreshes the exact peer and performs at most 3 continuity exchanges inside the existing 90-second total supervisor; certified replay retains its 4096-bundle/30-second bound. Status/Stage are hints; terminal admission and verified peer-retained prefix are separate. No key use, draft recovery, author reset, v1 delivery conversion, peer failover or automatic migration. Preserve every existing directory after uncertainty. An unsigned old-policy pending draft may need separate explicit recovery, which this command does not implement.";
const EXCHANGES: usize = 3;
const MAX_ANCESTORS: u64 = 4096 + 32;

pub(in crate::public_network::activity) fn recognizes(command: &str) -> bool {
    matches!(
        command,
        "continuity-init" | "continuity-select" | "continuity-status" | "continuity-step"
    )
}

trait ContinuityTransport: Transport {
    fn continuity(
        &mut self,
        route: &Endpoint,
        request: &wire::Request,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String>;
}
impl ContinuityTransport for Curl {
    fn continuity(
        &mut self,
        route: &Endpoint,
        request: &wire::Request,
        body: Option<&[u8]>,
        cancel: &AtomicBool,
    ) -> Result<(Vec<u8>, String), String> {
        http::exchange_continuity(route, request, body, cancel)
    }
}
// Deliberately private and narrow: production uses only the existing checked
// certified Context. Synthetic tests can exercise transport/storage failures.
trait Policy {
    fn floor(&self) -> wire::Observed;
    fn permit(&self, event: &VerifiedEvent) -> Result<(), String>;
}
impl Policy for Context {
    fn floor(&self) -> wire::Observed {
        wire::Observed {
            height: self.client.frontier().height,
            frontier: self.client.frontier().commitment(),
        }
    }
    fn permit(&self, event: &VerifiedEvent) -> Result<(), String> {
        // Includes scope, exact current policy revision and final journal HEAD.
        Context::permit(
            self,
            &UnsignedEvent::new(event.claims().clone()).map_err(preserved)?,
        )
    }
}

fn bounded_span(base: u64, terminal: u64) -> Result<(), String> {
    let ancestors = terminal
        .checked_sub(base)
        .and_then(|n| n.checked_sub(1))
        .ok_or("fixed terminal does not follow the published base")?;
    if ancestors > MAX_ANCESTORS {
        return Err("fixed target exceeds 4096 staged plus 32 inline ancestors; no automatic intermediate terminal".into());
    }
    Ok(())
}

fn canonical(raw: &str, label: &str) -> Result<u64, String> {
    let n: u64 = raw.parse().map_err(|_| format!("invalid {label}"))?;
    if n.to_string() != raw {
        return Err(format!("{label} must be canonical unsigned decimal"));
    }
    Ok(n)
}
fn operation() -> Result<[u8; 16], String> {
    for _ in 0..2 {
        let mut value = [0; 16];
        getrandom::fill(&mut value).map_err(|_| "secure operation entropy unavailable")?;
        if value != [0; 16] {
            return Ok(value);
        }
    }
    Err("secure operation entropy returned zero twice".into())
}
fn event(source: &NativeOutbox, sequence: u64) -> Result<VerifiedEvent, String> {
    if sequence > source.head().map_err(preserved)?.sequence()
        && source.load_pending().map_err(preserved)?.is_some()
    {
        return Err("selected position is an unsigned held draft: use ordinary resume only if its exact policy still permits; explicit old-policy draft recovery is unavailable here; nothing signed or replaced".into());
    }
    if sequence == 0 || sequence > source.head().map_err(preserved)?.sequence() {
        return Err("terminal/source position is not in the existing signed outbox; never infer or initialize an author".into());
    }
    source
        .read_page(sequence - 1, 1)
        .map_err(preserved)?
        .events
        .into_iter()
        .next()
        .ok_or_else(|| "exact local source frame missing".into())
}
fn position(source: &NativeOutbox, sequence: u64) -> Result<wire::Position, String> {
    if sequence == 0 {
        Ok(wire::Position::EMPTY)
    } else {
        Ok(wire::Position::of(&event(source, sequence)?))
    }
}
fn exact_position(source: &NativeOutbox, p: wire::Position) -> Result<(), String> {
    if position(source, p.sequence())? != p {
        return Err("peer position differs from exact local signed source".into());
    }
    Ok(())
}
fn range(source: &NativeOutbox, after: u64, count: usize) -> Result<Vec<VerifiedEvent>, String> {
    if count > 32 {
        return Err("continuity source page exceeds 32".into());
    }
    let mut out = Vec::with_capacity(count);
    while out.len() < count {
        let next = source
            .read_page(after + out.len() as u64, (count - out.len()).min(16))
            .map_err(preserved)?;
        if next.events.is_empty() {
            return Err("continuity source prefix is incomplete".into());
        }
        out.extend(next.events);
    }
    Ok(out)
}
fn select(
    source: &NativeOutbox,
    receipts: &mut NativeContinuity,
    terminal: &VerifiedEvent,
) -> Result<Snapshot, String> {
    let state = receipts.snapshot(source).map_err(preserved)?;
    let same = state.job().filter(|job| {
        job.terminal() == wire::Position::of(terminal)
            && job.frame_hash() == <[u8; 32]>::from(Sha256::digest(terminal.encode()))
    });
    let job = match same {
        Some(job) => job,
        None => ContinuityJob::new(operation()?, terminal).map_err(preserved)?,
    };
    receipts
        .publish(source, state.prepare_job(job).map_err(preserved)?)
        .map_err(preserved)
}

struct Submission<'a> {
    request: wire::Request,
    body: &'a [u8],
    fresh: bool,
}

struct Controller<'a> {
    peer: &'a mut NativePeerSession,
    source: &'a NativeOutbox,
    receipts: &'a mut NativeContinuity,
    policy: &'a dyn Policy,
}
impl Controller<'_> {
    fn context(&self, state: &Snapshot) -> Result<wire::RequestContext, String> {
        let claims = event(
            self.source,
            state
                .job()
                .ok_or("no selected terminal; use continuity-select")?
                .terminal()
                .sequence(),
        )?
        .claims()
        .clone();
        Ok(wire::RequestContext {
            scope: claims.scope.into(),
            nonce: nonce()?,
            operation: state.job().ok_or("no selected job")?.operation(),
            floor: self.policy.floor(),
        })
    }
    fn request(&self, state: &Snapshot, kind: wire::Kind) -> Result<wire::Request, String> {
        wire::Request::new(
            self.context(state)?,
            wire::Selection::Author(state.scope().author().author()),
            kind,
        )
        .map_err(|e| format!("continuity request: {e:?}"))
    }
    fn exchange(
        &mut self,
        state: &mut Snapshot,
        selected: &mut PeerSelection,
        submission: Submission<'_>,
        transport: &mut impl ContinuityTransport,
        clock: &impl Fn() -> Result<u64, String>,
        cancel: &AtomicBool,
    ) -> Result<wire::Reply, String> {
        let Submission {
            request,
            body,
            fresh,
        } = submission;
        cancelled(cancel)?;
        *state = self
            .receipts
            .publish(
                self.source,
                state.prepare_attempt(request, body).map_err(preserved)?,
            )
            .map_err(preserved)?;
        cancelled(cancel)?;
        let is_post = matches!(
            request.kind(),
            wire::Kind::Stage { .. } | wire::Kind::Commit { .. }
        );
        let at = clock()?;
        *selected = self
            .peer
            .checkpoint_clock(selected, at)
            .map_err(preserved)?;
        usable(selected, at, is_post)?;
        if fresh {
            let terminal = event(
                self.source,
                state
                    .job()
                    .ok_or("no selected terminal")?
                    .terminal()
                    .sequence(),
            )?;
            self.policy.permit(&terminal)?; // After durable reservation, before HTTP.
        }
        cancelled(cancel)?;
        let (bytes, proof) = transport.continuity(
            selected.endpoint(),
            &request,
            is_post.then_some(body),
            cancel,
        )?;
        cancelled(cancel)?;
        let proof = wire::ResponseProof::from_hex(&proof)
            .map_err(|e| format!("continuity proof framing: {e:?}"))?;
        let reply = proof
            .verify(selected.peer(), &request, &bytes)
            .map_err(|e| format!("continuity peer proof: {e:?}"))?
            .reply()
            .clone();
        // Extra range checks precede publication; the model independently checks
        // exact bytes/roles and the store compares the actual local source again.
        match &reply {
            wire::Reply::Status(s) => {
                exact_position(self.source, s.published)?;
                if let Some(ticket) = s.stage {
                    exact_position(self.source, ticket.tail())?;
                }
            }
            wire::Reply::Staged(s) => exact_position(self.source, s.ticket.tail())?,
            wire::Reply::Evidence(p) => exact_position(self.source, p.tip)?,
            wire::Reply::Committed(_) => (),
            wire::Reply::Feed(_) => {
                return Err("feed cannot install author continuity receipts".into())
            }
        }
        let candidate = state.prepare_response(&proof, &bytes).map_err(preserved)?;
        cancelled(cancel)?;
        *state = self
            .receipts
            .publish(self.source, candidate)
            .map_err(preserved)?;
        Ok(reply)
    }
    fn current_role(&mut self, state: &Snapshot) -> Result<bool, String> {
        let Some(reference) = state.retention().record() else {
            return Ok(false);
        };
        let record = self
            .receipts
            .read_record(self.source, reference.index())
            .map_err(preserved)?
            .ok_or("retained Evidence record missing")?;
        if record.reference() != reference {
            return Err("retained Evidence reference changed".into());
        }
        Ok(
            matches!(record.reply(), wire::Reply::Evidence(p) if p.entries.last().is_some_and(|e|
            e.role == wire::EvidenceRole::CurrentAdmission && wire::Position::of(&e.event) == state.retention().position())),
        )
    }
    fn step(
        &mut self,
        transport: &mut impl ContinuityTransport,
        clock: &impl Fn() -> Result<u64, String>,
        cancel: &AtomicBool,
    ) -> Result<SendOutcome, String> {
        let mut state = self.receipts.snapshot(self.source).map_err(preserved)?;
        let selected = self.peer.selection().map_err(preserved)?;
        if state.scope().history() != selected.scope()
            || state.scope().peer() != selected.peer()
            || state.scope().endpoint() != selected.endpoint()
            || state.scope().author() != self.source.head().map_err(preserved)?.scope()
        {
            return Err("receipt/source/selected peer scopes differ".into());
        }
        let job = state
            .job()
            .ok_or("no selected terminal; use continuity-select")?;
        let terminal = event(self.source, job.terminal().sequence())?;
        if wire::Position::of(&terminal) != job.terminal()
            || <[u8; 32]>::from(Sha256::digest(terminal.encode())) != job.frame_hash()
        {
            return Err("selected terminal source changed".into());
        }
        let mut exchanges = 0usize;
        let result = (|| {
            cancelled(cancel)?;
            if state.complete() {
                return Ok(());
            }
            let mut selected = refresh(self.peer, transport, clock, false, cancel)?;
            let at = clock()?;
            selected = self
                .peer
                .checkpoint_clock(&selected, at)
                .map_err(preserved)?;
            usable(&selected, at, false)?;
            let request = self.request(
                &state,
                wire::Kind::Status {
                    minimum: state.retention().position(),
                },
            )?;
            exchanges += 1;
            let wire::Reply::Status(mut remote) = self.exchange(
                &mut state,
                &mut selected,
                Submission {
                    request,
                    body: &[],
                    fresh: false,
                },
                transport,
                clock,
                cancel,
            )?
            else {
                return Err("Status reply has wrong role".into());
            };
            if remote.published.sequence() > job.terminal().sequence() {
                return Err("peer already published beyond this fixed target; explicitly select a later retained terminal".into());
            }
            while exchanges < EXCHANGES && !state.complete() {
                cancelled(cancel)?;
                let at = clock()?;
                selected = self
                    .peer
                    .checkpoint_clock(&selected, at)
                    .map_err(preserved)?;
                if remote.published.sequence() > state.retention().position().sequence() {
                    usable(&selected, at, false)?;
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
                    let wire::Reply::Evidence(page) = self.exchange(
                        &mut state,
                        &mut selected,
                        Submission {
                            request,
                            body: &[],
                            fresh: false,
                        },
                        transport,
                        clock,
                        cancel,
                    )?
                    else {
                        return Err("Evidence reply has wrong role".into());
                    };
                    // Another publication may have happened since Status. Never
                    // adopt its position as retention; the next exact page proves it.
                    if page.tip.sequence() > job.terminal().sequence() {
                        return Err("peer advanced beyond fixed target; preserve evidence and explicitly select a later terminal".into());
                    }
                    remote.published = page.tip;
                    remote.observed = page.observed;
                    remote.stage = None;
                    continue;
                }
                if remote.published != state.retention().position() {
                    return Err("peer published base differs from retained evidence".into());
                }
                let reconcile = state.retention().position() == job.terminal();
                let (base, stage) = if reconcile {
                    if !self.current_role(&state)? {
                        return Err("selected target is immutable historical-only evidence; select a later admitted terminal".into());
                    }
                    (position(self.source, job.terminal().sequence() - 1)?, None)
                } else {
                    let floor = self.policy.floor();
                    if remote.observed.height > floor.height {
                        return Err("peer reports a newer checkpoint; obtain independently certified journal catch-up before fresh work".into());
                    }
                    // No CLI historical verifier or signing fallback. The old
                    // unsigned reservation remains exactly where its author left it.
                    self.policy.permit(&terminal).map_err(|e| format!("fixed terminal is not current-policy permitted; preserve it and any held draft; explicit old-draft recovery is unavailable: {e}"))?;
                    bounded_span(remote.published.sequence(), job.terminal().sequence())?;
                    if remote.stage.is_some_and(|s| s.expires_at() <= at) {
                        return Err("temporary stage expired; preserve source and retry Status after peer maintenance; no lease extension inferred".into());
                    }
                    (remote.published, remote.stage)
                };
                usable(&selected, at, true)?;
                let tail = stage.map_or(base, |s| s.tail());
                if tail.sequence() >= job.terminal().sequence() {
                    return Err("temporary stage reaches/passes fixed terminal; no implicit target substitution".into());
                }
                let remaining = job.terminal().sequence() - tail.sequence() - 1;
                let context = self.context(&state)?;
                let (request, body) = if remaining > 32 {
                    let body = wire::Body::stage(range(self.source, tail.sequence(), 32)?)
                        .map_err(preserved)?;
                    let request = wire::Request::stage(
                        context,
                        state.scope().author().author(),
                        base,
                        stage,
                        &body,
                    )
                    .map_err(preserved)?;
                    (request, body.encode())
                } else {
                    let body = wire::Body::commit(
                        range(self.source, tail.sequence(), remaining as usize)?,
                        terminal.clone(),
                    )
                    .map_err(preserved)?;
                    let request = wire::Request::commit(
                        context,
                        state.scope().author().author(),
                        base,
                        stage,
                        &body,
                    )
                    .map_err(preserved)?;
                    (request, body.encode())
                };
                // Recheck after local frame loading/preparation, immediately
                // before persisting the outbound attempt and entering transport.
                if !reconcile {
                    self.policy.permit(&terminal)?;
                }
                exchanges += 1;
                match self.exchange(
                    &mut state,
                    &mut selected,
                    Submission {
                        request,
                        body: &body,
                        fresh: !reconcile,
                    },
                    transport,
                    clock,
                    cancel,
                )? {
                    wire::Reply::Staged(ack) => {
                        remote.stage = Some(ack.ticket);
                        remote.observed = ack.observed;
                    }
                    wire::Reply::Committed(receipt) => {
                        remote.published = wire::Position::of(&receipt.event);
                        remote.stage = None;
                        remote.observed = receipt.observed;
                    }
                    _ => return Err("mutation reply has wrong role".into()),
                }
            }
            Ok(())
        })();
        Ok(SendOutcome {
            report: report(
                &state,
                terminal.claims().scope,
                if result.is_err() {
                    "attempt-stopped"
                } else if state.complete() {
                    "one-peer-retention-complete"
                } else {
                    "more"
                },
                exchanges,
                self.peer.needs_reopen() || self.receipts.needs_reopen(),
            ),
            error: result.err(),
        })
    }
}

fn report(
    state: &Snapshot,
    room: RoomScope,
    status: &str,
    exchanges: usize,
    needs_reopen: bool,
) -> Value {
    let scope = state.scope();
    json!({"format":"vhalla-continuity-client/1", "status":status, "network":hex(&scope.author().network()),
        "bootstrapPin":hex(&scope.history().bootstrap_pin()), "realm":format!("{:032x}",room.realm.0),
        "directory":hex(room.directory.as_bytes()), "room":hex(room.room.as_bytes()),
        "author":hex(&scope.author().author()), "peer":hex(&scope.peer()), "endpoint":scope.endpoint().as_str(),
        "operation":state.job().map(|j|hex(&j.operation())), "targetSequence":state.job().map(|j|j.terminal().sequence().to_string()),
        "targetEvent":state.job().map(|j|hex(j.terminal().event_id().as_bytes())),
        "terminalAdmission":state.terminal().map(|t|json!({"sequence":t.position().sequence().to_string(),"event":hex(t.position().event_id().as_bytes()),"peerCursor":t.cursor().to_string(),"registry":hex(&t.registry())})),
        "peerAssertedRetainedThrough":state.retention().position().sequence().to_string(), "complete":state.complete(),
        "records":state.record_count().to_string(), "generation":state.generation().to_string(),
        "attemptPending":state.attempt().is_some(), "continuityAttempts":exchanges,"maxContinuityExchanges":EXCHANGES,
        "maxAdvertisementRefreshes":1,"needsReopen":needs_reopen,"v1Delivery":"unchanged","globalDelivery":"not-established",
        "heldUnsignedDraftRecovery":"not-supported-no-signing"})
}

fn run_inner(args: &[OsString], profile: Option<&Path>, cancel: &AtomicBool) -> Result<(), String> {
    let arg = |i: usize| args[i].to_str().ok_or("arguments must be UTF-8");
    let command = arg(2)?;
    let pin = hex32(arg(4)?)?;
    let bootstrap_path = Path::new(&args[3]);
    let bootstrap = Bootstrap::decode(&bytes(bootstrap_path, MAX_BOOTSTRAP_BYTES)?, pin)
        .map_err(|e| format!("pinned bootstrap: {e:?}"))?;
    let client =
        CertifiedClient::new(bootstrap, pin).map_err(|e| format!("network genesis: {e:?}"))?;
    let history = HistoryScope::new(client.network_id(), pin);
    let room = scope(&client, hex32(arg(6)?)?);
    let author = AuthorScope::new(room, hex32(arg(7)?)?);
    let peer = hex32(arg(9)?)?;
    let route = endpoint(arg(10)?)?;
    let limits = Limits {
        max_records: canonical(arg(12)?, "receipt record limit")?,
        max_bytes: canonical(arg(13)?, "receipt byte limit")?,
    };
    if !(1..=1_000_000).contains(&limits.max_records)
        || !(1..=8 * 1024 * 1024 * 1024).contains(&limits.max_bytes)
    {
        return Err("receipt limits exceed fixed format bounds".into());
    }
    let mut context = if command == "continuity-step" {
        Some(Context::load_paths(
            bootstrap_path,
            pin,
            Path::new(&args[14]),
            room.room,
            profile.map(|p| (p, false)),
        )?)
    } else {
        None
    };
    let mut peer_session =
        NativePeerSession::open(Path::new(&args[8]), history, peer, &route).map_err(preserved)?;
    let mut source = NativeOutbox::open(Path::new(&args[5]), author, history).map_err(preserved)?;
    let selected = SessionScope::new(author, history, peer, route).map_err(preserved)?;
    let terminal = if matches!(command, "continuity-init" | "continuity-select") {
        Some(event(&source, canonical(arg(14)?, "terminal sequence")?)?)
    } else {
        None
    };
    let mut receipts = if command == "continuity-init" {
        NativeContinuity::create_new(Path::new(&args[11]), selected, limits, &source)
    } else {
        NativeContinuity::open(Path::new(&args[11]), selected, limits, &source)
    }
    .map_err(preserved)?;
    if let Some(terminal) = terminal {
        let state = select(&source, &mut receipts, &terminal)?;
        println!(
            "{}",
            report(&state, room, "fixed-terminal-selected-no-dial", 0, false)
        );
        return Ok(());
    }
    if let Some(context) = context.as_mut() {
        let retained = source.history_head().map_err(preserved)?;
        if !context.replay_step(Some(retained))? {
            let state = receipts.snapshot(&source).map_err(preserved)?;
            println!(
                "{}",
                report(&state, room, "more-policy-replay-no-network", 0, false)
            );
            return Ok(());
        }
        if context.head != retained {
            source
                .advance_history(retained, context.head)
                .map_err(preserved)?;
        }
        context.check_current()?;
        http::preflight()?;
        let outcome = Controller {
            peer: &mut peer_session,
            source: &source,
            receipts: &mut receipts,
            policy: context,
        }
        .step(&mut Curl, &now, cancel)?;
        println!("{}", outcome.report);
        if let Some(error) = outcome.error {
            return Err(error);
        }
    } else {
        let state = receipts.snapshot(&source).map_err(preserved)?;
        println!(
            "{}",
            report(&state, room, "local-receipt-status-no-dial", 0, false)
        );
    }
    Ok(())
}

pub(in crate::public_network::activity) fn run(
    args: &[OsString],
    profile: Option<&Path>,
) -> Result<(), String> {
    let command = args.get(2).and_then(|v| v.to_str()).ok_or(HELP)?;
    let count = match command {
        "continuity-status" => 14,
        "continuity-init" | "continuity-select" | "continuity-step" => 15,
        _ => return Err(HELP.into()),
    };
    if args.len() != count || (profile.is_some() && command != "continuity-step") {
        return Err(HELP.into());
    }
    if command != "continuity-step" {
        return run_inner(args, None, &AtomicBool::new(false));
    }
    let args = args.to_vec();
    let profile = profile.map(Path::to_path_buf);
    supervised(Duration::from_secs(90), move |cancel| {
        run_inner(&args, profile.as_deref(), &cancel)
    })
}

#[cfg(test)]
#[path = "continuity/tests.rs"]
mod tests;
