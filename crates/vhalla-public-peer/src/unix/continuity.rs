//! Explicit bounded continuity mode. One existing integration mutex owns this
//! certified client and every store. It does not lock an external journal writer.
use super::*;
use activity::{activity_failure, check_current_client, cors, refresh_client, store_status};
use std::time::Instant;
use vhalla_public_protocol::{activity as legacy, continuity as wire};
use vhalla_room_activity::{AdmissionContext, RoomScope, SignedEvent};
use vhalla_room_activity_store::continuity::{
    AuthorPosition, ContinuityLimits, ContinuityStore, StageTicket, WorkAllowance, WorkExpectation,
};
use vhalla_rooms::RoomGenesisId;
mod http;
mod rate;
use rate::{Cost, Rate};

/// Explicit existing v2 store; no path or resource policy comes from a request.
#[derive(Clone, Debug)]
pub struct ContinuityRoomConfig {
    /// Full immutable room genesis in the pinned bootstrap scope.
    pub room: RoomGenesisId,
    /// Existing private `VHCF2` directory; never created/migrated during startup.
    pub directory: PathBuf,
    /// Exact immutable permanent and staging limits, checked before recovery.
    pub limits: ContinuityLimits,
}
/// Mutually exclusive alternative to legacy activity mode, selected at startup.
#[derive(Clone, Debug)]
pub struct ContinuityConfig {
    /// One to 32 unique full room IDs with exact operator-selected paths/limits.
    pub rooms: Vec<ContinuityRoomConfig>,
}
pub(super) struct Service {
    client: CertifiedClient,
    stores: BTreeMap<[u8; 32], ContinuityStore>,
    rate: Rate,
    #[cfg(test)]
    after_refresh: Option<Box<dyn FnOnce() + Send>>,
}
struct Reservation {
    request: wire::Request,
    source: IpAddr,
}
impl Service {
    pub(super) fn open(raw: &[u8], pin: [u8; 32], config: ContinuityConfig) -> Result<Self, Error> {
        if config.rooms.is_empty() || config.rooms.len() > MAX_ACTIVITY_ROOMS {
            return Err(Error::Config);
        }
        let bootstrap = Bootstrap::decode(raw, pin).map_err(|_| Error::Bootstrap)?;
        let client = CertifiedClient::new(bootstrap, pin).map_err(|_| Error::Bootstrap)?;
        let mut stores = BTreeMap::new();
        for room in config.rooms {
            if stores.contains_key(room.room.as_bytes()) {
                return Err(Error::Config);
            }
            let scope = RoomScope {
                network: client.network_id(),
                realm: client.registry().realm(),
                directory: client.registry().directory(),
                room: room.room,
            };
            let store = ContinuityStore::open_checked(room.directory, scope, room.limits, None)
                .map_err(|_| {
                    Error::State(
                        "continuity store must match exact existing scope, format and limits",
                    )
                })?;
            stores.insert(*room.room.as_bytes(), store);
        }
        Ok(Self {
            client,
            stores,
            rate: Rate::new(),
            #[cfg(test)]
            after_refresh: None,
        })
    }
    fn scope(&self, room: [u8; 32]) -> wire::Scope {
        RoomScope {
            network: self.client.network_id(),
            realm: self.client.registry().realm(),
            directory: self.client.registry().directory(),
            room: RoomGenesisId::from_bytes(room),
        }
        .into()
    }
    fn reserve(
        &mut self,
        request: wire::Request,
        source: IpAddr,
    ) -> Result<Reservation, StatusCode> {
        let scope = request.context().scope;
        if scope != self.scope(scope.room) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if !self.stores.contains_key(&scope.room) {
            return Err(StatusCode::NOT_FOUND);
        }
        if !self.rate.charge(
            Some(source),
            rate::request_cost(request.kind()),
            Instant::now(),
        ) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Ok(Reservation { request, source })
    }
    fn refresh(&mut self, journal: &Journal<FsStore>) -> Result<wire::Observed, StatusCode> {
        refresh_client(&mut self.client, journal)?;
        #[cfg(test)]
        if let Some(hook) = self.after_refresh.take() {
            hook();
        }
        check_current_client(&self.client, journal)?;
        let frontier = self.client.frontier();
        Ok(wire::Observed {
            height: frontier.height,
            frontier: frontier.commitment(),
        })
    }
    fn floor(&self, request: &wire::Request, journal: &Journal<FsStore>) -> Result<(), StatusCode> {
        let floor = request.context().floor;
        let frontier = self.client.frontier();
        if floor.height > frontier.height {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        journal
            .read_published_range(PublishedRange {
                after_height: floor.height,
                expected_predecessor: Some(floor.frontier),
                max_bundles: 1,
                max_bytes: vhalla_journal::MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(|_| StatusCode::CONFLICT)?;
        Ok(())
    }
    fn answer(
        &mut self,
        peer: &Peer,
        reservation: Reservation,
        raw: &[u8],
        clock: u64,
    ) -> Result<Vec<u8>, StatusCode> {
        let request = reservation.request;
        let body = if request.method() == "POST" {
            Some(
                request
                    .check_body(raw)
                    .map_err(|_| StatusCode::BAD_REQUEST)?,
            )
        } else {
            if !raw.is_empty() {
                return Err(StatusCode::BAD_REQUEST);
            }
            None
        };
        let observed = self.refresh(&peer.journal)?;
        self.floor(&request, &peer.journal)?;
        let room = request.context().scope.room;
        let store = self.stores.get(&room).ok_or(StatusCode::NOT_FOUND)?;
        let reply = match request.kind() {
            wire::Kind::Stage {
                base,
                prior,
                end,
                body: hash,
            } => {
                let body = body.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
                let expected = expectation(selected_author(&request)?, base, prior)?;
                let quote = store
                    .quote_stage(body.history(), expected, clock)
                    .map_err(store_status)?;
                check_current_client(&self.client, &peer.journal)?;
                let context = AdmissionContext::new(peer.network, self.client.registry())
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let store = self.stores.get_mut(&room).ok_or(StatusCode::NOT_FOUND)?;
                let ticket = store
                    .stage_checked(
                        body.history().to_vec(),
                        expected,
                        &context,
                        clock,
                        WorkAllowance {
                            frames: quote.frames(),
                            retained_ancestors: 0,
                        },
                    )
                    .map_err(store_status)?;
                wire::Reply::Staged(wire::StageAck {
                    observed,
                    base,
                    ticket: stage_ref(ticket)?,
                    submitted_end: end,
                    submitted_body: hash,
                })
            }
            wire::Kind::Commit { base, stage, .. } => {
                let body = body.as_ref().ok_or(StatusCode::BAD_REQUEST)?;
                let terminal = body.terminal().ok_or(StatusCode::BAD_REQUEST)?;
                let expected = expectation(selected_author(&request)?, base, stage)?;
                let quote = store
                    .quote_commit(body.history(), terminal, expected, clock)
                    .map_err(store_status)?;
                if !self.rate.charge(
                    Some(reservation.source),
                    Cost {
                        prefix: quote.retained_ancestors(),
                        ..Cost::default()
                    },
                    Instant::now(),
                ) {
                    return Err(StatusCode::TOO_MANY_REQUESTS);
                }
                check_current_client(&self.client, &peer.journal)?;
                let context = AdmissionContext::new(peer.network, self.client.registry())
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let store = self.stores.get_mut(&room).ok_or(StatusCode::NOT_FOUND)?;
                let receipt = store
                    .commit_checked(
                        body.history().to_vec(),
                        terminal.clone(),
                        expected,
                        &context,
                        clock,
                        WorkAllowance {
                            frames: quote.frames(),
                            retained_ancestors: quote.retained_ancestors(),
                        },
                    )
                    .map_err(store_status)?;
                wire::Reply::Committed(Box::new(wire::TerminalReceipt {
                    observed,
                    event: receipt.event().clone(),
                    cursor: receipt.cursor(),
                    registry: *receipt.registry_digest(),
                    reconciled: receipt.reconciled(),
                }))
            }
            wire::Kind::Status { .. } => {
                let status = store
                    .author_status(selected_author(&request)?, clock)
                    .map_err(store_status)?;
                wire::Reply::Status(wire::Status {
                    observed,
                    published: position(status.published())?,
                    stage: status.stage().map(stage_ref).transpose()?,
                })
            }
            wire::Kind::Feed { after, count } => {
                let tip = store.pin().feed_count();
                let entries = store
                    .feed(after, usize::from(count))
                    .map_err(store_status)?
                    .into_iter()
                    .map(|receipt| wire::Entry {
                        role: wire::EvidenceRole::CurrentAdmission,
                        committed_by: receipt.cursor(),
                        registry: *receipt.registry_digest(),
                        event: receipt.event().clone(),
                    })
                    .collect();
                wire::Reply::Feed(wire::FeedPage {
                    observed,
                    tip,
                    entries,
                })
            }
            wire::Kind::Evidence { after, count } => {
                let status = store
                    .author_status(selected_author(&request)?, clock)
                    .map_err(store_status)?;
                let entries = store
                    .author_evidence(
                        selected_author(&request)?,
                        after.sequence(),
                        usize::from(count),
                    )
                    .map_err(store_status)?
                    .into_iter()
                    .map(|record| wire::Entry {
                        role: record.role(),
                        committed_by: record.committed_by(),
                        registry: *record.registry_digest(),
                        event: record.event().clone(),
                    })
                    .collect();
                wire::Reply::Evidence(wire::EvidencePage {
                    observed,
                    tip: position(status.published())?,
                    entries,
                })
            }
        };
        reply.encode(&request).map_err(|_| StatusCode::CONFLICT)
    }
    pub(super) fn answer_legacy(
        &mut self,
        peer: &Peer,
        request: legacy::ActivityRequest,
        raw: &[u8],
        source: IpAddr,
    ) -> Result<Vec<u8>, StatusCode> {
        let cost = match request.kind() {
            legacy::ActivityKind::Post { .. } => Cost {
                requests: 1,
                submitted: 1,
                stored: 202,
                ..Cost::default()
            },
            legacy::ActivityKind::Page { count, .. } => Cost {
                requests: 1,
                stored: 2 * u64::from(count) + 1,
                ..Cost::default()
            },
        };
        if !self.stores.contains_key(&request.room()) {
            return Err(StatusCode::NOT_FOUND);
        }
        if !self.rate.charge(Some(source), cost, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        let observed = self.refresh(&peer.journal)?;
        match request.kind() {
            legacy::ActivityKind::Post { .. } => {
                request
                    .check_body(raw)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                let event = SignedEvent::decode(raw)
                    .and_then(SignedEvent::verify)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                if wire::Scope::from(event.claims().scope) != self.scope(request.room()) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                // This is a direct next-event expectation, never an inferred
                // stage. Retained old terminal retry remains exact reconciliation.
                let expected = WorkExpectation {
                    published: AuthorPosition::new(
                        event
                            .claims()
                            .sequence
                            .checked_sub(1)
                            .ok_or(StatusCode::BAD_REQUEST)?,
                        event.claims().previous,
                    )
                    .map_err(store_status)?,
                    stage: None,
                };
                let clock = now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let store = self
                    .stores
                    .get(&request.room())
                    .ok_or(StatusCode::NOT_FOUND)?;
                let quote = store
                    .quote_commit(&[], &event, expected, clock)
                    .map_err(store_status)?;
                if quote.retained_ancestors() != 0 {
                    return Err(StatusCode::CONFLICT);
                }
                check_current_client(&self.client, &peer.journal)?;
                let context = AdmissionContext::new(peer.network, self.client.registry())
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                let receipt = self
                    .stores
                    .get_mut(&request.room())
                    .ok_or(StatusCode::NOT_FOUND)?
                    .commit_checked(
                        vec![],
                        event,
                        expected,
                        &context,
                        clock,
                        WorkAllowance {
                            frames: 1,
                            retained_ancestors: 0,
                        },
                    )
                    .map_err(store_status)?;
                legacy::LocalReceipt::new(
                    receipt.event(),
                    receipt.cursor(),
                    *receipt.registry_digest(),
                    observed.height,
                    observed.frontier,
                    receipt.reconciled(),
                )
                .map(|receipt| receipt.encode())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
            legacy::ActivityKind::Page { after, count } => {
                if !raw.is_empty() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let store = self
                    .stores
                    .get(&request.room())
                    .ok_or(StatusCode::NOT_FOUND)?;
                let entries = store
                    .feed(after, usize::from(count))
                    .map_err(store_status)?
                    .into_iter()
                    .map(|receipt| {
                        legacy::ActivityEntry::new(
                            receipt.cursor(),
                            *receipt.registry_digest(),
                            receipt.event().clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                legacy::ActivityPage::new(
                    &request,
                    store.pin().feed_count(),
                    observed.height,
                    observed.frontier,
                    entries,
                )
                .map(|page| page.encode())
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
    fn maintain(&mut self, clock: u64) -> Result<(), Error> {
        for store in self.stores.values_mut() {
            let quote = store
                .maintenance_quote(clock, 1)
                .map_err(|_| Error::State("continuity maintenance requires reopen"))?;
            if !quote.clock_transition() && quote.pages() == 0 {
                continue;
            }
            let cost = Cost {
                stored: u64::from(quote.pages()) * 162,
                cleanup: u64::from(quote.pages()),
                ..Cost::default()
            };
            if !self.rate.charge(None, cost, Instant::now()) {
                return Ok(());
            }
            store
                .maintain_bounded(clock, quote.pages())
                .map_err(|_| Error::State("continuity maintenance uncertain; reopen"))?;
        }
        Ok(())
    }
}
fn selected_author(request: &wire::Request) -> Result<[u8; 32], StatusCode> {
    match request.selection() {
        wire::Selection::Author(author) => Ok(author),
        wire::Selection::RoomFeed => Err(StatusCode::BAD_REQUEST),
    }
}
fn position(value: AuthorPosition) -> Result<wire::Position, StatusCode> {
    wire::Position::new(value.sequence(), value.event_id())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
fn stage_ref(value: StageTicket) -> Result<wire::StageRef, StatusCode> {
    wire::StageRef::new(
        value.id(),
        position(value.base())?,
        position(value.tail())?,
        value.pages(),
        value.expires_at(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
fn expectation(
    author: [u8; 32],
    base: wire::Position,
    stage: Option<wire::StageRef>,
) -> Result<WorkExpectation, StatusCode> {
    let published = AuthorPosition::new(base.sequence(), base.event_id()).map_err(store_status)?;
    let stage = stage
        .map(|s| {
            StageTicket::new(
                s.id(),
                author,
                published,
                AuthorPosition::new(s.tail().sequence(), s.tail().event_id())
                    .map_err(store_status)?,
                s.pages(),
                s.expires_at(),
            )
            .map_err(store_status)
        })
        .transpose()?;
    Ok(WorkExpectation { published, stage })
}
impl Peer {
    fn reserve_continuity(
        &self,
        request: wire::Request,
        source: IpAddr,
    ) -> Result<Reservation, StatusCode> {
        self.current_advertisement()?;
        let mut slot = self
            .activity
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        match slot.as_mut() {
            Some(activity::Owner::Continuity(service)) => service.reserve(request, source),
            _ => Err(StatusCode::NOT_FOUND),
        }
    }
    fn continuity_answer(
        &self,
        reservation: Reservation,
        body: &[u8],
    ) -> Result<(Bytes, String), StatusCode> {
        self.current_advertisement()?;
        let request = reservation.request;
        let mut slot = self
            .activity
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let Some(activity::Owner::Continuity(service)) = slot.as_mut() else {
            return Err(StatusCode::NOT_FOUND);
        };
        let body = service.answer(
            self,
            reservation,
            body,
            now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )?;
        let unsigned = wire::UnsignedResponse::new(self.identity.public_key(), request, &body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let proof = self
            .identity
            .sign_continuity_response(unsigned)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((Bytes::from(body), hex(&proof.encode())))
    }
    pub(super) fn maintain_continuity(&self, clock: u64) -> Result<(), Error> {
        let mut slot = match self.activity.try_lock() {
            Ok(slot) => slot,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(Error::State("activity owner poisoned; reopen"))
            }
        };
        if let Some(activity::Owner::Continuity(service)) = slot.as_mut() {
            service.maintain(clock)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
