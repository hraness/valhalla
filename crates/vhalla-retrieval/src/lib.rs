#![no_std]
#![forbid(unsafe_code)]
//! Bounded optional peer candidates. No dial, persistence, agent wake, external
//! snippet, ranking claim, or public-network activation exists in this crate.
extern crate alloc;
#[cfg(test)]
extern crate std;
mod wire;
use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_crypto::VerifiedEnvelope;
use vhalla_discovery::{
    Budget as QueryBudget, DiscoverySnapshot, DiscoveryState, Filters, Query, Visibility,
};
use vhalla_social::{
    archive::{Archive, Budget, SyncCursor},
    view::{Eligibility, View},
    CanonicalTag, OwnerId, PostRef, RecordId, MAX_RECORD_BYTES,
};

/// Fixed versioned capability for envelope-v1 signed post/revision facet opcodes.
pub const CAPABILITY: &str = "social-facets-v1";
/// Frames fit the existing native signed-chat body ceiling with framing margin.
pub const MAX_FRAME: usize = 48 * 1024;
const _: () = assert!(MAX_FRAME <= vhalla_crypto::MAX_SIGNED_BODY_BYTES);
/// Maximum explicit peer pins in one request round.
pub const MAX_PEERS: usize = 4;
/// Maximum exact candidate references retained per peer for the entire round.
/// Each response has the same cap; later new hints cannot expand this reserve.
pub const MAX_HINTS: usize = 16;
/// Maximum signed records in a single hydration response.
pub const MAX_RECORDS_PER_FRAME: usize = 5;
/// Maximum response attempts, including malformed/duplicate/error responses, per peer.
pub const MAX_ATTEMPTS: usize = 32;
/// Maximum disclosed inventory IDs in a single request. A larger local archive
/// may disclose a bounded subset; omitted known records consume duplicate credit.
pub const MAX_KNOWN: usize = 1024;
/// Explicit locally selected authenticated outer channel. Its experimental
/// transport realm may differ from the inner requested social realm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelScope {
    /// Expected authenticated transport realm.
    pub realm: RealmId,
    /// Expected authenticated transport room.
    pub room: RoomId,
    /// Expected authenticated transport epoch.
    pub epoch: Epoch,
}

/// Stable bounded retrieval errors; none authorize a retry or another peer dial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Count, byte, or canonical input bounds failed.
    Bounds,
    /// Unsupported, malformed, trailing, or noncanonical frame bytes.
    Encoding,
    /// Peer pin, nonce, realm, capability, kind, sequence, or expiry did not match.
    Context,
    /// This peer's attempt/byte allowance is exhausted.
    Budget,
    /// Local social/query projection could not safely derive a result.
    Evidence,
}

/// Bounded query intentionally disclosed to selected peers. All additional typed
/// filters remain local and are reapplied after normal signed-record verification.
#[derive(Clone, Debug)]
pub struct Request {
    nonce: [u8; 32],
    realm: RealmId,
    query: Query,
    tag: Option<CanonicalTag>,
    known: Vec<RecordId>,
}
impl Request {
    /// Build an explicit request. Inventory must be sorted, unique, and bounded.
    /// Nonce freshness is a caller-owned OS-entropy responsibility at the adapter.
    pub fn new(
        nonce: [u8; 32],
        realm: RealmId,
        query: Query,
        tag: Option<CanonicalTag>,
        known: Vec<RecordId>,
    ) -> Result<Self, Error> {
        if known.len() > MAX_KNOWN || known.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::Bounds);
        };
        Ok(Self {
            nonce,
            realm,
            query,
            tag,
            known,
        })
    }
    /// Exact caller request nonce; never a timestamp or authorization credential.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// The explicit public realm whose records are requested.
    #[must_use]
    pub const fn realm(&self) -> RealmId {
        self.realm
    }
    /// Publicly disclosed literal query, not private preferences or read state.
    #[must_use]
    pub fn query(&self) -> &Query {
        &self.query
    }
    /// Encode bounded interoperable request bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::request(self)
    }
    /// Decode only an already authenticated transport message from the explicit
    /// pinned requester, with fresh caller-supplied evaluation time.
    pub fn from_message(
        message: &VerifiedEnvelope,
        requester: [u8; 32],
        channel: ChannelScope,
        now: u64,
    ) -> Result<Self, Error> {
        check_message(message, requester, channel, now)?;
        wire::decode_request(message.envelope().body())
    }
}

/// Reference hints and ordinary signed evidence. All fields remain private so
/// only canonical decoding or a normal provider can assemble a response.
#[derive(Clone, Debug)]
pub struct Response {
    nonce: [u8; 32],
    realm: RealmId,
    sequence: u8,
    hints: Vec<PostRef>,
    records: Vec<Vec<u8>>,
    provider_remaining: usize,
}
impl Response {
    /// Encode a bounded frame suitable for an independently pinned paired channel.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        wire::response(self)
    }
    /// Exact advertised candidates; these alone are not admitted posts.
    #[must_use]
    pub fn hints(&self) -> &[PostRef] {
        &self.hints
    }
    /// Records the provider still owes after this page; zero ends the round.
    #[must_use]
    pub const fn provider_remaining(&self) -> usize {
        self.provider_remaining
    }
}

/// Explicit bounded serving session. Inventory rotation delegates to the
/// maintained archive's owner/control/dependency scheduler, not a search-specific
/// unverified import path. It makes no completeness or malicious-peer claim.
/// Served record IDs grow the effective peer inventory each page, so
/// `provider_remaining` converges to zero instead of re-sending duplicates.
pub struct Provider {
    request: Request,
    cursor: SyncCursor,
    served: BTreeSet<RecordId>,
    sequence: u8,
}
impl Provider {
    /// Accept a decoded authenticated explicit request; no provider is auto-started.
    #[must_use]
    pub fn new(request: Request) -> Self {
        Self {
            request,
            cursor: SyncCursor::default(),
            served: BTreeSet::new(),
            sequence: 0,
        }
    }
    /// Derive query hints and a bounded ordinary missing-record page. The selected
    /// provider owner is explicit local public identity, never a private reader.
    pub fn next(&mut self, archive: &Archive, owner: OwnerId, now: u64) -> Result<Response, Error> {
        if archive.realm() != self.request.realm || usize::from(self.sequence) >= MAX_ATTEMPTS {
            return Err(Error::Context);
        };
        let eligibility = Eligibility::default();
        let view = View::new(archive, now, &eligibility);
        let state = DiscoveryState::new([0; 32]);
        let snapshot = DiscoverySnapshot::new(archive, &view, owner, &state, Visibility::Committed)
            .map_err(|_| Error::Evidence)?;
        let filters = Filters {
            tag: self
                .request
                .tag
                .as_ref()
                .map(|tag| String::from(tag.as_str())),
            ..Filters::default()
        };
        let found = snapshot
            .search(
                &self.request.query,
                &filters,
                QueryBudget::default(),
                MAX_HINTS,
            )
            .map_err(|_| Error::Evidence)?;
        let mut hints: Vec<_> = found.hits.iter().map(|hit| hit.reference).collect();
        hints.sort_unstable();
        hints.dedup();
        // Everything already served counts as held by the peer, so the
        // rotating cursor only owes records never sent in this session.
        let mut inventory: Vec<RecordId> = self
            .request
            .known
            .iter()
            .copied()
            .chain(self.served.iter().copied())
            .collect();
        inventory.sort_unstable();
        inventory.dedup();
        inventory.truncate(vhalla_social::MAX_RECORDS);
        let page = archive
            .next_page(
                &inventory,
                &mut self.cursor,
                MAX_RECORDS_PER_FRAME,
                MAX_RECORDS_PER_FRAME * MAX_RECORD_BYTES,
            )
            .map_err(|_| Error::Evidence)?;
        self.served.extend(page.ids.iter().copied());
        let response = Response {
            nonce: self.request.nonce,
            realm: self.request.realm,
            sequence: self.sequence,
            hints,
            records: page.records,
            provider_remaining: page.remaining,
        };
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Budget)?;
        Ok(response)
    }
}

/// Bounded accounting per pinned peer. Failures and duplicates consume allowance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerStats {
    /// Every explicit receive/failure attempt, including rejected frames.
    pub attempts: usize,
    /// Raw response body bytes charged before parsing or inner-record signature
    /// checks. Outer transport authentication has already happened.
    pub bytes: usize,
    /// All presented inner records, including duplicate and invalid signatures.
    pub record_attempts: usize,
    /// Ordinary archive ingest accepted a new exact record.
    pub accepted: usize,
    /// Presented evidence was already retained.
    pub duplicates: usize,
    /// Malformed/correlated/signature/capacity failures, including recorded timeouts.
    pub failures: usize,
    /// Records the provider still owed after the most recent accepted page.
    /// The round is complete for that peer when this reaches zero.
    pub provider_remaining: usize,
}
struct Peer {
    stats: PeerStats,
    next: u8,
    hints: BTreeSet<PostRef>,
}
/// One finite explicitly selected peer round. Private preference/read state is
/// never encoded; provider hints are separately retained from admitted evidence.
pub struct Round {
    request: Request,
    channel: ChannelScope,
    peers: BTreeMap<[u8; 32], Peer>,
    hints: BTreeSet<PostRef>,
    last_peer: Option<[u8; 32]>,
}
impl Round {
    /// Pins are local full application keys; hints cannot add peers or routes.
    pub fn new(
        request: Request,
        peers: Vec<[u8; 32]>,
        channel: ChannelScope,
    ) -> Result<Self, Error> {
        if peers.is_empty()
            || peers.len() > MAX_PEERS
            || peers.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::Bounds);
        };
        for key in &peers {
            let key = vhalla_crypto::VerifyingKey::from_bytes(key).map_err(|_| Error::Context)?;
            if key.is_weak() {
                return Err(Error::Context);
            }
        }
        Ok(Self {
            request,
            channel,
            peers: peers
                .into_iter()
                .map(|key| {
                    (
                        key,
                        Peer {
                            stats: PeerStats::default(),
                            next: 0,
                            hints: BTreeSet::new(),
                        },
                    )
                })
                .collect(),
            hints: BTreeSet::new(),
            last_peer: None,
        })
    }
    /// Rotate fairly over explicit peers still holding credit; this returns a pin,
    /// not a dial request. The caller chooses whether/how to contact that peer.
    pub fn next_peer(&mut self) -> Option<[u8; 32]> {
        let peers: Vec<_> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.stats.attempts < MAX_ATTEMPTS)
            .map(|(key, _)| *key)
            .collect();
        let next = peers
            .iter()
            .copied()
            .find(|key| self.last_peer.is_none_or(|last| *key > last))
            .or_else(|| peers.first().copied());
        self.last_peer = next;
        next
    }
    /// Account for one explicit transport timeout/failure without an automatic retry.
    pub fn failed(&mut self, pin: [u8; 32]) -> Result<(), Error> {
        let peer = self.peers.get_mut(&pin).ok_or(Error::Context)?;
        charge(peer, 0)?;
        peer.stats.failures += 1;
        Ok(())
    }
    /// Accept a fresh authenticated response from one pinned channel. Each inner
    /// record traverses normal bounded signature+archive admission; rejected data
    /// cannot stop later records in the same bounded page or another peer's budget.
    pub fn receive(
        &mut self,
        message: &VerifiedEnvelope,
        archive: &mut Archive,
        now: u64,
    ) -> Result<(), Error> {
        let pin = *message.signer_key();
        let peer = self.peers.get_mut(&pin).ok_or(Error::Context)?;
        let raw = message.envelope().body();
        charge(peer, raw.len())?;
        if archive.realm() != self.request.realm
            || check_message(message, pin, self.channel, now).is_err()
        {
            peer.stats.failures += 1;
            return Err(Error::Context);
        };
        let response = match wire::decode_response(raw) {
            Ok(response) => response,
            Err(error) => {
                peer.stats.failures += 1;
                return Err(error);
            }
        };
        if response.nonce != self.request.nonce
            || response.realm != self.request.realm
            || response.sequence != peer.next
        {
            peer.stats.failures += 1;
            return Err(Error::Context);
        };
        peer.next = peer.next.checked_add(1).ok_or(Error::Budget)?;
        peer.stats.provider_remaining = response.provider_remaining;
        for hint in response.hints {
            if peer.hints.len() < MAX_HINTS || peer.hints.contains(&hint) {
                peer.hints.insert(hint);
                self.hints.insert(hint);
            } else {
                peer.stats.failures += 1;
            }
        }
        for raw in response.records {
            peer.stats.record_attempts += 1;
            let before = archive.len();
            let mut budget = Budget::new(1, MAX_RECORD_BYTES).map_err(|_| Error::Bounds)?;
            match archive.ingest(&raw, &mut budget) {
                Ok(_) => {
                    if archive.len() == before {
                        peer.stats.duplicates += 1
                    } else {
                        peer.stats.accepted += 1
                    }
                }
                Err(_) => peer.stats.failures += 1,
            }
        }
        Ok(())
    }
    /// Exact per-peer usage; no claimed global search coverage is accepted.
    #[must_use]
    pub fn stats(&self, pin: [u8; 32]) -> Option<PeerStats> {
        self.peers.get(&pin).map(|peer| peer.stats)
    }
    /// Reapply the current local query and every caller filter after ordinary
    /// hydration and fresh authority evaluation. Return only hinted IDs that also
    /// match the actual maintained query engine; no external snippet is exposed.
    pub fn candidates(
        &self,
        archive: &Archive,
        now: u64,
        owner: OwnerId,
        state: &DiscoveryState,
        mut filters: Filters,
    ) -> Result<Candidates, Error> {
        if archive.realm() != self.request.realm {
            return Err(Error::Context);
        };
        if let Some(tag) = &self.request.tag {
            if filters
                .tag
                .as_ref()
                .is_some_and(|local| local != tag.as_str())
            {
                return Ok(Candidates {
                    references: Vec::new(),
                    unresolved: self.hints.len(),
                    local_query_complete: true,
                    network_complete: false,
                });
            };
            filters.tag = Some(String::from(tag.as_str()));
        }
        let eligibility = Eligibility::default();
        let view = View::new(archive, now, &eligibility);
        let snapshot = DiscoverySnapshot::new(archive, &view, owner, state, Visibility::Committed)
            .map_err(|_| Error::Evidence)?;
        let hints: Vec<_> = self.hints.iter().copied().collect();
        let page = snapshot
            .search_references(
                &self.request.query,
                &filters,
                QueryBudget::default(),
                &hints,
            )
            .map_err(|_| Error::Evidence)?;
        let references: BTreeSet<_> = page.hits.iter().map(|hit| hit.reference).collect();
        let local_query_complete = page.coverage.query_complete
            && page.coverage.history_complete
            && page.coverage.corpus_complete;
        let unresolved = self.hints.len() - references.len();
        Ok(Candidates {
            references: references.into_iter().collect(),
            unresolved,
            local_query_complete,
            network_complete: false,
        })
    }
}
/// Source-checked candidate references and honest coverage limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidates {
    /// References that pass the current local maintained query and authority view.
    pub references: Vec<PostRef>,
    /// Hints absent, invalidated, filtered, or outside bounded completed query work.
    pub unresolved: usize,
    /// Known local query/evidence construction completed within its bounds.
    pub local_query_complete: bool,
    /// Always false: peer omission/partition prevents global completeness proof.
    pub network_complete: bool,
}
fn charge(peer: &mut Peer, bytes: usize) -> Result<(), Error> {
    if peer.stats.attempts >= MAX_ATTEMPTS {
        return Err(Error::Budget);
    };
    peer.stats.attempts += 1;
    peer.stats.bytes = peer.stats.bytes.saturating_add(bytes);
    if bytes > MAX_FRAME || peer.stats.bytes > MAX_FRAME * MAX_ATTEMPTS {
        peer.stats.failures += 1;
        return Err(Error::Bounds);
    };
    Ok(())
}
fn check_message(
    message: &VerifiedEnvelope,
    pin: [u8; 32],
    channel: ChannelScope,
    now: u64,
) -> Result<(), Error> {
    let context = message.context();
    if *message.signer_key() != pin
        || context.realm != channel.realm
        || context.room != channel.room
        || context.epoch != channel.epoch
        || now > message.expires_at()
        || message.envelope().kind() != vhalla_wire::KIND_CHAT
        || message.envelope().body().len() > MAX_FRAME
    {
        return Err(Error::Context);
    };
    Ok(())
}

#[cfg(test)]
mod tests;
