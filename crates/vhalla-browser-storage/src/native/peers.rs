//! One explicitly selected peer, with durable advertisement and clock floors.
//!
//! This is local routing evidence, not bootstrap trust, room permission, or a
//! network operation. The immutable HTTPS endpoint is operator-selected. An
//! expired retained advertisement can restore a sequence floor, never authorize
//! activity; the controller may use only the selected endpoint for a fresh,
//! nonce-bound same-key advertisement request. It must check current endpoint
//! membership and READ/PUBLISH claims after persisting a refreshed descriptor.
//!
//! One bounded STATE/INTENT pair uses private exclusive custody. Valid expired
//! signed evidence is retained. No peer/route replacement, state reset, migration,
//! wall-clock repair, or old-floor eviction exists. Disk rollback and hostile
//! same-OS-owner mutation remain outside the local custody contract.

use super::disk::Disk;
use crate::{history::HistoryScope, Error, PublishError};
use sha2::{Digest, Sha256};
use std::{fs::File, path::Path};
use vhalla_public_protocol::{
    Capabilities, Endpoint, PeerAdvertisement, Scheme, VerificationPolicy, MAX_ADVERTISEMENT_BYTES,
    MAX_CLOCK_SKEW_SECONDS, MAX_ENDPOINT_BYTES, MAX_TTL_SECONDS,
};

const FORMAT: &[u8; 8] = b"VHNPER01";
const STATE_MAGIC: &[u8; 8] = b"VHNPS001";
const INTENT_MAGIC: &[u8; 8] = b"VHNPI001";
const MAX_STATE: usize = 4096;
const MAX_INTENT: usize = 8192;

/// Exact immutable selection snapshot for compare-and-swap operations.
/// Advertisement freshness and service availability must be checked again before
/// use. This snapshot cannot grant activity, validator, or host authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerSelection {
    scope: HistoryScope,
    peer: [u8; 32],
    endpoint: Endpoint,
    advertisement: PeerAdvertisement,
    clock: u64,
    generation: u64,
}
impl PeerSelection {
    /// Full independently pinned network/configuration scope.
    pub const fn scope(&self) -> HistoryScope {
        self.scope
    }
    /// Full selected application identity.
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
    /// Immutable operator-selected HTTPS endpoint, not a route grant.
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// Latest retained signed evidence, which may now be expired or withdrawn.
    pub const fn advertisement(&self) -> &PeerAdvertisement {
        &self.advertisement
    }
    /// Greatest local Unix-second clock checkpoint accepted by this session.
    pub const fn clock_floor(&self) -> u64 {
        self.clock
    }
    fn check(&self) -> Result<(), Error> {
        if self.scope.bootstrap_pin() == [0; 32] || self.endpoint.scheme() != Scheme::Https {
            return Err(Error::WrongScope);
        }
        let anchor = self
            .advertisement
            .restore_sequence_anchor(self.scope.network())
            .map_err(|_| Error::Corrupt)?;
        if *anchor.application_key() != self.peer {
            return Err(Error::WrongScope);
        }
        Ok(())
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = STATE_MAGIC.to_vec();
        out.extend_from_slice(&self.scope.network());
        out.extend_from_slice(&self.scope.bootstrap_pin());
        out.extend_from_slice(&self.peer);
        out.extend_from_slice(&self.clock.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        part(&mut out, self.endpoint.as_str().as_bytes());
        part(&mut out, &self.advertisement.encode());
        seal(out)
    }
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = checked(raw, MAX_STATE)?;
        if r.take(8)? != STATE_MAGIC {
            return Err(Error::Corrupt);
        }
        let scope = HistoryScope::new(r.array()?, r.array()?);
        let peer = r.array()?;
        let clock = u64::from_be_bytes(r.array()?);
        let generation = u64::from_be_bytes(r.array()?);
        let endpoint = Endpoint::parse(
            std::str::from_utf8(r.part(MAX_ENDPOINT_BYTES)?).map_err(|_| Error::Corrupt)?,
        )
        .map_err(|_| Error::Corrupt)?;
        let advertisement = PeerAdvertisement::decode(r.part(MAX_ADVERTISEMENT_BYTES)?)
            .map_err(|_| Error::Corrupt)?;
        r.end()?;
        let value = Self {
            scope,
            peer,
            endpoint,
            advertisement,
            clock,
            generation,
        };
        value.check()?;
        if value.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
    fn expect(
        &self,
        scope: HistoryScope,
        peer: [u8; 32],
        endpoint: &Endpoint,
    ) -> Result<(), Error> {
        if self.scope != scope || self.peer != peer || self.endpoint != *endpoint {
            return Err(Error::WrongScope);
        }
        Ok(())
    }
}

/// Durable private one-peer session, distinct from an author outbox.
/// A failed publication poisons this handle until it is dropped and reopened.
pub struct NativePeerSession {
    disk: Disk,
    _lock: File,
    selection: PeerSelection,
    poisoned: bool,
}
impl Drop for NativePeerSession {
    fn drop(&mut self) {
        // A fork or duplicated descriptor can retain this open file description
        // after the owning session ends. Release custody at this owner boundary,
        // rather than waiting for the final unrelated descriptor to close.
        // No field destructor publishes storage after this point.
        let _ = self._lock.unlock();
    }
}
impl NativePeerSession {
    /// Create only a new directory. Require a fresh signed advertisement naming
    /// the expected full key, selected HTTPS route, and READ. No PUBLISH required.
    /// Caller-supplied clock is Unix seconds and comes from its local clock.
    pub fn create_new(
        path: impl AsRef<Path>,
        scope: HistoryScope,
        expected_peer: [u8; 32],
        endpoint: Endpoint,
        raw_ad: &[u8],
        now: u64,
    ) -> Result<Self, Error> {
        let ad = decode_ad(raw_ad)?;
        let selection = PeerSelection {
            scope,
            peer: expected_peer,
            endpoint,
            advertisement: ad,
            clock: now,
            generation: 0,
        };
        selection.check()?;
        let fresh = selection
            .advertisement
            .verify(&policy(scope, now), None)
            .map_err(|_| Error::Corrupt)?;
        if !fresh.claims().capabilities.contains(Capabilities::READ)
            || !fresh.claims().endpoints.contains(&selection.endpoint)
        {
            return Err(Error::WrongScope);
        }
        let (mut disk, lock) = Disk::create(path.as_ref())?;
        disk.create_file("FORMAT", FORMAT)?;
        disk.create_file("STATE", &selection.encode())?;
        disk.sync()?;
        disk.sync_parent()?;
        Ok(Self {
            disk,
            _lock: lock,
            selection,
            poisoned: false,
        })
    }
    /// Open existing state and verify exact scope/key/route before recovery writes.
    /// Expiry does not erase the retained signed sequence floor. A complete
    /// unpublished staged intent is reconciled; a truncated unpublished scratch
    /// is discarded only before any effect, after validating current state.
    /// Corrupt authoritative intents and complete malformed scratch are preserved.
    pub fn open(
        path: impl AsRef<Path>,
        expected_scope: HistoryScope,
        expected_peer: [u8; 32],
        expected_endpoint: &Endpoint,
    ) -> Result<Self, Error> {
        let (disk, lock) = Disk::open(path.as_ref())?;
        if disk.read("FORMAT", FORMAT.len())? != FORMAT {
            return Err(Error::Corrupt);
        }
        let selection = PeerSelection::decode(&disk.read("STATE", MAX_STATE)?)?;
        selection.expect(expected_scope, expected_peer, expected_endpoint)?;
        let mut out = Self {
            disk,
            _lock: lock,
            selection,
            poisoned: true,
        };
        let final_intent = out.disk.optional("INTENT", MAX_INTENT)?;
        let staged = out.disk.optional("INTENT.tmp", MAX_INTENT)?;
        if final_intent.is_some() && staged.is_some() {
            return Err(Error::Corrupt);
        }
        if let Some(raw) = final_intent {
            let intent = Intent::decode(&raw)?;
            intent
                .before
                .expect(expected_scope, expected_peer, expected_endpoint)?;
            let next = intent.next()?;
            if out.selection != intent.before && out.selection != next {
                return Err(Error::Corrupt);
            }
            out.disk.resync("INTENT", MAX_INTENT)?;
            out.apply(&intent, &next)?;
            out.selection = next;
        } else if let Some(raw) = staged {
            if out.disk.present("STATE.tmp", MAX_STATE)? {
                return Err(Error::RecoveryRequired);
            }
            if incomplete_stage(&raw, &out.selection)? {
                out.disk.discard_staged_intent()?;
            } else {
                let intent = Intent::decode(&raw)?;
                intent
                    .before
                    .expect(expected_scope, expected_peer, expected_endpoint)?;
                if out.selection != intent.before {
                    return Err(Error::Corrupt);
                }
                let next = intent.next()?;
                out.disk.promote_staged_intent(&raw)?;
                out.apply(&intent, &next)?;
                out.selection = next;
            }
        } else if out.disk.present("STATE.tmp", MAX_STATE)? {
            return Err(Error::RecoveryRequired);
        }
        out.disk.resync("STATE", MAX_STATE)?;
        out.disk.sync_parent()?;
        out.poisoned = false;
        Ok(out)
    }
    /// True after an uncertain publication; reopen before any further operation.
    pub const fn needs_reopen(&self) -> bool {
        self.poisoned
    }
    /// Load the exact current retained snapshot; expiry does not remove it.
    pub fn selection(&self) -> Result<PeerSelection, Error> {
        self.ready()?;
        Ok(self.selection.clone())
    }
    /// Durably checkpoint local time before connecting and after responses.
    /// Reject a backward clock; do not clamp it or derive it from peer timestamps.
    /// This operation grants no freshness to the retained advertisement.
    pub fn checkpoint_clock(
        &mut self,
        expected: &PeerSelection,
        now: u64,
    ) -> Result<PeerSelection, PublishError> {
        self.publish(expected, Change::Clock(now))
    }
    /// Strictly check and retain signed same-key advertisement evidence by CAS.
    /// Different bytes require a strictly greater sequence; exact bytes recheck
    /// time/signature idempotently. Persist a valid newer withdrawal BEFORE the
    /// controller checks selected-route or service suitability. No routes change.
    pub fn observe(
        &mut self,
        expected: &PeerSelection,
        raw_ad: &[u8],
        now: u64,
    ) -> Result<PeerSelection, PublishError> {
        self.ready().map_err(PublishError::Rejected)?;
        if *expected != self.selection {
            return Err(PublishError::Rejected(Error::Stale));
        }
        if now < self.selection.clock {
            return Err(PublishError::Rejected(Error::Stale));
        }
        let ad = decode_ad(raw_ad).map_err(PublishError::Rejected)?;
        self.publish(expected, Change::Observe(ad, now))
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::NeedsReopen)
        } else {
            Ok(())
        }
    }
    fn publish(
        &mut self,
        expected: &PeerSelection,
        change: Change,
    ) -> Result<PeerSelection, PublishError> {
        self.ready().map_err(PublishError::Rejected)?;
        if *expected != self.selection {
            return Err(PublishError::Rejected(Error::Stale));
        }
        let intent = Intent {
            before: self.selection.clone(),
            change,
        };
        let next = intent.next().map_err(PublishError::Rejected)?;
        if next == self.selection {
            return Ok(next);
        }
        self.poisoned = true;
        let result = (|| {
            self.disk.stage_intent(&intent.encode())?;
            self.apply(&intent, &next)
        })();
        result.map_err(PublishError::ReopenRequired)?;
        self.selection = next.clone();
        self.poisoned = false;
        Ok(next)
    }
    fn apply(&mut self, intent: &Intent, next: &PeerSelection) -> Result<(), Error> {
        self.disk
            .replace_state(&intent.before.encode(), &next.encode())?;
        self.disk.remove_intent()
    }
}
fn policy(scope: HistoryScope, now: u64) -> VerificationPolicy {
    VerificationPolicy {
        network: scope.network(),
        now,
        max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
        max_ttl_seconds: MAX_TTL_SECONDS,
    }
}
fn decode_ad(raw: &[u8]) -> Result<PeerAdvertisement, Error> {
    if raw.len() > MAX_ADVERTISEMENT_BYTES {
        return Err(Error::Bounds);
    }
    let ad = PeerAdvertisement::decode(raw).map_err(|_| Error::Corrupt)?;
    if ad.encode() != raw {
        return Err(Error::Corrupt);
    }
    Ok(ad)
}
enum Change {
    Clock(u64),
    Observe(PeerAdvertisement, u64),
}
struct Intent {
    before: PeerSelection,
    change: Change,
}
impl Intent {
    fn next(&self) -> Result<PeerSelection, Error> {
        self.before.check()?;
        let mut next = self.before.clone();
        let now = match &self.change {
            Change::Clock(now) | Change::Observe(_, now) => *now,
        };
        if now < next.clock {
            return Err(Error::Stale);
        }
        if let Change::Observe(ad, _) = &self.change {
            if ad.unverified_claims().application_key != next.peer {
                return Err(Error::WrongScope);
            }
            let anchor = next
                .advertisement
                .restore_sequence_anchor(next.scope.network())
                .map_err(|_| Error::Corrupt)?;
            ad.verify(
                &policy(next.scope, now),
                if *ad == next.advertisement {
                    None
                } else {
                    Some(&anchor)
                },
            )
            .map_err(|_| Error::Corrupt)?;
            next.advertisement = ad.clone();
        }
        next.clock = now;
        if next != self.before {
            next.generation = next.generation.checked_add(1).ok_or(Error::Bounds)?;
        }
        next.check()?;
        Ok(next)
    }
    fn encode(&self) -> Vec<u8> {
        let mut raw = INTENT_MAGIC.to_vec();
        raw.extend_from_slice(&0u32.to_be_bytes());
        part(&mut raw, &self.before.encode());
        match &self.change {
            Change::Clock(now) => {
                raw.push(0);
                raw.extend_from_slice(&now.to_be_bytes());
            }
            Change::Observe(ad, now) => {
                raw.push(1);
                raw.extend_from_slice(&now.to_be_bytes());
                part(&mut raw, &ad.encode());
            }
        }
        let size = (raw.len() + 32) as u32;
        raw[8..12].copy_from_slice(&size.to_be_bytes());
        seal(raw)
    }
    fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = checked(raw, MAX_INTENT)?;
        if r.take(8)? != INTENT_MAGIC {
            return Err(Error::Corrupt);
        }
        if u32::from_be_bytes(r.array()?) as usize != raw.len() {
            return Err(Error::Corrupt);
        }
        let before = PeerSelection::decode(r.part(MAX_STATE)?)?;
        let tag = r.take(1)?[0];
        let now = u64::from_be_bytes(r.array()?);
        let change = match tag {
            0 => Change::Clock(now),
            1 => Change::Observe(decode_ad(r.part(MAX_ADVERTISEMENT_BYTES)?)?, now),
            _ => return Err(Error::Corrupt),
        };
        r.end()?;
        let out = Self { before, change };
        if out.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(out)
    }
}
// Only structurally truncated unpublished scratch can be dropped. Complete bad
// checksums, unknown formats, overlong declarations and foreign states are kept.
fn incomplete_stage(raw: &[u8], expected: &PeerSelection) -> Result<bool, Error> {
    if raw.len() > MAX_INTENT {
        return Err(Error::Bounds);
    }
    let prefix = raw.len().min(INTENT_MAGIC.len());
    if raw[..prefix] != INTENT_MAGIC[..prefix] {
        return Err(Error::Corrupt);
    }
    if raw.len() < 12 {
        return Ok(true);
    }
    let size = u32::from_be_bytes(raw[8..12].try_into().map_err(|_| Error::Corrupt)?) as usize;
    let before = expected.encode();
    let base = 16 + before.len();
    let clock_total = base + 1 + 8 + 32;
    if size < clock_total || size > MAX_INTENT {
        return Err(Error::Bounds);
    }
    let length = (before.len() as u32).to_be_bytes();
    let length_prefix = (raw.len() - 12).min(4);
    if raw[12..12 + length_prefix] != length[..length_prefix] {
        return Err(Error::Stale);
    }
    if raw.len() < 16 {
        return Ok(true);
    }
    let available = (raw.len() - 16).min(before.len());
    if raw[16..16 + available] != before[..available] {
        return Err(Error::Stale);
    }
    if raw.len() <= base {
        return Ok(true);
    }
    match raw[base] {
        0 if size == clock_total => {}
        1 => {
            let ad_len = size.checked_sub(clock_total + 4).ok_or(Error::Bounds)?;
            if ad_len == 0 || ad_len > MAX_ADVERTISEMENT_BYTES {
                return Err(Error::Bounds);
            }
            let length_at = base + 1 + 8;
            if raw.len() > length_at {
                let count = (raw.len() - length_at).min(4);
                if raw[length_at..length_at + count] != (ad_len as u32).to_be_bytes()[..count] {
                    return Err(Error::Corrupt);
                }
            }
        }
        _ => return Err(Error::Corrupt),
    }
    if raw.len() >= base + 9 {
        let now = u64::from_be_bytes(
            raw[base + 1..base + 9]
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        );
        if now < expected.clock {
            return Err(Error::Stale);
        }
    }
    Ok(raw.len() < size)
}

fn seal(mut raw: Vec<u8>) -> Vec<u8> {
    let hash = Sha256::digest(&raw);
    raw.extend_from_slice(&hash);
    raw
}
fn part(raw: &mut Vec<u8>, value: &[u8]) {
    raw.extend_from_slice(&(value.len() as u32).to_be_bytes());
    raw.extend_from_slice(value);
}
fn checked(raw: &[u8], max: usize) -> Result<Reader<'_>, Error> {
    if raw.len() > max {
        return Err(Error::Bounds);
    }
    let split = raw.len().checked_sub(32).ok_or(Error::Corrupt)?;
    let (body, sum) = raw.split_at(split);
    if Sha256::digest(body).as_slice() != sum {
        return Err(Error::Corrupt);
    }
    Ok(Reader(body))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::Corrupt);
        }
        let (out, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
    fn part(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > max {
            return Err(Error::Bounds);
        }
        self.take(n)
    }
    fn end(&self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
}
#[cfg(test)]
mod tests;
