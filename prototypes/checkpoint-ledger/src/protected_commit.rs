//! Single-step, fenced two-store advance over a pre-provisioned certified pin.
//!
//! The witness interface is an assumption about an independently controlled,
//! monotonic durable service, not an implementation or proof of one. A successful
//! result requires exact checked local bytes and an independently witnessed pin.
//! An error after any write is *unknown*: retain the intent and reconcile it.

use alloc::vec::Vec;
use valhalla_checkpoint_proof_prototype::TrustConfig;

use crate::persistence::{
    commit, decode_bundle, load_pinned, CommitOutcome, Pin, PreparedCommit, ProtocolError, Storage,
    StoreError, PIN_BYTES,
};
use crate::CertifiedLedger;

const INTENT_DOMAIN: &[u8] = b"vhalla/checkpoint-store/intent/v1";
/// Exact length of one canonical predecessor/target intent.
pub const INTENT_BYTES: usize = INTENT_DOMAIN.len() + 2 + 2 * PIN_BYTES;

/// Storage for one durably published intent in the SAME local lock domain as
/// the bundle and pin. Read failure is not absence. A successful write syncs
/// content and name, including when identical bytes were already visible.
/// The prototype does not rotate intents: a different pending intent refuses.
pub trait IntentStorage: Storage {
    /// Read no more than [`INTENT_BYTES`] bytes and distinguish absence from error.
    fn read_intent(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
    /// Atomically publish and sync the exact bytes and name, even on a retry.
    fn put_intent(&mut self, raw: &[u8]) -> Result<(), Self::Error>;
}

/// Independently controlled witness with a fixed owner/store identity and a
/// current, exclusive, revocable writer grant. Implementers MUST serialize all
/// CAS calls until durable resolution, compare full canonical pins, refuse stale
/// grants and non-successor/same-generation forks, and never treat a visible
/// unsynced write as success. A successful CAS must survive host restart; a CAS
/// error may have succeeded. `capture` returns the durable latest full pin, not
/// a client cache. This trait does not provide authentication or host custody.
pub trait FencedWitness {
    /// Opaque owner-issued grant, not derived from local files or certificates.
    type Grant;
    /// Outage, revocation, or indeterminate operation.
    type Error;
    /// Capture the latest durable full pin under the exclusive writer grant.
    fn capture(&mut self, grant: &Self::Grant) -> Result<Option<Pin>, Self::Error>;
    /// Durable, serialized full-pin CAS; false is a definitive mismatch only.
    fn compare_exchange(
        &mut self,
        grant: &Self::Grant,
        expected: &Pin,
        target: &Pin,
    ) -> Result<bool, Self::Error>;
}

/// One canonical intent; decoding is plain data, not certification or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Intent {
    predecessor: Pin,
    target: Pin,
}

impl Intent {
    /// Previously witnessed full pin.
    #[must_use]
    pub fn predecessor(&self) -> &Pin {
        &self.predecessor
    }
    /// Proposed full pin, not an acknowledgement.
    #[must_use]
    pub fn target(&self) -> &Pin {
        &self.target
    }
    /// Canonical fixed-width bytes; retained until separately reviewed cleanup.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(INTENT_BYTES);
        raw.extend_from_slice(INTENT_DOMAIN);
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&self.predecessor.encode());
        raw.extend_from_slice(&self.target.encode());
        raw
    }
    /// Parse structure only, never authenticate or trust a local intent.
    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() != INTENT_BYTES
            || !raw.starts_with(INTENT_DOMAIN)
            || raw[INTENT_DOMAIN.len()..INTENT_DOMAIN.len() + 2] != 1u16.to_be_bytes()
        {
            return Err(ProtocolError::InvalidEncoding);
        }
        let offset = INTENT_DOMAIN.len() + 2;
        let predecessor = Pin::decode(&raw[offset..offset + PIN_BYTES])?;
        let target = Pin::decode(&raw[offset + PIN_BYTES..])?;
        Ok(Self {
            predecessor,
            target,
        })
    }
}

/// Protected operations never call legacy `load` or repair missing data.
/// After any backend or witness error, the result may be indeterminate.
#[derive(Debug)]
pub enum Error<S, W> {
    /// No pre-provisioned independent witness or local pin exists.
    Missing,
    /// A different intent, local pin, witness pin or non-successor was seen.
    Conflict,
    /// Corrupt/noncanonical intent or invalid certified ancestry/data.
    Invalid(ProtocolError),
    /// Local store failed; earlier effects may still have landed.
    Local(StoreError<S>),
    /// Independent witness failed or revoked the grant; CAS may have landed.
    Witness(W),
}

/// Start one same-policy advance from a certified prepared candidate. There is
/// deliberately no protected bootstrap and no implicit legacy fallback. An
/// existing exact intent is reconciled; a different intent remains pending.
/// Keep the local store's exclusive lock and the witness grant through return.
pub fn advance<S: IntentStorage, W: FencedWitness>(
    storage: &mut S,
    witness: &mut W,
    grant: &W::Grant,
    prepared: &PreparedCommit,
    trust: TrustConfig,
    max_events: usize,
) -> Result<CertifiedLedger, Error<S::Error, W::Error>> {
    let predecessor = prepared.expected.as_ref().ok_or(Error::Conflict)?;
    let intent = Intent {
        predecessor: predecessor.clone(),
        target: prepared.pin.clone(),
    };
    if let Some(raw) = storage
        .read_intent()
        .map_err(|e| Error::Local(StoreError::Backend(e)))?
    {
        if Intent::decode(&raw).map_err(Error::Invalid)? != intent {
            return Err(Error::Conflict);
        }
        return reconcile(storage, witness, grant, trust, max_events);
    }
    let witnessed = witness
        .capture(grant)
        .map_err(Error::Witness)?
        .ok_or(Error::Missing)?;
    if witnessed != *predecessor {
        return Err(Error::Conflict);
    }
    if storage
        .read_pin()
        .map_err(|e| Error::Local(StoreError::Backend(e)))?
        .as_ref()
        != Some(predecessor)
    {
        return Err(Error::Conflict);
    }
    load_pinned(storage, predecessor, trust.clone(), max_events).map_err(Error::Local)?;
    // Revalidate candidate under the caller's policy before publishing any byte.
    let (snapshot, certificate) = decode_bundle(&prepared.bytes).map_err(Error::Invalid)?;
    let recovered = CertifiedLedger::recover(
        snapshot,
        certificate,
        &crate::RecoveryAnchor {
            checkpoint: prepared.pin.checkpoint(),
            trust_digest: prepared.pin.trust_digest(),
        },
        trust.clone(),
        max_events,
    )
    .map_err(|e| Error::Invalid(ProtocolError::History(e)))?;
    let checked = PreparedCommit::prepare(&recovered, certificate, Some(predecessor))
        .map_err(Error::Invalid)?;
    if checked.pin != prepared.pin || checked.bytes != prepared.bytes {
        return Err(Error::Conflict);
    }
    storage
        .put_bundle(prepared.pin.bundle(), &prepared.bytes)
        .map_err(|e| Error::Local(StoreError::Backend(e)))?;
    storage
        .put_intent(&intent.encode())
        .map_err(|e| Error::Local(StoreError::Backend(e)))?;
    reconcile(storage, witness, grant, trust, max_events)
}

/// Reconcile ONLY the one retained exact intent after a crash or lost response.
/// The candidate is reconstructed from stored snapshot/certificate bytes and
/// certified against the witnessed predecessor. A stale witness, missing or
/// corrupt bytes, local rollback, fork, or outage refuses without fallback.
/// Call again with a fresh fenced grant after resolving an unknown response.
pub fn reconcile<S: IntentStorage, W: FencedWitness>(
    storage: &mut S,
    witness: &mut W,
    grant: &W::Grant,
    trust: TrustConfig,
    max_events: usize,
) -> Result<CertifiedLedger, Error<S::Error, W::Error>> {
    let witnessed = witness
        .capture(grant)
        .map_err(Error::Witness)?
        .ok_or(Error::Missing)?;
    let raw_intent = storage
        .read_intent()
        .map_err(|e| Error::Local(StoreError::Backend(e)))?
        .ok_or(Error::Missing)?;
    let intent = Intent::decode(&raw_intent).map_err(Error::Invalid)?;
    if witnessed != intent.predecessor && witnessed != intent.target {
        return Err(Error::Conflict);
    }
    let local = storage
        .read_pin()
        .map_err(|e| Error::Local(StoreError::Backend(e)))?
        .ok_or(Error::Missing)?;
    if (witnessed == intent.target && local != intent.target)
        || (witnessed == intent.predecessor
            && local != intent.predecessor
            && local != intent.target)
    {
        return Err(Error::Conflict);
    }
    // The predecessor was already acknowledged. Even if the host now holds the
    // target, losing its older certificate is not permission to discard the
    // evidence required to verify that acknowledged prefix.
    load_pinned(storage, &intent.predecessor, trust.clone(), max_events).map_err(Error::Local)?;
    let bundle = storage
        .read_bundle(intent.target.bundle())
        .map_err(|e| Error::Local(StoreError::Backend(e)))?;
    if crate::persistence::bundle_id(&bundle) != intent.target.bundle() {
        return Err(Error::Invalid(ProtocolError::BundleMismatch));
    }
    let (snapshot, certificate) = decode_bundle(&bundle).map_err(Error::Invalid)?;
    let anchor = crate::RecoveryAnchor {
        checkpoint: intent.target.checkpoint(),
        trust_digest: intent.target.trust_digest(),
    };
    let model = CertifiedLedger::recover(snapshot, certificate, &anchor, trust.clone(), max_events)
        .map_err(|e| Error::Invalid(ProtocolError::History(e)))?;
    let prepared = PreparedCommit::prepare(&model, certificate, Some(&intent.predecessor))
        .map_err(Error::Invalid)?;
    if prepared.pin != intent.target || prepared.bytes != bundle {
        return Err(Error::Conflict);
    }
    // Re-establish durability even when bytes were merely visible after an
    // earlier failed sync. No host CAS before the local pin's successful sync.
    storage
        .put_intent(&raw_intent)
        .map_err(|e| Error::Local(StoreError::Backend(e)))?;
    match commit(storage, &prepared) {
        Ok(CommitOutcome::Committed | CommitOutcome::AlreadyCommitted) => {}
        Err(e) => return Err(Error::Local(e)),
    }
    let checked =
        load_pinned(storage, &intent.target, trust.clone(), max_events).map_err(Error::Local)?;
    if witnessed == intent.predecessor {
        match witness.compare_exchange(grant, &intent.predecessor, &intent.target) {
            Ok(true) => {}
            Ok(false) => return Err(Error::Conflict),
            Err(e) => return Err(Error::Witness(e)),
        }
    }
    if witness.capture(grant).map_err(Error::Witness)?.as_ref() != Some(&intent.target)
        || storage
            .read_pin()
            .map_err(|e| Error::Local(StoreError::Backend(e)))?
            .as_ref()
            != Some(&intent.target)
    {
        return Err(Error::Conflict);
    }
    // Check exact certified data again before acknowledging, never an older pin.
    load_pinned(storage, &intent.target, trust, max_events).map_err(Error::Local)?;
    Ok(checked)
}
