//! Bounded immutable bundles and a conditional local pin transaction.
//!
//! Durability and pin freshness are contracts of the owner-selected [`Storage`]
//! backend. A decoded [`Pin`] is plain data, never authenticated evidence. An
//! ordinary filesystem can provide crash consistency but cannot detect rollback
//! of both pin and bundles by an adversary controlling that filesystem.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use valhalla_checkpoint_proof_prototype::{TrustConfig, MAX_PROOF_BYTES};
use vhalla_core::{Epoch, RealmId};
use vhalla_ledger::{Checkpoint, EventDigest, StateRoot, MAX_SNAPSHOT_BYTES};

use crate::{CertifiedLedger, RecoveryAnchor};

const PIN_DOMAIN: &[u8] = b"vhalla/checkpoint-store/pin/v1";
const BUNDLE_DOMAIN: &[u8] = b"vhalla/checkpoint-store/bundle/v1";
const VERSION: u16 = 1;
/// Exact canonical pin size; backends check this before allocating a pin read.
pub const PIN_BYTES: usize = PIN_DOMAIN.len() + 170;
/// Maximum complete bundle, including its bounded snapshot and certificate.
pub const MAX_BUNDLE_BYTES: usize = BUNDLE_DOMAIN.len() + 10 + MAX_SNAPSHOT_BYTES + MAX_PROOF_BYTES;

/// Full SHA-256 content address of canonical bundle bytes.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BundleId(pub [u8; 32]);

/// Hash a bundle; hashing alone does not validate its structure or content.
#[must_use]
pub fn bundle_id(raw: &[u8]) -> BundleId {
    BundleId(Sha256::digest(raw).into())
}

/// Canonical local storage record; decoding grants no trust or host authority.
///
/// The owner-selected backend must protect the current record. Its generation
/// orders local commits, not network consensus or membership epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pin {
    generation: u64,
    bundle: BundleId,
    checkpoint: Checkpoint,
    trust_digest: [u8; 32],
}

impl Pin {
    /// Local commit generation, starting at one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact bundle recovery must load.
    #[must_use]
    pub fn bundle(&self) -> BundleId {
        self.bundle
    }
    /// Copy of the pinned checkpoint claim.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        self.checkpoint
    }
    /// Complete immutable certificate-policy digest.
    #[must_use]
    pub fn trust_digest(&self) -> [u8; 32] {
        self.trust_digest
    }

    /// Encode fixed-width fields in big endian, with domain and version.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PIN_BYTES);
        raw.extend_from_slice(PIN_DOMAIN);
        raw.extend_from_slice(&VERSION.to_be_bytes());
        raw.extend_from_slice(&self.generation.to_be_bytes());
        raw.extend_from_slice(&self.bundle.0);
        raw.extend_from_slice(&self.checkpoint.realm.0.to_be_bytes());
        raw.extend_from_slice(&self.checkpoint.epoch.0.to_be_bytes());
        raw.extend_from_slice(&self.trust_digest);
        raw.extend_from_slice(&self.checkpoint.head.0);
        raw.extend_from_slice(&self.checkpoint.state_root.0);
        raw.extend_from_slice(&self.checkpoint.height.to_be_bytes());
        raw
    }

    /// Parse only canonical structure. Callers must not treat a foreign pin as
    /// their local recovery expectation merely because this function succeeds.
    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() != PIN_BYTES {
            return Err(ProtocolError::InvalidEncoding);
        }
        let mut r = Reader(raw);
        if r.take(PIN_DOMAIN.len())? != PIN_DOMAIN || r.u16()? != VERSION {
            return Err(ProtocolError::InvalidEncoding);
        }
        let generation = r.u64()?;
        if generation == 0 {
            return Err(ProtocolError::InvalidEncoding);
        }
        let bundle = BundleId(r.array()?);
        let realm = RealmId(u128::from_be_bytes(r.array()?));
        let epoch = Epoch(r.u64()?);
        let trust_digest = r.array()?;
        let head = EventDigest(r.array()?);
        let state_root = StateRoot(r.array()?);
        let height = r.u64()?;
        Ok(Self {
            generation,
            bundle,
            checkpoint: Checkpoint {
                realm,
                epoch,
                head,
                state_root,
                height,
            },
            trust_digest,
        })
    }
}

/// Storage contract implemented only by the local owner-selected adapter.
///
/// Reads distinguish absence from corruption and I/O failure. A successful put
/// makes immutable bytes AND their name durable. A successful CAS makes the pin
/// durable even when expected and next are identical. CAS errors may occur after
/// a visible or durable write. Implementations must serialize CAS across writers.
/// Reads alone are not durability receipts; retries must re-establish durability.
pub trait Storage {
    /// Backend-specific failures, including capacity and malformed local data.
    type Error;
    /// Read the protected local pin; only actual absence returns `None`.
    fn read_pin(&mut self) -> Result<Option<Pin>, Self::Error>;
    /// Read at most [`MAX_BUNDLE_BYTES`] before allocating from a stored length.
    fn read_bundle(&mut self, id: BundleId) -> Result<Vec<u8>, Self::Error>;
    /// Persist immutable content and its name. Existing identical content must
    /// be synced again; visibility after an earlier failed sync is insufficient.
    fn put_bundle(&mut self, id: BundleId, raw: &[u8]) -> Result<(), Self::Error>;
    /// Atomically compare the full pin and durably install `next`. `false` means
    /// mismatch without mutation. Error means the caller must reconcile/retry.
    fn compare_exchange_pin(
        &mut self,
        expected: Option<&Pin>,
        next: &Pin,
    ) -> Result<bool, Self::Error>;
}

/// A fully checked candidate bound to its exact expected predecessor pin.
///
/// ```compile_fail
/// use valhalla_checkpoint_ledger_prototype::persistence::{Pin, PreparedCommit};
/// fn skip_validation(pin: Pin) -> PreparedCommit { pin.into() }
/// ```
///
/// ```compile_fail
/// use valhalla_checkpoint_ledger_prototype::persistence::{Pin, PreparedCommit};
/// fn replace_candidate(commit: &mut PreparedCommit, pin: Pin) { commit.pin = pin; }
/// ```
pub struct PreparedCommit {
    expected: Option<Pin>,
    pin: Pin,
    bytes: Vec<u8>,
}

impl PreparedCommit {
    /// Prepare a certified tip, requiring strict same-policy linear extension
    /// of the predecessor. Bootstrap is explicit via `None`; storage CAS still
    /// refuses it if a pin already exists. No storage writes occur here.
    pub fn prepare(
        model: &CertifiedLedger,
        certificate: &[u8],
        previous: Option<&Pin>,
    ) -> Result<Self, ProtocolError> {
        let checked = model.accepted().ok_or(ProtocolError::Uncertified)?;
        let anchor = checked.recovery_anchor();
        let snapshot = model.snapshot();
        CertifiedLedger::recover(
            &snapshot,
            certificate,
            &anchor,
            model.trust.clone(),
            vhalla_ledger::MAX_EVENTS,
        )
        .map_err(ProtocolError::History)?;
        let checkpoint = checked.checkpoint();
        let generation = if let Some(previous) = previous {
            if previous.trust_digest != anchor.trust_digest()
                || previous.checkpoint.realm != checkpoint.realm
                || previous.checkpoint.epoch != checkpoint.epoch
            {
                return Err(ProtocolError::WrongPredecessor);
            }
            if checkpoint.height <= previous.checkpoint.height {
                return Err(ProtocolError::NonAdvancing);
            }
            model
                .ledger
                .validate_retained_checkpoint(previous.checkpoint)
                .map_err(|e| ProtocolError::History(crate::Error::Ledger(e)))?;
            previous
                .generation
                .checked_add(1)
                .ok_or(ProtocolError::GenerationOverflow)?
        } else {
            1
        };
        let bytes = encode_bundle(&snapshot, certificate)?;
        let pin = Pin {
            generation,
            bundle: bundle_id(&bytes),
            checkpoint,
            trust_digest: anchor.trust_digest(),
        };
        Ok(Self {
            expected: previous.cloned(),
            pin,
            bytes,
        })
    }

    /// Proposed plain-data pin. It is not a durable-commit receipt.
    #[must_use]
    pub fn pin(&self) -> &Pin {
        &self.pin
    }
}

/// Outcome returned only after a successful durable backend CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// This attempt advanced the exact expected predecessor.
    Committed,
    /// The target was already visible and this attempt reconfirmed durability.
    AlreadyCommitted,
}

/// Persist content before conditionally advancing the pin. No fallback, implicit
/// rebase, or deletion occurs. A retry of an indeterminate operation is safe.
pub fn commit<S: Storage>(
    storage: &mut S,
    prepared: &PreparedCommit,
) -> Result<CommitOutcome, StoreError<S::Error>> {
    let current = storage.read_pin().map_err(StoreError::Backend)?;
    let retry = current.as_ref() == Some(&prepared.pin);
    if !retry && current != prepared.expected {
        return Err(StoreError::Conflict);
    }
    // Redo durability even on a visible retry: a previous file or directory sync
    // may have failed. Never equate a read with a durable acknowledgement.
    storage
        .put_bundle(prepared.pin.bundle, &prepared.bytes)
        .map_err(StoreError::Backend)?;
    match storage.compare_exchange_pin(current.as_ref(), &prepared.pin) {
        Ok(true) => Ok(if retry {
            CommitOutcome::AlreadyCommitted
        } else {
            CommitOutcome::Committed
        }),
        Ok(false) => Err(StoreError::Conflict),
        Err(error) => Err(StoreError::Indeterminate(error)),
    }
}

/// Load only the owner-selected backend's exact pin and reverify the referenced
/// bytes, certificate, context, and ledger. Missing/corrupt data never falls back
/// to an older generation. Returning a model is not a durable write receipt.
/// The result is consistent with the pin read at the start; another writer may
/// advance that pin while this read is in progress.
pub fn load<S: Storage>(
    storage: &mut S,
    trust: TrustConfig,
    max_events: usize,
) -> Result<Option<CertifiedLedger>, StoreError<S::Error>> {
    let Some(pin) = storage.read_pin().map_err(StoreError::Backend)? else {
        return Ok(None);
    };
    if pin.trust_digest != trust.digest() {
        return Err(StoreError::Invalid(ProtocolError::WrongPredecessor));
    }
    let raw = storage
        .read_bundle(pin.bundle)
        .map_err(StoreError::Backend)?;
    if raw.len() > MAX_BUNDLE_BYTES {
        return Err(StoreError::Invalid(ProtocolError::OversizedBundle));
    }
    if bundle_id(&raw) != pin.bundle {
        return Err(StoreError::Invalid(ProtocolError::BundleMismatch));
    }
    let (snapshot, certificate) = decode_bundle(&raw).map_err(StoreError::Invalid)?;
    // Trust is supplied by the local storage boundary, never by Pin::decode.
    let anchor = RecoveryAnchor {
        checkpoint: pin.checkpoint,
        trust_digest: pin.trust_digest,
    };
    CertifiedLedger::recover(snapshot, certificate, &anchor, trust, max_events)
        .map(Some)
        .map_err(|e| StoreError::Invalid(ProtocolError::History(e)))
}

/// Structural, ancestry, or checked-history failures before a commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// No certificate has been admitted for the candidate.
    Uncertified,
    /// Previous pin context or trust configuration differs.
    WrongPredecessor,
    /// Candidate height does not strictly advance the previous checkpoint.
    NonAdvancing,
    /// Local commit generation cannot advance without wrapping.
    GenerationOverflow,
    /// Unsupported, truncated, or noncanonical local record.
    InvalidEncoding,
    /// Bundle or one of its fields exceeds its hard bound.
    OversizedBundle,
    /// Exact bundle bytes do not match the pinned content address.
    BundleMismatch,
    /// Certificate or derived-history checks failed.
    History(crate::Error),
}

/// Storage errors never grant execution authority or imply safe fallback.
#[derive(Debug, Eq, PartialEq)]
pub enum StoreError<E> {
    /// Backend operation failed. This is not evidence that earlier work aborted.
    Backend(E),
    /// Pin CAS may have committed; retry the same prepared operation to reconcile.
    Indeterminate(E),
    /// Another pin won; reload and prepare a valid descendant explicitly.
    Conflict,
    /// Stored content failed a bounded structural or semantic check.
    Invalid(ProtocolError),
}

fn encode_bundle(snapshot: &[u8], certificate: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if snapshot.len() > MAX_SNAPSHOT_BYTES || certificate.len() > MAX_PROOF_BYTES {
        return Err(ProtocolError::OversizedBundle);
    }
    let mut raw = Vec::with_capacity(BUNDLE_DOMAIN.len() + 10 + snapshot.len() + certificate.len());
    raw.extend_from_slice(BUNDLE_DOMAIN);
    raw.extend_from_slice(&VERSION.to_be_bytes());
    raw.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
    raw.extend_from_slice(snapshot);
    raw.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
    raw.extend_from_slice(certificate);
    Ok(raw)
}

fn decode_bundle(raw: &[u8]) -> Result<(&[u8], &[u8]), ProtocolError> {
    if raw.len() > MAX_BUNDLE_BYTES {
        return Err(ProtocolError::OversizedBundle);
    }
    let mut r = Reader(raw);
    if r.take(BUNDLE_DOMAIN.len())? != BUNDLE_DOMAIN || r.u16()? != VERSION {
        return Err(ProtocolError::InvalidEncoding);
    }
    let snapshot_len = r.u32()? as usize;
    if snapshot_len > MAX_SNAPSHOT_BYTES {
        return Err(ProtocolError::OversizedBundle);
    }
    let snapshot = r.take(snapshot_len)?;
    let certificate_len = r.u32()? as usize;
    if certificate_len > MAX_PROOF_BYTES {
        return Err(ProtocolError::OversizedBundle);
    }
    let certificate = r.take(certificate_len)?;
    if !r.0.is_empty() {
        return Err(ProtocolError::InvalidEncoding);
    }
    Ok((snapshot, certificate))
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        if len > self.0.len() {
            return Err(ProtocolError::InvalidEncoding);
        }
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::InvalidEncoding)
    }
    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn canonical_records_match_independent_python_hash_vectors() {
        let raw = encode_bundle(&[1, 2, 3], &[4, 5]).unwrap();
        assert_eq!(raw.len(), 48);
        assert_eq!(
            format!("{:x}", Sha256::digest(&raw)),
            "4d2152067860e0d8e9b9cf33336db7b6b2fede196f1ae744f3fceddc68d91929"
        );
        let pin = Pin {
            generation: 9,
            bundle: BundleId([1; 32]),
            checkpoint: Checkpoint {
                realm: RealmId(42),
                epoch: Epoch(7),
                head: EventDigest([3; 32]),
                state_root: StateRoot([4; 32]),
                height: 5,
            },
            trust_digest: [2; 32],
        };
        assert_eq!(pin.encode().len(), 200);
        assert_eq!(
            format!("{:x}", Sha256::digest(pin.encode())),
            "829b308a1ee954cdeb8a77538ee6808ede66ea9afa529244fc79495881880a64"
        );
    }

    #[test]
    fn bundle_framing_rejects_every_truncation_trailing_bytes_and_oversized_fields() {
        let raw = encode_bundle(&[1, 2, 3], &[4, 5]).unwrap();
        assert_eq!(decode_bundle(&raw), Ok((&[1, 2, 3][..], &[4, 5][..])));
        for end in 0..raw.len() {
            assert!(decode_bundle(&raw[..end]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(
            decode_bundle(&trailing),
            Err(ProtocolError::InvalidEncoding)
        );
        for offset in [BUNDLE_DOMAIN.len() + 2, BUNDLE_DOMAIN.len() + 2 + 4 + 3] {
            let mut oversized = raw.clone();
            oversized[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(
                decode_bundle(&oversized),
                Err(ProtocolError::OversizedBundle)
            );
        }
    }
}
