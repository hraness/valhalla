//! Volatile reference verifier for a separately configured checkpoint trust rotation.
//!
//! This checks two quorums against a history-checked *current* old frontier.
//! It never changes the ledger epoch, installs policy, persists evidence, or
//! supplies an authorization token. An observer is not a durable conflict store.

use crate::{certificate_realm, CertifiedLedger};
use alloc::{collections::BTreeMap, vec::Vec};
use ed25519_dalek::{Signature, VerifyingKey};
use valhalla_checkpoint_proof_prototype::{
    Digest32, Reject as ProofReject, SignerId, TrustConfig, MAX_MEMBERS,
};
use vhalla_core::{Epoch, RealmId};
use vhalla_ledger::Checkpoint;

const DOMAIN: &[u8] = b"valhalla/checkpoint-ledger/rotation/v1";
const VERSION: u16 = 1;
const RECORD_BYTES: usize = 32 + 64;
/// Hard bound on one canonical transition certificate, including both quorums.
pub const MAX_ROTATION_BYTES: usize = 32 * 1024;
/// Maximum number of distinct transitions retained for one checked frontier.
pub const MAX_TRANSITIONS: usize = 8;

/// Extract an UNVERIFIED new-policy digest for looking up a separately configured
/// policy. The lookup must never construct or install policy from these bytes;
/// [`RotationObserver::observe`] authenticates the entire certificate afterward.
pub fn proposed_policy_digest(raw: &[u8]) -> Result<Digest32, Reject> {
    Ok(Reader::new(raw)?.statement()?.new_digest)
}

/// Independently configured policy; never decoded from an incoming transition.
///
/// The digest is the exact checkpoint-proof policy digest, including realm,
/// epoch, keys, threshold and certificate limits. Construct this with trusted
/// configuration, not from certificate bytes.
#[derive(Clone, Debug)]
pub struct RotationPolicy {
    realm: RealmId,
    epoch: Epoch,
    digest: Digest32,
    keys: BTreeMap<SignerId, VerifyingKey>,
    threshold: usize,
    max_signers: usize,
}

impl RotationPolicy {
    /// Reconstruct the complete configured checkpoint policy and its digest.
    pub fn new(
        realm: RealmId,
        epoch: Epoch,
        keys: impl IntoIterator<Item = VerifyingKey>,
        threshold: usize,
        max_signers: usize,
        max_proof_bytes: usize,
    ) -> Result<Self, Reject> {
        let keys: Vec<_> = keys.into_iter().take(MAX_MEMBERS + 1).collect();
        let trust = TrustConfig::new(
            certificate_realm(realm),
            epoch.0,
            keys.iter().copied(),
            threshold,
            max_signers,
            max_proof_bytes,
        )
        .map_err(Reject::Policy)?;
        Ok(Self {
            realm,
            epoch,
            digest: trust.digest(),
            keys: keys
                .into_iter()
                .map(|key| (SignerId(key.to_bytes()), key))
                .collect(),
            threshold,
            max_signers,
        })
    }

    /// Digest of the entire configured checkpoint policy.
    #[must_use]
    pub fn digest(&self) -> Digest32 {
        self.digest
    }
}

/// An untrusted, fixed-width rotation statement. A proposal is not evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationStatement {
    old: Checkpoint,
    old_digest: Digest32,
    new_digest: Digest32,
    next_epoch: Epoch,
}

impl RotationStatement {
    /// Old independently checked frontier (not a new-epoch genesis).
    #[must_use]
    pub fn old_frontier(&self) -> Checkpoint {
        self.old
    }

    /// Complete old policy digest.
    #[must_use]
    pub fn old_digest(&self) -> Digest32 {
        self.old_digest
    }

    /// Complete proposed new policy digest.
    #[must_use]
    pub fn new_digest(&self) -> Digest32 {
        self.new_digest
    }

    /// Exactly the next epoch, if the proposal was created by an observer.
    #[must_use]
    pub fn next_epoch(&self) -> Epoch {
        self.next_epoch
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN.len() + 2 + 16 + 16 + 32 * 4 + 8);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&self.old.realm.0.to_be_bytes());
        out.extend_from_slice(&self.old.epoch.0.to_be_bytes());
        out.extend_from_slice(&self.next_epoch.0.to_be_bytes());
        out.extend_from_slice(&self.old.head.0);
        out.extend_from_slice(&self.old.state_root.0);
        out.extend_from_slice(&self.old.height.to_be_bytes());
        out.extend_from_slice(&self.old_digest);
        out.extend_from_slice(&self.new_digest);
        out
    }

    /// Domain-separated signing bytes; the final byte binds the quorum role.
    /// The old (`0`) and new (`1`) signatures are not interchangeable even
    /// when the two policies share a key. No signing is performed here.
    #[must_use]
    pub fn transcript(&self, side: Side) -> Vec<u8> {
        let mut out = self.bytes();
        out.push(side as u8);
        out
    }
}

/// Which configured quorum signed the statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// Old policy authorizes leaving the checked frontier.
    Old = 0,
    /// New policy acknowledges the same transition.
    New = 1,
}

/// Validated evidence retained verbatim for diagnosis; never an activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionEvidence {
    statement: RotationStatement,
    bytes: Vec<u8>,
}

impl TransitionEvidence {
    /// Authenticated statement; no mutable projection.
    #[must_use]
    pub fn statement(&self) -> &RotationStatement {
        &self.statement
    }

    /// Canonical certificate bytes for an external, separately qualified store.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Bounded volatile observer scoped to one already checked, current frontier.
///
/// A shared reference to the ledger prevents appending while observing; a
/// caller must rebind to a newly checked tip after any append. No incoming
/// certificate chooses old or new keys: `observe` takes a new policy from the
/// caller's independent configuration on *every* attempt. `Recorded` does not
/// install that policy. Conflicts or exhaustion stick for this observer.
pub struct RotationObserver<'a> {
    ledger: &'a CertifiedLedger,
    old: Checkpoint,
    old_policy: RotationPolicy,
    max_transitions: usize,
    evidence: Vec<TransitionEvidence>,
    exhausted: bool,
}

impl<'a> RotationObserver<'a> {
    /// Bind the supplied old policy to the checked, current ledger tip.
    /// A trailing checkpoint or overflowing epoch cannot rotate.
    pub fn new(
        ledger: &'a CertifiedLedger,
        old_policy: RotationPolicy,
        max_transitions: usize,
    ) -> Result<Self, Reject> {
        if !(2..=MAX_TRANSITIONS).contains(&max_transitions) {
            return Err(Reject::InvalidBound);
        }
        let checked = ledger.accepted().ok_or(Reject::StaleFrontier)?;
        let old = checked.checkpoint();
        if ledger.head() != Some(old.head)
            || ledger
                .event_count()
                .checked_sub(1)
                .and_then(|count| u64::try_from(count).ok())
                != Some(old.height)
        {
            return Err(Reject::StaleFrontier);
        }
        if old.epoch.0.checked_add(1).is_none() {
            return Err(Reject::EpochOverflow);
        }
        if old_policy.realm != old.realm || old_policy.epoch != old.epoch {
            return Err(Reject::WrongContext);
        }
        if old_policy.digest != checked.proof().statement().trust_digest {
            return Err(Reject::WrongPolicy);
        }
        Ok(Self {
            ledger,
            old,
            old_policy,
            max_transitions,
            evidence: Vec::new(),
            exhausted: false,
        })
    }

    /// Checked old frontier used to scope an external evidence record.
    #[must_use]
    pub fn old_frontier(&self) -> Checkpoint {
        self.old
    }

    /// Independently configured old policy digest.
    #[must_use]
    pub fn old_policy_digest(&self) -> Digest32 {
        self.old_policy.digest
    }

    /// Make an unsigned proposal from *independently supplied* new policy.
    pub fn proposal(&self, new_policy: &RotationPolicy) -> Result<RotationStatement, Reject> {
        let next_epoch = Epoch(
            self.old
                .epoch
                .0
                .checked_add(1)
                .ok_or(Reject::EpochOverflow)?,
        );
        if new_policy.realm != self.old.realm || new_policy.epoch != next_epoch {
            return Err(Reject::WrongContext);
        }
        Ok(RotationStatement {
            old: self.old,
            old_digest: self.old_policy.digest,
            new_digest: new_policy.digest,
            next_epoch,
        })
    }

    /// Decode, authenticate both sides and retain evidence without choosing it.
    /// All failures leave retained certificates intact. A distinct valid claim
    /// at capacity makes the observer permanently blocked rather than evicting.
    pub fn observe(
        &mut self,
        raw: &[u8],
        new_policy: &RotationPolicy,
    ) -> Result<Observation, Reject> {
        // Keep the checked ledger borrowed for the lifetime of this observer.
        let _ = self.ledger;
        let expected = self.proposal(new_policy)?;
        let mut reader = Reader::new(raw)?;
        let statement = reader.statement()?;
        if statement != expected {
            return Err(Reject::WrongTransition);
        }
        reader.quorum(&statement, Side::Old, &self.old_policy)?;
        reader.quorum(&statement, Side::New, new_policy)?;
        if !reader.rest.is_empty() {
            return Err(Reject::TrailingBytes);
        }
        if self.exhausted {
            return Err(Reject::Capacity);
        }
        if self.evidence.iter().any(|item| item.statement == statement) {
            return if self.evidence.len() == 1 {
                Ok(Observation::Repeated)
            } else {
                Err(Reject::ConflictingTransitions)
            };
        }
        if self.evidence.len() == self.max_transitions {
            self.exhausted = true;
            return Err(Reject::Capacity);
        }
        self.evidence.push(TransitionEvidence {
            statement,
            bytes: raw.to_vec(),
        });
        if self.evidence.len() > 1 {
            Err(Reject::ConflictingTransitions)
        } else {
            Ok(Observation::Recorded)
        }
    }

    /// All retained valid claims, including both sides of a conflict.
    #[must_use]
    pub fn evidence(&self) -> &[TransitionEvidence] {
        &self.evidence
    }

    /// No policy can be selected while conflicting or exhausted.
    #[must_use]
    pub fn blocked(&self) -> bool {
        self.exhausted || self.evidence.len() > 1
    }
}

/// Results for the first valid observation and its exact transition retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// Recorded as evidence, not selected or activated.
    Recorded,
    /// The same statement already has valid evidence; no new state retained.
    Repeated,
}

/// Failure to decode, authenticate, or unambiguously retain a transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    /// The configured checkpoint policy is invalid.
    Policy(ProofReject),
    /// Observer's conflict count must be between 2 and 8.
    InvalidBound,
    /// Old certificate is absent or no longer names the current tip.
    StaleFrontier,
    /// Cannot advance beyond the maximum epoch.
    EpochOverflow,
    /// Configured realm or epoch does not match the checked frontier.
    WrongContext,
    /// Supplied old policy does not match the certified old policy digest.
    WrongPolicy,
    /// Incoming transition does not equal the expected checked proposal.
    WrongTransition,
    /// Bad domain, version, length, count, or truncation.
    InvalidEncoding,
    /// Certificate exceeds its hard bound or configured signer count.
    Oversized,
    /// Signers are not strictly increasing (including duplicates).
    NonCanonical,
    /// Additional bytes follow the two quorum records.
    TrailingBytes,
    /// Quorum did not meet its configured threshold.
    UnderThreshold,
    /// An approval names a key not present in its independently chosen policy.
    UnknownSigner,
    /// A signature does not verify for its configured key, role and statement.
    InvalidSignature,
    /// At least two different valid statements were observed for this frontier.
    ConflictingTransitions,
    /// Evidence bound was reached; no evidence was discarded.
    Capacity,
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Result<Self, Reject> {
        if raw.len() > MAX_ROTATION_BYTES {
            return Err(Reject::Oversized);
        }
        Ok(Self { rest: raw })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Reject> {
        if self.rest.len() < len {
            return Err(Reject::InvalidEncoding);
        }
        let (head, rest) = self.rest.split_at(len);
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        self.take(N)?
            .try_into()
            .map_err(|_| Reject::InvalidEncoding)
    }

    fn statement(&mut self) -> Result<RotationStatement, Reject> {
        if self.take(DOMAIN.len())? != DOMAIN || u16::from_be_bytes(self.array()?) != VERSION {
            return Err(Reject::InvalidEncoding);
        }
        let realm = RealmId(u128::from_be_bytes(self.array()?));
        let epoch = Epoch(u64::from_be_bytes(self.array()?));
        let next_epoch = Epoch(u64::from_be_bytes(self.array()?));
        Ok(RotationStatement {
            old: Checkpoint {
                realm,
                epoch,
                head: vhalla_ledger::EventDigest(self.array()?),
                state_root: vhalla_ledger::StateRoot(self.array()?),
                height: u64::from_be_bytes(self.array()?),
            },
            old_digest: self.array()?,
            new_digest: self.array()?,
            next_epoch,
        })
    }

    fn quorum(
        &mut self,
        statement: &RotationStatement,
        side: Side,
        policy: &RotationPolicy,
    ) -> Result<(), Reject> {
        let count = u16::from_be_bytes(self.array()?) as usize;
        if count > policy.max_signers || count > MAX_MEMBERS {
            return Err(Reject::Oversized);
        }
        if count < policy.threshold {
            return Err(Reject::UnderThreshold);
        }
        if self.rest.len() < count * RECORD_BYTES {
            return Err(Reject::InvalidEncoding);
        }
        let transcript = statement.transcript(side);
        let mut previous = None;
        for _ in 0..count {
            let id = SignerId(self.array()?);
            if previous.is_some_and(|before| id <= before) {
                return Err(Reject::NonCanonical);
            }
            previous = Some(id);
            let signature = Signature::from_bytes(&self.array()?);
            let key = policy.keys.get(&id).ok_or(Reject::UnknownSigner)?;
            key.verify_strict(&transcript, &signature)
                .map_err(|_| Reject::InvalidSignature)?;
        }
        Ok(())
    }
}
