//! Disposable, bounded checkpoint certificate model; not consensus or authority.
//!
//! A configured set of keys approves a context-bound statement. The verifier
//! authenticates that claim; it does not derive the state root or validate history.
//! A bounded observer detects conflicting certificates it has actually seen.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod wire;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const VERSION: u16 = 1;
const STATEMENT_DOMAIN: &[u8] = b"valhalla/checkpoint-proof/statement/v1";
const TRUST_DOMAIN: &[u8] = b"valhalla/checkpoint-proof/trust/v1";
const PROOF_DOMAIN: &[u8] = b"valhalla/checkpoint-proof/proof/v1";
pub const MAX_REALM: usize = 128;
pub const MAX_MEMBERS: usize = 128;
pub const MAX_PROOF_BYTES: usize = 64 * 1024;
pub const MAX_OBSERVATIONS: usize = 4096;

pub type Digest32 = [u8; 32];

/// Full public key, with no truncation to a short peer handle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignerId(pub [u8; 32]);

/// Untrusted claim. A signature does not establish that its root is correct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointStatement {
    pub version: u16,
    pub realm: String,
    pub epoch: u64,
    pub trust_digest: Digest32,
    pub head: Digest32,
    pub state_root: Digest32,
    pub height: u64,
}

impl CheckpointStatement {
    fn encoded_len(&self) -> Result<usize, Reject> {
        if self.version != VERSION || self.realm.is_empty() || self.realm.len() > MAX_REALM {
            return Err(Reject::InvalidStatement);
        }
        Ok(STATEMENT_DOMAIN.len() + 2 + 8 + self.realm.len() + 8 + 32 * 3 + 8)
    }

    /// One domain-separated, length-delimited signing transcript.
    pub fn transcript(&self) -> Result<Vec<u8>, Reject> {
        // Validate before allocating from untrusted lengths.
        let mut out = Vec::with_capacity(self.encoded_len()?);
        out.extend_from_slice(STATEMENT_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        put_bytes(&mut out, self.realm.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.trust_digest);
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.height.to_be_bytes());
        Ok(out)
    }
}

/// Untrusted approval; construction grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    pub statement: CheckpointStatement,
    pub signer: SignerId,
    pub signature: [u8; 64],
}

impl Approval {
    pub fn sign(key: &SigningKey, statement: CheckpointStatement) -> Result<Self, Reject> {
        let transcript = statement.transcript()?;
        Ok(Self {
            statement,
            signer: SignerId(key.verifying_key().to_bytes()),
            signature: key.sign(&transcript).to_bytes(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointProof {
    pub statement: CheckpointStatement,
    pub approvals: Vec<Approval>,
}

impl CheckpointProof {
    /// Size of the encoding: domain, outer statement, u64 count, then
    /// repeated statement/key/signature records. Structural admission is in `wire`.
    pub fn encoded_len(&self) -> Result<usize, Reject> {
        if self.approvals.len() > MAX_MEMBERS {
            return Err(Reject::OversizedProof);
        }
        let mut total = PROOF_DOMAIN.len() + self.statement.encoded_len()? + 8;
        for approval in &self.approvals {
            total += approval.statement.encoded_len()? + 32 + 64;
        }
        if total > MAX_PROOF_BYTES {
            return Err(Reject::OversizedProof);
        }
        Ok(total)
    }
}

/// Explicit, immutable trust policy for one realm epoch.
#[derive(Clone, Debug)]
pub struct TrustConfig {
    realm: String,
    epoch: u64,
    members: BTreeMap<SignerId, VerifyingKey>,
    threshold: usize,
    max_signers: usize,
    max_proof_bytes: usize,
    digest: Digest32,
}

impl TrustConfig {
    pub fn new(
        realm: impl Into<String>,
        epoch: u64,
        keys: impl IntoIterator<Item = VerifyingKey>,
        threshold: usize,
        max_signers: usize,
        max_proof_bytes: usize,
    ) -> Result<Self, Reject> {
        let realm = realm.into();
        if realm.is_empty()
            || realm.len() > MAX_REALM
            || threshold == 0
            || threshold > max_signers
            || max_signers > MAX_MEMBERS
            || max_proof_bytes == 0
            || max_proof_bytes > MAX_PROOF_BYTES
        {
            return Err(Reject::InvalidTrust);
        }
        let mut members = BTreeMap::new();
        for key in keys {
            if members.len() >= MAX_MEMBERS {
                return Err(Reject::TooManyMembers);
            }
            if key.is_weak() {
                return Err(Reject::InvalidTrust);
            }
            if members.insert(SignerId(key.to_bytes()), key).is_some() {
                return Err(Reject::DuplicateMember);
            }
        }
        if max_signers > members.len() {
            return Err(Reject::InvalidTrust);
        }
        let mut transcript = Vec::new();
        transcript.extend_from_slice(TRUST_DOMAIN);
        transcript.extend_from_slice(&VERSION.to_be_bytes());
        put_bytes(&mut transcript, realm.as_bytes());
        for n in [
            epoch,
            threshold as u64,
            max_signers as u64,
            max_proof_bytes as u64,
            members.len() as u64,
        ] {
            transcript.extend_from_slice(&n.to_be_bytes());
        }
        for member in members.keys() {
            transcript.extend_from_slice(&member.0);
        }
        let digest = Sha256::digest(transcript).into();
        Ok(Self {
            realm,
            epoch,
            members,
            threshold,
            max_signers,
            max_proof_bytes,
            digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest32 {
        self.digest
    }

    /// A convenience for constructing a claim, without validating its history.
    #[must_use]
    pub fn statement(
        &self,
        head: Digest32,
        state_root: Digest32,
        height: u64,
    ) -> CheckpointStatement {
        CheckpointStatement {
            version: VERSION,
            realm: self.realm.clone(),
            epoch: self.epoch,
            trust_digest: self.digest,
            head,
            state_root,
            height,
        }
    }

    /// All supplied approvals must be valid, distinct, and over one statement.
    pub fn verify(&self, proof: &CheckpointProof) -> Result<VerifiedProof, Reject> {
        if proof.approvals.len() > self.max_signers {
            return Err(Reject::OversizedProof);
        }
        if proof.encoded_len()? > self.max_proof_bytes {
            return Err(Reject::OversizedProof);
        }
        if proof.approvals.len() < self.threshold {
            return Err(Reject::UnderThreshold);
        }
        if proof.statement.realm != self.realm || proof.statement.epoch != self.epoch {
            return Err(Reject::WrongContext);
        }
        if proof.statement.trust_digest != self.digest {
            return Err(Reject::WrongTrust);
        }
        let transcript = proof.statement.transcript()?;
        let mut signers = BTreeSet::new();
        for approval in &proof.approvals {
            if approval.statement != proof.statement {
                return Err(Reject::ConflictingStatement);
            }
            if !signers.insert(approval.signer) {
                return Err(Reject::DuplicateSigner);
            }
            let key = self
                .members
                .get(&approval.signer)
                .ok_or(Reject::UnknownSigner)?;
            key.verify_strict(&transcript, &Signature::from_bytes(&approval.signature))
                .map_err(|_| Reject::InvalidSignature)?;
        }
        Ok(VerifiedProof {
            statement: proof.statement.clone(),
            signers,
        })
    }

    /// Bound and decode foreign bytes before authenticating their claim.
    /// This result still provides no history validation or host authority.
    pub fn verify_bytes(&self, raw: &[u8]) -> Result<VerifiedProof, Reject> {
        let proof = wire::decode_with_limits(raw, self.max_signers, self.max_proof_bytes)?;
        self.verify(&proof)
    }
}

/// Authenticated evidence, with no constructor or mutable projection.
/// It neither validates a ledger nor constructs a host capability.
///
/// ```compile_fail
/// use valhalla_checkpoint_proof_prototype::VerifiedProof;
/// fn tamper(proof: &mut VerifiedProof) {
///     proof.statement.height = 0;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProof {
    statement: CheckpointStatement,
    signers: BTreeSet<SignerId>,
}

impl VerifiedProof {
    #[must_use]
    pub fn statement(&self) -> &CheckpointStatement {
        &self.statement
    }
    #[must_use]
    pub fn signers(&self) -> &BTreeSet<SignerId> {
        &self.signers
    }
}

/// Volatile conflict observation, scoped to exactly one trust configuration.
/// No eviction: exhaustion requires an explicit recovery policy outside this model.
#[derive(Clone, Debug)]
pub struct ProofObserver {
    trust_digest: Digest32,
    max_heights: usize,
    seen: BTreeMap<u64, (Digest32, Digest32)>,
}

impl ProofObserver {
    pub fn new(trust: &TrustConfig, max_heights: usize) -> Result<Self, Reject> {
        if max_heights == 0 || max_heights > MAX_OBSERVATIONS {
            return Err(Reject::InvalidBound);
        }
        Ok(Self {
            trust_digest: trust.digest,
            max_heights,
            seen: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, proof: &VerifiedProof) -> Result<Observation, Reject> {
        let statement = proof.statement();
        if statement.trust_digest != self.trust_digest {
            return Err(Reject::WrongTrust);
        }
        let value = (statement.head, statement.state_root);
        if let Some(previous) = self.seen.get(&statement.height) {
            return if previous == &value {
                Ok(Observation::Duplicate)
            } else {
                Err(Reject::ConflictingCheckpoint)
            };
        }
        if self.seen.len() >= self.max_heights {
            return Err(Reject::Capacity);
        }
        self.seen.insert(statement.height, value);
        Ok(Observation::Recorded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Recorded,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    InvalidEncoding,
    NonCanonicalProof,
    TrailingBytes,
    InvalidStatement,
    InvalidTrust,
    TooManyMembers,
    DuplicateMember,
    OversizedProof,
    WrongContext,
    WrongTrust,
    UnknownSigner,
    DuplicateSigner,
    ConflictingStatement,
    InvalidSignature,
    UnderThreshold,
    InvalidBound,
    Capacity,
    ConflictingCheckpoint,
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }
    fn config() -> (TrustConfig, [SigningKey; 3]) {
        let keys = [key(1), key(2), key(3)];
        let trust = TrustConfig::new(
            "realm-a",
            7,
            keys.iter().map(|k| k.verifying_key()),
            2,
            3,
            4096,
        )
        .unwrap();
        (trust, keys)
    }
    fn proof(statement: CheckpointStatement, keys: &[SigningKey]) -> CheckpointProof {
        let approvals = keys
            .iter()
            .map(|k| Approval::sign(k, statement.clone()).unwrap())
            .collect();
        CheckpointProof {
            statement,
            approvals,
        }
    }

    #[test]
    fn threshold_order_and_duplicates() {
        let (trust, keys) = config();
        let statement = trust.statement([1; 32], [2; 32], 4);
        let mut certificate = proof(statement.clone(), &keys[..2]);
        let verified = trust.verify(&certificate).unwrap();
        certificate.approvals.reverse();
        assert_eq!(trust.verify(&certificate), Ok(verified));
        assert_eq!(
            trust.verify(&proof(statement, &keys[..1])),
            Err(Reject::UnderThreshold)
        );
        certificate.approvals[1] = certificate.approvals[0].clone();
        assert_eq!(trust.verify(&certificate), Err(Reject::DuplicateSigner));
    }

    #[test]
    fn malformed_or_extra_invalid_approvals_are_not_ignored() {
        let (trust, keys) = config();
        let body = trust.statement([1; 32], [2; 32], 4);
        let good = proof(body.clone(), &keys[..2]);
        let mut bad = good.clone();
        bad.approvals
            .push(Approval::sign(&key(9), body.clone()).unwrap());
        assert_eq!(trust.verify(&bad), Err(Reject::UnknownSigner));
        bad = good.clone();
        bad.approvals[0].signature[0] ^= 1;
        assert_eq!(trust.verify(&bad), Err(Reject::InvalidSignature));
        bad = good.clone();
        bad.approvals[0].statement.height += 1;
        assert_eq!(trust.verify(&bad), Err(Reject::ConflictingStatement));
        bad = good.clone();
        bad.approvals.resize(4, good.approvals[0].clone());
        assert_eq!(trust.verify(&bad), Err(Reject::OversizedProof));
        let tiny = TrustConfig::new(
            "realm-a",
            7,
            keys.iter().map(|k| k.verifying_key()),
            2,
            3,
            1,
        )
        .unwrap();
        assert_eq!(
            tiny.verify(&proof(tiny.statement([0; 32], [0; 32], 0), &keys[..2])),
            Err(Reject::OversizedProof)
        );
        let mut invalid = body;
        invalid.version = 2;
        assert_eq!(
            Approval::sign(&keys[0], invalid),
            Err(Reject::InvalidStatement)
        );
    }

    #[test]
    fn trust_identity_is_order_independent_but_policy_bound() {
        let (trust, keys) = config();
        let certificate = proof(trust.statement([1; 32], [2; 32], 4), &keys);
        let reversed = TrustConfig::new(
            "realm-a",
            7,
            keys.iter().rev().map(|k| k.verifying_key()),
            2,
            3,
            4096,
        )
        .unwrap();
        assert_eq!(trust.digest(), reversed.digest());
        assert!(reversed.verify(&certificate).is_ok());
        for (threshold, max_signers, bytes) in [(3, 3, 4096), (2, 2, 4096), (2, 3, 4095)] {
            let changed = TrustConfig::new(
                "realm-a",
                7,
                keys.iter().map(|k| k.verifying_key()),
                threshold,
                max_signers,
                bytes,
            )
            .unwrap();
            assert_ne!(trust.digest(), changed.digest());
            assert!(changed.verify(&certificate).is_err());
        }
        let changed = TrustConfig::new(
            "realm-a",
            7,
            [
                keys[0].verifying_key(),
                keys[1].verifying_key(),
                key(9).verifying_key(),
            ],
            2,
            3,
            4096,
        )
        .unwrap();
        assert_eq!(changed.verify(&certificate), Err(Reject::WrongTrust));
    }

    #[test]
    fn trust_bounds_and_weak_keys_fail_closed() {
        let keys = [key(1).verifying_key(), key(2).verifying_key()];
        for (threshold, max_signers, bytes) in [
            (0, 1, 100),
            (2, 1, 100),
            (1, 3, 100),
            (1, 1, 0),
            (1, 1, MAX_PROOF_BYTES + 1),
        ] {
            assert!(matches!(
                TrustConfig::new("r", 0, keys, threshold, max_signers, bytes),
                Err(Reject::InvalidTrust)
            ));
        }
        assert!(matches!(
            TrustConfig::new("r", 0, [keys[0]; 2], 1, 2, 100),
            Err(Reject::DuplicateMember)
        ));
        let mut identity = [0; 32];
        identity[0] = 1;
        let weak = VerifyingKey::from_bytes(&identity).unwrap();
        assert!(matches!(
            TrustConfig::new("r", 0, [weak], 1, 1, 100),
            Err(Reject::InvalidTrust)
        ));
        let many: Vec<_> = (0..=MAX_MEMBERS as u8)
            .map(|n| key(n).verifying_key())
            .collect();
        assert!(matches!(
            TrustConfig::new("r", 0, many, 1, 128, 100),
            Err(Reject::TooManyMembers)
        ));
    }

    #[test]
    fn two_conflicting_certificates_can_verify_but_observation_fails_closed() {
        let (trust, keys) = config();
        let first = trust
            .verify(&proof(trust.statement([1; 32], [2; 32], 4), &keys[..2]))
            .unwrap();
        let conflicting = trust
            .verify(&proof(trust.statement([9; 32], [2; 32], 4), &keys[1..]))
            .unwrap();
        // Stateless signature verification cannot prevent two sets signing conflicts.
        let mut observer = ProofObserver::new(&trust, 1).unwrap();
        assert_eq!(observer.observe(&first), Ok(Observation::Recorded));
        assert_eq!(
            observer.observe(&conflicting),
            Err(Reject::ConflictingCheckpoint)
        );
        assert_eq!(observer.observe(&first), Ok(Observation::Duplicate));
        let later = trust
            .verify(&proof(trust.statement([3; 32], [4; 32], 5), &keys[..2]))
            .unwrap();
        assert_eq!(observer.observe(&later), Err(Reject::Capacity));
        assert_eq!(observer.observe(&first), Ok(Observation::Duplicate));
        let changed = TrustConfig::new(
            "realm-a",
            8,
            keys.iter().map(|k| k.verifying_key()),
            2,
            3,
            4096,
        )
        .unwrap();
        assert_eq!(
            ProofObserver::new(&changed, 1).unwrap().observe(&first),
            Err(Reject::WrongTrust)
        );
        assert!(matches!(
            ProofObserver::new(&trust, MAX_OBSERVATIONS + 1),
            Err(Reject::InvalidBound)
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn every_signed_field_is_bound(
            epoch in any::<u64>(), height in any::<u64>(),
            head in any::<Digest32>(), root in any::<Digest32>(),
            realm in "[a-z]{1,32}",
        ) {
            let keys = [key(1), key(2)];
            let trust = TrustConfig::new(realm, epoch, keys.iter().map(|k| k.verifying_key()), 2, 2, 4096).unwrap();
            let original = proof(trust.statement(head, root, height), &keys);
            prop_assert!(trust.verify(&original).is_ok());
            for field in 0..7 {
                let mut changed = original.clone();
                match field {
                    0 => changed.statement.version = 2,
                    1 => changed.statement.realm.push('x'),
                    2 => changed.statement.epoch ^= 1,
                    3 => changed.statement.trust_digest[0] ^= 1,
                    4 => changed.statement.head[0] ^= 1,
                    5 => changed.statement.state_root[0] ^= 1,
                    _ => changed.statement.height ^= 1,
                }
                for approval in &mut changed.approvals { approval.statement = changed.statement.clone(); }
                prop_assert!(trust.verify(&changed).is_err());
            }
        }

        #[test]
        fn transcript_is_injective_for_distinct_bounded_statements(
            a in ("[a-z]{1,32}", any::<u64>(), any::<Digest32>(), any::<Digest32>(), any::<u64>()),
            b in ("[a-z]{1,32}", any::<u64>(), any::<Digest32>(), any::<Digest32>(), any::<u64>()),
        ) {
            prop_assume!(a != b);
            let from = |(realm, epoch, head, state_root, height)| CheckpointStatement {
                version: 1, realm, epoch, trust_digest: [3; 32], head, state_root, height
            };
            prop_assert_ne!(from(a).transcript().unwrap(), from(b).transcript().unwrap());
        }
    }

    #[test]
    fn size_checks_precede_unbounded_allocation_or_crypto() {
        let (trust, keys) = config();
        let mut body = trust.statement([1; 32], [2; 32], 4);
        body.realm = "r".repeat(MAX_REALM + 1);
        assert_eq!(body.transcript(), Err(Reject::InvalidStatement));
        let approval = Approval::sign(&keys[0], trust.statement([1; 32], [2; 32], 4)).unwrap();
        let huge = CheckpointProof {
            statement: body,
            approvals: vec![approval; MAX_MEMBERS + 1],
        };
        assert_eq!(huge.encoded_len(), Err(Reject::OversizedProof));
    }

    #[test]
    fn independent_transcript_vector() {
        // Generated with Python struct.pack('>HQ', 1, 1), b'r', epoch u64,
        // three 32-byte fields, height u64, and hashlib.sha256; see README.
        let body = CheckpointStatement {
            version: 1,
            realm: "r".into(),
            epoch: 7,
            trust_digest: [3; 32],
            head: [1; 32],
            state_root: [2; 32],
            height: 4,
        };
        let bytes = body.transcript().unwrap();
        assert_eq!(bytes.len(), 161);
        let expected = [
            84, 181, 27, 169, 242, 177, 194, 229, 84, 103, 109, 65, 15, 149, 134, 149, 40, 150,
            158, 33, 139, 241, 113, 233, 21, 220, 165, 155, 123, 107, 69, 237,
        ];
        assert_eq!(Digest32::from(Sha256::digest(bytes)), expected);
    }
}
