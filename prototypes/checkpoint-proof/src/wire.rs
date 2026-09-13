//! Canonical, bounded reference encoding. Decoding returns untrusted evidence.
//!
//! ```compile_fail
//! use valhalla_checkpoint_proof_prototype::{wire, VerifiedProof};
//! fn decode_authority(bytes: &[u8]) -> VerifiedProof {
//!     wire::decode(bytes).unwrap()
//! }
//! ```

use crate::{
    Approval, CheckpointProof, CheckpointStatement, Reject, SignerId, MAX_MEMBERS, MAX_PROOF_BYTES,
    MAX_REALM, PROOF_DOMAIN, STATEMENT_DOMAIN, VERSION,
};
use alloc::{string::String, vec::Vec};

/// Canonicalize the approval order, rejecting duplicates and mixed statements.
/// Signatures remain untrusted; this function does not authenticate them.
pub fn encode(proof: &CheckpointProof) -> Result<Vec<u8>, Reject> {
    let size = proof.encoded_len()?;
    let mut approvals: Vec<_> = proof.approvals.iter().collect();
    approvals.sort_unstable_by_key(|approval| approval.signer);
    let mut previous = None;
    for approval in &approvals {
        if approval.statement != proof.statement {
            return Err(Reject::ConflictingStatement);
        }
        if previous == Some(approval.signer) {
            return Err(Reject::DuplicateSigner);
        }
        previous = Some(approval.signer);
    }
    let statement_bytes = proof.statement.transcript()?;
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(PROOF_DOMAIN);
    out.extend_from_slice(&statement_bytes);
    out.extend_from_slice(&(approvals.len() as u64).to_be_bytes());
    for approval in approvals {
        out.extend_from_slice(&statement_bytes);
        out.extend_from_slice(&approval.signer.0);
        out.extend_from_slice(&approval.signature);
    }
    Ok(out)
}

/// Parse at most 64 KiB / 128 approvals, without authenticating the result.
pub fn decode(raw: &[u8]) -> Result<CheckpointProof, Reject> {
    decode_with_limits(raw, MAX_MEMBERS, MAX_PROOF_BYTES)
}

pub(crate) fn decode_with_limits(
    raw: &[u8],
    max_signers: usize,
    max_bytes: usize,
) -> Result<CheckpointProof, Reject> {
    if raw.len() > max_bytes.min(MAX_PROOF_BYTES) {
        return Err(Reject::OversizedProof);
    }
    let mut reader = Reader(raw);
    reader.domain(PROOF_DOMAIN)?;
    let statement = reader.statement()?;
    let count = reader.u64()?;
    if count > max_signers.min(MAX_MEMBERS) as u64 {
        return Err(Reject::OversizedProof);
    }
    // Every record must repeat the outer statement, so its exact size is known.
    // Check backing bytes before allocating any approval slots.
    let count = count as usize;
    let record_size = statement.encoded_len()? + 32 + 64;
    if reader.0.len() < count * record_size {
        return Err(Reject::InvalidEncoding);
    }
    let mut approvals = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let nested = reader.statement()?;
        if nested != statement {
            return Err(Reject::ConflictingStatement);
        }
        let signer = SignerId(reader.array()?);
        if previous.is_some_and(|id| signer <= id) {
            return Err(Reject::NonCanonicalProof);
        }
        previous = Some(signer);
        approvals.push(Approval {
            statement: nested,
            signer,
            signature: reader.array()?,
        });
    }
    if !reader.0.is_empty() {
        return Err(Reject::TrailingBytes);
    }
    Ok(CheckpointProof {
        statement,
        approvals,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Reject> {
        if length > self.0.len() {
            return Err(Reject::InvalidEncoding);
        }
        let (value, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(value)
    }
    fn domain(&mut self, expected: &[u8]) -> Result<(), Reject> {
        if self.take(expected.len())? != expected {
            return Err(Reject::InvalidEncoding);
        }
        Ok(())
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Reject> {
        self.take(N)?
            .try_into()
            .map_err(|_| Reject::InvalidEncoding)
    }
    fn u64(&mut self) -> Result<u64, Reject> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn statement(&mut self) -> Result<CheckpointStatement, Reject> {
        self.domain(STATEMENT_DOMAIN)?;
        let version = u16::from_be_bytes(self.array()?);
        if version != VERSION {
            return Err(Reject::InvalidStatement);
        }
        let length = self.u64()?;
        if length == 0 || length > MAX_REALM as u64 {
            return Err(Reject::InvalidStatement);
        }
        let realm = String::from(
            core::str::from_utf8(self.take(length as usize)?)
                .map_err(|_| Reject::InvalidEncoding)?,
        );
        Ok(CheckpointStatement {
            version,
            realm,
            epoch: self.u64()?,
            trust_digest: self.array()?,
            head: self.array()?,
            state_root: self.array()?,
            height: self.u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, ProofObserver, TrustConfig};
    use alloc::vec;
    use ed25519_dalek::SigningKey;
    use proptest::prelude::*;

    fn fixture() -> (TrustConfig, CheckpointProof) {
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        ];
        let trust = TrustConfig::new(
            "room",
            7,
            keys.iter().map(|k| k.verifying_key()),
            2,
            2,
            4096,
        )
        .unwrap();
        let statement = trust.statement([3; 32], [4; 32], 1);
        let approvals = keys
            .iter()
            .map(|k| Approval::sign(k, statement.clone()).unwrap())
            .collect();
        (
            trust,
            CheckpointProof {
                statement,
                approvals,
            },
        )
    }

    #[test]
    fn bytes_to_verified_observation_and_order_independence() {
        let (trust, mut proof) = fixture();
        let raw = encode(&proof).unwrap();
        assert_eq!(raw.len(), proof.encoded_len().unwrap());
        assert_eq!(encode(&decode(&raw).unwrap()).unwrap(), raw);
        proof.approvals.reverse();
        assert_eq!(encode(&proof).unwrap(), raw);
        let verified = trust.verify_bytes(&raw).unwrap();
        assert_eq!(verified, trust.verify(&proof).unwrap());
        let mut observer = ProofObserver::new(&trust, 2).unwrap();
        assert_eq!(observer.observe(&verified), Ok(Observation::Recorded));
        assert_eq!(
            observer.observe(&trust.verify_bytes(&raw).unwrap()),
            Ok(Observation::Duplicate)
        );
    }

    #[test]
    fn every_truncation_and_trailing_bytes_fail() {
        let (_, proof) = fixture();
        let raw = encode(&proof).unwrap();
        for cut in 0..raw.len() {
            assert!(decode(&raw[..cut]).is_err(), "accepted prefix at {cut}");
        }
        let mut extra = raw;
        extra.push(0);
        assert_eq!(decode(&extra), Err(Reject::TrailingBytes));
    }

    #[test]
    fn forged_lengths_domains_versions_and_utf8_fail_before_signatures() {
        let (_, proof) = fixture();
        let raw = encode(&proof).unwrap();
        let outer = PROOF_DOMAIN.len();
        let version = outer + STATEMENT_DOMAIN.len();
        let realm_length = version + 2;
        let count = outer + proof.statement.encoded_len().unwrap();
        for offset in [0, outer, version, realm_length, count] {
            let mut bad = raw.clone();
            bad[offset] = 255;
            assert!(
                decode(&bad).is_err(),
                "accepted malformed field at {offset}"
            );
        }
        let mut invalid_utf8 = raw.clone();
        invalid_utf8[realm_length + 8] = 255;
        assert_eq!(decode(&invalid_utf8), Err(Reject::InvalidEncoding));
        let huge = vec![0; MAX_PROOF_BYTES + 1];
        assert_eq!(decode(&huge), Err(Reject::OversizedProof));
        assert_eq!(
            decode_with_limits(&raw, 1, MAX_PROOF_BYTES),
            Err(Reject::OversizedProof)
        );
        assert_eq!(
            decode_with_limits(&raw, MAX_MEMBERS, raw.len() - 1),
            Err(Reject::OversizedProof)
        );
    }

    #[test]
    fn duplicate_unsorted_and_mixed_records_are_rejected() {
        let (_, mut proof) = fixture();
        let raw = encode(&proof).unwrap();
        let statement_len = proof.statement.encoded_len().unwrap();
        let records = PROOF_DOMAIN.len() + statement_len + 8;
        let record_len = statement_len + 96;
        let mut reordered = raw.clone();
        reordered[records..].rotate_left(record_len);
        assert_eq!(decode(&reordered), Err(Reject::NonCanonicalProof));
        let mut duplicate = raw.clone();
        let first = duplicate[records..records + record_len].to_vec();
        duplicate[records + record_len..].copy_from_slice(&first);
        assert_eq!(decode(&duplicate), Err(Reject::NonCanonicalProof));
        let mut mixed = raw;
        // Last byte of the nested statement's height.
        mixed[records + statement_len - 1] ^= 1;
        assert_eq!(decode(&mixed), Err(Reject::ConflictingStatement));
        proof.approvals[1] = proof.approvals[0].clone();
        assert_eq!(encode(&proof), Err(Reject::DuplicateSigner));
        proof.approvals[1].statement.height += 1;
        assert_eq!(encode(&proof), Err(Reject::ConflictingStatement));
    }

    #[test]
    fn parsing_never_authenticates_a_signature() {
        let (trust, proof) = fixture();
        let mut raw = encode(&proof).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(decode(&raw).is_ok());
        assert_eq!(trust.verify_bytes(&raw), Err(Reject::InvalidSignature));
    }

    #[test]
    fn maximum_realm_and_approval_count_round_trip() {
        let (_, mut proof) = fixture();
        proof.statement.realm = "r".repeat(MAX_REALM);
        proof.approvals = (0..MAX_MEMBERS)
            .map(|i| Approval {
                statement: proof.statement.clone(),
                signer: SignerId([i as u8; 32]),
                signature: [0; 64],
            })
            .collect();
        let raw = encode(&proof).unwrap();
        assert!(raw.len() <= MAX_PROOF_BYTES);
        assert_eq!(decode(&raw), Ok(proof.clone()));
        proof.approvals.push(proof.approvals[0].clone());
        assert_eq!(encode(&proof), Err(Reject::OversizedProof));
    }

    #[test]
    fn independent_certificate_encoding_vector() {
        use sha2::{Digest, Sha256};
        let statement = CheckpointStatement {
            version: 1,
            realm: "r".into(),
            epoch: 7,
            trust_digest: [3; 32],
            head: [1; 32],
            state_root: [2; 32],
            height: 4,
        };
        let proof = CheckpointProof {
            statement: statement.clone(),
            approvals: vec![Approval {
                statement,
                signer: SignerId([1; 32]),
                signature: [2; 64],
            }],
        };
        // Python struct/hashlib-generated framing fixture, not a valid signature.
        let expected = [
            255, 208, 255, 116, 132, 188, 70, 167, 91, 239, 50, 43, 53, 41, 23, 237, 50, 11, 233,
            90, 139, 175, 132, 41, 13, 78, 244, 143, 50, 5, 243, 26,
        ];
        let raw = encode(&proof).unwrap();
        assert_eq!(raw.len(), 460);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&raw)), expected);
        assert_eq!(decode(&raw), Ok(proof));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn canonical_round_trip_at_byte_and_integer_boundaries(
            realm in ".{1,32}", epoch in any::<u64>(), height in any::<u64>(),
            head in any::<[u8;32]>(), root in any::<[u8;32]>(),
        ) {
            let key = SigningKey::from_bytes(&[9;32]);
            let trust = TrustConfig::new(realm, epoch, [key.verifying_key()], 1, 1, 4096).unwrap();
            let statement = trust.statement(head, root, height);
            let proof = CheckpointProof { statement: statement.clone(), approvals: vec![Approval::sign(&key, statement).unwrap()] };
            let raw = encode(&proof).unwrap();
            prop_assert_eq!(decode(&raw).unwrap(), proof.clone());
            prop_assert_eq!(trust.verify_bytes(&raw).unwrap(), trust.verify(&proof).unwrap());
        }

        #[test]
        fn arbitrary_bounded_bytes_never_panic_and_accepted_bytes_are_canonical(raw in prop::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok(proof) = decode(&raw) { prop_assert_eq!(encode(&proof).unwrap(), raw); }
        }

        #[test]
        fn one_bit_mutation_cannot_preserve_a_verified_certificate(index in any::<usize>(), bit in 0u8..8) {
            let (trust, proof) = fixture();
            let mut raw = encode(&proof).unwrap();
            let offset = index % raw.len(); raw[offset] ^= 1 << bit;
            prop_assert!(trust.verify_bytes(&raw).is_err());
        }
    }
}
