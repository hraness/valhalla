//! Finite conformance to the Lean corpus, not a Rust refinement proof.

use super::*;

use arc_malachitebft_core_types::{CommitCertificate, CommitSignature};

use crate::cert::{
    canonical_bytes, verify_canonical_certificate, verify_commit_certificate, CertError,
};
use crate::signing::RoomSigner;

struct QuorumCase {
    id: String,
    powers: Vec<u64>,
    signers: Vec<usize>,
    accept: bool,
}

fn corpus() -> Vec<QuorumCase> {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../../../../verify/lean/corpus.json")).unwrap();
    assert_eq!(document["version"].as_u64(), Some(1));
    let cases = document["cases"].as_array().unwrap();
    assert_eq!(
        cases.len(),
        354,
        "Lean corpus must retain its complete scope"
    );
    cases
        .iter()
        .map(|case| QuorumCase {
            id: case["id"].as_str().unwrap().to_owned(),
            powers: case["powers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|power| power.as_u64().unwrap())
                .collect(),
            signers: case["signers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|signer| usize::try_from(signer.as_u64().unwrap()).unwrap())
                .collect(),
            accept: case["accept"].as_bool().unwrap(),
        })
        .collect()
}

fn key(index: usize) -> PrivateKey {
    let seed = u8::try_from(index + 1).unwrap();
    PrivateKey::from([seed; 32])
}

fn signed_certificate(
    powers: &[u64],
    signers: &[usize],
    height: u64,
    round: Round,
    value_id: RoomValueId,
) -> (RoomValidatorSet, CommitCertificate<RoomContext>) {
    // Corpus indices name the original identities, not the sorted positions
    // of RoomValidatorSet: unequal powers deliberately reorder validators.
    let validators = RoomValidatorSet::try_new(
        powers
            .iter()
            .enumerate()
            .map(|(index, power)| RoomValidator::new(key(index).public_key(), *power))
            .collect(),
    )
    .unwrap();
    let certificate = CommitCertificate {
        height: Height::new(height),
        round,
        value_id,
        commit_signatures: signers
            .iter()
            .map(|index| {
                let signer = key(*index);
                let address = Address::from_public_key(&signer.public_key());
                let vote = RoomVote::new(
                    VoteType::Precommit,
                    Height::new(height),
                    round,
                    NilOrVal::Val(value_id),
                    address,
                );
                CommitSignature::new(
                    address,
                    RoomSigner::new(signer).sign(&vote_sign_bytes(&vote)),
                )
            })
            .collect(),
    };
    (validators, certificate)
}

#[test]
fn lean_shared_quorum_corpus_matches_authenticated_verifiers() {
    let mut ids = std::collections::BTreeSet::new();
    let mut accepted_small = std::collections::BTreeMap::<Vec<u64>, Vec<Vec<usize>>>::new();
    let mut small_cases = 0;
    for case in corpus() {
        assert!(
            ids.insert(case.id.clone()),
            "duplicate case id: {}",
            case.id
        );
        let (validators, certificate) = signed_certificate(
            &case.powers,
            &case.signers,
            19,
            Round::new(7),
            RoomValueId([31; 32]),
        );
        let raw = canonical_bytes(&certificate);
        let engine = verify_commit_certificate(&certificate, &validators);
        assert_eq!(engine.is_ok(), case.accept, "{}: engine", case.id);
        assert_eq!(
            verify_canonical_certificate(&raw, 19, &certificate.value_id, &validators),
            case.accept,
            "{}: canonical",
            case.id
        );
        if let Ok(accepted) = engine {
            assert_eq!(accepted.bytes, raw, "{}: stored bytes", case.id);
            assert_eq!(accepted.height, 19, "{}: accepted height", case.id);
            assert_eq!(
                accepted.value_id, certificate.value_id,
                "{}: accepted value",
                case.id
            );
            if case.id.starts_with("small-") {
                accepted_small
                    .entry(case.powers.clone())
                    .or_default()
                    .push(case.signers.clone());
            }
        }
        if case.id.starts_with("small-") {
            small_cases += 1;
        }
    }
    assert_eq!(small_cases, 340);
    assert_eq!(accepted_small.len(), 30);

    // These pairs come from successful calls to both authenticated Rust
    // verifiers above. Enumerate fault masks only after their certificates
    // have been checked, avoiding repeated signature verification per pair.
    // This is finite conformance evidence for the theorem, not its proof.
    let mut checked_pairs = 0;
    let mut checked_fault_assignments = 0;
    for (powers, certificates) in accepted_small {
        let total: u64 = powers.iter().sum();
        for left in &certificates {
            for right in &certificates {
                checked_pairs += 1;
                for faulty in 0..(1usize << powers.len()) {
                    let faulty_power: u64 = powers
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| faulty & (1 << index) != 0)
                        .map(|(_, power)| power)
                        .sum();
                    if 3 * faulty_power > total {
                        continue;
                    }
                    let honest_overlap: u64 = powers
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| {
                            left.contains(index)
                                && right.contains(index)
                                && faulty & (1 << index) == 0
                        })
                        .map(|(_, power)| power)
                        .sum();
                    assert!(
                        honest_overlap > 0,
                        "{powers:?}: {left:?}, {right:?}, {faulty}"
                    );
                    checked_fault_assignments += 1;
                }
            }
        }
    }
    assert_eq!(checked_pairs, 315);
    assert_eq!(checked_fault_assignments, 1451);
}

#[test]
fn lean_reserved_maximum_round_is_rejected_by_both_certificate_verifiers() {
    for (round, expected) in [(u32::MAX - 1, true), (u32::MAX, false)] {
        let (validators, certificate) = signed_certificate(
            &[1, 2],
            &[0, 1],
            19,
            Round::new(round),
            RoomValueId([31; 32]),
        );
        let canonical = verify_canonical_certificate(
            &canonical_bytes(&certificate),
            19,
            &certificate.value_id,
            &validators,
        );
        assert_eq!(canonical, expected, "canonical round {round}");
        assert_eq!(
            verify_commit_certificate(&certificate, &validators).is_ok(),
            expected,
            "engine round {round} must agree with canonical admission"
        );
        if !expected {
            assert_eq!(
                verify_commit_certificate(&certificate, &validators),
                Err(CertError::ReservedRound)
            );
        }
    }
}

fn assert_rejected_by_both(
    label: &str,
    certificate: &CommitCertificate<RoomContext>,
    validators: &RoomValidatorSet,
    error: CertError,
) {
    assert_eq!(
        verify_commit_certificate(certificate, validators),
        Err(error),
        "{label}: engine"
    );
    assert!(
        !verify_canonical_certificate(
            &canonical_bytes(certificate),
            certificate.height.as_u64(),
            &certificate.value_id,
            validators,
        ),
        "{label}: canonical"
    );
}

#[test]
fn lean_authenticated_signatures_bind_each_certificate_context_field() {
    let (validators, original) =
        signed_certificate(&[1, 3], &[1], 19, Round::new(7), RoomValueId([31; 32]));
    assert!(verify_commit_certificate(&original, &validators).is_ok());
    assert!(verify_canonical_certificate(
        &canonical_bytes(&original),
        19,
        &original.value_id,
        &validators
    ));

    let mut changed = original.clone();
    changed.height = Height::new(20);
    assert_rejected_by_both(
        "changed height",
        &changed,
        &validators,
        CertError::BadSignature,
    );
    let mut changed = original.clone();
    changed.round = Round::new(8);
    assert_rejected_by_both(
        "changed round",
        &changed,
        &validators,
        CertError::BadSignature,
    );
    let mut changed = original.clone();
    changed.value_id = RoomValueId([32; 32]);
    assert_rejected_by_both(
        "changed value",
        &changed,
        &validators,
        CertError::BadSignature,
    );
    let mut changed = original.clone();
    changed.commit_signatures[0].address = Address::from_public_key(&key(0).public_key());
    assert_rejected_by_both(
        "changed signer",
        &changed,
        &validators,
        CertError::BadSignature,
    );

    let mut changed = original.clone();
    let signer = key(1);
    let prevote = RoomVote::new(
        VoteType::Prevote,
        original.height,
        original.round,
        NilOrVal::Val(original.value_id),
        changed.commit_signatures[0].address,
    );
    changed.commit_signatures[0].signature =
        RoomSigner::new(signer).sign(&vote_sign_bytes(&prevote));
    assert_rejected_by_both(
        "prevote signature",
        &changed,
        &validators,
        CertError::BadSignature,
    );

    // Canonical consumers also bind expected bundle metadata before checking
    // the signatures, independent of the signed certificate's own header.
    let raw = canonical_bytes(&original);
    assert!(!verify_canonical_certificate(
        &raw,
        20,
        &original.value_id,
        &validators
    ));
    assert!(!verify_canonical_certificate(
        &raw,
        19,
        &RoomValueId([32; 32]),
        &validators
    ));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(!verify_canonical_certificate(
        &trailing,
        19,
        &original.value_id,
        &validators
    ));
    assert!(!verify_canonical_certificate(
        &raw[..raw.len() - 1],
        19,
        &original.value_id,
        &validators
    ));
}

#[test]
fn lean_signer_identity_and_certificate_bounds_are_admission_premises() {
    for (label, signers, error) in [
        ("empty", vec![], CertError::TooManySignatures),
        ("duplicate", vec![1, 1], CertError::DuplicateSigner),
        ("unknown", vec![1, 2], CertError::UnknownSigner),
        ("oversized", vec![1; 65], CertError::TooManySignatures),
    ] {
        let (validators, certificate) =
            signed_certificate(&[1, 3], &signers, 19, Round::new(7), RoomValueId([31; 32]));
        assert_rejected_by_both(label, &certificate, &validators, error);
    }
    let (validators, certificate) =
        signed_certificate(&[1, 3], &[1], 19, Round::Nil, RoomValueId([31; 32]));
    assert_rejected_by_both("Nil round", &certificate, &validators, CertError::NilRound);
}

#[test]
fn lean_invalid_rosters_fail_closed_before_certificate_admission() {
    let (valid, certificate) =
        signed_certificate(&[1, 3], &[0, 1], 19, Round::new(7), RoomValueId([31; 32]));
    let mut reversed = valid.clone();
    reversed.validators.reverse();
    let mut repeated = valid.clone();
    repeated.validators.push(repeated.validators[0].clone());
    let mut wrong_address = valid.clone();
    wrong_address.validators[0].address = Address::from_public_key(&key(2).public_key());
    for (label, validators) in [
        ("empty", RoomValidatorSet::new(vec![])),
        (
            "zero power",
            RoomValidatorSet::new(vec![RoomValidator::new(key(0).public_key(), 0)]),
        ),
        (
            "over cap",
            RoomValidatorSet::new(vec![RoomValidator::new(
                key(0).public_key(),
                u64::MAX / 3 + 1,
            )]),
        ),
        (
            "sum over cap",
            RoomValidatorSet::new(vec![
                RoomValidator::new(key(0).public_key(), u64::MAX / 3),
                RoomValidator::new(key(1).public_key(), 1),
            ]),
        ),
        (
            "65 validators",
            RoomValidatorSet::new(
                (0..65)
                    .map(|index| RoomValidator::new(key(index).public_key(), 1))
                    .collect(),
            ),
        ),
        ("reordered", reversed),
        ("repeated identity", repeated),
        ("mismatched public key", wrong_address),
    ] {
        assert_rejected_by_both(
            label,
            &certificate,
            &validators,
            CertError::InvalidValidatorSet,
        );
    }
}
