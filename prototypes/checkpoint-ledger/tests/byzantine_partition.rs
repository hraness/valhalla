//! Partition counterexample for the certificate layer.
//!
//! This deliberately tests the boundary of quorum certificates, not a
//! consensus engine. A certificate verifier can reject a 2–2 partition with a
//! three-of-four threshold, but it cannot by itself prevent equivocation by a
//! validator that signs two conflicting statements. Locking, ordering and
//! durable recovery remain engine obligations.

use ed25519_dalek::SigningKey;
use valhalla_checkpoint_proof_prototype::{
    wire, Approval, CheckpointProof, CheckpointStatement, Reject, TrustConfig,
};

const REALM: &str = "partition-fixture";
const EPOCH: u64 = 9;

fn keys() -> [SigningKey; 4] {
    [21, 22, 23, 24].map(|seed| SigningKey::from_bytes(&[seed; 32]))
}

fn trust() -> TrustConfig {
    TrustConfig::new(
        REALM,
        EPOCH,
        keys().iter().map(SigningKey::verifying_key),
        3,
        4,
        64 * 1024,
    )
    .unwrap()
}

fn statement(trust: &TrustConfig, head: u8) -> CheckpointStatement {
    trust.statement([head; 32], [head.wrapping_add(1); 32], u64::from(head))
}

fn certificate(statement: CheckpointStatement, signer_indices: &[usize]) -> Vec<u8> {
    let keys = keys();
    let approvals = signer_indices
        .iter()
        .map(|&index| Approval::sign(&keys[index], statement.clone()).unwrap())
        .collect();
    wire::encode(&CheckpointProof {
        statement,
        approvals,
    })
    .unwrap()
}

#[test]
fn every_three_of_four_quorum_verifies_but_two_two_partition_does_not() {
    let trust = trust();
    let statement_a = statement(&trust, 1);
    let statement_b = statement(&trust, 2);

    // A partition with two validators on each side cannot create a proof.
    assert_eq!(
        trust.verify_bytes(&certificate(statement_a.clone(), &[0, 1])),
        Err(Reject::UnderThreshold)
    );
    assert_eq!(
        trust.verify_bytes(&certificate(statement_b.clone(), &[2, 3])),
        Err(Reject::UnderThreshold)
    );

    // Once connectivity restores, each three-member subset is a valid quorum
    // for the exact statement it signed. The verifier does not choose an order
    // or establish that two conflicting proofs cannot both exist.
    for subset in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
        assert!(trust
            .verify_bytes(&certificate(statement_a.clone(), &subset))
            .is_ok());
    }
    assert!(trust
        .verify_bytes(&certificate(statement_b, &[0, 1, 2]))
        .is_ok());
}

#[test]
fn a_certificate_cannot_become_finality_by_changing_the_threshold_afterward() {
    let statement = statement(&trust(), 3);
    let proof = certificate(statement, &[0, 1]);
    assert_eq!(trust().verify_bytes(&proof), Err(Reject::UnderThreshold));

    // A lower threshold is a different trust policy and therefore a different
    // digest. It cannot reinterpret a proof under the pinned three-of-four one.
    let lower = TrustConfig::new(
        REALM,
        EPOCH,
        keys().iter().map(SigningKey::verifying_key),
        2,
        4,
        64 * 1024,
    )
    .unwrap();
    assert_eq!(lower.verify_bytes(&proof), Err(Reject::WrongTrust));
}
