use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use valhalla_checkpoint_ledger_prototype::{
    certificate_realm,
    rotation::{
        Observation, Reject, RotationObserver, RotationPolicy, RotationStatement, Side,
        MAX_ROTATION_BYTES,
    },
    CertifiedLedger,
};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

const REALM: RealmId = RealmId(42);
const EPOCH: Epoch = Epoch(7);
const MAX_PROOF: usize = 4096;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn policy(realm: RealmId, epoch: Epoch, seeds: &[u8], threshold: usize) -> RotationPolicy {
    RotationPolicy::new(
        realm,
        epoch,
        seeds.iter().map(|seed| key(*seed).verifying_key()),
        threshold,
        seeds.len(),
        MAX_PROOF,
    )
    .unwrap()
}

fn model(epoch: Epoch) -> CertifiedLedger {
    let trust = TrustConfig::new(
        certificate_realm(REALM),
        epoch.0,
        [1, 2, 3].map(|seed| key(seed).verifying_key()),
        2,
        3,
        MAX_PROOF,
    )
    .unwrap();
    CertifiedLedger::new(REALM, epoch, trust, 10).unwrap()
}

fn certify(ledger: &mut CertifiedLedger) {
    let statement = ledger.propose_tip().unwrap();
    let proof = CheckpointProof {
        approvals: [1, 2]
            .map(|seed| Approval::sign(&key(seed), statement.clone()).unwrap())
            .to_vec(),
        statement,
    };
    ledger.admit(&wire::encode(&proof).unwrap()).unwrap();
}

fn checked_model() -> CertifiedLedger {
    let mut ledger = model(EPOCH);
    ledger
        .append(Event::new(
            None,
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(1),
            b"genesis".to_vec(),
        ))
        .unwrap();
    certify(&mut ledger);
    ledger
}

fn observer(ledger: &CertifiedLedger, cap: usize) -> RotationObserver<'_> {
    RotationObserver::new(ledger, policy(REALM, EPOCH, &[1, 2, 3], 2), cap).unwrap()
}

// Test-side encoder only: the production module has no signer, encoder or
// authority-bearing constructor. Sort full public keys, never short handles.
fn certificate(statement: &RotationStatement, old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut bytes = statement.transcript(Side::Old);
    bytes.pop(); // the proposal fields, without the signer role byte
    for (side, seeds) in [(Side::Old, old), (Side::New, new)] {
        let transcript = statement.transcript(side);
        let mut records: Vec<_> = seeds
            .iter()
            .map(|seed| {
                let signer = key(*seed);
                (
                    signer.verifying_key().to_bytes(),
                    signer.sign(&transcript).to_bytes(),
                )
            })
            .collect();
        records.sort_unstable_by_key(|(id, _)| *id);
        bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
        for (id, signature) in records {
            bytes.extend_from_slice(&id);
            bytes.extend_from_slice(&signature);
        }
    }
    bytes
}

#[test]
fn two_independently_configured_quorums_bind_the_checked_tip_and_next_epoch() {
    let ledger = checked_model();
    let mut verifier = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let statement = verifier.proposal(&next).unwrap();
    assert_eq!(
        statement.old_frontier(),
        ledger.accepted().unwrap().checkpoint()
    );
    assert_eq!(
        statement.old_digest(),
        policy(REALM, EPOCH, &[1, 2, 3], 2).digest()
    );
    assert_eq!(statement.new_digest(), next.digest());
    assert_eq!(statement.next_epoch(), Epoch(8));
    assert_ne!(
        statement.transcript(Side::Old),
        statement.transcript(Side::New)
    );
    let raw = certificate(&statement, &[1, 2], &[4, 5]);
    assert_eq!(verifier.observe(&raw, &next), Ok(Observation::Recorded));
    assert_eq!(verifier.observe(&raw, &next), Ok(Observation::Repeated));
    assert_eq!(verifier.evidence()[0].bytes(), raw);
    assert!(!verifier.blocked());
    // No epoch change, effect or policy install is possible through this API.
    assert_eq!(ledger.accepted().unwrap().checkpoint().epoch, EPOCH);
    assert_eq!(ledger.snapshot(), checked_model().snapshot());
}

#[test]
fn tampering_forged_policies_and_missing_approvals_preserve_evidence() {
    let ledger = checked_model();
    let mut verifier = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let statement = verifier.proposal(&next).unwrap();
    let raw = certificate(&statement, &[1, 2], &[4, 5]);
    // Every signed field (including domain, realm, frontier and both policy
    // digests) is checked against the configured proposal or signatures.
    let statement_len = statement.transcript(Side::Old).len() - 1;
    for offset in 0..statement_len {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert!(
            verifier.observe(&changed, &next).is_err(),
            "field offset {offset}"
        );
    }
    for (old, new) in [
        (&[1, 2][..], &[4][..]),
        (&[1][..], &[4, 5][..]),
        (&[1, 2, 9][..], &[4, 5][..]),
    ] {
        assert!(verifier
            .observe(&certificate(&statement, old, new), &next)
            .is_err());
    }
    let other = policy(REALM, Epoch(8), &[4, 5, 7], 2);
    assert_eq!(verifier.observe(&raw, &other), Err(Reject::WrongTransition));
    let wrong_old = policy(REALM, EPOCH, &[1, 2, 9], 2);
    assert_eq!(
        RotationObserver::new(&ledger, wrong_old, 2).err(),
        Some(Reject::WrongPolicy)
    );
    assert_eq!(
        verifier.proposal(&policy(RealmId(43), Epoch(8), &[4, 5], 2)),
        Err(Reject::WrongContext)
    );
    assert_eq!(
        verifier.proposal(&policy(REALM, EPOCH, &[4, 5], 2)),
        Err(Reject::WrongContext)
    );
    assert_eq!(
        verifier.proposal(&policy(REALM, Epoch(9), &[4, 5], 2)),
        Err(Reject::WrongContext)
    );
    assert!(verifier.evidence().is_empty());
}

#[test]
fn malformed_records_are_bounded_canonical_and_authenticated() {
    let ledger = checked_model();
    let mut verifier = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let statement = verifier.proposal(&next).unwrap();
    let raw = certificate(&statement, &[1, 2], &[4, 5]);
    for cut in 0..raw.len() {
        assert!(
            verifier.observe(&raw[..cut], &next).is_err(),
            "truncated {cut}"
        );
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert_eq!(verifier.observe(&extra, &next), Err(Reject::TrailingBytes));
    assert_eq!(
        verifier.observe(&vec![0; MAX_ROTATION_BYTES + 1], &next),
        Err(Reject::Oversized)
    );
    let start = statement.transcript(Side::Old).len() - 1 + 2;
    let mut reverse = raw.clone();
    reverse[start..start + 192].rotate_left(96);
    assert_eq!(verifier.observe(&reverse, &next), Err(Reject::NonCanonical));
    let mut duplicate = raw.clone();
    duplicate.copy_within(start..start + 96, start + 96);
    assert_eq!(
        verifier.observe(&duplicate, &next),
        Err(Reject::NonCanonical)
    );
    let mut unknown = certificate(&statement, &[1, 9], &[4, 5]);
    assert_eq!(
        verifier.observe(&unknown, &next),
        Err(Reject::UnknownSigner)
    );
    let last = unknown.len() - 1;
    unknown[last] ^= 1;
    assert!(verifier.observe(&unknown, &next).is_err());
    let mut wrong_sig = raw.clone();
    let last = wrong_sig.len() - 1;
    wrong_sig[last] ^= 1;
    assert_eq!(
        verifier.observe(&wrong_sig, &next),
        Err(Reject::InvalidSignature)
    );
    let mut excess_count = raw;
    excess_count[start - 2..start].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        verifier.observe(&excess_count, &next),
        Err(Reject::Oversized)
    );
    assert!(verifier.evidence().is_empty());
}

#[test]
fn shared_key_cannot_replay_old_role_as_new_approval() {
    let ledger = checked_model();
    let mut verifier = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[1, 2, 3], 2);
    let statement = verifier.proposal(&next).unwrap();
    let mut bytes = certificate(&statement, &[1, 2], &[1, 2]);
    let old_records = statement.transcript(Side::Old).len() - 1 + 2;
    let new_records = old_records + 192 + 2;
    let replay = bytes[old_records..old_records + 192].to_vec();
    bytes[new_records..new_records + 192].copy_from_slice(&replay);
    assert_eq!(
        verifier.observe(&bytes, &next),
        Err(Reject::InvalidSignature)
    );
    assert!(verifier.evidence().is_empty());
}

#[test]
fn stale_frontier_and_epoch_overflow_refuse_to_rotate() {
    let mut ledger = model(EPOCH);
    assert_eq!(
        RotationObserver::new(&ledger, policy(REALM, EPOCH, &[1, 2, 3], 2), 2).err(),
        Some(Reject::StaleFrontier)
    );
    ledger
        .append(Event::new(
            None,
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(1),
            b"one".to_vec(),
        ))
        .unwrap();
    certify(&mut ledger);
    let stale = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let raw = certificate(&stale.proposal(&next).unwrap(), &[1, 2], &[4, 5]);
    drop(stale); // the borrow prevents appending while the old observer is alive
    ledger
        .append(Event::new(
            ledger.head(),
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(2),
            b"two".to_vec(),
        ))
        .unwrap();
    assert_eq!(
        RotationObserver::new(&ledger, policy(REALM, EPOCH, &[1, 2, 3], 2), 2).err(),
        Some(Reject::StaleFrontier)
    );
    certify(&mut ledger);
    let mut current = observer(&ledger, 2);
    assert_eq!(current.observe(&raw, &next), Err(Reject::WrongTransition));
    let mut max_epoch = model(Epoch(u64::MAX));
    max_epoch
        .append(Event::new(
            None,
            REALM,
            Epoch(u64::MAX),
            PeerId(1),
            Sequence(1),
            vec![],
        ))
        .unwrap();
    certify(&mut max_epoch);
    assert_eq!(
        RotationObserver::new(&max_epoch, policy(REALM, Epoch(u64::MAX), &[1, 2, 3], 2), 2).err(),
        Some(Reject::EpochOverflow)
    );
}

#[test]
fn distinct_valid_transitions_remain_conflicts_without_eviction_or_selection() {
    let ledger = checked_model();
    let mut verifier = observer(&ledger, 2);
    let a = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let b = policy(REALM, Epoch(8), &[4, 5, 7], 2);
    let c = policy(REALM, Epoch(8), &[4, 5, 8], 2);
    let ra = certificate(&verifier.proposal(&a).unwrap(), &[1, 2], &[4, 5]);
    let rb = certificate(&verifier.proposal(&b).unwrap(), &[1, 2], &[4, 5]);
    let rc = certificate(&verifier.proposal(&c).unwrap(), &[1, 2], &[4, 5]);
    assert_eq!(verifier.observe(&ra, &a), Ok(Observation::Recorded));
    assert_eq!(
        verifier.observe(&rb, &b),
        Err(Reject::ConflictingTransitions)
    );
    assert!(verifier.blocked());
    assert_eq!(verifier.evidence().len(), 2);
    assert_eq!(verifier.evidence()[0].bytes(), ra);
    assert_eq!(verifier.evidence()[1].bytes(), rb);
    assert_eq!(
        verifier.observe(&ra, &a),
        Err(Reject::ConflictingTransitions)
    );
    assert_eq!(verifier.observe(&rc, &c), Err(Reject::Capacity));
    assert_eq!(verifier.observe(&ra, &a), Err(Reject::Capacity));
    assert_eq!(verifier.evidence().len(), 2);
    assert_eq!(
        RotationObserver::new(&ledger, policy(REALM, EPOCH, &[1, 2, 3], 2), 1).err(),
        Some(Reject::InvalidBound)
    );
}

#[test]
fn fixed_python_transcript_vector() {
    // Independent hashlib/struct encoding with fixture public keys derived by
    // OpenSSL from public test seeds [1,2,3] and [4,5,6]. See README.
    let ledger = checked_model();
    let verifier = observer(&ledger, 2);
    let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
    let statement = verifier.proposal(&next).unwrap();
    let old = statement.transcript(Side::Old);
    let new = statement.transcript(Side::New);
    assert_eq!(old.len(), 209);
    assert_eq!(&old[..old.len() - 1], &new[..new.len() - 1]);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&old)),
        [
            0x55, 0xf6, 0xaa, 0x8b, 0xd4, 0xe6, 0x60, 0x63, 0xb9, 0x7e, 0x66, 0x5f, 0x9c, 0x37,
            0xec, 0xba, 0xf1, 0xd5, 0x82, 0xbc, 0xf5, 0x58, 0x79, 0xcd, 0x81, 0xb4, 0x39, 0xcb,
            0xbb, 0x1f, 0xb5, 0xa8,
        ]
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&new)),
        [
            0x2a, 0x1a, 0x89, 0x0c, 0x22, 0x13, 0xcd, 0xfa, 0x6a, 0x10, 0xa3, 0x28, 0x48, 0x48,
            0x81, 0x0e, 0x09, 0x14, 0xf1, 0x3d, 0x7d, 0x93, 0x80, 0xfc, 0x3b, 0x22, 0xad, 0xd4,
            0x91, 0x2b, 0x2b, 0x10,
        ]
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn arbitrary_bytes_cannot_panic_or_mutate_existing_evidence(raw in prop::collection::vec(any::<u8>(), 0..2048)) {
        let ledger = checked_model();
        let mut verifier = observer(&ledger, 2);
        let next = policy(REALM, Epoch(8), &[4, 5, 6], 2);
        let valid = certificate(&verifier.proposal(&next).unwrap(), &[1, 2], &[4, 5]);
        prop_assert_eq!(verifier.observe(&valid, &next), Ok(Observation::Recorded));
        let _ = verifier.observe(&raw, &next);
        prop_assert_eq!(verifier.evidence()[0].bytes(), valid);
    }
}
