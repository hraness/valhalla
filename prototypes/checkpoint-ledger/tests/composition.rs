use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use valhalla_checkpoint_ledger_prototype::{certificate_realm, CertifiedLedger, Error};
use valhalla_checkpoint_proof_prototype::{
    wire, Approval, CheckpointProof, CheckpointStatement, Reject, TrustConfig, MAX_PROOF_BYTES,
};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::{Error as LedgerError, Event, Ledger, MAX_PAYLOAD};

const REALM: RealmId = RealmId(0x1234_abcd_0000_0000_ffff_1234_5678_9abc);
const EPOCH: Epoch = Epoch(7);
const CAPACITY: usize = 32;

fn keys() -> [SigningKey; 3] {
    [1, 2, 3].map(|seed| SigningKey::from_bytes(&[seed; 32]))
}

fn trust_for(realm: impl Into<String>, epoch: u64) -> TrustConfig {
    TrustConfig::new(
        realm,
        epoch,
        keys().iter().map(SigningKey::verifying_key),
        2,
        3,
        MAX_PROOF_BYTES,
    )
    .unwrap()
}

fn trust() -> TrustConfig {
    trust_for(certificate_realm(REALM), EPOCH.0)
}

fn model() -> CertifiedLedger {
    CertifiedLedger::new(REALM, EPOCH, trust(), CAPACITY).unwrap()
}

fn sign(statement: CheckpointStatement) -> Vec<u8> {
    let approvals = keys()[..2]
        .iter()
        .map(|key| Approval::sign(key, statement.clone()).unwrap())
        .collect();
    wire::encode(&CheckpointProof {
        statement,
        approvals,
    })
    .unwrap()
}

fn append(model: &mut CertifiedLedger, sequence: u64, payload: &[u8]) {
    model
        .append(Event::new(
            model.head(),
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(sequence),
            payload.to_vec(),
        ))
        .unwrap();
}

fn certify(model: &mut CertifiedLedger) -> Vec<u8> {
    let certificate = sign(model.propose_tip().unwrap());
    model.admit(&certificate).unwrap();
    certificate
}

fn reject_without_mutation(model: &mut CertifiedLedger, certificate: &[u8], expected: Error) {
    let snapshot = model.snapshot();
    let accepted = model.accepted().cloned();
    assert_eq!(model.admit(certificate).err(), Some(expected));
    assert_eq!(model.snapshot(), snapshot);
    assert_eq!(model.accepted(), accepted.as_ref());
}

#[test]
fn exact_realm_spelling_and_epoch_are_constructor_requirements() {
    assert_eq!(
        certificate_realm(RealmId(0)),
        "vhalla/realm/u128/v1/00000000000000000000000000000000"
    );
    assert_eq!(
        certificate_realm(RealmId(u128::MAX)),
        "vhalla/realm/u128/v1/ffffffffffffffffffffffffffffffff"
    );
    let canonical = certificate_realm(REALM);
    for alias in [
        canonical.to_uppercase(),
        canonical.replace("9abc", "9ABC"),
        canonical.replace("u128/v1/", "u128/v1/0"),
        canonical.replace("/v1/", "/v2/"),
        format!(" {canonical}"),
        format!("{canonical}\n"),
        REALM.0.to_string(),
        format!("{:032x}", REALM.0),
        certificate_realm(RealmId(REALM.0 ^ (1 << 127))),
    ] {
        assert_eq!(
            CertifiedLedger::new(REALM, EPOCH, trust_for(alias, EPOCH.0), CAPACITY).err(),
            Some(Error::TrustContextMismatch)
        );
    }
    assert_eq!(
        CertifiedLedger::new(REALM, EPOCH, trust_for(canonical, EPOCH.0 + 1), CAPACITY).err(),
        Some(Error::TrustContextMismatch)
    );
    assert_eq!(
        CertifiedLedger::new(
            RealmId(1),
            EPOCH,
            trust_for("vhalla/realm/u128/v1/1", EPOCH.0),
            CAPACITY,
        )
        .err(),
        Some(Error::TrustContextMismatch)
    );
}

#[test]
fn signed_bytes_create_immutable_history_checked_evidence() {
    let mut model = model();
    assert_eq!(model.propose_tip(), Err(Error::EmptyHistory));
    assert!(model.accepted().is_none());
    append(&mut model, 1, b"genesis");
    let proposal = model.propose_tip().unwrap();
    assert!(model.accepted().is_none());
    let certificate = sign(proposal.clone());
    let checked = model.admit(&certificate).unwrap().clone();
    assert_eq!(checked.proof().statement(), &proposal);
    assert_eq!(checked.proof().signers().len(), 2);
    assert_eq!(checked.checkpoint().realm, REALM);
    assert_eq!(checked.checkpoint().epoch, EPOCH);
    assert_eq!(checked.checkpoint().head, model.head().unwrap());
    assert_eq!(checked.checkpoint().state_root.0, proposal.state_root);
    assert_eq!(checked.checkpoint().height, 0);
    assert_eq!(checked.recovery_anchor().trust_digest(), trust().digest());

    let mut detached_copy = checked.checkpoint();
    detached_copy.height = 100;
    assert_ne!(detached_copy, checked.checkpoint());
    let snapshot = model.snapshot();
    assert_eq!(model.admit(&certificate).unwrap(), &checked);
    assert_eq!(model.snapshot(), snapshot);
}

#[test]
fn valid_signatures_over_false_roots_heights_and_heads_preserve_live_state() {
    let mut model = model();
    append(&mut model, 1, b"first");
    let first_certificate = certify(&mut model);
    append(&mut model, 2, b"second");
    let tip = model.propose_tip().unwrap();

    let mut wrong_root = tip.clone();
    wrong_root.state_root[0] ^= 1;
    let mut wrong_height = tip.clone();
    wrong_height.height += 1;
    let mut wrong_head = tip;
    wrong_head.head[31] ^= 1;
    for (statement, error) in [
        (wrong_root, LedgerError::RootMismatch),
        (wrong_height, LedgerError::HeightMismatch),
        (wrong_head, LedgerError::StaleCheckpoint),
    ] {
        let certificate = sign(statement);
        assert!(trust().verify_bytes(&certificate).is_ok());
        reject_without_mutation(&mut model, &certificate, Error::Ledger(error));
    }
    reject_without_mutation(
        &mut model,
        &first_certificate,
        Error::Ledger(LedgerError::StaleCheckpoint),
    );
    certify(&mut model);
    assert_eq!(model.accepted().unwrap().checkpoint().height, 1);
}

#[test]
fn proof_context_policy_and_signature_rejections_preserve_accepted_evidence() {
    let mut model = model();
    append(&mut model, 1, b"first");
    let certificate = certify(&mut model);
    let proposal = model.propose_tip().unwrap();
    for foreign in [
        trust_for(certificate_realm(RealmId(999)), EPOCH.0),
        trust_for(certificate_realm(REALM), EPOCH.0 + 1),
    ] {
        let foreign_certificate =
            sign(foreign.statement(proposal.head, proposal.state_root, proposal.height));
        assert!(foreign.verify_bytes(&foreign_certificate).is_ok());
        reject_without_mutation(
            &mut model,
            &foreign_certificate,
            Error::Proof(Reject::WrongContext),
        );
    }
    let changed_policy = TrustConfig::new(
        certificate_realm(REALM),
        EPOCH.0,
        keys().iter().map(SigningKey::verifying_key),
        1,
        3,
        MAX_PROOF_BYTES,
    )
    .unwrap();
    let other_certificate =
        sign(changed_policy.statement(proposal.head, proposal.state_root, proposal.height));
    reject_without_mutation(
        &mut model,
        &other_certificate,
        Error::Proof(Reject::WrongTrust),
    );
    let mut tampered = certificate;
    *tampered.last_mut().unwrap() ^= 1;
    reject_without_mutation(
        &mut model,
        &tampered,
        Error::Proof(Reject::InvalidSignature),
    );
}

#[test]
fn a_fresh_anchor_rejects_old_valid_snapshots_and_old_valid_certificates() {
    let mut model = model();
    append(&mut model, 1, b"first");
    let old_certificate = certify(&mut model);
    let old_snapshot = model.snapshot();
    let old_anchor = model.accepted().unwrap().recovery_anchor();
    append(&mut model, 2, b"second");
    let fresh_certificate = certify(&mut model);
    let fresh_snapshot = model.snapshot();
    let fresh_anchor = model.accepted().unwrap().recovery_anchor();

    for snapshot in [&old_snapshot, &fresh_snapshot] {
        assert_eq!(
            CertifiedLedger::recover(snapshot, &old_certificate, &fresh_anchor, trust(), CAPACITY)
                .err(),
            Some(Error::AnchorMismatch)
        );
    }
    assert_eq!(
        CertifiedLedger::recover(
            &old_snapshot,
            &fresh_certificate,
            &fresh_anchor,
            trust(),
            CAPACITY,
        )
        .err(),
        Some(Error::Ledger(LedgerError::StaleCheckpoint))
    );
    let recovered = CertifiedLedger::recover(
        &fresh_snapshot,
        &fresh_certificate,
        &fresh_anchor,
        trust(),
        CAPACITY,
    )
    .unwrap();
    assert_eq!(recovered.snapshot(), fresh_snapshot);

    // An old but matching pin remains consistent: freshness must come from the
    // owner's separate storage boundary, which this in-memory model cannot prove.
    let old_recovery = CertifiedLedger::recover(
        &old_snapshot,
        &old_certificate,
        &old_anchor,
        trust(),
        CAPACITY,
    )
    .unwrap();
    assert_eq!(old_recovery.snapshot(), old_snapshot);
    assert_eq!(old_recovery.event_count(), 1);
}

#[test]
fn recovery_rejects_forks_foreign_contexts_and_uncertified_suffixes() {
    let mut model = model();
    append(&mut model, 1, b"shared genesis");
    let genesis_certificate = certify(&mut model);
    let genesis_anchor = model.accepted().unwrap().recovery_anchor();
    append(&mut model, 2, b"chosen branch");
    let suffix_snapshot = model.snapshot();
    assert_eq!(
        CertifiedLedger::recover(
            &suffix_snapshot,
            &genesis_certificate,
            &genesis_anchor,
            trust(),
            CAPACITY,
        )
        .err(),
        Some(Error::Ledger(LedgerError::StaleCheckpoint))
    );
    let certificate = certify(&mut model);
    let anchor = model.accepted().unwrap().recovery_anchor();

    let mut fork = CertifiedLedger::new(REALM, EPOCH, trust(), CAPACITY).unwrap();
    append(&mut fork, 1, b"shared genesis");
    append(&mut fork, 2, b"other branch");
    assert_eq!(
        CertifiedLedger::recover(&fork.snapshot(), &certificate, &anchor, trust(), CAPACITY).err(),
        Some(Error::Ledger(LedgerError::StaleCheckpoint))
    );

    for (realm, epoch) in [(RealmId(999), EPOCH), (REALM, Epoch(EPOCH.0 + 1))] {
        let mut foreign = Ledger::new(realm, epoch, CAPACITY);
        foreign
            .append(Event::new(
                None,
                realm,
                epoch,
                PeerId(1),
                Sequence(1),
                b"foreign genesis".to_vec(),
            ))
            .unwrap();
        assert_eq!(
            CertifiedLedger::recover(
                &foreign.snapshot(),
                &certificate,
                &anchor,
                trust(),
                CAPACITY,
            )
            .err(),
            Some(Error::Ledger(LedgerError::WrongContext))
        );
    }
}

#[test]
fn snapshot_checkpoint_metadata_cannot_nominate_an_anchor_but_may_trail_it() {
    let mut model = model();
    append(&mut model, 1, b"first");
    let snapshot_without_checkpoint = model.snapshot();
    let first_certificate = certify(&mut model);
    let first_anchor = model.accepted().unwrap().recovery_anchor();
    let first_recovery = CertifiedLedger::recover(
        &snapshot_without_checkpoint,
        &first_certificate,
        &first_anchor,
        trust(),
        CAPACITY,
    )
    .unwrap();
    assert_eq!(first_recovery.accepted(), model.accepted());
    assert_eq!(first_recovery.snapshot(), model.snapshot());

    append(&mut model, 2, b"second");
    let snapshot_with_old_checkpoint = model.snapshot();
    let second_certificate = certify(&mut model);
    let second_anchor = model.accepted().unwrap().recovery_anchor();
    let second_recovery = CertifiedLedger::recover(
        &snapshot_with_old_checkpoint,
        &second_certificate,
        &second_anchor,
        trust(),
        CAPACITY,
    )
    .unwrap();
    assert_eq!(second_recovery.accepted(), model.accepted());
    assert_eq!(second_recovery.snapshot(), model.snapshot());
}

#[test]
fn recovery_binds_all_trust_policy_fields_but_not_member_input_order() {
    let mut model = model();
    append(&mut model, 1, b"first");
    let certificate = certify(&mut model);
    let anchor = model.accepted().unwrap().recovery_anchor();
    let snapshot = model.snapshot();
    let key_set = keys();
    let policy = |threshold, max_signers, max_bytes| {
        TrustConfig::new(
            certificate_realm(REALM),
            EPOCH.0,
            key_set.iter().map(SigningKey::verifying_key),
            threshold,
            max_signers,
            max_bytes,
        )
        .unwrap()
    };
    let replacement = SigningKey::from_bytes(&[4; 32]);
    let changed_members = TrustConfig::new(
        certificate_realm(REALM),
        EPOCH.0,
        [
            key_set[0].verifying_key(),
            key_set[1].verifying_key(),
            replacement.verifying_key(),
        ],
        2,
        3,
        MAX_PROOF_BYTES,
    )
    .unwrap();
    for changed in [
        policy(1, 3, MAX_PROOF_BYTES),
        policy(2, 2, MAX_PROOF_BYTES),
        policy(2, 3, MAX_PROOF_BYTES - 1),
        changed_members,
        trust_for(certificate_realm(REALM), EPOCH.0 + 1),
        trust_for(certificate_realm(RealmId(999)), EPOCH.0),
    ] {
        assert_eq!(
            CertifiedLedger::recover(&snapshot, &certificate, &anchor, changed, CAPACITY).err(),
            Some(Error::TrustChanged)
        );
    }
    let reordered = TrustConfig::new(
        certificate_realm(REALM),
        EPOCH.0,
        key_set.iter().rev().map(SigningKey::verifying_key),
        2,
        3,
        MAX_PROOF_BYTES,
    )
    .unwrap();
    let recovered =
        CertifiedLedger::recover(&snapshot, &certificate, &anchor, reordered, CAPACITY).unwrap();
    assert_eq!(recovered.snapshot(), snapshot);
}

#[test]
fn append_bounds_and_recovery_bounds_fail_without_partial_admission() {
    let mut model = CertifiedLedger::new(REALM, EPOCH, trust(), 1).unwrap();
    let empty_snapshot = model.snapshot();
    let oversized = Event::new(
        None,
        REALM,
        EPOCH,
        PeerId(1),
        Sequence(1),
        vec![0; MAX_PAYLOAD + 1],
    );
    assert_eq!(
        model.append(oversized),
        Err(Error::Ledger(LedgerError::PayloadTooLarge))
    );
    assert_eq!(model.snapshot(), empty_snapshot);
    append(&mut model, 1, &vec![0; MAX_PAYLOAD]);
    let certificate = certify(&mut model);
    let anchor = model.accepted().unwrap().recovery_anchor();
    let snapshot = model.snapshot();
    let accepted = model.accepted().cloned();
    let overflow = Event::new(model.head(), REALM, EPOCH, PeerId(1), Sequence(2), vec![]);
    assert_eq!(
        model.append(overflow),
        Err(Error::Ledger(LedgerError::Capacity))
    );
    assert_eq!(model.snapshot(), snapshot);
    assert_eq!(model.accepted(), accepted.as_ref());
    assert_eq!(
        CertifiedLedger::recover(&snapshot, &certificate, &anchor, trust(), 0).err(),
        Some(Error::Ledger(LedgerError::InvalidSnapshotBounds))
    );
    let tight_policy = TrustConfig::new(
        certificate_realm(REALM),
        EPOCH.0,
        keys().iter().map(SigningKey::verifying_key),
        2,
        3,
        1,
    )
    .unwrap();
    let mut tight = CertifiedLedger::new(REALM, EPOCH, tight_policy, CAPACITY).unwrap();
    append(&mut tight, 1, b"first");
    let too_large_certificate = sign(tight.propose_tip().unwrap());
    reject_without_mutation(
        &mut tight,
        &too_large_certificate,
        Error::Proof(Reject::OversizedProof),
    );
}

#[test]
fn recovery_restores_actor_replay_rejection_and_permits_the_next_sequence() {
    let mut model = model();
    append(&mut model, 8, b"first");
    let certificate = certify(&mut model);
    let anchor = model.accepted().unwrap().recovery_anchor();
    let mut recovered =
        CertifiedLedger::recover(&model.snapshot(), &certificate, &anchor, trust(), CAPACITY)
            .unwrap();
    for sequence in [0, 7, 8] {
        let before = recovered.snapshot();
        let replay = Event::new(
            recovered.head(),
            REALM,
            EPOCH,
            PeerId(1),
            Sequence(sequence),
            b"different payload".to_vec(),
        );
        assert_eq!(
            recovered.append(replay),
            Err(Error::Ledger(LedgerError::NonMonotonicSequence))
        );
        assert_eq!(recovered.snapshot(), before);
        assert_eq!(recovered.accepted(), model.accepted());
    }
    append(&mut recovered, 9, b"next sequence");
    assert_eq!(recovered.event_count(), 2);
    assert_eq!(recovered.accepted(), model.accepted());
    certify(&mut recovered);
    assert_eq!(recovered.accepted().unwrap().checkpoint().height, 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn realm_mapping_preserves_all_bits_and_has_one_canonical_spelling(
        realm in any::<u128>(),
        changed_bit in 0u32..128,
    ) {
        let encoded = certificate_realm(RealmId(realm));
        let digits = encoded.strip_prefix("vhalla/realm/u128/v1/").unwrap();
        prop_assert_eq!(digits.len(), 32);
        prop_assert!(digits.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        prop_assert_eq!(u128::from_str_radix(digits, 16).unwrap(), realm);
        prop_assert_ne!(encoded, certificate_realm(RealmId(realm ^ (1u128 << changed_bit))));
    }

    #[test]
    fn generated_append_admit_recover_schedules_preserve_history_and_replay_state(
        actions in prop::collection::vec((0usize..4, any::<u16>(), any::<bool>(), any::<bool>()), 1..25),
    ) {
        let mut model = model();
        let mut sequences = [0u64; 4];
        let mut latest_certificate = None;
        for (index, (actor, payload, admit, recover)) in actions.into_iter().enumerate() {
            sequences[actor] += 1;
            let prior_accepted = model.accepted().cloned();
            model.append(Event::new(
                model.head(), REALM, EPOCH, PeerId(actor as u128),
                Sequence(sequences[actor]), payload.to_be_bytes().to_vec(),
            )).unwrap();
            prop_assert_eq!(model.event_count(), index + 1);
            prop_assert_eq!(model.accepted(), prior_accepted.as_ref());
            if admit {
                latest_certificate = Some(certify(&mut model));
                prop_assert_eq!(model.accepted().unwrap().checkpoint().height, index as u64);
            }
            if recover {
                if let Some(certificate) = &latest_certificate {
                    let anchor = model.accepted().unwrap().recovery_anchor();
                    let snapshot = model.snapshot();
                    let recovered = CertifiedLedger::recover(&snapshot, certificate, &anchor, trust(), CAPACITY);
                    if admit {
                        let recovered = recovered.unwrap();
                        prop_assert_eq!(recovered.snapshot(), snapshot);
                        prop_assert_eq!(recovered.accepted(), model.accepted());
                        model = recovered;
                    } else {
                        prop_assert_eq!(recovered.err(), Some(Error::Ledger(LedgerError::StaleCheckpoint)));
                    }
                }
            }
            let snapshot = model.snapshot();
            let evidence = model.accepted().cloned();
            let replay = Event::new(
                model.head(), REALM, EPOCH, PeerId(actor as u128),
                Sequence(sequences[actor]), b"sequence reuse".to_vec(),
            );
            prop_assert_eq!(model.append(replay), Err(Error::Ledger(LedgerError::NonMonotonicSequence)));
            prop_assert_eq!(model.snapshot(), snapshot);
            prop_assert_eq!(model.accepted(), evidence.as_ref());
        }
        let certificate = certify(&mut model);
        let anchor = model.accepted().unwrap().recovery_anchor();
        let recovered = CertifiedLedger::recover(&model.snapshot(), &certificate, &anchor, trust(), CAPACITY).unwrap();
        prop_assert_eq!(recovered.snapshot(), model.snapshot());
        prop_assert_eq!(recovered.accepted(), model.accepted());
    }

    #[test]
    fn altered_certificate_or_snapshot_cannot_recover_a_pinned_frontier(
        payload in prop::collection::vec(any::<u8>(), 0..65),
        byte in any::<usize>(),
        bit in 0u8..8,
    ) {
        let mut model = model();
        append(&mut model, 1, &payload);
        let certificate = certify(&mut model);
        let anchor = model.accepted().unwrap().recovery_anchor();
        let snapshot = model.snapshot();
        let mut altered_snapshot = snapshot.clone();
        let offset = byte % altered_snapshot.len();
        altered_snapshot[offset] ^= 1 << bit;
        prop_assert!(CertifiedLedger::recover(&altered_snapshot, &certificate, &anchor, trust(), CAPACITY).is_err());
        let mut altered_certificate = certificate.clone();
        let offset = byte % altered_certificate.len();
        altered_certificate[offset] ^= 1 << bit;
        prop_assert!(CertifiedLedger::recover(&snapshot, &altered_certificate, &anchor, trust(), CAPACITY).is_err());
        prop_assert_eq!(model.snapshot(), snapshot);
    }
}
