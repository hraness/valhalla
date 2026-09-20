use super::*;

#[test]
fn confidential_joining_proof_is_not_a_relayable_predecessor_envelope() {
    block_on(async {
        let mut pair = joined().await;
        let zero = ControlFloor::new(0, None).unwrap();
        let proofs = pair.member.controls(zero, 16).await.unwrap();
        assert_eq!(proofs.records.len(), 1);
        SignedOwnerControl::decode(proofs.records[0].bytes())
            .unwrap()
            .verify()
            .unwrap();
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .apply_control(proofs.records[0].bytes(), pair.now)
                .await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == before);
        assert!(!pair.member.needs_reopen());
        assert!(matches!(
            pair.member.encrypted_controls(zero, 16).await,
            Err(Error::Missing)
        ));
        pair.reopen_member().await;
        let joined = pair.member.status().control_floor;
        let empty = pair.member.encrypted_controls(joined, 16).await.unwrap();
        assert_eq!(empty.base, joined);
        assert_eq!(empty.head, joined);
        assert!(empty.records.is_empty());
        let owner = pair.owner.encrypted_controls(zero, 16).await.unwrap();
        assert_eq!(owner.records.len(), 1);
        assert_eq!(owner.records[0].scope(), pair.owner.status().context.scope);
        assert_eq!(owner.records[0].floor(), joined);
        assert!(matches!(
            pair.member
                .apply_control(owner.records[0].bytes(), pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(pair.member_disk.snapshot() == before);
    });
}

#[test]
fn confidential_member_can_encrypt_but_cannot_authorize_an_owner_transition() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let removal = pair
            .owner
            .remove(op(2), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        let mut packet = decode_for_member(&pair, removal.bytes());
        let work = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        let mut claims = packet.control.claims().clone();
        claims.owner_device = pair.member.status().context.device;
        let unsigned = UnsignedOwnerControl::new(claims).unwrap();
        packet.control = unsigned
            .attach(
                work.signer()
                    .unwrap()
                    .sign(&unsigned.signing_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap()
            .verify()
            .unwrap();
        let forged = transport::seal(&work, &work.group().unwrap(), &packet).unwrap();
        // Prove that this is not a trivial tag failure: the actual member has
        // the predecessor exporter and can decrypt its forged valid envelope.
        transport::open(&work, &transport::Envelope::decode(&forged).unwrap()).unwrap();
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_control(&forged, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        assert!(!pair.member.status().quarantined);
        pair.reopen_member().await;
        pair.member
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(pair.member.status().phase, Phase::Removed);
    });
}

#[test]
fn confidential_wrong_scope_purpose_epoch_and_tamper_have_no_effects() {
    block_on(async {
        let mut pair = joined().await;
        let mut foreign = joined().await;
        let foreign_wire = foreign
            .owner
            .remove(op(2), foreign.member.status().context.device, foreign.now)
            .await
            .unwrap();
        let wire = pair
            .owner
            .remove(op(2), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        let mut purpose = wire.bytes().to_vec();
        purpose[8] ^= 1; // closed version/purpose header
        let mut epoch = wire.bytes().to_vec();
        epoch[10..18].copy_from_slice(&2u64.to_be_bytes());
        epoch[18..26].copy_from_slice(&3u64.to_be_bytes());
        let mut altered = wire.bytes().to_vec();
        *altered.last_mut().unwrap() ^= 1;
        for input in [
            foreign_wire.bytes(),
            &purpose,
            &epoch,
            &altered,
            &wire.bytes()[..25],
        ] {
            let before = pair.member_disk.snapshot();
            assert!(pair.member.apply_control(input, pair.now).await.is_err());
            assert!(pair.member_disk.snapshot() == before);
            assert!(!pair.member.status().quarantined);
            pair.reopen_member().await;
        }
        let work = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        let mut changed_scope = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        let mut anchor_claims = changed_scope.state.anchor.claims().clone();
        anchor_claims.owner_device = pair.member.status().context.device;
        changed_scope.state.anchor = UnsignedRoomAnchor::new(anchor_claims)
            .unwrap()
            .sign(&pair.owner_account)
            .unwrap()
            .verify()
            .unwrap();
        assert!(matches!(
            transport::open(
                &changed_scope,
                &transport::Envelope::decode(wire.bytes()).unwrap()
            ),
            Err(Error::Authentication)
        ));
        let mut changed_floor = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        changed_floor.state.floor = ControlFloor::new(
            changed_floor.state.floor.sequence(),
            Some(ControlId::from_bytes([0x57; 32]).unwrap()),
        )
        .unwrap();
        assert!(matches!(
            transport::open(
                &changed_floor,
                &transport::Envelope::decode(wire.bytes()).unwrap()
            ),
            Err(Error::Authentication)
        ));
        let mut changed_roster = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        changed_roster.state.roster[0] = retained_work(
            &foreign.member_disk,
            &foreign.member_key,
            foreign.member.status().context,
        )
        .state
        .local;
        assert!(matches!(
            transport::open(
                &changed_roster,
                &transport::Envelope::decode(wire.bytes()).unwrap()
            ),
            Err(Error::Authentication)
        ));
        transport::open(&work, &transport::Envelope::decode(wire.bytes()).unwrap()).unwrap();
        pair.member
            .apply_control(wire.bytes(), pair.now)
            .await
            .unwrap();
    });
}

#[test]
fn confidential_changed_old_ciphertext_is_not_fork_evidence_and_exact_retry_needs_no_key() {
    block_on(async {
        let mut pair = joined().await;
        let base = pair.member.status().control_floor;
        let removal = pair
            .owner
            .remove(op(2), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        pair.reopen_member().await;
        let before = pair.member_disk.snapshot();
        pair.member
            .apply_control(removal.bytes(), pair.now + 10000)
            .await
            .unwrap();
        assert!(pair.member_disk.snapshot() == before);
        let page = pair.member.encrypted_controls(base, 16).await.unwrap();
        assert_eq!(page.records[0].bytes(), removal.bytes());
        let mut changed = removal.bytes().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            pair.member.apply_control(&changed, pair.now).await,
            Err(Error::Conflict)
        ));
        assert!(pair.member_disk.snapshot() == before);
        assert!(!pair.member.status().quarantined);
        pair.reopen_member().await;
        assert!(pair.member.fork_evidence().await.unwrap().is_none());
        assert!(pair.member.prepare_message(b"removed").is_err());
    });
}

#[test]
fn confidential_owner_uncertainty_and_cancellation_recover_exact_envelope() {
    block_on(async {
        for fault in [Fault::Before, Fault::After, Fault::HangAfter] {
            let mut pair = joined().await;
            let base = pair.owner.status().control_floor;
            let target = pair.member.status().context.device;
            let before = pair.owner_disk.snapshot();
            pair.owner_disk.fault(fault);
            if matches!(fault, Fault::HangAfter) {
                let pending = pair.owner.remove(op(2), target, pair.now);
                futures::pin_mut!(pending);
                assert!(futures::poll!(pending).is_pending());
            } else {
                assert!(pair.owner.remove(op(2), target, pair.now).await.is_err());
            }
            assert!(pair.owner.needs_reopen());
            if matches!(fault, Fault::Before) {
                assert!(pair.owner_disk.snapshot() == before);
            }
            pair.reopen_owner().await;
            let retained = if matches!(fault, Fault::Before) {
                None
            } else {
                Some(
                    pair.owner
                        .encrypted_controls(base, 1)
                        .await
                        .unwrap()
                        .records
                        .remove(0),
                )
            };
            let retry = pair.owner.remove(op(2), target, pair.now).await.unwrap();
            if let Some(retained) = retained {
                assert_eq!(retained.bytes(), retry.bytes());
            }
            let page = pair.owner.encrypted_controls(base, 1).await.unwrap();
            assert_eq!(page.records[0].bytes(), retry.bytes());
            pair.member
                .apply_control(retry.bytes(), pair.now)
                .await
                .unwrap();
            assert_eq!(pair.member.status().phase, Phase::Removed);
        }
    });
}

#[test]
fn confidential_receiver_uncertainty_reopens_with_exact_proof_and_wire() {
    block_on(async {
        for fault in [Fault::Before, Fault::After, Fault::HangAfter] {
            let mut pair = joined().await;
            let base = pair.member.status().control_floor;
            let removal = pair
                .owner
                .remove(op(2), pair.member.status().context.device, pair.now)
                .await
                .unwrap();
            let before = pair.member_disk.snapshot();
            pair.member_disk.fault(fault);
            if matches!(fault, Fault::HangAfter) {
                let pending = pair.member.apply_control(removal.bytes(), pair.now);
                futures::pin_mut!(pending);
                assert!(futures::poll!(pending).is_pending());
            } else {
                assert!(pair
                    .member
                    .apply_control(removal.bytes(), pair.now)
                    .await
                    .is_err());
            }
            assert!(pair.member.needs_reopen());
            if matches!(fault, Fault::Before) {
                assert!(pair.member_disk.snapshot() == before);
            }
            pair.reopen_member().await;
            pair.member
                .apply_control(removal.bytes(), pair.now)
                .await
                .unwrap();
            let page = pair.member.encrypted_controls(base, 1).await.unwrap();
            assert_eq!(page.records[0].bytes(), removal.bytes());
            assert_eq!(pair.member.status().phase, Phase::Removed);
        }
    });
}

#[test]
fn confidential_envelope_and_record_bounds_and_legacy_state_refuse_without_repair() {
    block_on(async {
        let mut pair = joined().await;
        let before = pair.member_disk.snapshot();
        let oversized = vec![0; packets::MAX_PACKET + 1];
        assert!(matches!(
            pair.member.apply_control(&oversized, pair.now).await,
            Err(Error::Bounds)
        ));
        assert!(pair.member_disk.snapshot() == before);
        let mut clear = codec::unseal(
            &pair.member_key,
            pair.member.status().context,
            b"current-state",
            pair.member_disk.image().as_bytes(),
            MAX_IMAGE_BYTES,
        )
        .unwrap();
        assert_eq!(&clear[..10], b"VHPKSTATE\x04");
        clear[9] = 3;
        let old = Image::from_bytes(
            &codec::seal(
                &pair.member_key,
                pair.member.status().context,
                b"current-state",
                &clear,
                MAX_IMAGE_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        pair.member_disk.0.borrow_mut().image = Some(old);
        let preserved = pair.member_disk.snapshot();
        assert!(matches!(
            Kernel::open(
                pair.member_disk.clone(),
                &pair.member_key,
                pair.member.status().context
            )
            .await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == preserved);
    });
}
