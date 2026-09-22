use super::*;

#[test]
fn member_acceptance_requires_durable_receive_and_binds_exact_ciphertext_and_signer() {
    block_on(async {
        let mut pair = joined().await;
        let original = pair
            .owner
            .test_send(op(30), b"review this work", pair.now)
            .await
            .unwrap();
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .issue_acceptance(op(31), original.bytes(), pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let accepted = pair
            .member
            .receive(original.bytes(), pair.now)
            .await
            .unwrap();
        let receipt = pair
            .member
            .issue_acceptance(op(31), original.bytes(), pair.now)
            .await
            .unwrap();
        let inbound = pair.owner.receive(receipt.bytes(), pair.now).await.unwrap();
        let context = pair.owner.status().context;
        let proof = MemberAcceptance::verify(context, &original, &inbound)
            .unwrap()
            .unwrap();
        assert_eq!(proof.recipient(), pair.member.status().context.device);
        assert_eq!(proof.received_sequence(), accepted.sequence());
        let other = pair
            .owner
            .test_send(op(32), b"different work", pair.now)
            .await
            .unwrap();
        assert!(MemberAcceptance::verify(context, &other, &inbound).is_err());
        let mut wrong = context;
        wrong.scope.anchor = AnchorId::from_bytes(codec::random().unwrap()).unwrap();
        assert!(MemberAcceptance::verify(wrong, &original, &inbound).is_err());
        let mut forged = inbound.clone();
        *forged.body.last_mut().unwrap() ^= 1;
        assert!(matches!(
            MemberAcceptance::verify(context, &original, &forged),
            Err(Error::Authentication)
        ));
        forged = inbound.clone();
        forged.sender = pair.owner.status().context.device;
        assert!(MemberAcceptance::verify(context, &original, &forged).is_err());
        assert!(matches!(
            pair.owner
                .issue_acceptance(op(33), receipt.bytes(), pair.now)
                .await,
            Err(Error::Policy)
        ));
    });
}

#[test]
fn member_acceptance_uncertain_publication_reopens_and_returns_exact_receipt() {
    block_on(async {
        for fault in [Fault::Before, Fault::After] {
            let mut pair = joined().await;
            let original = pair
                .owner
                .test_send(op(40), b"durable receive before acknowledgement", pair.now)
                .await
                .unwrap();
            pair.member
                .receive(original.bytes(), pair.now)
                .await
                .unwrap();
            let head = pair.member.status().outbox_head;
            pair.member_disk.fault(fault);
            assert!(pair
                .member
                .issue_acceptance(op(41), original.bytes(), pair.now)
                .await
                .is_err());
            assert!(pair.member.needs_reopen());
            pair.reopen_member().await;
            let receipt = pair
                .member
                .issue_acceptance(op(41), original.bytes(), pair.now + 1)
                .await
                .unwrap();
            let saved = pair.member_disk.snapshot();
            pair.reopen_member().await;
            assert_eq!(
                pair.member
                    .issue_acceptance(op(41), original.bytes(), pair.now + 2)
                    .await
                    .unwrap()
                    .bytes(),
                receipt.bytes()
            );
            assert!(pair.member_disk.snapshot() == saved);
            assert_eq!(pair.member.status().outbox_head, head + 1);
            let inbound = pair
                .owner
                .receive(receipt.bytes(), pair.now + 2)
                .await
                .unwrap();
            assert!(
                MemberAcceptance::verify(pair.owner.status().context, &original, &inbound)
                    .unwrap()
                    .is_some()
            );
        }
    });
}

#[test]
fn member_acceptance_cancellation_after_commit_returns_exact_retained_retry() {
    block_on(async {
        let mut pair = joined().await;
        let original = pair
            .owner
            .test_send(op(50), b"receipt cancellation fixture", pair.now)
            .await
            .unwrap();
        pair.member
            .receive(original.bytes(), pair.now)
            .await
            .unwrap();
        let before_head = pair.member.status().outbox_head;
        pair.member_disk.fault(Fault::HangAfter);
        {
            let pending = pair
                .member
                .issue_acceptance(op(51), original.bytes(), pair.now);
            futures::pin_mut!(pending);
            assert!(futures::poll!(pending).is_pending());
        }
        assert!(pair.member.needs_reopen());
        let committed = pair.member_disk.snapshot();
        pair.reopen_member().await;
        let receipt = pair
            .member
            .issue_acceptance(op(51), original.bytes(), pair.now + 1)
            .await
            .unwrap();
        assert!(pair.member_disk.snapshot() == committed);
        assert_eq!(pair.member.status().outbox_head, before_head + 1);
        let inbound = pair
            .owner
            .receive(receipt.bytes(), pair.now + 1)
            .await
            .unwrap();
        assert!(
            MemberAcceptance::verify(pair.owner.status().context, &original, &inbound)
                .unwrap()
                .is_some()
        );
    });
}

#[test]
fn member_acceptance_retry_survives_epoch_change_and_operation_collision_refuses() {
    block_on(async {
        let mut pair = joined().await;
        let original = pair
            .owner
            .test_send(op(60), b"before renewal", pair.now)
            .await
            .unwrap();
        pair.member
            .receive(original.bytes(), pair.now)
            .await
            .unwrap();
        let receipt = pair
            .member
            .issue_acceptance(op(61), original.bytes(), pair.now)
            .await
            .unwrap();
        let enrollment = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
        let update = pair
            .owner
            .renew_owner(op(62), enrollment, pair.now + 1)
            .await
            .unwrap();
        pair.member
            .apply_control(update.bytes(), pair.now + 1)
            .await
            .unwrap();
        let after_update = pair.member_disk.snapshot();
        let retry = pair
            .member
            .issue_acceptance(op(61), original.bytes(), pair.now + 2)
            .await
            .unwrap();
        assert_eq!(retry.bytes(), receipt.bytes());
        assert!(pair.member_disk.snapshot() == after_update);
        let different = pair
            .owner
            .test_send(op(63), b"different original", pair.now + 2)
            .await
            .unwrap();
        pair.member
            .receive(different.bytes(), pair.now + 2)
            .await
            .unwrap();
        let before_collision = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .issue_acceptance(op(61), different.bytes(), pair.now + 2)
                .await,
            Err(Error::Conflict)
        ));
        assert!(pair.member_disk.snapshot() == before_collision);
    });
}

#[test]
fn authenticated_mls_body_cannot_forge_acceptance_or_trigger_ack_of_ack() {
    block_on(async {
        let mut pair = joined().await;
        let original = pair
            .owner
            .test_send(op(70), b"original body", pair.now)
            .await
            .unwrap();
        pair.member
            .receive(original.bytes(), pair.now)
            .await
            .unwrap();
        let receipt = pair
            .member
            .issue_acceptance(op(71), original.bytes(), pair.now)
            .await
            .unwrap();
        let valid = pair.owner.receive(receipt.bytes(), pair.now).await.unwrap();
        assert_eq!(
            MemberAcceptance::claimed_ciphertext(valid.body()),
            Some(MemberAcceptance::ciphertext_commitment(original.bytes()))
        );
        let mut body = valid.body().to_vec();
        *body.last_mut().unwrap() ^= 1;
        // The lookup hint still exists: only inner verification is authority.
        assert!(MemberAcceptance::claimed_ciphertext(&body).is_some());
        let forged = pair
            .member
            .test_send(op(72), &body, pair.now)
            .await
            .unwrap();
        let authenticated = pair.owner.receive(forged.bytes(), pair.now).await.unwrap();
        assert!(matches!(
            MemberAcceptance::verify(pair.owner.status().context, &original, &authenticated),
            Err(Error::Authentication)
        ));
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .issue_acceptance(op(73), forged.bytes(), pair.now)
                .await,
            Err(Error::Policy)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        assert!(MemberAcceptance::claimed_ciphertext(&body[..body.len() - 1]).is_none());
        body.push(0);
        assert!(MemberAcceptance::claimed_ciphertext(&body).is_none());
    });
}
