//! Different grants share one kernel without sharing allowances or draft state.

use super::*;

fn access(kernel: &Kernel<Disk>) -> (AgentAccess, RevocationHandle) {
    let (grant, authority) = LocalGrant::for_status(
        kernel.status(),
        Duration::from_secs(600),
        permissions(),
        budget(),
    )
    .unwrap();
    (AgentAccess::new(kernel, grant).unwrap(), authority)
}

#[test]
fn grants_keep_independent_drafts_allowances_and_revocation_over_one_kernel() {
    block_on(async {
        let mut pair = Pair::fresh(100, 100).await;
        pair.join().await;
        let (mut first, first_authority) = access(&pair.owner);
        let (mut second, _second_authority) = access(&pair.owner);
        let first_draft = first.prepare(&pair.owner, b"first grant").unwrap();
        let second_draft = second.prepare(&pair.owner, b"second grant").unwrap();
        assert_ne!(first_draft, second_draft);
        assert!(matches!(
            first.queue(&mut pair.owner, op(2), second_draft).await,
            Err(Error::StaleDraft)
        ));
        assert_eq!(first.grant.budget.messages, budget().messages);
        first
            .queue(&mut pair.owner, op(2), first_draft)
            .await
            .unwrap();
        assert_eq!(
            first.status(&pair.owner).unwrap().remaining.messages,
            budget().messages - 1
        );
        let independent = second.status(&pair.owner).unwrap();
        assert_eq!(independent.remaining.messages, budget().messages);
        assert_eq!(independent.pending, Some(second_draft));
        second
            .queue(&mut pair.owner, op(3), second_draft)
            .await
            .unwrap();
        first_authority.revoke();
        assert!(matches!(first.status(&pair.owner), Err(Error::Revoked)));
        assert_eq!(
            second.status(&pair.owner).unwrap().remaining.messages,
            budget().messages - 1
        );
        assert_eq!(pair.owner.status().outbox_head, 3);
    });
}

#[test]
fn cancelled_read_or_prewrite_load_latches_its_grant_without_changing_shared_state() {
    block_on(async {
        for writing in [false, true] {
            let mut pair = Pair::fresh(100, 100).await;
            pair.join().await;
            let (mut first, _first_authority) = access(&pair.owner);
            let (mut second, _second_authority) = access(&pair.owner);
            let draft = first.prepare(&pair.owner, b"unpublished").unwrap();
            let before = pair.owner_disk.image(pair.owner_context);
            let accepted = pair.owner.status();
            pair.owner_disk.0.borrow_mut().read_pause = Some(Rc::new(Cell::new(false)));
            if writing {
                assert!(first
                    .queue(&mut pair.owner, op(2), draft)
                    .now_or_never()
                    .is_none());
                assert_eq!(first.grant.budget.messages, budget().messages - 1);
                assert_eq!(first.grant.budget.body_bytes, budget().body_bytes - 11);
            } else {
                assert!(first.inbox(&mut pair.owner, 0, 1).now_or_never().is_none());
                assert_eq!(first.grant.budget.read_records, budget().read_records - 1);
                assert_eq!(
                    first.grant.budget.read_bytes,
                    budget().read_bytes - MAX_BODY_BYTES as u64
                );
            }
            assert!(first.failed);
            assert!(matches!(first.status(&pair.owner), Err(Error::NeedsReopen)));
            assert!(!pair.owner.needs_reopen());
            assert_eq!(pair.owner.status(), accepted);
            assert!(pair.owner_disk.image(pair.owner_context) == before);
            assert!(pair
                .owner_disk
                .clone()
                .read(pair.owner_context, RecordKey::Operation(op(2)))
                .await
                .unwrap()
                .is_none());
            assert_eq!(second.status(&pair.owner).unwrap().remaining, budget());
            let draft = second
                .prepare(&pair.owner, b"independent authorization")
                .unwrap();
            let queued = second.queue(&mut pair.owner, op(3), draft).await.unwrap();
            assert_eq!(queued.sequence, accepted.outbox_head + 1);
            assert!(matches!(first.status(&pair.owner), Err(Error::NeedsReopen)));
        }
    });
}

#[test]
fn uncertain_or_cancelled_publication_fences_every_grant_through_the_shared_kernel() {
    block_on(async {
        for fault in [Fault::PendingAfter, Fault::After] {
            let mut pair = Pair::fresh(100, 100).await;
            pair.join().await;
            let (mut first, _first_authority) = access(&pair.owner);
            let (mut second, _second_authority) = access(&pair.owner);
            let draft = first
                .prepare(&pair.owner, b"published but uncertain")
                .unwrap();
            let before = pair.owner_disk.image(pair.owner_context);
            pair.owner_disk.fault(fault);
            let result = first.queue(&mut pair.owner, op(2), draft).now_or_never();
            match fault {
                Fault::PendingAfter => assert!(result.is_none()),
                Fault::After => assert!(matches!(
                    result,
                    Some(Err(Error::Kernel(
                        vhalla_private_kernel::Error::NeedsReopen
                    )))
                )),
                _ => unreachable!(),
            }
            assert!(first.failed);
            assert!(pair.owner.needs_reopen());
            assert!(pair.owner_disk.image(pair.owner_context) != before);
            assert!(matches!(
                second.status(&pair.owner),
                Err(Error::NeedsReopen)
            ));
            assert!(matches!(
                second.prepare(&pair.owner, b"must not advance ratchet"),
                Err(Error::NeedsReopen)
            ));
            assert_eq!(second.grant.budget, budget());
        }
    });
}

#[test]
fn trusted_membership_changes_invalidate_each_retained_grant_without_reauthorizing_it() {
    block_on(async {
        let mut pair = Pair::fresh(100, 100).await;
        pair.join().await;
        let (mut first, _first_authority) = access(&pair.owner);
        let (mut second, _second_authority) = access(&pair.owner);
        let first_draft = first.prepare(&pair.owner, b"old roster one").unwrap();
        let second_draft = second.prepare(&pair.owner, b"old roster two").unwrap();
        pair.owner
            .remove(op(2), pair.member_context.device, pair.now)
            .await
            .unwrap();
        assert!(matches!(
            first.queue(&mut pair.owner, op(3), first_draft).await,
            Err(Error::AuthorityChanged)
        ));
        assert!(matches!(
            second.queue(&mut pair.owner, op(4), second_draft).await,
            Err(Error::AuthorityChanged)
        ));
        assert_eq!(first.grant.budget.messages, budget().messages);
        assert_eq!(second.grant.budget.messages, budget().messages);
        // The trusted controller can still reconcile retained ciphertext; an
        // invalid or absent plaintext grant does not own the kernel's lifetime.
        assert_eq!(pair.owner.outbox(0, 16).await.unwrap().head, 2);
        assert!(matches!(
            first.status(&pair.owner),
            Err(Error::AuthorityChanged)
        ));
        assert!(matches!(
            second.status(&pair.owner),
            Err(Error::AuthorityChanged)
        ));
    });
}
