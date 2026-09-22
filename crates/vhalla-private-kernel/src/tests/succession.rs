use super::*;

/// Enroll a second device of the owner account and carry it into the roster as
/// an ordinary member; returns it ready to accept a succession grant.
async fn joined_successor(pair: &mut Pair, operation: u64) -> (Kernel<Memory>, Memory, StorageKey) {
    let (mut successor, disk, key) = pending_device(pair, &pair.owner_account).await;
    let control = add_device(pair, &mut successor, operation).await;
    pair.member.apply_control(&control, pair.now).await.unwrap();
    (successor, disk, key)
}
fn validity_now(pair: &Pair) -> Validity {
    validity(pair.now)
}
fn owner_device(disk: &Memory, key: &StorageKey, context: Context) -> Key {
    retained_work(disk, key, context)
        .state
        .owner
        .claims()
        .device
}
async fn grant(pair: &mut Pair, successor: Key, validity: Validity) -> SignedOwnerSuccession {
    pair.owner
        .succession_request(successor, validity)
        .await
        .unwrap()
        .sign(&pair.owner_account)
        .unwrap()
}

#[test]
fn owner_handoff_demotes_predecessor_promotes_member_and_stays_retryable() {
    block_on(async {
        let mut pair = joined().await;
        let (mut successor, successor_disk, successor_key) = joined_successor(&mut pair, 10).await;
        let successor_device = successor.status().context.device;
        let predecessor_device = pair.owner.status().context.device;
        let window = validity_now(&pair);
        let grant = grant(&mut pair, successor_device, window).await;
        let handoff = pair
            .owner
            .succeed(op(20), grant.clone(), pair.now)
            .await
            .unwrap();
        // The predecessor is demoted in the same transaction; it keeps ordinary
        // membership rather than being removed.
        assert_eq!(pair.owner.status().phase, Phase::MemberJoined);
        let owner = owner_device(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        assert_eq!(owner, successor_device);
        // Exact retries return the retained ciphertext, never a second commit.
        pair.reopen_owner().await;
        assert_eq!(
            pair.owner
                .succeed(op(20), grant.clone(), pair.now + 1)
                .await
                .unwrap()
                .bytes(),
            handoff.bytes()
        );
        // The demoted device can no longer prepare owner-scoped work. Every
        // refused transaction latches the fail-closed reopen flag.
        assert!(matches!(
            pair.owner
                .succession_request(successor_device, validity(pair.now))
                .await,
            Err(Error::Policy)
        ));
        pair.reopen_owner().await;
        assert!(matches!(
            pair.owner.remove(op(21), successor_device, pair.now).await,
            Err(Error::Policy)
        ));
        pair.reopen_owner().await;
        // Ordinary members apply the same sealed envelope once; a byte-exact
        // replay is an idempotent no-op rather than a fork.
        pair.member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(successor.status().phase, Phase::OwnerJoined);
        assert_eq!(
            successor.status().control_floor,
            pair.member.status().control_floor
        );
        successor = Kernel::open(
            successor_disk.clone(),
            &successor_key,
            successor.status().context,
        )
        .await
        .unwrap();
        assert_eq!(successor.status().phase, Phase::OwnerJoined);
        // Authority is generational: the control carrying the grant is still
        // attributed to the predecessor, later ones to the successor.
        let work = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        let carried = pair.member.status().control_floor.sequence();
        assert_eq!(
            work.state.owner_device_at(carried).unwrap(),
            predecessor_device
        );
        assert_eq!(
            work.state.owner_device_at(carried + 1).unwrap(),
            successor_device
        );
        assert!(work.state.was_owner(predecessor_device));
        // The demoted predecessor cannot emit another owner control; its
        // owner-scoped operations refuse before any MLS change even with a
        // well-formed package.
        pair.reopen_owner().await;
        let (mut pending, _, _) = pending_device(&pair, &account()).await;
        let package = pending.key_package(op(90), pair.now).await.unwrap();
        assert!(matches!(
            pair.owner
                .invite(op(23), package.bytes(), validity(pair.now), pair.now)
                .await,
            Err(Error::Policy)
        ));
        pair.reopen_owner().await;
        // The successor immediately holds owner authority: the next control it
        // signs applies everywhere under the new generation.
        let removal = successor
            .remove(op(22), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        pair.owner
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(pair.owner.status().phase, Phase::MemberJoined);
        // The promoted successor still renews its own enrollment under the
        // anchored account; the device pin follows the generation.
        let next = successor
            .owner_renewal_request(Validity::new(pair.now, pair.now + 14400).unwrap())
            .unwrap()
            .sign(&pair.owner_account)
            .unwrap();
        let update = successor.renew_owner(op(24), next, pair.now).await.unwrap();
        pair.owner
            .apply_control(update.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(
            owner_device(
                &pair.owner_disk,
                &pair.owner_key,
                pair.owner.status().context
            ),
            successor_device
        );
    });
}

#[test]
fn succession_request_requires_a_live_rostered_successor_and_owner_role() {
    block_on(async {
        let mut pair = joined().await;
        let (successor, _, _) = pending_device(&pair, &pair.owner_account).await;
        let device = successor.status().context.device;
        // A device that never joined the roster cannot be named.
        assert!(matches!(
            pair.owner
                .succession_request(device, validity(pair.now))
                .await,
            Err(Error::Policy)
        ));
        pair.reopen_owner().await;
        // Members never prepare a handoff; only the owner role may request one.
        assert!(matches!(
            pair.member
                .succession_request(device, validity(pair.now))
                .await,
            Err(Error::Policy)
        ));
        pair.reopen_member().await;
        // The predecessor cannot name itself.
        assert!(pair
            .owner
            .succession_request(pair.owner.status().context.device, validity(pair.now))
            .await
            .is_err());
        pair.reopen_owner().await;
        // A rostered device of a foreign account cannot produce a valid grant:
        // construction pins the embedded enrollment's account to the owner.
        let (mut foreign, _, _) = pending_device(&pair, &account()).await;
        let foreign_device = foreign.status().context.device;
        let control = add_device(&mut pair, &mut foreign, 10).await;
        pair.member.apply_control(&control, pair.now).await.unwrap();
        assert!(pair
            .owner
            .succession_request(foreign_device, validity(pair.now))
            .await
            .is_err());
    });
}

#[test]
fn stale_foreign_account_and_expired_grants_are_refused_without_state_change() {
    block_on(async {
        let mut pair = joined().await;
        let (mut successor, _, _) = joined_successor(&mut pair, 10).await;
        let device = successor.status().context.device;
        let request = pair
            .owner
            .succession_request(device, validity(pair.now))
            .await
            .unwrap();
        // A grant signing request bound to the owner account refuses a
        // foreign signer outright.
        assert!(request.clone().sign(&account()).is_err());
        // The owner account's grant at the pinned floor is valid, but once the
        // floor advances the exact same grant is stale.
        let stale = request.sign(&pair.owner_account).unwrap();
        let first = renewal(&pair, Validity::new(pair.now, pair.now + 9000).unwrap());
        let update = pair
            .owner
            .renew_owner(op(30), first, pair.now)
            .await
            .unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner.succeed(op(31), stale, pair.now).await,
            Err(Error::Scope)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        // An already-expired grant window is refused at commit.
        pair.reopen_owner().await;
        let expired = pair
            .owner
            .succession_request(device, Validity::new(pair.now - 90, pair.now - 60).unwrap())
            .await
            .unwrap()
            .sign(&pair.owner_account)
            .unwrap();
        assert!(matches!(
            pair.owner.succeed(op(32), expired, pair.now).await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        // A member missing the intervening renewal cannot skip a generation:
        // the handoff was sealed under a newer epoch and fails closed.
        let window = validity_now(&pair);
        let fresh_grant = grant(&mut pair, device, window).await;
        let handoff = pair
            .owner
            .succeed(op(33), fresh_grant, pair.now)
            .await
            .unwrap();
        let member_before = pair.member_disk.snapshot();
        assert!(pair
            .member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .is_err());
        assert!(pair.member_disk.snapshot() == member_before);
        // Once the renewal envelope arrives the same handoff applies cleanly.
        pair.reopen_member().await;
        pair.member
            .apply_control(update.bytes(), pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        // The successor must also see every earlier control before it owns.
        successor
            .apply_control(update.bytes(), pair.now)
            .await
            .unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(successor.status().phase, Phase::OwnerJoined);
    });
}

#[test]
fn foreign_room_handoff_and_wrong_member_chain_cannot_authenticate() {
    block_on(async {
        let mut pair = joined().await;
        let (successor, _, _) = joined_successor(&mut pair, 10).await;
        let device = successor.status().context.device;
        let window = validity_now(&pair);
        let grant = grant(&mut pair, device, window).await;
        let handoff = pair.owner.succeed(op(20), grant, pair.now).await.unwrap();
        // A foreign room's succession envelope fails group/scope
        // authentication on this member.
        let mut other = joined().await;
        let (mut foreign, _, _) = pending_device(&other, &other.owner_account).await;
        add_device(&mut other, &mut foreign, 40).await;
        let foreign_grant = other
            .owner
            .succession_request(foreign.status().context.device, validity(other.now))
            .await
            .unwrap()
            .sign(&other.owner_account)
            .unwrap();
        let foreign_handoff = other
            .owner
            .succeed(op(41), foreign_grant, other.now)
            .await
            .unwrap();
        let before = pair.member_disk.snapshot();
        assert!(pair
            .member
            .apply_control(foreign_handoff.bytes(), pair.now)
            .await
            .is_err());
        assert!(pair.member_disk.snapshot() == before);
        // The real handoff applies, and the member records the exact grant.
        pair.reopen_member().await;
        pair.member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        let work = retained_work(
            &pair.member_disk,
            &pair.member_key,
            pair.member.status().context,
        );
        assert_eq!(work.state.successions.len(), 1);
        assert_eq!(work.state.owner_device_at(u64::MAX).unwrap(), device);
    });
}

#[test]
fn succeeded_room_joins_only_with_the_exact_retained_chain() {
    block_on(async {
        let mut pair = joined().await;
        let (mut successor, successor_disk, successor_key) = joined_successor(&mut pair, 10).await;
        let device = successor.status().context.device;
        let window = validity_now(&pair);
        let grant = grant(&mut pair, device, window).await;
        let handoff = pair
            .owner
            .succeed(op(20), grant.clone(), pair.now)
            .await
            .unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        // After the handoff the successor issues invitations; a fresh member
        // draft must carry the retained chain, not just the new owner.
        let work = retained_work(&successor_disk, &successor_key, successor.status().context);
        let anchor = work.state.anchor.signed().clone();
        let owner = work.state.owner.signed().clone();
        let chain: Vec<OwnerSuccessionProof> = work.state.successions.clone();
        let scope = successor.status().context.scope;
        let account = account();
        let validity = validity(pair.now);
        // The anchor-owner constructor refuses: the selected owner is not the
        // anchor device anymore.
        assert!(matches!(
            MemberDraft::new(
                scope,
                anchor.clone(),
                owner.clone(),
                key(&account),
                validity,
                pair.now,
            ),
            Err(Error::Scope)
        ));
        // A stale or truncated chain is refused rather than downgraded.
        assert!(matches!(
            MemberDraft::new_succeeded(
                scope,
                anchor.clone(),
                owner.clone(),
                Vec::new(),
                key(&account),
                validity,
                pair.now,
            ),
            Err(Error::Scope)
        ));
        // The complete chain initializes the draft, and the invite packet the
        // successor emits joins it end to end.
        let draft = MemberDraft::new_succeeded(
            scope,
            anchor,
            owner,
            chain,
            key(&account),
            validity,
            pair.now,
        )
        .unwrap();
        let enrollment = draft.enrollment_request().sign(&account).unwrap();
        let disk = Memory::default();
        let secret = storage_key();
        let mut member = draft
            .initialize(disk.clone(), &secret, enrollment, pair.now)
            .await
            .unwrap();
        let package = member.key_package(op(1), pair.now).await.unwrap();
        let invitation = successor
            .invite(op(50), package.bytes(), validity, pair.now)
            .await
            .unwrap();
        member.join(invitation.bytes(), pair.now).await.unwrap();
        assert_eq!(member.status().phase, Phase::MemberJoined);
        let work = retained_work(&disk, &secret, member.status().context);
        assert_eq!(work.state.successions.len(), 1);
        assert_eq!(work.state.owner.claims().device, device);
    });
}

async fn short_lived_successor(pair: &mut Pair) -> Kernel<Memory> {
    let owner = pair.owner.membership().await.unwrap();
    let draft = MemberDraft::new(
        owner.status().context.scope,
        owner.anchor().clone(),
        owner.owner().clone(),
        key(&pair.owner_account),
        Validity::new(pair.now - 30, pair.now + 10).unwrap(),
        pair.now,
    )
    .unwrap();
    let enrollment = draft
        .enrollment_request()
        .sign(&pair.owner_account)
        .unwrap();
    let mut successor = draft
        .initialize(Memory::default(), &storage_key(), enrollment, pair.now)
        .await
        .unwrap();
    let control = add_device(pair, &mut successor, 60).await;
    pair.member.apply_control(&control, pair.now).await.unwrap();
    successor
}

#[test]
fn expired_successor_refuses_both_emission_and_application_without_mutation() {
    block_on(async {
        let mut pair = joined().await;
        let successor = short_lived_successor(&mut pair).await;
        let window = validity(pair.now);
        let grant = grant(&mut pair, successor.status().context.device, window).await;
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .succeed(op(61), grant.clone(), pair.now + 10)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        assert!(matches!(pair.owner.status().phase, Phase::OwnerJoined));
        pair.reopen_owner().await;
        // A handoff legitimately emitted before expiry still cannot promote an
        // expired successor on a recipient that catches up later.
        let handoff = pair.owner.succeed(op(61), grant, pair.now).await.unwrap();
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .apply_control(handoff.bytes(), pair.now + 10)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.member_disk.snapshot() == before);
    });
}

#[test]
fn expired_predecessor_can_still_handoff_to_a_current_successor() {
    block_on(async {
        let mut pair = fresh_with_lifetimes(10, 7200).await;
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let invitation = pair
            .owner
            .invite(op(1), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        pair.member
            .join(invitation.bytes(), pair.now)
            .await
            .unwrap();
        let (mut successor, _, _) = joined_successor(&mut pair, 10).await;
        let window = validity(pair.now);
        let grant = grant(&mut pair, successor.status().context.device, window).await;
        let handoff = pair
            .owner
            .succeed(op(62), grant, pair.now + 10)
            .await
            .unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now + 10)
            .await
            .unwrap();
        pair.member
            .apply_control(handoff.bytes(), pair.now + 10)
            .await
            .unwrap();
        assert_eq!(successor.status().phase, Phase::OwnerJoined);
        assert_eq!(pair.owner.status().phase, Phase::MemberJoined);
    });
}

#[test]
fn successor_signed_contact_cannot_substitute_a_prepared_account_grant_for_proof() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let (mut successor, disk, secret) = joined_successor(&mut pair, 10).await;
        let window = validity(pair.now);
        let prepared = grant(&mut pair, successor.status().context.device, window).await;
        // Even a legitimate prepared grant cannot construct bootstrap authority.
        assert!(OwnerSuccessionProof::decode(&prepared.encode()).is_err());
        let handoff = pair
            .owner
            .succeed(op(63), prepared.clone(), pair.now)
            .await
            .unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        let recipient = account();
        let offer = successor
            .create_contact_offer(op(64), key(&recipient), window, pair.now)
            .await
            .unwrap();
        let original = offer.confidential_bytes();
        assert_eq!(&original[..10], b"VHPKOFFER\x03");
        // Fixed bootstrap metadata ends at its proof count (byte 585). Replace
        // the sole proof with the real account-signed grant, then authenticate
        // the whole counterfeit offer with the actual successor device key.
        assert_eq!(original[585], 1);
        let mut forged = original[..586].to_vec();
        let raw = prepared.encode();
        forged.extend((raw.len() as u32).to_be_bytes());
        forged.extend(raw);
        forged.extend_from_slice(&original[original.len() - 128..original.len() - 64]);
        let mut signing = b"vhalla/private/contact/owner-offer/v1\0".to_vec();
        signing.extend(&forged);
        let work = retained_work(&disk, &secret, successor.status().context);
        forged.extend(work.signer().unwrap().sign(&signing).unwrap());
        assert!(ContactBootstrap::inspect(
            &forged,
            key(&pair.owner_account),
            key(&recipient),
            pair.now
        )
        .is_err());
        assert!(ContactBootstrap::inspect(
            original,
            key(&pair.owner_account),
            key(&recipient),
            pair.now
        )
        .is_ok());
    });
}

#[test]
fn two_generation_proof_chain_supports_fresh_joins_and_rejects_a_wrong_predecessor() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let (mut successor, _, _) = joined_successor(&mut pair, 10).await;
        let window = validity(pair.now);
        let grant = grant(&mut pair, successor.status().context.device, window).await;
        let handoff = pair.owner.succeed(op(65), grant, pair.now).await.unwrap();
        successor
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(handoff.bytes(), pair.now)
            .await
            .unwrap();
        let first = pair.owner.membership().await.unwrap().successions()[0].clone();
        let request = successor
            .succession_request(pair.owner.status().context.device, window)
            .await
            .unwrap();
        let next = request.sign(&pair.owner_account).unwrap();
        // A former owner plus the account cannot substitute its own device for
        // the current predecessor in the second generation.
        let mut false_grant = next.claims().clone();
        false_grant.predecessor = pair.owner.status().context.device;
        false_grant.successor = first.claims().successor.clone();
        let false_grant = UnsignedOwnerSuccession::new(false_grant)
            .unwrap()
            .sign(&pair.owner_account)
            .unwrap();
        let mut claims = first.control().claims().clone();
        claims.parent = pair.owner.status().control_floor;
        claims.prior_epoch = pair.owner.status().epoch;
        claims.next_epoch = claims.prior_epoch + 1;
        claims.change = ControlChange::Succession {
            grant: Box::new(false_grant),
        };
        let unsigned = UnsignedOwnerControl::new(claims).unwrap();
        let work = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        let false_control = unsigned
            .attach(
                work.signer()
                    .unwrap()
                    .sign(&unsigned.signing_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        let false_proof = OwnerSuccessionProof::from_control(false_control).unwrap();
        assert!(crate::model::check_succession_chain(
            &work.state.anchor,
            &[first.clone(), false_proof]
        )
        .is_err());
        let back = successor.succeed(op(66), next, pair.now).await.unwrap();
        pair.owner
            .apply_control(back.bytes(), pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(back.bytes(), pair.now)
            .await
            .unwrap();
        let snapshot = pair.owner.membership().await.unwrap();
        assert_eq!(snapshot.successions().len(), 2);
        let mut reversed = snapshot.successions().to_vec();
        reversed.reverse();
        assert!(MemberDraft::new_succeeded(
            snapshot.status().context.scope,
            snapshot.anchor().clone(),
            snapshot.owner().clone(),
            reversed,
            key(&account()),
            window,
            pair.now
        )
        .is_err());
        let (mut newcomer, disk, secret) = pending_device(&pair, &account()).await;
        add_device(&mut pair, &mut newcomer, 67).await;
        let state = retained_work(&disk, &secret, newcomer.status().context);
        assert_eq!(state.state.successions.len(), 2);
        assert_eq!(newcomer.status().phase, Phase::MemberJoined);
        let offer = pair
            .owner
            .create_contact_offer(op(68), key(&account()), window, pair.now)
            .await
            .unwrap();
        assert_eq!(offer.confidential_bytes().len(), 714 + 2 * (4 + 637));
    });
}

#[test]
fn legacy_grant_only_bootstrap_formats_refuse_without_repair() {
    block_on(async {
        let mut pair = fresh().await;
        let offer = pair
            .owner
            .create_contact_offer(
                op(70),
                pair.member.status().context.account,
                validity(pair.now),
                pair.now,
            )
            .await
            .unwrap();
        let mut old_offer = offer.confidential_bytes().to_vec();
        old_offer[9] = 2;
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .contact_request(op(2), &old_offer, pair.now)
                .await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let invite = pair
            .owner
            .invite(op(71), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let mut old_invite = invite.bytes().to_vec();
        assert_eq!(&old_invite[..11], b"VHPKINVITE\x04");
        old_invite[10] = 3;
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.join(&old_invite, pair.now).await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == before);
    });
}
