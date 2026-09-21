use super::*;
use crate::contact::{Frame, Offer};

async fn offer(pair: &mut Pair) -> ConfidentialContactOffer {
    pair.owner
        .create_contact_offer(
            op(100),
            pair.member.status().context.account,
            validity(pair.now),
            pair.now,
        )
        .await
        .unwrap()
}
async fn request(pair: &mut Pair) -> (ConfidentialContactOffer, CommittedOutbox) {
    let secret = offer(pair).await;
    let request = pair
        .member
        .contact_request(op(200), secret.confidential_bytes(), pair.now)
        .await
        .unwrap();
    (secret, request)
}
fn owner_work(pair: &Pair) -> model::Working {
    retained_work(
        &pair.owner_disk,
        &pair.owner_key,
        pair.owner.status().context,
    )
}
fn member_work(pair: &Pair) -> model::Working {
    retained_work(
        &pair.member_disk,
        &pair.member_key,
        pair.member.status().context,
    )
}

#[test]
fn contact_roundtrip_contiguous_redacted_outbox_and_exact_recovery() {
    block_on(async {
        let mut pair = fresh().await;
        let (secret, request) = request(&mut pair).await;
        assert_eq!(secret.operation(), op(100));
        assert_eq!(request.kind(), OutboxKind::ContactRequest);
        let before_accept = pair.owner_disk.0.borrow().records.len();
        let response = pair
            .owner
            .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        assert_eq!(response.kind(), OutboxKind::ContactInvitation);
        assert_eq!(pair.owner_disk.0.borrow().records.len(), before_accept + 3);
        assert!(owner_work(&pair).state.offers.is_empty());
        pair.reopen_owner().await;
        let retained = pair
            .owner
            .create_contact_offer(
                op(100),
                pair.member.status().context.account,
                validity(pair.now),
                pair.now + 1,
            )
            .await
            .unwrap();
        assert_eq!(retained.confidential_bytes(), secret.confidential_bytes());
        assert!(owner_work(&pair).state.offers.is_empty());
        assert_eq!(
            pair.owner
                .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now + 1)
                .await
                .unwrap()
                .bytes(),
            response.bytes()
        );
        let owner_page = pair.owner.outbox(0, 1).await.unwrap();
        assert_eq!(owner_page.head, 2);
        assert_eq!(owner_page.next, Some(1));
        assert!(owner_page.records[0].artifact().is_none());
        assert!(matches!(owner_page.records.as_slice(),
            [OutboxEntry::ConfidentialOffer { sequence: 1, operation }] if *operation == op(100)));
        let owner_page = pair.owner.outbox(1, 1).await.unwrap();
        assert_eq!(owner_page.next, None);
        assert_eq!(
            owner_page.records[0].artifact().unwrap().bytes(),
            response.bytes()
        );
        assert!(
            matches!(owner_page.records.as_slice(), [OutboxEntry::Artifact(a)]
            if a.sequence() == 2 && a.bytes() == response.bytes())
        );
        pair.reopen_member().await;
        let joined = pair
            .member
            .join_contact(response.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(joined.phase, Phase::MemberJoined);
        assert!(member_work(&pair).state.contact.is_none());
        pair.reopen_member().await;
        let unchanged = pair.member_disk.snapshot();
        assert_eq!(
            pair.member
                .join_contact(response.bytes(), pair.now + 1)
                .await
                .unwrap(),
            joined
        );
        assert_eq!(
            pair.member
                .contact_request(op(200), secret.confidential_bytes(), pair.now + 1)
                .await
                .unwrap()
                .bytes(),
            request.bytes()
        );
        assert!(pair.member_disk.snapshot() == unchanged);
        let message = pair
            .owner
            .test_send(op(102), b"private inert message", pair.now)
            .await
            .unwrap();
        assert_eq!(
            pair.member
                .receive(message.bytes(), pair.now)
                .await
                .unwrap()
                .body(),
            b"private inert message"
        );
        let base = pair.member.status().control_floor;
        assert!(pair
            .member
            .encrypted_controls(base, 1)
            .await
            .unwrap()
            .records
            .is_empty());
        let removal = pair
            .owner
            .remove(op(103), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(pair.member.status().phase, Phase::Removed);
        assert_eq!(
            pair.member
                .encrypted_controls(base, 1)
                .await
                .unwrap()
                .records[0]
                .bytes(),
            removal.bytes()
        );
    });
}

#[test]
fn contact_consumption_cannot_reactivate_or_accept_changed_requests() {
    block_on(async {
        let mut pair = fresh().await;
        let (secret, request) = request(&mut pair).await;
        let response = pair
            .owner
            .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .accept_contact(op(102), request.bytes(), validity(pair.now), pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let mut changed = request.bytes().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            pair.owner
                .accept_contact(op(101), &changed, validity(pair.now), pair.now)
                .await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let changed_recipient = key(&account());
        assert!(matches!(
            pair.owner
                .create_contact_offer(op(100), changed_recipient, validity(pair.now), pair.now)
                .await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        assert_eq!(
            pair.owner
                .create_contact_offer(
                    op(100),
                    pair.member.status().context.account,
                    validity(pair.now),
                    pair.now + 10_000
                )
                .await
                .unwrap()
                .confidential_bytes(),
            secret.confidential_bytes()
        );
        assert!(pair.owner_disk.snapshot() == before);
        assert_eq!(
            pair.owner
                .accept_contact(
                    op(101),
                    request.bytes(),
                    validity(pair.now),
                    pair.now + 10_000
                )
                .await
                .unwrap()
                .bytes(),
            response.bytes()
        );
        assert!(owner_work(&pair).state.offers.is_empty());
    });
}

#[test]
fn contact_pinned_scope_account_owner_and_direction_fail_without_effects() {
    block_on(async {
        let mut pair = fresh().await;
        let secret = offer(&mut pair).await;
        let original = Offer::decode(secret.confidential_bytes()).unwrap();
        let before = pair.member_disk.snapshot();
        for mutation in 0..4 {
            let mut altered = Offer::decode(secret.confidential_bytes()).unwrap();
            match mutation {
                0 => altered.recipient = key(&account()),
                1 => altered.scope.room = RoomId::from_bytes([7; 32]).unwrap(),
                2 => altered.owner_device = key(&account()),
                _ => altered.owner_basis[0] ^= 1,
            }
            match altered.encode() {
                Ok(raw) => assert!(matches!(
                    pair.member.contact_request(op(200), &raw, pair.now).await,
                    Err(Error::Scope)
                )),
                Err(error) => assert!(matches!(error, Error::Scope | Error::Authentication)),
            }
            assert!(pair.member_disk.snapshot() == before);
            pair.reopen_member().await;
        }
        let request = pair
            .member
            .contact_request(op(200), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let owner_before = pair.owner_disk.snapshot();
        let mut changed = request.bytes().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(matches!(
            pair.owner
                .accept_contact(op(101), &changed, validity(pair.now), pair.now)
                .await,
            Err(Error::Authentication)
        ));
        assert!(pair.owner_disk.snapshot() == owner_before);
        pair.reopen_owner().await;
        let response = pair
            .owner
            .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let member_before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.join_contact(request.bytes(), pair.now).await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == member_before);
        assert!(matches!(
            pair.owner
                .accept_contact(op(102), response.bytes(), validity(pair.now), pair.now)
                .await,
            Err(Error::Encoding)
        ));
        let frame = Frame::decode(response.bytes()).unwrap();
        let clear = original
            .open(&frame, Some(crate::contact::request_hash(request.bytes())))
            .unwrap();
        // Plaintext manual join cannot bypass the retained confidential pending request.
        assert!(matches!(
            pair.member.join(&clear, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == member_before);
        pair.reopen_member().await;
        let swapped = original.seal(Some([9; 32]), &clear).unwrap();
        assert!(matches!(
            pair.member.join_contact(&swapped, pair.now).await,
            Err(Error::Scope)
        ));
        assert!(pair.member_disk.snapshot() == member_before);
        pair.reopen_member().await;
        pair.member
            .join_contact(response.bytes(), pair.now)
            .await
            .unwrap();
    });
}

#[test]
fn contact_cipher_uses_separate_keys_and_binds_full_metadata() {
    block_on(async {
        let mut pair = fresh().await;
        let secret = offer(&mut pair).await;
        let offer = Offer::decode(secret.confidential_bytes()).unwrap();
        let raw = offer.seal(None, b"opaque request").unwrap();
        assert_eq!(Frame::decode(&raw).unwrap().id, offer.id);
        assert_ne!(offer.id, [0; 32]);
        assert!(!raw.windows(16).any(|part| part == op(100).as_bytes()));
        assert_eq!(
            &*offer.open(&Frame::decode(&raw).unwrap(), None).unwrap(),
            b"opaque request"
        );
        let mut encoded = secret.confidential_bytes().to_vec();
        let n = encoded.len() - 64;
        let request_key = encoded[n - 64..n - 32].to_vec();
        let response_key = encoded[n - 32..n].to_vec();
        assert_ne!(request_key, response_key);
        encoded[n - 64..n - 32].copy_from_slice(&response_key);
        encoded[n - 32..n].copy_from_slice(&request_key);
        assert!(matches!(
            Offer::decode(&encoded),
            Err(Error::Authentication)
        ));
        // Change a request into response framing with a nonzero hash. Even with
        // consistent parsing and expected hash, the other direction's key/AAD
        // cannot authenticate the request ciphertext.
        let mut reversed = raw.clone();
        let direction_offset = b"VHPKCONTACT\x01".len();
        reversed[direction_offset] = 2;
        reversed[direction_offset + 1 + 32..direction_offset + 1 + 64].fill(9);
        assert!(matches!(
            offer.open(&Frame::decode(&reversed).unwrap(), Some([9; 32])),
            Err(Error::Authentication)
        ));
        for mutation in 0..7 {
            let mut changed = Offer::decode(secret.confidential_bytes()).unwrap();
            match mutation {
                0 => changed.scope.room = RoomId::from_bytes([8; 32]).unwrap(),
                1 => changed.scope.anchor = AnchorId::from_bytes([8; 32]).unwrap(),
                2 => changed.owner_account = key(&account()),
                3 => changed.owner_device = key(&account()),
                4 => changed.recipient = key(&account()),
                5 => changed.owner_basis[0] ^= 1,
                _ => changed.issued -= 1,
            }
            assert!(matches!(
                changed.open(&Frame::decode(&raw).unwrap(), None),
                Err(Error::Authentication)
            ));
        }
        let response = offer
            .seal(Some(crate::contact::request_hash(&raw)), b"opaque response")
            .unwrap();
        assert!(matches!(
            offer.open(&Frame::decode(&response).unwrap(), Some([1; 32])),
            Err(Error::Scope)
        ));
        assert!(matches!(
            offer.open(&Frame::decode(&raw).unwrap(), Some([1; 32])),
            Err(Error::Scope)
        ));
        // Public frame fields do not explicitly serialize the pinned identity or room.
        for identity in [
            offer.owner_account.as_bytes(),
            offer.owner_device.as_bytes(),
            offer.recipient.as_bytes(),
            offer.scope.room.as_bytes(),
            offer.scope.anchor.as_bytes(),
        ] {
            assert!(!raw.windows(32).any(|part| part == identity));
            assert!(!response.windows(32).any(|part| part == identity));
        }
    });
}

#[test]
fn contact_aead_possession_does_not_grant_inner_recipient_or_owner_authority() {
    block_on(async {
        let mut pair = fresh().await;
        let secret = offer(&mut pair).await;
        let offer = Offer::decode(secret.confidential_bytes()).unwrap();
        let stranger = account();
        let (mut third, _, _) = pending_device(&pair, &stranger).await;
        let foreign = third.key_package(op(300), pair.now).await.unwrap();
        // A holder of the bootstrap secret can encrypt, but cannot make the
        // pinned recipient account endorse a different device's enrollment.
        let forged = offer.seal(None, foreign.bytes()).unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .accept_contact(op(101), &forged, validity(pair.now), pair.now)
                .await,
            Err(Error::Scope)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let request = pair
            .member
            .contact_request(op(200), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let response = pair
            .owner
            .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let frame = Frame::decode(response.bytes()).unwrap();
        let request_hash = crate::contact::request_hash(request.bytes());
        let mut clear = offer.open(&frame, Some(request_hash)).unwrap();
        // Corrupt the signed checkpoint, then form a completely valid outer
        // AEAD using the recipient-held response key. Inner signature still wins.
        *clear.last_mut().unwrap() ^= 1;
        let forged = offer.seal(Some(request_hash), &clear).unwrap();
        let before = pair.member_disk.snapshot();
        assert!(pair.member.join_contact(&forged, pair.now).await.is_err());
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .join_contact(response.bytes(), pair.now)
            .await
            .unwrap();
    });
}

#[test]
fn contact_offer_capacity_expiry_clock_and_renewal_are_bounded() {
    block_on(async {
        let mut pair = fresh_with_lifetimes(200_000, 7200).await;
        let recipient = pair.member.status().context.account;
        let expires = pair.now + 5;
        let short = Validity::new(pair.now, expires).unwrap();
        let mut first = None;
        for index in 1..=MAX_CONTACT_OFFERS {
            let issued = pair
                .owner
                .create_contact_offer(op(index as u64), recipient, short, pair.now)
                .await
                .unwrap();
            if index == 1 {
                first = Some(issued);
            }
        }
        assert_eq!(owner_work(&pair).state.offers.len(), MAX_CONTACT_OFFERS);
        let full = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .create_contact_offer(op(65), recipient, short, pair.now)
                .await,
            Err(Error::Bounds)
        ));
        assert!(pair.owner_disk.snapshot() == full);
        pair.reopen_owner().await;
        pair.owner
            .create_contact_offer(
                op(65),
                recipient,
                Validity::new(expires, expires + 30).unwrap(),
                expires,
            )
            .await
            .unwrap();
        assert_eq!(owner_work(&pair).state.offers.len(), 1);
        assert_eq!(pair.owner.status().outbox_head, 65);
        assert_eq!(
            pair.owner
                .create_contact_offer(op(1), recipient, short, expires)
                .await
                .unwrap()
                .confidential_bytes(),
            first.unwrap().confidential_bytes()
        );
        assert_eq!(owner_work(&pair).state.offers.len(), 1);
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .create_contact_offer(op(66), recipient, validity(pair.now), pair.now)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        assert!(pair
            .owner
            .create_contact_offer(
                op(66),
                recipient,
                Validity::new(expires, expires + MAX_CONTACT_TTL + 1).unwrap(),
                expires
            )
            .await
            .is_err());
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let replacement = renewal(
            &pair,
            Validity::new(pair.now - 10, pair.now + 250_000).unwrap(),
        );
        pair.owner
            .renew_owner(op(66), replacement, expires)
            .await
            .unwrap();
        assert!(owner_work(&pair).state.offers.is_empty());
        let active_before_renewal = pair
            .owner
            .create_contact_offer(
                op(65),
                recipient,
                Validity::new(expires, expires + 30).unwrap(),
                expires,
            )
            .await
            .unwrap();
        assert!(owner_work(&pair).state.offers.is_empty());
        let old = Offer::decode(active_before_renewal.confidential_bytes()).unwrap();
        assert!(matches!(
            old.check_owner(&owner_work(&pair).state),
            Err(Error::Scope)
        ));
    });
}

#[test]
fn contact_expired_offer_owner_expiry_and_renewed_basis_refuse_admission() {
    block_on(async {
        let mut pair = fresh().await;
        let recipient = pair.member.status().context.account;
        let before = pair.owner_disk.snapshot();
        assert!(pair
            .owner
            .create_contact_offer(
                op(99),
                recipient,
                Validity::new(pair.now, pair.now + 7201).unwrap(),
                pair.now
            )
            .await
            .is_err());
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let short = Validity::new(pair.now, pair.now + 2).unwrap();
        let secret = pair
            .owner
            .create_contact_offer(op(100), recipient, short, pair.now)
            .await
            .unwrap();
        let request = pair
            .member
            .contact_request(op(200), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(pair
            .owner
            .accept_contact(op(101), request.bytes(), short, pair.now + 2)
            .await
            .is_err());
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let replacement = renewal(
            &pair,
            Validity::new(pair.now - 10, pair.now + 8000).unwrap(),
        );
        pair.owner
            .renew_owner(op(102), replacement, pair.now)
            .await
            .unwrap();
        let after = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .accept_contact(op(101), request.bytes(), short, pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(pair.owner_disk.snapshot() == after);
    });
}

#[test]
fn contact_faults_before_after_and_cancellation_reopen_exact_each_step() {
    block_on(async {
        for step in 0..4 {
            for fault in [Fault::Before, Fault::After, Fault::HangAfter] {
                let mut pair = fresh().await;
                let recipient = pair.member.status().context.account;
                let secret = if step == 0 {
                    None
                } else {
                    Some(offer(&mut pair).await)
                };
                let request = if step <= 1 {
                    None
                } else {
                    Some(
                        pair.member
                            .contact_request(
                                op(200),
                                secret.as_ref().unwrap().confidential_bytes(),
                                pair.now,
                            )
                            .await
                            .unwrap(),
                    )
                };
                let response = if step <= 2 {
                    None
                } else {
                    Some(
                        pair.owner
                            .accept_contact(
                                op(101),
                                request.as_ref().unwrap().bytes(),
                                validity(pair.now),
                                pair.now,
                            )
                            .await
                            .unwrap(),
                    )
                };
                let disk = if step == 0 || step == 2 {
                    pair.owner_disk.clone()
                } else {
                    pair.member_disk.clone()
                };
                let before = disk.snapshot();
                disk.fault(fault);
                let action = async {
                    match step {
                        0 => {
                            pair.owner
                                .create_contact_offer(
                                    op(100),
                                    recipient,
                                    validity(pair.now),
                                    pair.now,
                                )
                                .await?;
                        }
                        1 => {
                            pair.member
                                .contact_request(
                                    op(200),
                                    secret.as_ref().unwrap().confidential_bytes(),
                                    pair.now,
                                )
                                .await?;
                        }
                        2 => {
                            pair.owner
                                .accept_contact(
                                    op(101),
                                    request.as_ref().unwrap().bytes(),
                                    validity(pair.now),
                                    pair.now,
                                )
                                .await?;
                        }
                        _ => {
                            pair.member
                                .join_contact(response.as_ref().unwrap().bytes(), pair.now)
                                .await?;
                        }
                    }
                    Ok::<(), Error>(())
                };
                if matches!(fault, Fault::HangAfter) {
                    use futures::FutureExt;
                    assert!(action.now_or_never().is_none());
                } else {
                    assert!(action.await.is_err());
                }
                assert!(if step == 0 || step == 2 {
                    pair.owner.needs_reopen()
                } else {
                    pair.member.needs_reopen()
                });
                if matches!(fault, Fault::Before) {
                    assert!(disk.snapshot() == before);
                }
                let after = disk.snapshot();
                pair.reopen_owner().await;
                pair.reopen_member().await;
                match step {
                    0 => {
                        pair.owner
                            .create_contact_offer(op(100), recipient, validity(pair.now), pair.now)
                            .await
                            .unwrap();
                    }
                    1 => {
                        pair.member
                            .contact_request(
                                op(200),
                                secret.as_ref().unwrap().confidential_bytes(),
                                pair.now,
                            )
                            .await
                            .unwrap();
                    }
                    2 => {
                        pair.owner
                            .accept_contact(
                                op(101),
                                request.as_ref().unwrap().bytes(),
                                validity(pair.now),
                                pair.now,
                            )
                            .await
                            .unwrap();
                    }
                    _ => {
                        pair.member
                            .join_contact(response.as_ref().unwrap().bytes(), pair.now)
                            .await
                            .unwrap();
                    }
                }
                if !matches!(fault, Fault::Before) {
                    assert!(disk.snapshot() == after);
                }
                let added = disk.0.borrow().records.len() - before.1.len();
                assert_eq!(
                    added,
                    if step == 2 {
                        3
                    } else if step == 3 {
                        1
                    } else {
                        2
                    }
                );
                if step == 2 {
                    assert!(owner_work(&pair).state.offers.is_empty());
                }
            }
        }
    });
}

#[test]
fn contact_malformed_bounds_and_plaintext_requests_never_publish() {
    block_on(async {
        let mut pair = fresh().await;
        let secret = offer(&mut pair).await;
        for n in 0..secret.confidential_bytes().len() {
            assert!(Offer::decode(&secret.confidential_bytes()[..n]).is_err());
        }
        let mut too_long = secret.confidential_bytes().to_vec();
        too_long.push(0);
        assert!(Offer::decode(&too_long).is_err());
        assert!(Offer::decode(&vec![0; crate::contact::MAX_OFFER_BYTES + 1]).is_err());
        let mut bad_keys = secret.confidential_bytes().to_vec();
        let n = bad_keys.len() - 64;
        bad_keys[n - 64..n - 32].fill(0);
        assert!(Offer::decode(&bad_keys).is_err());
        let offer = Offer::decode(secret.confidential_bytes()).unwrap();
        let raw = offer.seal(None, b"not a JoinRequest").unwrap();
        for n in 0..raw.len() {
            assert!(Frame::decode(&raw[..n]).is_err());
        }
        assert!(Frame::decode(&vec![0; packets::MAX_PACKET + 1]).is_err());
        let before = pair.owner_disk.snapshot();
        assert!(pair
            .owner
            .accept_contact(op(101), &raw, validity(pair.now), pair.now)
            .await
            .is_err());
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let request = pair.member.key_package(op(200), pair.now).await.unwrap();
        assert!(pair
            .owner
            .accept_contact(op(101), request.bytes(), validity(pair.now), pair.now)
            .await
            .is_err());
        assert!(pair.owner_disk.snapshot() == before);
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .contact_request(op(201), secret.confidential_bytes(), pair.now)
                .await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
    });
}

#[test]
fn contact_single_secret_file_initializes_fresh_recipient_after_pinned_inspection() {
    block_on(async {
        let mut pair = fresh().await;
        let recipient = account();
        let recipient_key = key(&recipient);
        let owner_key = key(&pair.owner_account);
        let secret = pair
            .owner
            .create_contact_offer(op(400), recipient_key, validity(pair.now), pair.now)
            .await
            .unwrap();
        assert_eq!(
            secret.confidential_bytes().len(),
            crate::contact::MAX_OFFER_BYTES
        );
        assert_eq!(crate::contact::MAX_OFFER_BYTES, 713);
        assert!(matches!(
            ContactBootstrap::inspect(
                secret.confidential_bytes(),
                key(&account()),
                recipient_key,
                pair.now
            ),
            Err(Error::Scope)
        ));
        assert!(matches!(
            ContactBootstrap::inspect(
                secret.confidential_bytes(),
                owner_key,
                key(&account()),
                pair.now
            ),
            Err(Error::Scope)
        ));
        assert!(ContactBootstrap::inspect(
            secret.confidential_bytes(),
            owner_key,
            recipient_key,
            pair.now - 1
        )
        .is_err());
        assert!(ContactBootstrap::inspect(
            secret.confidential_bytes(),
            owner_key,
            recipient_key,
            pair.now + 7200
        )
        .is_err());
        let checked = ContactBootstrap::inspect(
            secret.confidential_bytes(),
            owner_key,
            recipient_key,
            pair.now,
        )
        .unwrap();
        assert_eq!(checked.recipient(), recipient_key);
        assert_eq!(checked.validity(), validity(pair.now));
        assert_eq!(checked.scope(), pair.owner.status().context.scope);
        let draft = MemberDraft::new(
            checked.scope(),
            checked.anchor().clone(),
            checked.owner().clone(),
            checked.recipient(),
            validity(pair.now),
            pair.now,
        )
        .unwrap();
        let signed = draft.enrollment_request().sign(&recipient).unwrap();
        let disk = Memory::default();
        let store_key = storage_key();
        let mut fresh_recipient = draft
            .initialize(disk, &store_key, signed, pair.now)
            .await
            .unwrap();
        let request = fresh_recipient
            .contact_request(op(401), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let response = pair
            .owner
            .accept_contact(op(402), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        fresh_recipient
            .join_contact(response.bytes(), pair.now)
            .await
            .unwrap();
        let message = pair
            .owner
            .test_send(op(403), b"one confidential bootstrap", pair.now)
            .await
            .unwrap();
        assert_eq!(
            fresh_recipient
                .receive(message.bytes(), pair.now)
                .await
                .unwrap()
                .body(),
            b"one confidential bootstrap"
        );
    });
}

#[test]
fn contact_rekeyed_offer_with_attacker_signature_never_releases_key_package() {
    use ed25519_dalek::Signer;
    block_on(async {
        let mut pair = fresh().await;
        let secret = offer(&mut pair).await;
        let mut forged = secret.confidential_bytes().to_vec();
        let signature_start = forged.len() - 64;
        forged[signature_start - 64..signature_start - 32].fill(11);
        forged[signature_start - 32..signature_start].fill(12);
        // Preserve all legitimate account-signed anchor/enrollment metadata,
        // then sign the exact full canonical preimage with the attacker's key.
        let mut preimage = b"vhalla/private/contact/owner-offer/v1\0".to_vec();
        preimage.extend(&forged[..signature_start]);
        forged[signature_start..].copy_from_slice(&account().sign(&preimage).to_bytes());
        assert!(matches!(Offer::decode(&forged), Err(Error::Authentication)));
        assert!(matches!(
            ContactBootstrap::inspect(
                &forged,
                key(&pair.owner_account),
                pair.member.status().context.account,
                pair.now
            ),
            Err(Error::Authentication)
        ));
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .contact_request(op(200), &forged, pair.now)
                .await,
            Err(Error::Authentication)
        ));
        assert!(pair.member_disk.snapshot() == before);
        assert_eq!(pair.member.status().outbox_head, 0);
        pair.member
            .contact_request(op(200), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
    });
}

#[test]
fn contact_request_preview_binds_offer_pins_ciphertext_scope_and_enrollment() {
    block_on(async {
        let mut pair = fresh().await;
        let (secret, request) = request(&mut pair).await;
        let owner = pair.owner.status().context.account;
        let recipient = pair.member.status().context.account;
        let other = pair
            .owner
            .create_contact_offer(op(201), recipient, validity(pair.now), pair.now)
            .await
            .unwrap();
        let before_owner = pair.owner_disk.snapshot();
        let before_member = pair.member_disk.snapshot();
        let inspect = |offer: &[u8], request: &[u8], owner, recipient, now| {
            ContactBootstrap::inspect_request(offer, request, owner, recipient, now)
        };
        let (metadata, enrollment) = inspect(
            secret.confidential_bytes(),
            request.bytes(),
            owner,
            recipient,
            pair.now,
        )
        .unwrap();
        assert_eq!(metadata.scope(), pair.owner.status().context.scope);
        assert_eq!(metadata.owner(), owner_work(&pair).state.owner.signed());
        assert_eq!(enrollment.claims().account, recipient);
        assert_eq!(
            enrollment.claims().device,
            pair.member.status().context.device
        );
        assert!(inspect(
            other.confidential_bytes(),
            request.bytes(),
            owner,
            recipient,
            pair.now
        )
        .is_err());
        assert!(inspect(
            secret.confidential_bytes(),
            request.bytes(),
            key(&account()),
            recipient,
            pair.now
        )
        .is_err());
        assert!(inspect(
            secret.confidential_bytes(),
            request.bytes(),
            owner,
            key(&account()),
            pair.now
        )
        .is_err());
        assert!(inspect(
            secret.confidential_bytes(),
            request.bytes(),
            owner,
            recipient,
            metadata.validity().expires_at()
        )
        .is_err());
        for length in [0, 1, request.bytes().len() - 1] {
            assert!(inspect(
                secret.confidential_bytes(),
                &request.bytes()[..length],
                owner,
                recipient,
                pair.now
            )
            .is_err());
        }
        let mut changed = request.bytes().to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(inspect(
            secret.confidential_bytes(),
            &changed,
            owner,
            recipient,
            pair.now
        )
        .is_err());
        let mut trailing = request.bytes().to_vec();
        trailing.push(0);
        assert!(inspect(
            secret.confidential_bytes(),
            &trailing,
            owner,
            recipient,
            pair.now
        )
        .is_err());

        // Authenticated wrong-scope and wrong-recipient payloads still refuse.
        let offer = Offer::decode(secret.confidential_bytes()).unwrap();
        let clear = offer
            .open(&Frame::decode(request.bytes()).unwrap(), None)
            .unwrap();
        let mut join = crate::packets::JoinRequest::decode(&clear).unwrap();
        join.scope.room = RoomId::from_bytes([3; 32]).unwrap();
        let foreign = offer.seal(None, &join.encode().unwrap()).unwrap();
        assert!(matches!(
            inspect(
                secret.confidential_bytes(),
                &foreign,
                owner,
                recipient,
                pair.now
            ),
            Err(Error::Scope)
        ));
        let mut join = crate::packets::JoinRequest::decode(&clear).unwrap();
        let alien = account();
        join.enrollment = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
            account: key(&alien),
            device: join.enrollment.claims().device,
            validity: validity(pair.now),
        })
        .unwrap()
        .sign(&alien)
        .unwrap()
        .verify()
        .unwrap();
        let foreign = offer.seal(None, &join.encode().unwrap()).unwrap();
        assert!(matches!(
            inspect(
                secret.confidential_bytes(),
                &foreign,
                owner,
                recipient,
                pair.now
            ),
            Err(Error::Scope)
        ));
        let response = offer
            .seal(Some(crate::contact::request_hash(request.bytes())), &clear)
            .unwrap();
        assert!(inspect(
            secret.confidential_bytes(),
            &response,
            owner,
            recipient,
            pair.now
        )
        .is_err());
        assert!(pair.owner_disk.snapshot() == before_owner);
        assert!(pair.member_disk.snapshot() == before_member);
    });
}

#[test]
fn contact_request_preview_preserves_signed_expiry_for_delayed_admission() {
    block_on(async {
        let mut pair = fresh().await;
        let end = pair.now + 3600;
        let secret = pair
            .owner
            .create_contact_offer(
                op(100),
                pair.member.status().context.account,
                Validity::new(pair.now, end).unwrap(),
                pair.now,
            )
            .await
            .unwrap();
        let request = pair
            .member
            .contact_request(op(200), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let later = pair.now + 5;
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .accept_contact(
                    op(101),
                    request.bytes(),
                    Validity::new(later, later + 3600).unwrap(),
                    later
                )
                .await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let (metadata, enrollment) = ContactBootstrap::inspect_request(
            secret.confidential_bytes(),
            request.bytes(),
            pair.owner.status().context.account,
            pair.member.status().context.account,
            later,
        )
        .unwrap();
        let expiry = metadata
            .validity()
            .expires_at()
            .min(enrollment.claims().validity.expires_at());
        assert_eq!(expiry, end);
        let response = pair
            .owner
            .accept_contact(
                op(101),
                request.bytes(),
                Validity::new(later, expiry).unwrap(),
                later,
            )
            .await
            .unwrap();
        assert_eq!(
            pair.member
                .join_contact(response.bytes(), later)
                .await
                .unwrap()
                .phase,
            Phase::MemberJoined
        );
    });
}

#[test]
fn contact_request_preview_refuses_expired_recipient_before_owner_mutation() {
    block_on(async {
        let mut pair = fresh_with_lifetimes(7200, 10).await;
        let (secret, request) = request(&mut pair).await;
        let before = pair.owner_disk.snapshot();
        assert!(ContactBootstrap::inspect_request(
            secret.confidential_bytes(),
            request.bytes(),
            pair.owner.status().context.account,
            pair.member.status().context.account,
            pair.now + 10
        )
        .is_err());
        assert!(pair.owner_disk.snapshot() == before);
    });
}

#[test]
fn same_account_fresh_device_rejoins_and_exchanges() {
    block_on(async {
        let mut pair = fresh().await;
        let owner_account_key = key(&pair.owner_account);
        let snapshot = pair.owner.membership().await.unwrap();
        // A fresh device for the SAME account: new device material signed by
        // the same account key, on its own store. No old ratchet is copied.
        let draft = MemberDraft::new(
            snapshot.status().context.scope,
            snapshot.anchor().clone(),
            snapshot.owner().clone(),
            owner_account_key,
            validity(pair.now),
            pair.now,
        )
        .unwrap();
        let enrollment = draft
            .enrollment_request()
            .sign(&pair.owner_account)
            .unwrap();
        let disk = Memory::default();
        let storage = storage_key();
        let mut device = draft
            .initialize(disk.clone(), &storage, enrollment, pair.now)
            .await
            .unwrap();
        assert_eq!(device.status().phase, Phase::AwaitingWelcome);
        // The owner issues a confidential offer addressed to its own account.
        let secret = pair
            .owner
            .create_contact_offer(op(110), owner_account_key, validity(pair.now), pair.now)
            .await
            .unwrap();
        let request = device
            .contact_request(op(1), secret.confidential_bytes(), pair.now)
            .await
            .unwrap();
        let response = pair
            .owner
            .accept_contact(op(111), request.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let joined = device
            .join_contact(response.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(joined.phase, Phase::MemberJoined);
        let device_context = device.status().context;
        assert_eq!(device_context.account, owner_account_key);
        assert_ne!(device_context.device, snapshot.status().context.device);
        // The roster now holds two distinct devices under one account.
        let snapshot = pair.owner.membership().await.unwrap();
        assert_eq!(snapshot.members().len(), 2);
        assert!(snapshot
            .members()
            .iter()
            .all(|m| m.claims().account == owner_account_key));
        assert_ne!(
            snapshot.members()[0].claims().device,
            snapshot.members()[1].claims().device
        );
        // The fresh device has no history before its joining checkpoint.
        assert_eq!(device.inbox(0, 4).await.unwrap().records.len(), 0);
        // Bidirectional exchange between the two same-account devices.
        let sent = pair
            .owner
            .test_send(op(2), b"owner to fresh device", pair.now)
            .await
            .unwrap();
        let received = device.receive(sent.bytes(), pair.now).await.unwrap();
        assert_eq!(received.sender(), snapshot.status().context.device);
        assert_eq!(received.body(), b"owner to fresh device");
        let reply = device
            .test_send(op(2), b"fresh device to owner", pair.now)
            .await
            .unwrap();
        let owner_received = pair.owner.receive(reply.bytes(), pair.now).await.unwrap();
        assert_eq!(owner_received.sender(), device_context.device);
        assert_eq!(owner_received.body(), b"fresh device to owner");
        // Exact reopen and retained retry hold on the fresh device too.
        let mut reopened = Kernel::open(disk, &storage, device_context).await.unwrap();
        assert_eq!(reopened.status().phase, Phase::MemberJoined);
        assert_eq!(
            reopened
                .receive(sent.bytes(), pair.now + 1)
                .await
                .unwrap()
                .sequence(),
            received.sequence()
        );
        assert_eq!(
            reopened
                .test_send(op(2), b"fresh device to owner", pair.now + 1)
                .await
                .unwrap()
                .bytes(),
            reply.bytes()
        );
        // A changed body under the same operation refuses; retries are exact.
        assert!(reopened
            .test_send(op(2), b"changed body", pair.now + 1)
            .await
            .is_err());
    });
}
