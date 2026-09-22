use super::*;
use crate::{Access, PublishError};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use vhalla_public_protocol::activity::UnsignedActivityResponse;
use vhalla_room_activity::UnsignedEvent;

fn event(sequence: u64, previous: EventId, text: &str) -> VerifiedEvent {
    let key = SigningKey::from_bytes(&[3; 32]);
    let mut raw = b"VHRA\x01".to_vec();
    raw.extend_from_slice(&[7; 32]);
    raw.extend_from_slice(&77u128.to_be_bytes());
    raw.extend_from_slice(&[5; 32]);
    raw.extend_from_slice(&[8; 32]);
    raw.extend_from_slice(&[9; 32]);
    raw.extend_from_slice(&key.verifying_key().to_bytes());
    raw.extend_from_slice(&sequence.to_be_bytes());
    raw.extend_from_slice(previous.as_bytes());
    raw.extend_from_slice(&1234u64.to_be_bytes());
    raw.push(0);
    raw.extend_from_slice(&(text.len() as u16).to_be_bytes());
    raw.extend_from_slice(text.as_bytes());
    UnsignedEvent::decode(&raw)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .verify()
        .unwrap()
}
fn scope(event: &VerifiedEvent) -> AuthorScope {
    AuthorScope::new(event.claims().scope, event.claims().author)
}
fn receipt(event: &VerifiedEvent, peer_seed: u8, nonce: u8, cursor: u64) -> DeliveryRecord {
    let peer = SigningKey::from_bytes(&[peer_seed; 32]);
    let request = ActivityRequest::post(
        [nonce; 32],
        *event.claims().scope.room.as_bytes(),
        &event.encode(),
    )
    .unwrap();
    let body = LocalReceipt::new(event, cursor, [9; 32], 5, [6; 32], false)
        .unwrap()
        .encode();
    let proof = UnsignedActivityResponse::new(
        event.claims().scope.network,
        peer.verifying_key().to_bytes(),
        request,
        &body,
    )
    .unwrap()
    .sign_with_key(&peer)
    .unwrap();
    DeliveryRecord::new(
        scope(event),
        peer.verifying_key().to_bytes(),
        &request,
        &proof,
        &body,
    )
    .unwrap()
}

#[test]
fn exact_peer_evidence_roundtrips_and_rejects_tampering_and_oversize() {
    let first = event(1, EventId::ZERO, "first signed post");
    let record = receipt(&first, 8, 1, 12);
    assert_eq!(DeliveryRecord::decode(record.as_bytes()).unwrap(), record);
    assert_eq!(
        DeliveryHead::decode(&record.head().encode()).unwrap(),
        record.head()
    );
    assert_eq!(record.check_event(&first.encode()).unwrap(), first);
    for length in 0..record.as_bytes().len() {
        assert!(DeliveryRecord::decode(&record.as_bytes()[..length]).is_err());
    }
    let mut trailing = record.as_bytes().to_vec();
    trailing.push(0);
    assert!(DeliveryRecord::decode(&trailing).is_err());
    let mut altered = record.as_bytes().to_vec();
    *altered.last_mut().unwrap() ^= 1;
    assert!(DeliveryRecord::decode(&altered).is_err());
    assert_eq!(
        DeliveryRecord::decode(&vec![0; MAX_DELIVERY_RECORD_BYTES + 1]),
        Err(Error::Bounds)
    );
    let different = event(1, EventId::ZERO, "other content");
    assert!(record.check_event(&different.encode()).is_err());
    let fresh_request =
        ActivityRequest::post([2; 32], record.request().room(), &first.encode()).unwrap();
    assert!(DeliveryRecord::new(
        scope(&first),
        record.head().peer(),
        &fresh_request,
        record.proof(),
        &record.receipt().encode()
    )
    .is_err());
}

#[test]
fn full_scope_author_and_exact_peer_are_required_even_with_valid_receipt_signatures() {
    let first = event(1, EventId::ZERO, "scoped post");
    let record = receipt(&first, 8, 1, 1);
    let peer = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    assert!(DeliveryRecord::new(
        scope(&first),
        peer,
        record.request(),
        record.proof(),
        &record.receipt().encode()
    )
    .is_err());
    let mut wrong_network = scope(&first);
    wrong_network.network[0] ^= 1;
    assert!(DeliveryRecord::new(
        wrong_network,
        record.head().peer(),
        record.request(),
        record.proof(),
        &record.receipt().encode()
    )
    .is_err());
    let mut wrong_author = scope(&first);
    wrong_author.author = peer;
    assert!(DeliveryRecord::new(
        wrong_author,
        record.head().peer(),
        record.request(),
        record.proof(),
        &record.receipt().encode()
    )
    .is_err());
    let mut claims = first.claims().clone();
    claims.scope.realm.0 += 1;
    let other_realm = UnsignedEvent::new(claims)
        .unwrap()
        .sign_with_key(&SigningKey::from_bytes(&[3; 32]))
        .unwrap()
        .verify()
        .unwrap();
    let other_record = receipt(&other_realm, 8, 2, 1);
    // Receipts carry a room, author and ID, not a complete realm/directory scope.
    // Only comparison with the retained signed event establishes those fields.
    let misbound = DeliveryRecord::new(
        scope(&first),
        other_record.head().peer(),
        other_record.request(),
        other_record.proof(),
        &other_record.receipt().encode(),
    )
    .unwrap();
    assert_eq!(
        misbound.check_event(&other_realm.encode()),
        Err(Error::WrongScope)
    );
}

#[test]
fn monotone_per_peer_prefix_refuses_gaps_forks_and_cursor_reset_but_keeps_original_retry() {
    let first = event(1, EventId::ZERO, "first");
    let first_record = receipt(&first, 8, 1, 10);
    let first_head = first_record.head();
    assert_eq!(advance(None, None, &first_record, &first), Ok(true));
    let second = event(2, first.id(), "second");
    let second_record = receipt(&second, 8, 2, 11);
    assert_eq!(
        advance(
            Some(&first_head),
            Some(&first_head),
            &second_record,
            &second
        ),
        Ok(true)
    );
    assert_eq!(
        advance(None, Some(&first_head), &second_record, &second),
        Err(Error::Stale)
    );
    let skipped = event(3, second.id(), "skip second");
    assert_eq!(
        advance(
            Some(&first_head),
            Some(&first_head),
            &receipt(&skipped, 8, 3, 12),
            &skipped
        ),
        Err(Error::Stale)
    );
    let fork = event(2, EventId::from_bytes([99; 32]), "another predecessor");
    assert_eq!(
        advance(
            Some(&first_head),
            Some(&first_head),
            &receipt(&fork, 8, 3, 12),
            &fork
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        advance(
            Some(&first_head),
            Some(&first_head),
            &receipt(&second, 8, 3, 9),
            &second
        ),
        Err(Error::Stale)
    );
    let retry = receipt(&first, 8, 4, 1);
    assert_ne!(retry.as_bytes(), first_record.as_bytes());
    assert_eq!(
        advance(Some(&first_head), Some(&first_head), &retry, &first),
        Ok(false),
        "exact event retry retains original cursor and proof"
    );
    let other_peer = receipt(&first, 9, 5, 1);
    assert_eq!(advance(None, None, &other_peer, &first), Ok(true));
    assert_eq!(
        advance(Some(&first_head), Some(&first_head), &other_peer, &first),
        Err(Error::WrongScope)
    );
    assert_ne!(
        prefix(scope(&first), first_head.peer()),
        prefix(scope(&first), other_peer.head().peer())
    );
}

#[derive(Clone, Default)]
struct Disk {
    head: Option<DeliveryHead>,
    records: BTreeMap<u64, Vec<u8>>,
}
enum Outcome {
    Complete,
    AbortBefore,
    CancelBefore,
    CancelAfter,
}
fn publish(
    access: &mut Access,
    disk: &mut Disk,
    expected: Option<&DeliveryHead>,
    record: &DeliveryRecord,
    stored_event: &[u8],
    outcome: Outcome,
) -> Option<Result<(), PublishError>> {
    if let Err(error) = access.begin() {
        return Some(Err(PublishError::Rejected(error)));
    }
    let event = record.check_event(stored_event).unwrap();
    let write = match advance(expected, disk.head.as_ref(), record, &event) {
        Ok(write) => write,
        Err(error) => {
            *access = Access::NeedsReopen;
            return Some(Err(PublishError::ReopenRequired(error)));
        }
    };
    if matches!(outcome, Outcome::AbortBefore) {
        *access = Access::NeedsReopen;
        return Some(Err(PublishError::ReopenRequired(Error::Storage)));
    }
    if matches!(outcome, Outcome::CancelBefore) {
        return None;
    }
    if write {
        let mut candidate = disk.clone();
        assert!(candidate
            .records
            .insert(record.head().sequence(), record.as_bytes().to_vec())
            .is_none());
        candidate.head = Some(record.head());
        *disk = candidate;
    }
    if matches!(outcome, Outcome::CancelAfter) {
        return None;
    }
    Some(access.completed().map_err(PublishError::ReopenRequired))
}

#[test]
fn uncertain_receipt_write_requires_reopen_and_never_overwrites_original_evidence() {
    let first = event(1, EventId::ZERO, "durable local event");
    let record = receipt(&first, 8, 1, 7);
    for outcome in [
        Outcome::AbortBefore,
        Outcome::CancelBefore,
        Outcome::CancelAfter,
    ] {
        let mut disk = Disk::default();
        let mut access = Access::Ready;
        assert_ne!(
            publish(
                &mut access,
                &mut disk,
                None,
                &record,
                &first.encode(),
                outcome
            ),
            Some(Ok(()))
        );
        assert_eq!(access.ready(), Err(Error::NeedsReopen));
        assert_eq!(disk.head.is_some(), disk.records.contains_key(&1));
        if let Some(head) = disk.head {
            let retained = disk.records[&1].clone();
            assert_eq!(DeliveryRecord::decode(&retained).unwrap(), record);
            let retry = receipt(&first, 8, 2, 1);
            assert_eq!(
                publish(
                    &mut Access::Ready,
                    &mut disk,
                    Some(&head),
                    &retry,
                    &first.encode(),
                    Outcome::Complete
                ),
                Some(Ok(()))
            );
            assert_eq!(disk.head, Some(head));
            assert_eq!(disk.records[&1], retained);
        }
    }
}
