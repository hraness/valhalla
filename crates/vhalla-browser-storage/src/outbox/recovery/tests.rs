use super::*;
use crate::{
    history::{HistoryFrontier, HistoryHead},
    identity::IdentitySnapshot,
    Image, Slot,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use vhalla_public_protocol::activity::{ActivityRequest, LocalReceipt, UnsignedActivityResponse};
use vhalla_room_activity::{UnsignedEvent, VerifiedEvent};

fn event(sequence: u64, previous: EventId) -> VerifiedEvent {
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
    raw.extend_from_slice(&5u16.to_be_bytes());
    raw.extend_from_slice(b"hello");
    UnsignedEvent::decode(&raw)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .verify()
        .unwrap()
}
fn fixture(count: u64, pending: bool) -> (Snapshot, Vec<Entry>, IdentitySnapshot) {
    let first = event(1, EventId::ZERO);
    let scope = AuthorScope::new(first.claims().scope, first.claims().author);
    let history = HistoryScope::new([7; 32], [10; 32]);
    let mut head = AuthorHead::fresh_scope_authorized(scope);
    let mut records = BTreeMap::new();
    for sequence in 1..=count {
        let e = event(sequence, head.event_id());
        head = AuthorHead {
            scope,
            sequence,
            event: e.id(),
        };
        records.insert(format!("event/{sequence:016x}"), e.encode());
        records.insert(format!("outbox/{sequence:016x}"), e.encode());
    }
    let draft = if pending {
        let e = event(count + 1, head.event_id());
        Some(
            ReservedDraft::new(
                head,
                HistoryHead::new(
                    history,
                    HistoryFrontier {
                        height: 1,
                        value: [1; 32],
                        registry: [2; 32],
                        social: [3; 32],
                        control: [4; 32],
                        time: 1234,
                    },
                    [5; 32],
                )
                .unwrap(),
                UnsignedEvent::new(e.claims().clone()).unwrap(),
            )
            .unwrap(),
        )
    } else {
        None
    };
    records.insert("head".into(), head.encode());
    if let Some(d) = &draft {
        records.insert("pending".into(), d.as_bytes().to_vec());
    }
    let snapshot = Snapshot::new(head, history, draft, None).unwrap();
    let entries = records
        .into_iter()
        .map(|(k, v)| Entry::new(k, v, &snapshot).unwrap())
        .collect();
    let hex = include_str!("../../../../vhalla-browser-vault/vectors/v1-envelope.hex").trim();
    let mut raw: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|v| u8::from_str_radix(std::str::from_utf8(v).unwrap(), 16).unwrap())
        .collect();
    raw[45..77].copy_from_slice(&scope.author());
    let vault = Image::new(Slot::Vault, &[&raw]).unwrap();
    let identity = IdentitySnapshot::decode(Some(vault.as_bytes()), None).unwrap();
    (snapshot, entries, identity)
}
fn pages(snapshot: &Snapshot, entries: &[Entry]) -> Vec<AuthorBackupPage> {
    let mut stream = Export::new(snapshot.clone(), [11; 32]);
    let mut pages = Vec::new();
    for entries in entries.chunks(PAGE_ENTRIES) {
        let page = stream.page(entries, false).unwrap();
        stream = stream.advance(&page).unwrap();
        pages.push(page);
    }
    stream.validator.finish(snapshot).unwrap();
    let final_page = stream.page(&[], true).unwrap();
    stream = stream.advance(&final_page).unwrap();
    assert!(stream.ended);
    pages.push(final_page);
    pages
}
#[test]
fn explicit_zero_floor_pending_and_multiple_pages_roundtrip_without_lifetime_cap() {
    for (count, pending) in [(0, false), (0, true), (33, true)] {
        let (snapshot, entries, identity) = fixture(count, pending);
        let pages = pages(&snapshot, &entries);
        let mut stream = Export::new(snapshot.clone(), [11; 32]);
        for page in pages {
            assert_eq!(decode_page(&page).unwrap().0, snapshot);
            stream = stream.advance(&page).unwrap();
            assert_eq!(Export::decode(&stream.encode()).unwrap(), stream);
        }
        assert!(stream.ended);
        let import = Import {
            stream,
            identity,
            verified_after: String::new(),
            verified: false,
        };
        assert!(Import::decode(&import.encode()).unwrap() == import);
        let raw = import.encode();
        for at in 0..raw.len() {
            let mut corrupt = raw.clone();
            corrupt[at] ^= 1;
            assert!(Import::decode(&corrupt).is_err());
        }
        assert!(!import.ready_to_activate());
        assert!(import.received_final());
    }
}
#[test]
fn reordered_missing_extra_pages_wrong_scope_and_final_only_never_complete() {
    let (snapshot, entries, _) = fixture(10, true);
    let pages = pages(&snapshot, &entries);
    let initial = Export::new(snapshot.clone(), [11; 32]);
    assert!(initial.advance(pages.last().unwrap()).is_err());
    assert!(initial.advance(&pages[1]).is_err());
    let one = initial.advance(&pages[0]).unwrap();
    assert!(one.advance(&pages[0]).is_err());
    let mut context = *pages[0].scope();
    context[175] ^= 1;
    let changed =
        AuthorBackupPage::new(context, [11; 32], 0, [0; 32], false, pages[0].payload()).unwrap();
    assert!(initial.advance(&changed).is_err());
    let mut missing = entries.clone();
    missing.remove(0);
    let page = initial.page(&missing[..PAGE_ENTRIES], false).unwrap();
    assert!(initial.advance(&page).is_err());
    let mut raw = pages[0].payload().to_vec();
    raw.push(0);
    let extra =
        AuthorBackupPage::new(*pages[0].scope(), [11; 32], 0, [0; 32], false, &raw).unwrap();
    assert!(decode_page(&extra).is_err());
    let mut validator = Validator::default();
    for e in &entries {
        if e.key() != "pending" {
            validator.push(&snapshot, e).unwrap();
        }
    }
    assert!(validator.finish(&snapshot).is_err());
}
#[test]
fn original_peer_evidence_requires_complete_contiguous_prefix_and_exact_local_bytes() {
    let (snapshot, mut entries, _) = fixture(2, false);
    let peer = SigningKey::from_bytes(&[8; 32]);
    let peerhex = peer
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect::<String>();
    let first = event(1, EventId::ZERO);
    let second = event(2, first.id());
    let mut receipts = Vec::new();
    for event in [&first, &second] {
        let request = ActivityRequest::post(
            [event.claims().sequence as u8; 32],
            *event.claims().scope.room.as_bytes(),
            &event.encode(),
        )
        .unwrap();
        let body = LocalReceipt::new(
            event,
            event.claims().sequence + 10,
            [9; 32],
            5,
            [6; 32],
            false,
        )
        .unwrap()
        .encode();
        let proof =
            UnsignedActivityResponse::new([7; 32], peer.verifying_key().to_bytes(), request, &body)
                .unwrap()
                .sign_with_key(&peer)
                .unwrap();
        receipts.push(
            DeliveryRecord::new(
                snapshot.head.scope(),
                peer.verifying_key().to_bytes(),
                &request,
                &proof,
                &body,
            )
            .unwrap(),
        );
    }
    entries.push(
        Entry::new(
            format!("delivery/{peerhex}/head"),
            receipts[1].head().encode(),
            &snapshot,
        )
        .unwrap(),
    );
    for record in &receipts {
        entries.push(
            Entry::new(
                format!(
                    "delivery/{peerhex}/receipt/{:016x}",
                    record.head().sequence()
                ),
                record.as_bytes().to_vec(),
                &snapshot,
            )
            .unwrap(),
        );
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    assert!(pages(&snapshot, &entries).last().unwrap().is_final());
    for drop_sequence in [1, 2] {
        let mut check = Validator::default();
        let mut failure = false;
        for entry in &entries {
            if entry
                .key
                .ends_with(&format!("receipt/{drop_sequence:016x}"))
            {
                continue;
            }
            if check.push(&snapshot, entry).is_err() {
                failure = true;
                break;
            }
        }
        assert!(failure || check.finish(&snapshot).is_err());
    }
    assert!(receipts[0].check_event(&second.encode()).is_err());
    assert!(receipts[1].check_event(&second.encode()).is_ok());
}
#[test]
fn interrupted_staging_preserves_absence_of_authority_and_exact_resume_only() {
    let (snapshot, entries, identity) = fixture(2, true);
    let pages = pages(&snapshot, &entries);
    let initial = Import {
        stream: Export::new(snapshot.clone(), [11; 32]),
        identity,
        verified_after: String::new(),
        verified: false,
    };
    let mut staged = BTreeMap::new();
    staged.insert("recovery/stage".to_owned(), initial.encode());
    let mut current = initial.clone();
    assert!(initial.guard(&initial, &initial.identity, false).is_ok());
    assert_eq!(
        initial.guard(&initial, &initial.identity, true),
        Err(Error::Stale)
    );
    assert_eq!(
        initial.guard(&initial, &IdentitySnapshot::empty(), false),
        Err(Error::Stale)
    );
    let mut other = initial.clone();
    other.stream.backup[0] ^= 1;
    assert_eq!(
        initial.guard(&other, &initial.identity, false),
        Err(Error::Stale)
    );
    for page in &pages {
        let next = current.advance(page).unwrap();
        let (_, entries) = decode_page(page).unwrap();
        let before = staged.clone();
        for entry in entries {
            if entry.key() != "head" {
                assert!(staged.insert(entry.key, entry.value).is_none());
            }
        }
        staged.insert("recovery/stage".into(), next.encode());
        assert!(!staged.contains_key("head"));
        assert!(Import::decode(staged.get("recovery/stage").unwrap()).unwrap() == next);
        assert!(next.advance(page).unwrap() == next);
        assert_ne!(before, staged);
        current = next;
    }
    assert!(!current.ready_to_activate());
    assert!(current.stream.advance(&pages[0]).is_err());
    current.verified = true;
    assert!(current.ready_to_activate());
    staged.insert("head".into(), snapshot.head.encode());
    staged.remove("recovery/stage");
    assert!(AuthorHead::decode(staged.get("head").unwrap()).unwrap() == snapshot.head);
    assert!(staged.contains_key("pending"));
    assert!(!staged.is_empty());
    // Existing state and any partial namespace must reject fresh initialization.
    assert!(crate::identity::fresh_author_check(
        &initial.identity,
        &initial.identity,
        snapshot.head.scope().author(),
        true
    )
    .is_err());
    let mut changed = snapshot.clone();
    changed.revision = Some(1);
    assert_eq!(snapshot.compare(&changed), Err(Error::Stale));
    changed = snapshot.clone();
    changed.pending = None;
    assert_eq!(snapshot.compare(&changed), Err(Error::Stale));
}
