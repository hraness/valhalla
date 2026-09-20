use super::*;
use crate::{EventClaims, EventId, UnsignedEvent};
use alloc::string::ToString;
use ed25519_dalek::SigningKey;
use vhalla_core::RealmId;
use vhalla_rooms::{DirectoryId, RoomGenesisId, RoomRecordId};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn scope() -> RoomScope {
    RoomScope {
        network: [1; 32],
        realm: RealmId(2),
        directory: DirectoryId::from_bytes([3; 32]),
        room: RoomGenesisId::from_bytes([4; 32]),
    }
}
fn event_at(text: Text, scope: RoomScope, key: &SigningKey, sequence: u64) -> VerifiedEvent {
    UnsignedEvent::new(EventClaims {
        scope,
        policy: RoomRecordId::from_bytes([9; 32]),
        author: key.verifying_key().to_bytes(),
        sequence,
        previous: if sequence == 1 {
            EventId::ZERO
        } else {
            EventId::from_bytes([8; 32])
        },
        created_at: 1,
        content: Content::Text(text),
    })
    .unwrap()
    .sign_with_key(key)
    .unwrap()
    .verify()
    .unwrap()
}
fn event(text: Text) -> VerifiedEvent {
    event_at(text, scope(), &key(), 1)
}
fn collector(kind: Kind, raw: &[u8]) -> Collector {
    Collector::new(
        scope(),
        key().verifying_key().to_bytes(),
        kind,
        Sha256::digest(raw).into(),
    )
    .unwrap()
}
fn replace_line(text: &Text, index: usize, replacement: &str) -> String {
    let mut lines: Vec<_> = text.as_str().split('\n').collect();
    lines[index] = replacement;
    lines.join("\n")
}

#[test]
fn one_part_matches_frozen_sha256_and_base64url_vector() {
    let texts = pack(Kind::Responses, b"abc").unwrap();
    assert_eq!(texts.len(), 1);
    assert_eq!(
        texts[0].as_str(),
        "vhalla-puzzle-share/1\nresponses\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n3\n0/1\nYWJj"
    );
    let part = Part::decode(texts[0].as_str()).unwrap();
    assert_eq!(part.data(), b"abc");
    assert_eq!(part.artifact_len(), 3);
    assert_eq!(part.index(), 0);
    assert_eq!(part.count(), 1);
    assert_eq!(part.kind(), Kind::Responses);
    assert_eq!(part.encode(), texts[0]);
}
#[test]
fn all_kinds_and_maximum_94_part_artifact_reorder_and_roundtrip() {
    assert_eq!(MAX_PARTS, 94);
    for kind in [Kind::PublicChallenges, Kind::Responses, Kind::Admission] {
        for length in [1, CHUNK_BYTES, CHUNK_BYTES + 1, MAX_ARTIFACT_BYTES] {
            let raw: Vec<_> = (0..length).map(|n| (n % 251) as u8).collect();
            let texts = pack(kind, &raw).unwrap();
            assert_eq!(texts.len(), length.div_ceil(CHUNK_BYTES));
            let mut selected = collector(kind, &raw);
            assert_eq!(selected.total(), None);
            assert!(selected.bytes().is_none());
            for (arrival, text) in texts.iter().rev().enumerate() {
                assert!(text.as_str().len() < MAX_TEXT_BYTES);
                assert!(Text::new(text.as_str()).is_ok());
                let parsed = Part::decode(text.as_str()).unwrap();
                assert_eq!(parsed.encode(), *text);
                let status = selected
                    .push(&event_at(
                        text.clone(),
                        scope(),
                        &key(),
                        100 + arrival as u64,
                    ))
                    .unwrap();
                assert_eq!(
                    status,
                    if arrival + 1 == texts.len() {
                        CollectStatus::Complete
                    } else {
                        CollectStatus::Added
                    }
                );
            }
            assert_eq!(selected.received(), texts.len());
            assert_eq!(selected.total(), Some(texts.len()));
            assert_eq!(selected.bytes().unwrap(), raw);
            assert_eq!(selected.into_bytes().unwrap(), raw);
        }
    }
}
#[test]
fn byte_bounds_and_hostile_declared_geometry_refuse() {
    assert_eq!(pack(Kind::Admission, b""), Err(Error::Bounds));
    assert_eq!(
        pack(Kind::Admission, &vec![0; MAX_ARTIFACT_BYTES + 1]),
        Err(Error::Bounds)
    );
    let valid = &pack(Kind::Admission, b"abc").unwrap()[0];
    for length in [
        "0",
        "262145",
        "4294967295",
        "18446744073709551615",
        "99999999999999999999999999999999999",
    ] {
        assert_eq!(
            Part::decode(&replace_line(valid, 3, length)),
            Err(Error::Bounds)
        );
    }
    for shape in ["0/0", "0/2", "1/1", "94/94", "0/95"] {
        assert_eq!(
            Part::decode(&replace_line(valid, 4, shape)),
            Err(Error::Bounds)
        );
    }
    assert_eq!(
        Part::decode(&"x".repeat(MAX_TEXT_BYTES + 1)),
        Err(Error::Bounds)
    );
    assert!(Part::decode(&replace_line(valid, 5, "YQ")).is_err());
}
#[test]
fn noncanonical_headers_alphabet_padding_bits_and_trailing_data_refuse() {
    let valid = &pack(Kind::Responses, &[255]).unwrap()[0];
    for (line, bad) in [
        (0, "vhalla-puzzle-share/2"),
        (1, "badge"),
        (1, "Responses"),
        (3, "01"),
        (3, "+1"),
        (3, " 1"),
        (3, "１"),
        (4, "00/1"),
        (4, "0/01"),
        (4, "0/+1"),
        (4, "0/1/1"),
        (5, "_x"),
        (5, "/w"),
    ] {
        assert!(
            Part::decode(&replace_line(valid, line, bad)).is_err(),
            "{line} {bad}"
        );
    }
    let upper = Part::decode(valid.as_str())
        .unwrap()
        .digest()
        .iter()
        .map(|v| format!("{v:02X}"))
        .collect::<String>();
    assert!(Part::decode(&replace_line(valid, 2, &upper)).is_err());
    assert!(Part::decode(&replace_line(valid, 5, "_w==")).is_err());
    assert!(Part::decode(&format!("{}\n", valid.as_str())).is_err());
    assert!(Part::decode(&valid.as_str().replace('\n', "\r\n")).is_err());
    for end in 0..valid.as_str().len() {
        assert!(Part::decode(&valid.as_str()[..end]).is_err());
    }
}
#[test]
fn wrong_complete_scope_author_kind_and_digest_do_not_allocate_or_advance() {
    let text = pack(Kind::Admission, b"abc").unwrap().remove(0);
    let mut selected = collector(Kind::Admission, b"abc");
    let mut scopes = [scope(); 4];
    scopes[0].network = [2; 32];
    scopes[1].realm = RealmId(3);
    scopes[2].directory = DirectoryId::from_bytes([8; 32]);
    scopes[3].room = RoomGenesisId::from_bytes([8; 32]);
    for other in scopes {
        assert_eq!(
            selected.push(&event_at(text.clone(), other, &key(), 1)),
            Err(Error::Scope)
        );
    }
    assert_eq!(
        selected.push(&event_at(
            text,
            scope(),
            &SigningKey::from_bytes(&[8; 32]),
            1
        )),
        Err(Error::Scope)
    );
    assert_eq!(
        selected.push(&event(pack(Kind::Responses, b"abc").unwrap().remove(0))),
        Err(Error::Artifact)
    );
    assert_eq!(
        selected.push(&event(pack(Kind::Admission, b"def").unwrap().remove(0))),
        Err(Error::Artifact)
    );
    assert_eq!(selected.received(), 0);
    assert_eq!(selected.total(), None);
    assert_eq!(selected.data.capacity(), 0);
    assert_eq!(
        selected.push(&event(pack(Kind::Admission, b"abc").unwrap().remove(0))),
        Ok(CollectStatus::Complete)
    );
}
#[test]
fn exact_duplicates_are_idempotent_even_at_another_author_sequence() {
    let raw = vec![5; CHUNK_BYTES + 1];
    let texts = pack(Kind::Responses, &raw).unwrap();
    let mut selected = collector(Kind::Responses, &raw);
    assert_eq!(
        selected.push(&event(texts[0].clone())),
        Ok(CollectStatus::Added)
    );
    let capacity = selected.data.capacity();
    let duplicate = event_at(texts[0].clone(), scope(), &key(), 17);
    for _ in 0..1000 {
        assert_eq!(selected.push(&duplicate), Ok(CollectStatus::Duplicate));
    }
    assert_eq!(selected.data.capacity(), capacity);
    assert_eq!(selected.received(), 1);
    assert!(selected.bytes().is_none());
    assert_eq!(
        selected.push(&event(texts[1].clone())),
        Ok(CollectStatus::Complete)
    );
    assert_eq!(selected.push(&duplicate), Ok(CollectStatus::Duplicate));
    assert_eq!(selected.bytes().unwrap(), raw);
}
#[test]
fn conflicting_selected_part_poison_preserves_first_bytes() {
    let raw = vec![5; CHUNK_BYTES + 1];
    let texts = pack(Kind::Admission, &raw).unwrap();
    let mut selected = collector(Kind::Admission, &raw);
    selected.push(&event(texts[0].clone())).unwrap();
    let before = selected.data.clone();
    let mut changed = Part::decode(texts[0].as_str()).unwrap();
    changed.data[0] ^= 1;
    assert_eq!(
        selected.push(&event(changed.encode())),
        Err(Error::Conflict)
    );
    assert_eq!(selected.data, before);
    assert!(selected.bytes().is_none());
    assert_eq!(selected.push(&event(texts[1].clone())), Err(Error::Failed));
    assert_eq!(selected.into_bytes(), Err(Error::Failed));
}
#[test]
fn matching_digest_with_changed_length_metadata_poison() {
    let raw = vec![5; CHUNK_BYTES + 1];
    let texts = pack(Kind::Admission, &raw).unwrap();
    let mut selected = collector(Kind::Admission, &raw);
    selected.push(&event(texts[0].clone())).unwrap();
    let changed = Text::new(&replace_line(&texts[0], 3, &(CHUNK_BYTES + 2).to_string())).unwrap();
    assert_eq!(selected.push(&event(changed)), Err(Error::Conflict));
    assert!(selected.bytes().is_none());
}
#[test]
fn final_digest_is_mandatory_and_conflicts_revoke_completed_view() {
    let original = pack(Kind::Responses, b"abc").unwrap().remove(0);
    let mut forged = Part::decode(original.as_str()).unwrap();
    forged.data[0] = b'd';
    let mut selected = collector(Kind::Responses, b"abc");
    assert_eq!(selected.push(&event(forged.encode())), Err(Error::Digest));
    assert!(selected.bytes().is_none());
    assert_eq!(selected.push(&event(original.clone())), Err(Error::Failed));
    let mut selected = collector(Kind::Responses, b"abc");
    selected.push(&event(original)).unwrap();
    assert!(selected.bytes().is_some());
    assert_eq!(selected.push(&event(forged.encode())), Err(Error::Conflict));
    assert!(selected.bytes().is_none());
}
#[test]
fn missing_parts_never_expose_prefilled_or_partial_artifacts() {
    let raw = vec![42; CHUNK_BYTES * 2 + 1];
    let texts = pack(Kind::PublicChallenges, &raw).unwrap();
    let mut selected = collector(Kind::PublicChallenges, &raw);
    selected.push(&event(texts[2].clone())).unwrap();
    selected.push(&event(texts[0].clone())).unwrap();
    assert_eq!(selected.received(), 2);
    assert!(selected.bytes().is_none());
    assert_eq!(selected.into_bytes(), Err(Error::Incomplete));
}
#[test]
fn selection_rejects_weak_keys_and_zero_network() {
    let mut weak = [0; 32];
    weak[0] = 1;
    assert!(matches!(
        Collector::new(scope(), weak, Kind::Admission, [1; 32]),
        Err(Error::Selection)
    ));
    let mut zero = scope();
    zero.network = [0; 32];
    assert!(matches!(
        Collector::new(
            zero,
            key().verifying_key().to_bytes(),
            Kind::Admission,
            [1; 32]
        ),
        Err(Error::Selection)
    ));
}
#[test]
fn malformed_signed_text_does_not_poison_unrelated_collection() {
    let mut selected = collector(Kind::Admission, b"abc");
    assert_eq!(
        selected.push(&event(Text::new("ordinary room discussion").unwrap())),
        Err(Error::Encoding)
    );
    assert_eq!(selected.received(), 0);
    assert_eq!(selected.data.capacity(), 0);
    assert_eq!(
        selected.push(&event(pack(Kind::Admission, b"abc").unwrap().remove(0))),
        Ok(CollectStatus::Complete)
    );
}
