use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::RealmId;
use vhalla_social::{
    Actor, Body, Error, Operation, OwnerId, RecordId, References, SignedRecord, Text,
    UnsignedRecord,
};
use vhalla_social_facets_spike::*;
fn body(text: &str) -> Body {
    Body::Social {
        actor: Actor::Owner {
            owner: OwnerId::from_bytes([1; 32]),
            control: RecordId::from_bytes([2; 32]),
        },
        realm: RealmId(7),
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: vhalla_social::Placement::Profile,
            text: Text::new(text).unwrap(),
            reply: None,
            quote: None,
        },
    }
}
fn fixture() -> Vec<Facet> {
    vec![
        Facet {
            start: 0,
            end: 6,
            kind: Kind::Mention(Target::Owner(OwnerId::from_bytes([3; 32]))),
        },
        Facet {
            start: 7,
            end: 12,
            kind: Kind::Tag("rust".into()),
        },
    ]
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn both_encodings_sign_exact_revisions_but_preserving_v1_costs_no_migration_of_old_ids() {
    let a = sign_revision(
        &key(),
        body("@alice #Rust"),
        fixture(),
        Encoding::NewOpcodesV1,
    )
    .unwrap();
    let b = sign_revision(
        &key(),
        body("@alice #Rust"),
        fixture(),
        Encoding::EnvelopeV2,
    )
    .unwrap();
    let av = verify_revision(&a).unwrap();
    let bv = verify_revision(&b).unwrap();
    assert_eq!(a.len(), b.len());
    assert_ne!(av.id(), bv.id());
    assert_eq!(av.annotated(), bv.annotated());
    assert_eq!(decode_legacy(&a), Err(Error::Encoding));
    assert_eq!(
        SignedRecord::decode(&a).unwrap().verify().unwrap().id(),
        av.id()
    );
    assert_eq!(decode_legacy(&b), Err(Error::Encoding));
    assert_eq!(
        hex(&a),
        include_str!("../vectors/faceted-post-v1.hex").trim()
    );
    assert_eq!(
        hex(&b),
        include_str!("../vectors/faceted-post-v2.hex").trim()
    );
    let legacy = UnsignedRecord::new(key().verifying_key().to_bytes(), body("@alice #Rust"))
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap();
    assert!(legacy.clone().verify().is_ok());
    assert_eq!(
        hex(&legacy.encode()),
        include_str!("../vectors/legacy-post-v1.hex").trim()
    );
}
#[test]
fn migration_does_not_allow_ignoring_an_unknown_writer_chain_member() {
    let first = verify_revision(
        &sign_revision(
            &key(),
            body("@alice #Rust"),
            fixture(),
            Encoding::NewOpcodesV1,
        )
        .unwrap(),
    )
    .unwrap();
    let mut next = body("legacy again");
    if let Body::Social {
        sequence, previous, ..
    } = &mut next
    {
        *sequence = 1;
        *previous = Some(first.id());
    }
    let signed = UnsignedRecord::new(key().verifying_key().to_bytes(), next)
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap();
    let decoded = SignedRecord::decode(&signed.encode())
        .unwrap()
        .verify()
        .unwrap();
    assert!(
        matches!(decoded.body(), Body::Social { previous: Some(id), sequence: 1, .. } if *id == first.id())
    );
    // The legacy reader can parse this successor but cannot reconstruct or verify
    // its unsupported predecessor. Capability negotiation cannot be omitted.
}
#[test]
fn cross_revision_metadata_copy_breaks_signature_even_when_spans_stay_valid() {
    let a = sign_revision(
        &key(),
        body("@alice #Rust"),
        fixture(),
        Encoding::NewOpcodesV1,
    )
    .unwrap();
    let mut other = fixture();
    other[0].kind = Kind::Mention(Target::Owner(OwnerId::from_bytes([4; 32])));
    let mut b = sign_revision(&key(), body("@alice #Rust"), other, Encoding::NewOpcodesV1).unwrap();
    let n = a.len();
    b[n - 65..n - 1].copy_from_slice(&a[n - 65..n - 1]);
    assert!(matches!(verify_revision(&b), Err(Error::Signature)));
    let mut text_changed = a.clone();
    let pos = text_changed.windows(5).position(|w| w == b"alice").unwrap();
    text_changed[pos] = b'm';
    assert!(matches!(
        verify_revision(&text_changed),
        Err(Error::Signature)
    ));
}
#[test]
fn spans_are_utf8_sorted_nonoverlapping_and_bounded() {
    let text = Text::new("💠 @a #Rust").unwrap();
    let valid = vec![
        Facet {
            start: 5,
            end: 7,
            kind: Kind::Mention(Target::Owner(OwnerId::from_bytes([1; 32]))),
        },
        Facet {
            start: 8,
            end: 13,
            kind: Kind::Tag("rust".into()),
        },
    ];
    assert!(FacetedText::new(text.clone(), valid.clone()).is_ok());
    for (start, end) in [(1, 3), (5, 5), (5, 14), (5, 9)] {
        let mut invalid = valid.clone();
        invalid[0].start = start;
        invalid[0].end = end;
        assert!(FacetedText::new(text.clone(), invalid).is_err());
    }
    let mut reversed = valid.clone();
    reversed.reverse();
    assert!(FacetedText::new(text.clone(), reversed).is_err());
    assert!(FacetedText::new(text, vec![valid[0].clone(); 17]).is_err());
}
#[test]
fn distinct_recipient_and_tag_budgets_apply_even_when_spans_fit() {
    let mut text = String::new();
    let mut facets = Vec::new();
    for i in 0..9 {
        let start = text.len() as u16;
        text.push_str("@a ");
        facets.push(Facet {
            start,
            end: start + 2,
            kind: Kind::Mention(Target::Owner(OwnerId::from_bytes([i; 32]))),
        });
    }
    assert_eq!(
        FacetedText::new(Text::new(&text).unwrap(), facets.clone()),
        Err(Error::Bounds)
    );
    for f in &mut facets {
        f.kind = Kind::Mention(Target::Owner(OwnerId::from_bytes([1; 32])));
    }
    assert!(FacetedText::new(Text::new(&text).unwrap(), facets).is_ok());
    let mut text = String::new();
    let mut facets = Vec::new();
    for i in 0..9 {
        let start = text.len() as u16;
        let tag = format!("tag{i}");
        text.push_str(&format!("#{tag} "));
        facets.push(Facet {
            start,
            end: text.len() as u16 - 1,
            kind: Kind::Tag(tag),
        });
    }
    assert_eq!(
        FacetedText::new(Text::new(&text).unwrap(), facets),
        Err(Error::Bounds)
    );
}
#[test]
fn signed_labels_do_not_prove_alias_ownership_or_resolve_ambiguity() {
    let honest = Target::Owner(OwnerId::from_bytes([1; 32]));
    let attacker = Target::Owner(OwnerId::from_bytes([2; 32]));
    let book = [("alice", honest.clone())];
    assert_eq!(
        resolve_alias("alice", &attacker, &book),
        Err(Error::Context)
    );
    assert_eq!(
        resolve_alias(
            "alice",
            &honest,
            &[("alice", honest.clone()), ("alice", attacker.clone())]
        ),
        Err(Error::Context)
    );
    assert_eq!(
        resolve_alias("missing", &honest, &book),
        Err(Error::Missing)
    );
    let foreign = FacetedText::new(
        Text::new("@alice").unwrap(),
        vec![Facet {
            start: 0,
            end: 6,
            kind: Kind::Mention(attacker.clone()),
        }],
    )
    .unwrap();
    assert_eq!(foreign.facets()[0].kind, Kind::Mention(attacker));
    assert_eq!(
        foreign.untrusted_label(&foreign.facets()[0]),
        Some("@alice")
    );
}
#[test]
fn ascii_keys_are_exact_and_unicode_lowercase_is_not_normalization() {
    assert_eq!(canonical_tag("RUST_1-x"), Ok("rust_1-x".into()));
    for invalid in [
        "",
        "-x",
        "a b",
        "é",
        "e\u{301}",
        "İ",
        "ß",
        "Ｒust",
        "rust\u{202e}",
    ] {
        assert!(canonical_tag(invalid).is_err());
    }
    assert_ne!("É".to_lowercase(), "E\u{301}".to_lowercase());
    assert_eq!("İ".to_lowercase(), "i\u{307}");
    assert_eq!("ß".to_lowercase(), "ß"); // Full case folding would produce ss.
    let mut mismatch = fixture();
    mismatch[1].kind = Kind::Tag("Rust".into());
    assert!(FacetedText::new(Text::new("@alice #Rust").unwrap(), mismatch).is_err());
}
#[test]
fn max_text_and_reference_payload_with_sixteen_facets_fits_existing_envelope() {
    let mut text = String::new();
    let mut facets = Vec::new();
    for i in 0..8 {
        let start = text.len() as u16;
        text.push_str("@a ");
        facets.push(Facet {
            start,
            end: start + 2,
            kind: Kind::Mention(Target::Owner(OwnerId::from_bytes([i; 32]))),
        });
    }
    for i in 0..8 {
        let tag = format!("{i}{}", "a".repeat(47));
        let start = text.len() as u16;
        text.push_str(&format!("#{tag} "));
        facets.push(Facet {
            start,
            end: text.len() as u16 - 1,
            kind: Kind::Tag(tag),
        });
    }
    text.push_str(&"x".repeat(4096 - text.len()));
    let mut value = body("");
    if let Body::Social { operation, .. } = &mut value {
        *operation = Operation::Revise {
            post: RecordId::from_bytes([9; 32]),
            text: Text::new(&text).unwrap(),
            supersedes: References::new((0..16).map(|n| RecordId::from_bytes([n; 32])).collect())
                .unwrap(),
        };
    }
    let signed = sign_revision(&key(), value, facets, Encoding::NewOpcodesV1).unwrap();
    assert_eq!(signed.len(), 5570);
    assert!(verify_revision(&signed).is_ok());
}
proptest! {
    #[test] fn arbitrary_utf8_spans_never_panic(text in ".{0,128}", start in any::<u16>(), end in any::<u16>()) {
        let text = Text::new(&text).unwrap(); let _ = FacetedText::new(text, vec![Facet { start,end,kind:Kind::Mention(Target::Owner(OwnerId::from_bytes([0;32]))) }]);
    }
    #[test] fn ascii_normalization_is_idempotent(raw in "[A-Za-z0-9_][A-Za-z0-9_-]{0,47}") {
        let canonical = canonical_tag(&raw).unwrap(); prop_assert_eq!(canonical_tag(&canonical).unwrap(), canonical);
    }
    #[test] fn arbitrary_wire_is_total(raw in prop::collection::vec(any::<u8>(), 0..8500)) { let _ = verify_revision(&raw); }
    #[test] fn every_single_byte_mutation_changes_evidence_or_is_rejected(offset in 0usize..300, bit in 0u8..8) {
        let mut raw = sign_revision(&key(), body("@alice #Rust"), fixture(), Encoding::NewOpcodesV1).unwrap();
        let expected = verify_revision(&raw).unwrap().id(); let i = offset % raw.len(); raw[i] ^= 1 << bit;
        if let Ok(record) = verify_revision(&raw) { prop_assert_ne!(record.id(), expected); }
    }
}
