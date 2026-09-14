//! Signed facet codec bounds, migration vectors and generated invariants.
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_core::RealmId;
use vhalla_social::*;
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn fixture() -> Vec<Facet> {
    vec![
        Facet {
            start: 0,
            end: 6,
            kind: FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([3; 32]))),
        },
        Facet {
            start: 7,
            end: 12,
            kind: FacetKind::Tag(CanonicalTag::new("rust").unwrap()),
        },
    ]
}
fn body(operation: Operation) -> Body {
    Body::Social {
        actor: Actor::Owner {
            owner: OwnerId::from_bytes([1; 32]),
            control: RecordId::from_bytes([2; 32]),
        },
        realm: RealmId(7),
        sequence: 0,
        previous: None,
        operation,
    }
}
fn post(content: FacetedText) -> Operation {
    Operation::PostFaceted {
        placement: Placement::Profile,
        content,
        reply: None,
        quote: None,
    }
}
fn signed(operation: Operation) -> SignedRecord {
    UnsignedRecord::new(key().verifying_key().to_bytes(), body(operation))
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap()
}
fn decode_hex(text: &str) -> Vec<u8> {
    text.trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn old_and_extended_v1_golden_bytes_are_frozen() {
    let legacy = signed(Operation::Post {
        placement: Placement::Profile,
        text: Text::new("@alice #Rust").unwrap(),
        reply: None,
        quote: None,
    });
    let extended = signed(post(
        FacetedText::new(Text::new("@alice #Rust").unwrap(), fixture()).unwrap(),
    ));
    for (record, bytes, id) in [
        (
            legacy,
            include_str!("vectors/legacy-post-v1.hex"),
            include_str!("vectors/legacy-post-v1.id"),
        ),
        (
            extended,
            include_str!("vectors/faceted-post-v1.hex"),
            include_str!("vectors/faceted-post-v1.id"),
        ),
    ] {
        assert_eq!(record.encode(), decode_hex(bytes));
        assert_eq!(record.id().as_bytes().as_slice(), decode_hex(id));
        let verified = SignedRecord::decode(&record.encode())
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(verified.id(), record.id());
    }
}
#[test]
fn exact_text_and_recipient_are_signature_bound() {
    let original = signed(post(
        FacetedText::new(Text::new("@alice #Rust").unwrap(), fixture()).unwrap(),
    ))
    .encode();
    let mut text_changed = original.clone();
    let pos = text_changed.windows(5).position(|w| w == b"alice").unwrap();
    text_changed[pos] = b'm';
    assert_eq!(
        SignedRecord::decode(&text_changed).unwrap().verify(),
        Err(Error::Signature)
    );
    let mut facets = fixture();
    facets[0].kind = FacetKind::Mention(MentionTarget::Agent(AgentId::from_bytes([3; 32])));
    let mut target_changed = signed(post(
        FacetedText::new(Text::new("@alice #Rust").unwrap(), facets).unwrap(),
    ))
    .encode();
    let n = original.len();
    target_changed[n - 65..n - 1].copy_from_slice(&original[n - 65..n - 1]);
    assert_eq!(
        SignedRecord::decode(&target_changed).unwrap().verify(),
        Err(Error::Signature)
    );
}
#[test]
fn strict_decoder_rejects_noncanonical_keys_counts_spans_and_unsupported_opcode() {
    let original = signed(post(
        FacetedText::new(Text::new("@alice #Rust").unwrap(), fixture()).unwrap(),
    ))
    .encode();
    let size = u32::from_be_bytes(original[..4].try_into().unwrap()) as usize;
    let mut uppercase = original.clone();
    uppercase[4 + size - 4] = b'R';
    assert_eq!(SignedRecord::decode(&uppercase), Err(Error::Encoding));
    let mut count = original.clone();
    count[4 + 146] = 17;
    assert_eq!(SignedRecord::decode(&count), Err(Error::Bounds));
    let mut offset = original.clone();
    offset[4 + 146 + 1] = 255;
    assert_eq!(SignedRecord::decode(&offset), Err(Error::Encoding));
    let mut opcode = original.clone();
    opcode[4 + 128] = 10;
    assert_eq!(SignedRecord::decode(&opcode), Err(Error::Encoding));
    for n in 0..original.len() {
        assert!(SignedRecord::decode(&original[..n]).is_err());
    }
}
#[test]
fn constructor_bounds_sorted_spans_and_unicode_are_fixed() {
    let text = Text::new("💠 @a #Rust").unwrap();
    let valid = vec![
        Facet {
            start: 5,
            end: 7,
            kind: FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([1; 32]))),
        },
        Facet {
            start: 8,
            end: 13,
            kind: FacetKind::Tag(CanonicalTag::new("RUST").unwrap()),
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
    for value in [
        "",
        "-rust",
        "ß",
        "Ｒust",
        "É",
        "E\u{301}",
        "rust\u{202e}",
        "x y",
    ] {
        assert!(CanonicalTag::new(value).is_err());
    }
    assert_eq!(
        CanonicalTag::new("Rust_42-x").unwrap().as_str(),
        "rust_42-x"
    );
}
#[test]
fn distinct_recipient_and_tag_limits_are_checked() {
    let mut text = String::new();
    let mut facets = Vec::new();
    for i in 0..9 {
        let start = text.len() as u16;
        text.push_str("@a ");
        facets.push(Facet {
            start,
            end: start + 2,
            kind: FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([i; 32]))),
        });
    }
    assert_eq!(
        FacetedText::new(Text::new(&text).unwrap(), facets.clone()),
        Err(Error::Bounds)
    );
    for f in &mut facets {
        f.kind = FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([1; 32])));
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
            kind: FacetKind::Tag(CanonicalTag::new(&tag).unwrap()),
        });
    }
    assert_eq!(
        FacetedText::new(Text::new(&text).unwrap(), facets),
        Err(Error::Bounds)
    );
}
#[test]
fn maximum_revision_frame_and_nonempty_supersedes_are_enforced() {
    let mut text = String::new();
    let mut facets = Vec::new();
    for i in 0..8 {
        let start = text.len() as u16;
        text.push_str("@a ");
        facets.push(Facet {
            start,
            end: start + 2,
            kind: FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([i; 32]))),
        });
    }
    for i in 0..8 {
        let tag = format!("{i}{}", "a".repeat(47));
        let start = text.len() as u16;
        text.push_str(&format!("#{tag} "));
        facets.push(Facet {
            start,
            end: text.len() as u16 - 1,
            kind: FacetKind::Tag(CanonicalTag::new(&tag).unwrap()),
        });
    }
    text.push_str(&"x".repeat(MAX_TEXT_BYTES - text.len()));
    let content = FacetedText::new(Text::new(&text).unwrap(), facets).unwrap();
    let operation = Operation::ReviseFaceted {
        post: RecordId::from_bytes([9; 32]),
        content: content.clone(),
        supersedes: References::new((0..16).map(|n| RecordId::from_bytes([n; 32])).collect())
            .unwrap(),
    };
    let record = signed(operation);
    assert_eq!(record.encode().len(), 5570);
    assert!(SignedRecord::decode(&record.encode())
        .unwrap()
        .verify()
        .is_ok());
    assert_eq!(
        UnsignedRecord::new(
            key().verifying_key().to_bytes(),
            body(Operation::ReviseFaceted {
                post: RecordId::from_bytes([9; 32]),
                content,
                supersedes: References::default()
            })
        ),
        Err(Error::Encoding)
    );
}
proptest! {
    #[test] fn arbitrary_utf8_spans_never_panic(text in ".{0,128}",start in any::<u16>(),end in any::<u16>()) {
        let _=FacetedText::new(Text::new(&text).unwrap(),vec![Facet { start,end,kind:FacetKind::Mention(MentionTarget::Owner(OwnerId::from_bytes([0;32]))) }]);
    }
    #[test] fn tag_normalization_idempotent(raw in "[A-Za-z0-9_][A-Za-z0-9_-]{0,47}") { let tag=CanonicalTag::new(&raw).unwrap();prop_assert_eq!(CanonicalTag::new(tag.as_str()).unwrap(),tag); }
    #[test] fn signed_facets_roundtrip(raw in "[A-Za-z0-9_][A-Za-z0-9_-]{0,47}",target in any::<[u8;32]>()) {
        let text=format!("@agent #{raw}");let facets=vec![Facet { start:0,end:6,kind:FacetKind::Mention(MentionTarget::Agent(AgentId::from_bytes(target))) },Facet { start:7,end:text.len() as u16,kind:FacetKind::Tag(CanonicalTag::new(&raw).unwrap()) }];
        let record=signed(post(FacetedText::new(Text::new(&text).unwrap(),facets).unwrap()));let raw=record.encode();
        let verified=SignedRecord::decode(&raw).unwrap().verify().unwrap();
        prop_assert_eq!(verified.body(),record.body());
    }
}

#[test]
fn faceted_revision_matches_independently_assembled_spike_vector() {
    let original = RecordId::from_bytes(
        decode_hex(include_str!("vectors/faceted-post-v1.id"))
            .try_into()
            .unwrap(),
    );
    let operation = Operation::ReviseFaceted {
        post: original,
        content: FacetedText::new(
            Text::new("#Wasm").unwrap(),
            vec![Facet {
                start: 0,
                end: 5,
                kind: FacetKind::Tag(CanonicalTag::new("wasm").unwrap()),
            }],
        )
        .unwrap(),
        supersedes: References::sorted(vec![original]).unwrap(),
    };
    let mut value = body(operation);
    if let Body::Social {
        sequence, previous, ..
    } = &mut value
    {
        *sequence = 1;
        *previous = Some(original);
    }
    let record = UnsignedRecord::new(key().verifying_key().to_bytes(), value)
        .unwrap()
        .sign_with_key(&key())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        record.encode(),
        decode_hex(include_str!("vectors/faceted-revision-v1.hex"))
    );
    assert_eq!(
        record.id().as_bytes().as_slice(),
        decode_hex(include_str!("vectors/faceted-revision-v1.id"))
    );
    assert_eq!(
        SignedRecord::decode(&record.encode())
            .unwrap()
            .verify()
            .unwrap()
            .body(),
        record.body()
    );
}
