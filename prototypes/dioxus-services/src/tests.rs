use super::*;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use vhalla_attention::Attention;
use vhalla_discovery::DiscoveryState;
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    Actor, Body, ControlAction, FacetKind, FacetedText, MentionTarget, Operation, Placement,
    References, SignedRecord, Text, UnsignedRecord, MAX_RECORD_BYTES,
};

fn signed(seed: u8, body: Body) -> SignedRecord {
    let key = SigningKey::from_bytes(&[seed; 32]);
    UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .finish()
        .unwrap()
}
pub(crate) fn fixture(profile: u8) -> Engine {
    let mut archive = Archive::new(vhalla_core::RealmId(51), Limits::default()).unwrap();
    let source = signed(
        1,
        Body::OwnerGenesis {
            controller: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            recovery: None,
            nonce: [1; 32],
        },
    );
    let recipient = signed(
        2,
        Body::OwnerGenesis {
            controller: SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            recovery: None,
            nonce: [2; 32],
        },
    );
    let owner = OwnerId::from_bytes(*recipient.id().as_bytes());
    let source_owner = OwnerId::from_bytes(*source.id().as_bytes());
    let mut records = vec![source.clone(), recipient];
    let mut previous = None;
    for sequence in 0..3 {
        let record = signed(
            1,
            Body::Social {
                actor: Actor::Owner {
                    owner: source_owner,
                    control: source.id(),
                },
                realm: archive.realm(),
                sequence,
                previous,
                operation: Operation::PostFaceted {
                    placement: Placement::Profile,
                    content: FacetedText::new(
                        Text::new(&format!("@reader hostile <script> {sequence}")).unwrap(),
                        vec![Facet {
                            start: 0,
                            end: 7,
                            kind: FacetKind::Mention(MentionTarget::Owner(owner)),
                        }],
                    )
                    .unwrap(),
                    reply: None,
                    quote: None,
                },
            },
        );
        previous = Some(record.id());
        records.push(record);
    }
    records.push(signed(
        1,
        Body::Control {
            owner: source_owner,
            previous: source.id(),
            action: ControlAction::Seal {
                realm: archive.realm(),
                heads: References::sorted(vec![previous.unwrap()]).unwrap(),
            },
        },
    ));
    for record in records {
        archive
            .ingest(
                &record.encode(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
    }
    let scope = ReaderScope::new(&archive, 10, owner, None, [profile; 32], [0; 32]).unwrap();
    Engine::new(
        archive,
        scope,
        Attention::new(scope),
        DiscoveryState::new(scope.digest()),
    )
    .unwrap()
}

#[test]
fn projection_is_inert_exact_and_reading_never_mutates_private_state() {
    let mut engine = fixture(1);
    let before = engine.image().encode();
    let page = engine
        .project(Screen::Search(Query::parse("hostile").unwrap()), 10)
        .unwrap();
    assert_eq!(page.posts.len(), 3);
    assert!(page.posts.iter().all(|p| p.text.contains("<script>")
        && p.state == RecordState::Committed
        && p.facets.len() == 1
        && p.evidence.original.owner == p.owner
        && p.evidence.revision_signer.owner == p.owner
        && p.evidence.position == RevisionPosition::Current
        && matches!(p.evidence.current, CurrentRevisions::Resolved(_))
        && p.evidence.revision_state == RecordState::Committed));
    assert_eq!(page.basis.archive_root, engine.image().archive.root());
    assert_eq!(page.post_matches, 3);
    assert_eq!(engine.image().encode(), before);
    assert_eq!(page.persistence, Persistence::Ephemeral);
}

#[test]
fn typed_search_filter_is_reapplied_to_verified_source_attribution() {
    let mut engine = fixture(1);
    let query = Query::parse("hostile").unwrap();
    let source = engine
        .project(Screen::Search(query.clone()), 10)
        .unwrap()
        .posts[0]
        .owner;
    let selected = engine
        .project(
            Screen::FilteredSearch {
                query: query.clone(),
                filters: Filters {
                    owner: Some(source),
                    ..Filters::default()
                },
            },
            10,
        )
        .unwrap();
    assert_eq!(selected.posts.len(), 3);
    let excluded = engine
        .project(
            Screen::FilteredSearch {
                query,
                filters: Filters {
                    owner: Some(engine.reader().owner()),
                    ..Filters::default()
                },
            },
            10,
        )
        .unwrap();
    assert!(excluded.posts.is_empty());
    assert!(excluded.coverage.query_complete);
}
#[test]
fn failed_transaction_preserves_memory_and_disk_then_restart_reads_exact_marks() {
    let mut engine = fixture(1);
    let mut disk = MemoryStorage::new(&engine.image());
    let page = engine.project(Screen::Inbox, 10).unwrap();
    let before = disk.bytes().to_vec();
    let intent = Intent::acknowledge(page.receipt, vec![page.notifications[0].id]).unwrap();
    assert_eq!(
        disk.submit(&mut engine, intent.clone(), 10, true)
            .unwrap_err(),
        Error::Storage
    );
    assert_eq!(disk.bytes(), before);
    assert_eq!(engine.image().encode(), before);
    let saved = disk.submit(&mut engine, intent, 10, false).unwrap();
    assert_eq!(
        saved
            .notifications
            .iter()
            .filter(|n| n.read == ReadState::Read)
            .count(),
        1
    );
    let mut reopened = Engine::from_image(
        disk.reopen(engine.reader(), Limits::default()).unwrap(),
        Persistence::Ephemeral,
    )
    .unwrap();
    let next = reopened.project(Screen::Inbox, 10).unwrap();
    assert_eq!(
        next.notifications
            .iter()
            .filter(|n| n.read == ReadState::Read)
            .count(),
        1
    );
}
#[test]
fn stale_and_foreign_receipts_never_acknowledge_siblings_or_new_pages() {
    let mut one = fixture(1);
    let mut two = fixture(2);
    let page = one.project(Screen::Inbox, 10).unwrap();
    two.project(Screen::Inbox, 10).unwrap();
    let intent = Intent::acknowledge(page.receipt, vec![page.notifications[0].id]).unwrap();
    assert_eq!(
        two.apply_ephemeral(intent.clone(), 10).unwrap_err(),
        Error::Stale
    );
    one.project(Screen::Inbox, 10).unwrap();
    assert_eq!(one.apply_ephemeral(intent, 10).unwrap_err(), Error::Stale);
    assert!(Image::decode(&one.image().encode(), two.reader(), Limits::default()).is_err());
}
#[test]
fn concurrent_tabs_compare_exact_source_and_private_image_before_publication() {
    let mut a = fixture(1);
    let mut b = fixture(1);
    let mut disk = MemoryStorage::new(&a.image());
    let pa = a.project(Screen::Inbox, 10).unwrap();
    let pb = b.project(Screen::Inbox, 10).unwrap();
    disk.submit(
        &mut a,
        Intent::acknowledge(pa.receipt, vec![pa.notifications[0].id]).unwrap(),
        10,
        false,
    )
    .unwrap();
    assert_eq!(
        disk.submit(
            &mut b,
            Intent::acknowledge(pb.receipt, vec![pb.notifications[1].id]).unwrap(),
            10,
            false
        )
        .unwrap_err(),
        Error::Stale
    );
}
#[test]
fn missing_source_and_mutated_image_never_become_a_new_saved_claim() {
    let engine = fixture(1);
    let mut raw = engine.image().encode();
    let offset = raw.len() / 2;
    raw[offset] ^= 1;
    assert!(Image::decode(&raw, engine.reader(), Limits::default()).is_err());
    let mut engine = engine;
    let page = engine
        .project(Screen::Search(Query::parse("hostile").unwrap()), 10)
        .unwrap();
    let fake = PostRef {
        post: RecordId::from_bytes([0; 32]),
        revision: RecordId::from_bytes([0; 32]),
    };
    assert_eq!(
        engine
            .apply_ephemeral(Intent::seen(page.receipt, fake), 10)
            .unwrap_err(),
        Error::Stale
    );
    let mut bad = engine.image();
    bad.archive = Archive::new(bad.scope.realm(), Limits::default()).unwrap();
    assert_eq!(bad.validate_delta(&engine.image()), Err(Error::Stale));
}

#[test]
fn hostile_declared_source_count_is_rejected_before_record_verification() {
    use sha2::{Digest, Sha256};
    let engine = fixture(1);
    let mut raw = engine.image().encode();
    // Image prefix40 + part length4 + snapshot count offset24.
    raw[68..72].copy_from_slice(&129u32.to_be_bytes());
    let checksum_at = raw.len() - 32;
    let mut hash = Sha256::new();
    hash.update(b"vhalla/ui/storage-spike/v1\0");
    hash.update(&raw[..checksum_at]);
    raw[checksum_at..].copy_from_slice(&hash.finalize());
    assert!(matches!(
        Image::decode(&raw, engine.reader(), Limits::default()),
        Err(Error::Bounds)
    ));
}
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn arbitrary_exact_ack_subsets_only_change_the_named_items(mask in 1u8..8) {
        let mut engine=fixture(1);let page=engine.project(Screen::Inbox,10).unwrap();
        let ids:Vec<_>=page.notifications.iter().enumerate().filter(|(i,_)| mask & (1<<i)!=0).map(|(_,n)|n.id).collect();
        let result=engine.apply_ephemeral(Intent::acknowledge(page.receipt,ids.clone()).unwrap(),10).unwrap();
        for n in result.notifications {prop_assert_eq!(n.read==ReadState::Read,ids.contains(&n.id));}
    }
    #[test]
    fn arbitrary_corrupt_images_fail_closed(bytes in prop::collection::vec(any::<u8>(),0..4096)) {
        let engine=fixture(1);prop_assert!(Image::decode(&bytes,engine.reader(),Limits::default()).is_err());
    }
}
