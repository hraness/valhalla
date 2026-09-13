#[path = "../examples/fixture.rs"]
mod fixture;
use vhalla_social::{
    archive::Archive,
    view::{Content, Eligibility, RecordState, Register, View},
    Body, Placement,
};
use vhalla_social_discovery_spike::*;

#[test]
fn signed_archive_admitted_view_supplies_query_corpus() {
    let archive = fixture::archive(64, 256);
    let eligibility = Eligibility::default();
    let view = View::new(&archive, 100, &eligibility);
    let posts = view.posts(None);
    assert_eq!(posts.len(), 62);
    let documents: Vec<_> = posts
        .iter()
        .map(|p| {
            assert_eq!(p.state, RecordState::Committed);
            let Content::Present(Register::Resolved { value, .. }) = &p.committed else {
                panic!("fixture must be committed")
            };
            Document {
                id: *p.id.as_bytes(),
                revision: *value.revision.as_bytes(),
                owner: *p.attribution.owner.as_bytes(),
                agent: None,
                channel: match p.placement {
                    Placement::Channel(room) => Some(room.0 as u32),
                    _ => None,
                },
                root: *p.root.as_bytes(),
                text: value.text,
                tags: &[],
                mentions: &[],
                first_observed: 1,
                committed: true,
            }
        })
        .collect();
    let query = Query::parse("rust \"proof budget\" café").unwrap();
    let filter = Filter {
        channel: Some(1),
        committed_only: true,
        ..Filter::default()
    };
    let scan = scan(&documents, &query, filter, Budget::standard(), 64).unwrap();
    let indexed = Index::build(&documents, 262144)
        .unwrap()
        .search(&query, filter, Budget::standard(), 64)
        .unwrap();
    assert_eq!(scan.hits, indexed.hits);
    assert_eq!(scan.matches, 16);
    assert!(scan.complete);
}

#[test]
fn signed_text_without_owner_closure_never_enters_the_query_corpus() {
    let archive = fixture::archive(64, 256);
    let eligible = Eligibility::default();
    let records: Vec<_> = archive
        .records()
        .filter(|r| !matches!(r.body(), Body::OwnerGenesis { .. }))
        .collect();
    let mut raw = b"VHSA\0\0\0\x01".to_vec();
    raw.extend_from_slice(&fixture::REALM.0.to_be_bytes());
    raw.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        let bytes = record.encode();
        raw.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        raw.extend(bytes);
    }
    let partial = Archive::from_snapshot(fixture::REALM, fixture::limits(), &raw).unwrap();
    assert_eq!(partial.len(), 63);
    let view = View::new(&partial, 100, &eligible);
    assert!(view.posts(None).is_empty());
    assert!(!view.basis().known_history_complete);
}
