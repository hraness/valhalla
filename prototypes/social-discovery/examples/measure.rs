mod fixture;
use std::{hint::black_box, time::Instant};
use vhalla_social::{
    archive::Archive,
    view::{Content, Eligibility, RecordState, Register, View},
    Actor, Placement,
};
use vhalla_social_discovery_spike::*;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let count: usize = args.get(1).map_or(64, |v| v.parse().unwrap());
    let text_bytes: usize = args.get(2).map_or(256, |v| v.parse().unwrap());
    let started = Instant::now();
    let raw = fixture::corpus(count, text_bytes);
    let sign_us = started.elapsed().as_micros();
    let started = Instant::now();
    let archive = Archive::from_snapshot(fixture::REALM, fixture::limits(), &raw).unwrap();
    let restore_us = started.elapsed().as_micros();
    let eligibility = Eligibility::default();
    let started = Instant::now();
    let view = View::new(&archive, 100, &eligibility);
    let posts = view.posts(None);
    let view_us = started.elapsed().as_micros();
    let documents: Vec<_> = posts
        .iter()
        .enumerate()
        .filter_map(|(i, p)| match &p.committed {
            Content::Present(Register::Resolved { value, .. })
                if p.state == RecordState::Committed =>
            {
                Some(Document {
                    id: *p.id.as_bytes(),
                    revision: *value.revision.as_bytes(),
                    owner: *p.attribution.owner.as_bytes(),
                    agent: match p.attribution.actor {
                        Actor::Agent { agent, .. } => Some(*agent.as_bytes()),
                        _ => None,
                    },
                    channel: match p.placement {
                        Placement::Channel(room) => Some(room.0 as u32),
                        _ => None,
                    },
                    root: *p.root.as_bytes(),
                    text: value.text,
                    tags: &[],
                    mentions: &[],
                    first_observed: i as u64,
                    committed: true,
                })
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        documents.len(),
        count / 64 * 62,
        "fixture must actually admit the complete signed corpus"
    );
    let started = Instant::now();
    let index = Index::build(&documents, 4_194_304).unwrap();
    let index_us = started.elapsed().as_micros();
    println!("records={count}, documents={}, text_bytes={}, signed_snapshot_bytes={}, document_payload_bytes={}, post_view_inline_bytes={}, sign_us={sign_us}, restore_us={restore_us}, view_us={view_us}, index_build_us={index_us}, index_entries={}, index_payload_bytes={}", documents.len(), documents.iter().map(|d| d.text.len()).sum::<usize>(), raw.len(), documents.capacity() * std::mem::size_of::<Document<'_>>(), posts.capacity() * std::mem::size_of_val(&posts[0]), index.entries(), index.retained_payload_bytes());
    for query in ["rust \"proof budget\"", "zzzzzzzzz", "owner 13", "é"] {
        let query = Query::parse(query).unwrap();
        let measure_budget = Budget {
            comparisons: 64 * 1024 * 1024,
            ..Budget::standard()
        };
        let standard_complete = scan(
            &documents,
            &query,
            Filter::default(),
            Budget::standard(),
            64,
        )
        .unwrap()
        .complete;
        let started = Instant::now();
        let mut scanned = None;
        for _ in 0..20 {
            scanned = Some(black_box(
                scan(
                    black_box(&documents),
                    &query,
                    Filter::default(),
                    measure_budget,
                    64,
                )
                .unwrap(),
            ));
        }
        let scan_us = started.elapsed().as_micros() / 20;
        let started = Instant::now();
        let mut indexed = None;
        for _ in 0..20 {
            indexed = Some(black_box(
                index
                    .search(&query, Filter::default(), measure_budget, 64)
                    .unwrap(),
            ));
        }
        let index_query_us = started.elapsed().as_micros() / 20;
        let scanned = scanned.unwrap();
        let indexed = indexed.unwrap();
        assert!(scanned.complete && indexed.complete);
        assert_eq!(scanned.hits, indexed.hits);
        assert_eq!(scanned.matches, indexed.matches);
        println!("query={:?}, matches={}, scan_us={scan_us}, index_us={index_query_us}, standard_complete={standard_complete}, scan_comparisons={}, index_comparisons={}", query.terms(), scanned.matches, measure_budget.comparisons - scanned.remaining.comparisons, measure_budget.comparisons - indexed.remaining.comparisons);
    }
}
