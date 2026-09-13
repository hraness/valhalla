use proptest::prelude::*;
use std::collections::BTreeSet;
use vhalla_social_discovery_spike::*;

fn id(n: usize) -> Id {
    let mut id = [0; 32];
    id[24..].copy_from_slice(&(n as u64).to_be_bytes());
    id
}
fn doc(text: &str, i: usize) -> Document<'_> {
    Document {
        id: id(i),
        revision: id(i),
        owner: id(i % 3),
        agent: Some(id(i % 5)),
        channel: Some((i % 4) as u32),
        root: id(i % 7),
        text,
        tags: &["rust"],
        mentions: &[],
        first_observed: (i % 4) as u64,
        committed: i.is_multiple_of(2),
    }
}

#[test]
fn parser_and_utf8_contract() {
    assert_eq!(
        Query::parse("rust \"proof  budget\" café").unwrap().terms(),
        &["rust", "proof  budget", "café"]
    );
    for q in ["\"missing", "\"\"", "x\"y", "\"x\"y", "x\\y"] {
        assert!(Query::parse(q).is_err());
    }
    let docs = [doc("Rust proof  budget café CAFÉ cafe\u{301}", 0)];
    for (q, expected) in [
        ("rust", 1),
        ("\"proof budget\"", 0),
        ("\"proof  budget\"", 1),
        ("café", 1),
        ("CafÉ", 1),
        ("CAFé", 1),
        ("cafÈ", 0),
    ] {
        assert_eq!(
            scan(
                &docs,
                &Query::parse(q).unwrap(),
                Filter::default(),
                Budget::standard(),
                64
            )
            .unwrap()
            .matches,
            expected
        );
    }
    let docs = [doc("café", 0)];
    assert_eq!(
        scan(
            &docs,
            &Query::parse("CAFÉ").unwrap(),
            Filter::default(),
            Budget::standard(),
            64
        )
        .unwrap()
        .matches,
        0
    );
    assert_eq!(
        scan(
            &docs,
            &Query::parse("cafe\u{301}").unwrap(),
            Filter::default(),
            Budget::standard(),
            64
        )
        .unwrap()
        .matches,
        0
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]
    #[test]
    fn index_scan_and_independent_oracle_agree(texts in prop::collection::vec("[a-zA-Z éΩ!?_-]{0,120}", 0..50), terms in prop::collection::vec("[a-zA-ZéΩ!?_-]{1,8}", 0..5), owner in prop::option::of(0usize..4), committed in any::<bool>()) {
        let docs: Vec<_> = texts.iter().enumerate().map(|(i,s)| doc(s,i)).collect();
        let query = Query::parse(&terms.join(" ")).unwrap();
        let filter = Filter { owner: owner.map(id), committed_only: committed, ..Filter::default() };
        let mut expected: Vec<_> = docs.iter().filter(|d| owner.is_none_or(|o| id(o) == d.owner) && (!committed || d.committed))
            .filter(|d| terms.iter().all(|term| d.text.to_ascii_lowercase().contains(&term.to_ascii_lowercase())))
            .map(|d| (std::cmp::Reverse(d.first_observed), d.id, d.revision)).collect();
        expected.sort();
        let scan = scan(&docs, &query, filter, Budget::standard(), 64).unwrap();
        let index = Index::build(&docs, 262144).unwrap();
        let indexed = index.search(&query, filter, Budget::standard(), 64).unwrap();
        prop_assert!(scan.complete && indexed.complete);
        prop_assert_eq!(&scan.hits, &indexed.hits);
        prop_assert_eq!(scan.matches, indexed.matches);
        prop_assert_eq!(scan.hits.iter().map(|h| (std::cmp::Reverse(h.observed),h.id,h.revision)).collect::<Vec<_>>(), expected);
    }
}

#[test]
fn no_match_filter_and_adversarial_prefix_costs_are_bounded() {
    let body = "a".repeat(4096);
    let docs: Vec<_> = (0..100).map(|i| doc(&body, i)).collect();
    for filter in [
        Filter::default(),
        Filter {
            owner: Some(id(100)),
            ..Filter::default()
        },
    ] {
        let out = scan(
            &docs,
            &Query::parse("missing").unwrap(),
            filter,
            Budget {
                documents: 5,
                bytes: 5 * 4096,
                comparisons: 100000,
            },
            64,
        )
        .unwrap();
        assert!(!out.complete);
        assert_eq!(out.matches, 0);
        assert_eq!(out.examined, 5);
    }
    let query = Query::parse(&("a".repeat(95) + "b")).unwrap();
    let out = scan(
        &docs,
        &query,
        Filter::default(),
        Budget {
            documents: 100,
            bytes: 409600,
            comparisons: 1000,
        },
        64,
    )
    .unwrap();
    assert!(!out.complete);
    assert_eq!(out.examined, 1);
    assert_eq!(out.remaining.comparisons, 0);
    assert!(matches!(Index::build(&docs, 20), Err(Error::Budget)));
}

#[test]
fn typed_filters_and_top_k_are_exact_and_not_text_identity() {
    let docs: Vec<_> = (0..200).map(|i| doc("@victim #fake rust", i)).collect();
    let filter = Filter {
        owner: Some(id(1)),
        channel: Some(1),
        tag: Some("rust"),
        committed_only: false,
        ..Filter::default()
    };
    let out = scan(
        &docs,
        &Query::parse("").unwrap(),
        filter,
        Budget::standard(),
        3,
    )
    .unwrap();
    assert_eq!(out.hits.len(), 3);
    assert!(out.matches > 3);
    assert!(out
        .hits
        .windows(2)
        .all(|w| (std::cmp::Reverse(w[0].observed), w[0].id)
            < (std::cmp::Reverse(w[1].observed), w[1].id)));
    assert_eq!(
        scan(
            &docs,
            &Query::parse("").unwrap(),
            Filter {
                mention: Some(Target::Owner(id(9))),
                ..Filter::default()
            },
            Budget::standard(),
            64
        )
        .unwrap()
        .matches,
        0
    );
    assert_eq!(
        scan(
            &docs,
            &Query::parse("").unwrap(),
            Filter {
                tag: Some("fake"),
                ..Filter::default()
            },
            Budget::standard(),
            64
        )
        .unwrap()
        .matches,
        0
    );
}

#[test]
fn pagination_rechecks_live_authority_without_reordering_frozen_freshness() {
    let basis = Basis {
        corpus: id(1),
        reader: id(2),
        preferences: 1,
        observations: 1,
        policy: 1,
        ranking_cutoff: 50,
    };
    let mut cursor = Cursor::new(
        basis,
        String::from("rust"),
        vec![(id(3), id(30)), (id(4), id(40))],
        1,
    )
    .unwrap();
    assert_eq!(
        cursor.page(basis, "rust", 2, 1, |_, _| true).unwrap(),
        &[(id(3), id(30))]
    );
    assert_eq!(
        cursor.page(basis, "rust", 3, 1, |_, now| now < 3),
        Err(Error::Stale)
    );
    assert_eq!(
        cursor.page(basis, "rust", 2, 1, |_, _| true),
        Err(Error::Clock)
    );
    assert_eq!(
        cursor.page(
            Basis {
                preferences: 2,
                ..basis
            },
            "rust",
            4,
            1,
            |_, _| true
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        cursor.page(
            Basis {
                corpus: id(9),
                ..basis
            },
            "rust",
            4,
            1,
            |_, _| true
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        cursor.page(
            Basis {
                reader: id(9),
                ..basis
            },
            "rust",
            4,
            1,
            |_, _| true
        ),
        Err(Error::Stale)
    );
}

#[test]
fn expiry_cannot_hydrate_a_different_revision_of_the_same_visible_post() {
    let basis = Basis {
        corpus: id(1),
        reader: id(2),
        preferences: 1,
        observations: 1,
        policy: 1,
        ranking_cutoff: 50,
    };
    let mut cursor = Cursor::new(basis, String::from("rust"), vec![(id(3), id(30))], 1).unwrap();
    // Original post 3 remains visible, but provisional revision 30 expired and
    // current content falls back to committed revision 3. Exact binding rejects.
    assert_eq!(
        cursor.page(basis, "rust", 3, 1, |(post, revision), _| post == id(3)
            && revision == id(3)),
        Err(Error::Stale)
    );
}

#[test]
fn fresh_eligible_observation_survives_duplicates_seals_and_batch_permutation() {
    let mut a = Observations::default();
    let mut b = Observations::default();
    a.observe_eligible(&[id(2), id(1)]).unwrap();
    b.observe_eligible(&[id(1), id(2)]).unwrap();
    assert_eq!(a.ordinal(id(1)), b.ordinal(id(1)));
    // Pending raw input had no ordinal. Becoming eligible later receives one.
    assert_eq!(a.ordinal(id(3)), None);
    let before = a.ordinal(id(1));
    a.observe_eligible(&[id(1), id(2), id(1), id(3)]).unwrap();
    assert_eq!(a.ordinal(id(1)), before);
    assert!(a.ordinal(id(3)) > a.ordinal(id(2)));
}

fn row(i: usize, owner: usize, root: usize) -> RankInput<'static> {
    RankInput {
        id: id(i),
        revision: id(i),
        owner: id(owner),
        root: id(root),
        followed: false,
        subscribed: false,
        topic_affinity: 0,
        endorsers: &[],
        observed: 50,
        unseen: true,
    }
}

#[test]
fn rank_owner_root_repost_and_sybil_caps_and_reader_private_feedback() {
    let rows: Vec<_> = (0..1000).map(|i| row(i, 1, i)).collect();
    assert_eq!(rank(&rows, &BTreeSet::new(), 50, 64).unwrap().len(), 2);
    let rows: Vec<_> = (0..1000).map(|i| row(i, i, 1)).collect();
    assert_eq!(rank(&rows, &BTreeSet::new(), 50, 64).unwrap().len(), 1);
    let sybils: Vec<_> = (0..1000).map(id).collect();
    let promoted = RankInput {
        endorsers: &sybils,
        ..row(3000, 2000, 3000)
    };
    assert_eq!(
        rank(&[promoted], &BTreeSet::new(), 50, 1).unwrap()[0].why[3],
        0
    );
    assert_eq!(
        rank(&[promoted], &sybils.iter().copied().collect(), 50, 1).unwrap()[0].why[3],
        32
    );
    let rows = [
        RankInput {
            topic_affinity: 4,
            ..row(1, 1, 1)
        },
        RankInput {
            topic_affinity: -4,
            ..row(2, 2, 2)
        },
    ];
    assert_eq!(rank(&rows, &BTreeSet::new(), 50, 2).unwrap()[0].id, id(1));
    let swapped = [
        RankInput {
            topic_affinity: -4,
            ..rows[0]
        },
        RankInput {
            topic_affinity: 4,
            ..rows[1]
        },
    ];
    assert_eq!(
        rank(&swapped, &BTreeSet::new(), 50, 2).unwrap()[0].id,
        id(2)
    );
    let duplicates = vec![rows[0]; 1000];
    assert_eq!(
        rank(&duplicates, &BTreeSet::new(), 50, 64).unwrap(),
        rank(&rows[..1], &BTreeSet::new(), 50, 64).unwrap()
    );
}

#[test]
fn rank_duplicate_routes_merge_independent_of_arrival_order() {
    let endorsers = [id(7), id(8), id(8)];
    let mut rows = vec![
        RankInput {
            followed: true,
            endorsers: &endorsers[..1],
            ..row(1, 1, 1)
        },
        RankInput {
            subscribed: true,
            endorsers: &endorsers[1..],
            ..row(1, 1, 1)
        },
    ];
    let selected = endorsers.into_iter().collect();
    let a = rank(&rows, &selected, 50, 64).unwrap();
    rows.reverse();
    assert_eq!(a, rank(&rows, &selected, 50, 64).unwrap());
    assert_eq!(a[0].why, [128, 64, 0, 16, 15, 8]);
}
