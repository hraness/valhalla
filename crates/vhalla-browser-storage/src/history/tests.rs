use super::*;
use crate::{Access, PublishError};
use std::collections::BTreeMap;

fn model_page(
    store: &Store,
    start: u64,
    limit: usize,
    budget: usize,
) -> Result<HistoryPage, Error> {
    page_bounds(start, limit, budget)?;
    let head = HistoryHead::decode(store.head.as_deref().ok_or(Error::Corrupt)?)?;
    let mut page = HistoryPage {
        head,
        records: Vec::new(),
    };
    let mut remaining = budget;
    let mut height = start;
    while height <= head.frontier().height && page.records.len() < limit {
        let raw = store.records.get(&height).ok_or(Error::Corrupt)?;
        if raw.len() > remaining {
            if page.records.is_empty() {
                return Err(Error::Bounds);
            }
            break;
        }
        page.records.push(page_record(&page, height, raw)?);
        remaining -= raw.len();
        if height == head.frontier().height {
            break;
        }
        height = height.checked_add(1).ok_or(Error::Bounds)?;
    }
    Ok(page)
}

#[test]
fn page_reads_bound_work_and_reject_gaps_wrong_heights_and_broken_frontiers() {
    let mut store = Store {
        head: Some(at(3).encode()),
        records: (1..=4)
            .map(|height| (height, record(height).as_bytes().to_vec()))
            .collect(),
    };
    // A retained value beyond the snapshotted head is not part of this read.
    let page = model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES).unwrap();
    assert_eq!(page.records.len(), 3);
    assert_eq!(page.head, at(3));
    assert!(model_page(&store, 4, 16, MAX_HISTORY_PAGE_BYTES)
        .unwrap()
        .records
        .is_empty());
    assert_eq!(
        model_page(&store, 1, 2, MAX_HISTORY_PAGE_BYTES)
            .unwrap()
            .records
            .len(),
        2
    );
    let record_bytes = record(1).as_bytes().len();
    assert_eq!(
        model_page(&store, 1, 16, record_bytes)
            .unwrap()
            .records
            .len(),
        1
    );
    assert!(matches!(
        model_page(&store, 1, 16, record_bytes - 1),
        Err(Error::Bounds)
    ));

    store.records.remove(&2);
    assert!(matches!(
        model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES),
        Err(Error::Corrupt)
    ));
    store.records.insert(2, record(3).as_bytes().to_vec());
    assert!(matches!(
        model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES),
        Err(Error::Corrupt)
    ));
    let mut wrong = at(1).frontier();
    wrong.control[0] ^= 1;
    let wrong_base = HistoryHead::new(scope(), wrong, at(1).bundle_id()).unwrap();
    store.records.insert(
        2,
        HistoryRecord::new(wrong_base, at(2), b"opaque")
            .unwrap()
            .as_bytes()
            .to_vec(),
    );
    assert!(matches!(
        model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES),
        Err(Error::Corrupt)
    ));
    store.records.insert(2, record(2).as_bytes().to_vec());
    let mut wrong_head = at(3).frontier();
    wrong_head.registry[0] ^= 1;
    store.head = Some(
        HistoryHead::new(scope(), wrong_head, at(3).bundle_id())
            .unwrap()
            .encode(),
    );
    assert!(matches!(
        model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES),
        Err(Error::Corrupt)
    ));
    store.head = Some(at(3).encode());
    store.records.get_mut(&3).unwrap().push(0);
    assert!(matches!(
        model_page(&store, 1, 16, MAX_HISTORY_PAGE_BYTES),
        Err(Error::Corrupt)
    ));
}

fn scope() -> HistoryScope {
    HistoryScope::new([1; 32], [2; 32])
}
fn at(height: u64) -> HistoryHead {
    HistoryHead::new(
        scope(),
        HistoryFrontier {
            height,
            value: [height as u8; 32],
            registry: [3; 32],
            social: [4; 32],
            control: [5; 32],
            time: height,
        },
        if height == 0 {
            [0; 32]
        } else {
            [height as u8; 32]
        },
    )
    .unwrap()
}
fn record(height: u64) -> HistoryRecord {
    HistoryRecord::new(at(height - 1), at(height), b"opaque certified bundle").unwrap()
}

#[test]
fn canonical_metadata_keeps_full_height_scope_and_every_frontier_field() {
    for height in [0, 1, (1 << 53) + 1, u64::MAX] {
        let head = at(height);
        assert_eq!(HistoryHead::decode(&head.encode()).unwrap(), head);
        assert!(record_key(scope(), height).ends_with(&format!("{height:016x}")));
    }
    let record = record(1);
    assert_eq!(HistoryRecord::decode(record.as_bytes()).unwrap(), record);
    assert_eq!(record.bundle_bytes(), b"opaque certified bundle");
    let other = HistoryScope::new([1; 32], [9; 32]);
    assert_ne!(prefix(scope()), prefix(other));
    let foreign = HistoryHead::new(other, at(1).frontier(), [1; 32]).unwrap();
    assert_eq!(
        HistoryRecord::new(at(0), foreign, b"x"),
        Err(Error::WrongScope)
    );
    assert_eq!(HistoryRecord::new(at(0), at(2), b"x"), Err(Error::Corrupt));
    assert_eq!(
        HistoryRecord::new(at(u64::MAX), at(0), b"x"),
        Err(Error::Corrupt)
    );

    // Structural storage parsing intentionally confers no signature authority.
    // A controller must replay even well-framed bytes instead of trusting labels.
    let mut opaque_tamper = record.as_bytes().to_vec();
    *opaque_tamper.last_mut().unwrap() ^= 1;
    assert_ne!(
        HistoryRecord::decode(&opaque_tamper)
            .unwrap()
            .bundle_bytes(),
        record.bundle_bytes()
    );
}

#[test]
fn malformed_frames_and_operation_budgets_fail_before_retaining_bytes() {
    let encoded = record(1).as_bytes().to_vec();
    for end in 0..encoded.len() {
        assert!(HistoryRecord::decode(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(HistoryRecord::decode(&trailing), Err(Error::Corrupt));
    let mut version = encoded.clone();
    version[7] ^= 1;
    assert_eq!(HistoryRecord::decode(&version), Err(Error::Corrupt));
    let mut length = encoded;
    length[RECORD_HEADER_BYTES - 4..RECORD_HEADER_BYTES].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(HistoryRecord::decode(&length), Err(Error::Corrupt));
    assert_eq!(HistoryRecord::new(at(0), at(1), &[]), Err(Error::Bounds));
    assert_eq!(
        HistoryRecord::new(at(0), at(1), &vec![0; MAX_HISTORY_BUNDLE_BYTES + 1]),
        Err(Error::Bounds)
    );
    assert!(page_bounds(1, 16, MAX_HISTORY_PAGE_BYTES).is_ok());
    for (start, count, bytes) in [
        (0, 1, 1),
        (1, 0, 1),
        (1, 17, 1),
        (1, 1, 0),
        (1, 1, MAX_HISTORY_PAGE_BYTES + 1),
    ] {
        assert_eq!(page_bounds(start, count, bytes), Err(Error::Bounds));
    }
}

// Event/outcome model: shares production exact-CAS and availability predicates.
// It does not emulate IndexedDB or substitute for real browser transaction QA.
#[derive(Clone, Copy)]
enum Completion {
    Complete,
    Abort,
    CancelBefore,
    CancelAfter,
}
struct Store {
    head: Option<Vec<u8>>,
    records: BTreeMap<u64, Vec<u8>>,
}
fn publish(
    store: &mut Store,
    access: &mut Access,
    base: &HistoryHead,
    record: &HistoryRecord,
    completion: Completion,
) -> Option<Result<(), PublishError>> {
    if let Err(error) = access.begin() {
        return Some(Err(PublishError::Rejected(error)));
    }
    if let Err(error) = append_check(scope(), store.head.as_deref(), base, record) {
        *access = Access::NeedsReopen;
        return Some(Err(PublishError::ReopenRequired(error)));
    }
    if store.records.contains_key(&record.head().frontier().height) {
        *access = Access::NeedsReopen;
        return Some(Err(PublishError::ReopenRequired(Error::Storage)));
    }
    if matches!(completion, Completion::Abort) {
        *access = Access::NeedsReopen;
        return Some(Err(PublishError::ReopenRequired(Error::Storage)));
    }
    if matches!(completion, Completion::CancelBefore) {
        return None;
    }
    // A modeled atomic IDB commit publishes both or neither.
    store
        .records
        .insert(record.head().frontier().height, record.as_bytes().to_vec());
    store.head = Some(record.head().encode());
    if matches!(completion, Completion::CancelAfter) {
        return None;
    }
    Some(access.completed().map_err(PublishError::ReopenRequired))
}

#[test]
fn immutable_append_head_cas_and_uncertain_outcomes_preserve_committed_pairs() {
    for completion in [
        Completion::Complete,
        Completion::Abort,
        Completion::CancelBefore,
        Completion::CancelAfter,
    ] {
        let mut store = Store {
            head: Some(at(0).encode()),
            records: BTreeMap::new(),
        };
        let mut access = Access::Ready;
        let outcome = publish(&mut store, &mut access, &at(0), &record(1), completion);
        let published = matches!(completion, Completion::Complete | Completion::CancelAfter);
        assert_eq!(store.records.contains_key(&1), published);
        assert_eq!(store.head, Some(at(u64::from(published)).encode()));
        if matches!(completion, Completion::Complete) {
            assert_eq!(outcome, Some(Ok(())));
            // A competing tab still using genesis cannot overwrite the winner.
            let mut stale_tab = Access::Ready;
            assert_eq!(
                publish(
                    &mut store,
                    &mut stale_tab,
                    &at(0),
                    &record(1),
                    Completion::Complete
                ),
                Some(Err(PublishError::ReopenRequired(Error::Stale)))
            );
        } else {
            assert_ne!(outcome, Some(Ok(())));
            assert_eq!(access.ready(), Err(Error::NeedsReopen));
        }
    }
    // Orphan records must not be overwritten, even if the head was tampered back.
    let mut store = Store {
        head: Some(at(0).encode()),
        records: BTreeMap::from([(1, b"preserved conflicting record".to_vec())]),
    };
    assert!(publish(
        &mut store,
        &mut Access::Ready,
        &at(0),
        &record(1),
        Completion::Complete
    )
    .unwrap()
    .is_err());
    assert_eq!(store.records[&1], b"preserved conflicting record");
    assert_eq!(store.head, Some(at(0).encode()));
}

#[test]
fn append_history_extends_beyond_image_record_limit_without_rewriting_old_bytes() {
    let mut store = Store {
        head: Some(at(0).encode()),
        records: BTreeMap::new(),
    };
    let mut access = Access::Ready;
    for height in 1..=4097 {
        assert_eq!(
            publish(
                &mut store,
                &mut access,
                &at(height - 1),
                &record(height),
                Completion::Complete
            ),
            Some(Ok(()))
        );
    }
    assert_eq!(store.records.len(), 4097);
    assert_eq!(store.records[&1], record(1).as_bytes());
    assert_eq!(
        HistoryHead::decode(store.head.as_ref().unwrap()).unwrap(),
        at(4097)
    );
}
