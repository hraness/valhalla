use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_HOME: AtomicU64 = AtomicU64::new(0);

fn home() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = NEXT_HOME.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("vaal-test-{}-{nanos:x}-{n}", std::process::id()))
}

fn author(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn steady_state_append_is_two_barriers() {
    let dir = home();
    let mut store = Store::create(&dir).unwrap();
    let base = store.sync_count();
    for sequence in 1..=8 {
        store.append(author(1), sequence, b"payload").unwrap();
    }
    assert_eq!(store.sync_count() - base, 16, "two F_FULLFSYNC per append");
    drop(store);
    let mut store = Store::open(&dir).unwrap();
    assert!(!store.recovery_required());
    assert_eq!(store.head().count, 8);
    let page = store.read_page(0, MAX_PAGE).unwrap();
    assert_eq!(page.len(), 8);
    assert_eq!(page[7].sequence, 8);
    // Exact retry reconciles without another intent.
    let retried = store.append(author(1), 8, b"payload").unwrap();
    assert_eq!(retried.ordinal, 8);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retained_intent_completes_once_and_exact_retry_is_idempotent() {
    let dir = home();
    {
        let mut store = Store::create(&dir).unwrap();
        store.fault(Step::HeadSlotWritten);
        assert!(matches!(
            store.append(author(1), 1, b"kept"),
            Err(Error::Injected)
        ));
    }
    // The slot pwrite happened before the fault step, so the head may already
    // be durable; corrupt it to model the unsynced write being lost.
    let head_path = dir.join(HEAD_FILE);
    let mut raw = fs::read(&head_path).unwrap();
    raw[SLOT_BYTES] ^= 0xFF; // generation-1 slot
    raw[SLOT_BYTES + SLOT_HASH_AT] ^= 0xFF;
    fs::write(&head_path, &raw).unwrap();
    {
        let mut store = Store::open(&dir).unwrap();
        assert!(store.recovery_required());
        assert_eq!(store.head().count, 0);
        let recovered = store.recover().unwrap().unwrap();
        assert_eq!(recovered.ordinal, 1);
        assert!(!store.recovery_required());
        assert_eq!(store.recover().unwrap(), None);
        let retried = store.append(author(1), 1, b"kept").unwrap();
        assert_eq!(retried.ordinal, 1);
        assert_eq!(store.head().count, 1);
    }
    let store = Store::open(&dir).unwrap();
    assert_eq!(store.head().count, 1);
    assert_eq!(store.read_page(0, 64).unwrap()[0].payload, b"kept");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn different_intent_is_refused_and_preserved() {
    let dir = home();
    {
        let mut store = Store::create(&dir).unwrap();
        store.fault(Step::IndexWritten);
        assert!(matches!(
            store.append(author(1), 1, b"old intent"),
            Err(Error::Injected)
        ));
        // A different admission while the intent is retained refuses.
        assert!(matches!(
            store.append(author(1), 1, b"replacement"),
            Err(Error::RecoveryRequired)
        ));
    }
    let mut store = Store::open(&dir).unwrap();
    let recovered = store.recover().unwrap().unwrap();
    assert_eq!(recovered.payload, b"old intent");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn torn_tail_is_retained_then_discarded_by_explicit_recovery() {
    let dir = home();
    let mut store = Store::create(&dir).unwrap();
    store.append(author(1), 1, b"committed").unwrap();
    drop(store);
    // Simulate a crash mid-entry-write: half a frame appended after the head.
    let mut partial = encode_frame(2, author(1), 2, Head::default(), 300, b"partial");
    partial.truncate(partial.len() / 2);
    OpenOptions::new()
        .append(true)
        .open(dir.join(LOG_FILE))
        .unwrap()
        .write_all(&partial)
        .unwrap();
    {
        let mut store = Store::open(&dir).unwrap();
        assert!(store.recovery_required());
        assert!(matches!(
            store.append(author(1), 2, b"replacement"),
            Err(Error::RecoveryRequired)
        ));
        assert!(matches!(
            store.read_page(0, 1),
            Err(Error::RecoveryRequired)
        ));
        assert!(store.recover().unwrap().is_none());
        assert!(!store.recovery_required());
        assert_eq!(store.head().count, 1);
        store.append(author(1), 2, b"replacement").unwrap();
        assert_eq!(store.head().count, 2);
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn torn_live_slot_falls_back_to_previous_complete_head() {
    let dir = home();
    {
        let mut store = Store::create(&dir).unwrap();
        for sequence in 1..=3 {
            store.append(author(1), sequence, b"x").unwrap();
        }
    }
    // Corrupt the newest slot (generation 3 lives in slot 1); open must
    // serve generation 2 from slot 0 and expose the lost entry as intent.
    let path = dir.join(HEAD_FILE);
    let mut raw = fs::read(&path).unwrap();
    for byte in raw.iter_mut().skip(SLOT_BYTES).take(SLOT_HASH_AT) {
        *byte ^= 0x5A;
    }
    fs::write(&path, &raw).unwrap();
    let mut store = Store::open(&dir).unwrap();
    assert_eq!(store.head().generation, 2);
    assert_eq!(store.head().count, 2);
    assert!(store.recovery_required());
    let recovered = store.recover().unwrap().unwrap();
    assert_eq!(recovered.ordinal, 3);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn both_slots_lost_fall_back_to_genesis_and_intents_recomplete() {
    let dir = home();
    let mut store = Store::create(&dir).unwrap();
    store.append(author(1), 1, b"x").unwrap();
    drop(store);
    fs::write(dir.join(HEAD_FILE), [0xAB; 2 * SLOT_BYTES]).unwrap();
    // No valid slot: genesis is the only fallback, and genesis can never
    // contradict committed state — the committed entry re-presents as a
    // retained intent and completes idempotently. Nothing is rewritten.
    let mut store = Store::open(&dir).unwrap();
    assert_eq!(store.head().count, 0);
    assert!(store.recovery_required());
    let recovered = store.recover().unwrap().unwrap();
    assert_eq!(recovered.ordinal, 1);
    assert_eq!(store.head().count, 1);
    assert_eq!(store.read_page(0, 1).unwrap()[0].payload, b"x");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn foreign_format_marker_is_refused() {
    let dir = home();
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(FORMAT_FILE), b"VRW2\0\0\0\0").unwrap();
    File::create(dir.join(LOCK_FILE)).unwrap();
    File::create(dir.join(LOG_FILE)).unwrap();
    File::create(dir.join(INDEX_FILE)).unwrap();
    File::create(dir.join(HEAD_FILE))
        .unwrap()
        .set_len(2 * SLOT_BYTES as u64)
        .unwrap();
    assert!(matches!(Store::open(&dir), Err(Error::ForeignFormat)));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn sequence_gaps_and_dedup_and_page_bounds_hold() {
    let dir = home();
    let mut store = Store::create(&dir).unwrap();
    store.append(author(1), 1, b"a").unwrap();
    store.append(author(2), 1, b"b").unwrap();
    assert!(matches!(
        store.append(author(1), 3, b"gap"),
        Err(Error::Gap)
    ));
    store.append(author(1), 2, b"a2").unwrap();
    let page = store.read_page(1, 2).unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].author, author(2));
    assert!(matches!(store.read_page(0, 65), Err(Error::Capacity)));
    fs::remove_dir_all(&dir).unwrap();
}
