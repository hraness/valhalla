use super::*;
use crate::{BundleParts, FsStore, GENESIS_NEXT};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Trace {
    pin_reads: usize,
    marker_reads: Vec<u64>,
    bundle_reads: usize,
}

struct ReadOnlyStore {
    pin: Option<Vec<u8>>,
    subsequent_pin: Option<Vec<u8>>,
    markers: BTreeMap<u64, [u8; 32]>,
    bundles: BTreeMap<[u8; 32], Vec<u8>>,
    trace: RefCell<Trace>,
}

macro_rules! forbidden_methods {
    () => {
        fn lock(&self, _: &Path, _: bool) -> Result<File, JournalError> {
            panic!("reader acquired writer lock")
        }
        fn read_pin_tmp(&self, _: &Path) -> Result<Option<Vec<u8>>, JournalError> {
            panic!("reader inspected unpublished temp")
        }
        fn remove_pin_tmp(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader removed temp")
        }
        fn create_bundle(&self, _: &Path, _: [u8; 32], _: &[u8]) -> Result<bool, JournalError> {
            panic!("reader created bundle")
        }
        fn sync_bundle(&self, _: &Path, _: [u8; 32]) -> Result<(), JournalError> {
            panic!("reader synced bundle")
        }
        fn sync_bundles_dir(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader synced bundle directory")
        }
        fn list_bundles(&self, _: &Path) -> Result<Vec<[u8; 32]>, JournalError> {
            panic!("reader enumerated bundles/orphans")
        }
        fn write_height_marker(&self, _: &Path, _: u64, _: [u8; 32]) -> Result<(), JournalError> {
            panic!("reader wrote marker")
        }
        fn sync_height_marker(&self, _: &Path, _: u64) -> Result<(), JournalError> {
            panic!("reader synced marker")
        }
        fn sync_heights_dir(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader synced marker directory")
        }
        fn list_height_markers(&self, _: &Path) -> Result<Vec<u64>, JournalError> {
            panic!("reader enumerated heights")
        }
        fn remove_height_marker(&self, _: &Path, _: u64) -> Result<(), JournalError> {
            panic!("reader removed marker")
        }
        fn write_pin_tmp(&self, _: &Path, _: &[u8]) -> Result<(), JournalError> {
            panic!("reader wrote temp")
        }
        fn sync_pin_tmp(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader synced temp")
        }
        fn rename_pin(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader published HEAD")
        }
        fn sync_dir(&self, _: &Path) -> Result<(), JournalError> {
            panic!("reader synced directory")
        }
    };
}

impl Store for ReadOnlyStore {
    forbidden_methods!();

    fn read_pin(&self, _: &Path) -> Result<Option<Vec<u8>>, JournalError> {
        let mut trace = self.trace.borrow_mut();
        trace.pin_reads += 1;
        if trace.pin_reads > 1 && self.subsequent_pin.is_some() {
            return Ok(self.subsequent_pin.clone());
        }
        Ok(self.pin.clone())
    }
    fn read_bundle(&self, _: &Path, id: [u8; 32]) -> Result<Vec<u8>, JournalError> {
        self.trace.borrow_mut().bundle_reads += 1;
        self.bundles
            .get(&id)
            .cloned()
            .ok_or_else(|| JournalError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)))
    }
    fn read_height_marker(&self, _: &Path, height: u64) -> Result<Option<[u8; 32]>, JournalError> {
        self.trace.borrow_mut().marker_reads.push(height);
        Ok(self.markers.get(&height).copied())
    }
}

fn frontier(height: u64) -> [u8; 32] {
    let mut raw = [0x44; 32];
    raw[..8].copy_from_slice(&height.to_be_bytes());
    raw
}

fn bundle(predecessor: [u8; 32], height: u64, payload: usize) -> Bundle {
    Bundle::new(BundleParts {
        certificate: b"opaque-certificate".to_vec(),
        predecessor,
        next: frontier(height),
        batch: vec![0x51; payload],
        value: height.to_be_bytes().to_vec(),
        configuration: b"configuration".to_vec(),
        control_record: b"control".to_vec(),
        debit_marker: b"debit".to_vec(),
        height,
    })
    .unwrap()
}

fn pin(bundle: &Bundle) -> Pin {
    Pin {
        predecessor: bundle.predecessor(),
        next: bundle.next(),
        bundle: bundle.id(),
        height: bundle.height(),
    }
}

fn chain(count: u64) -> ReadOnlyStore {
    let mut store = ReadOnlyStore {
        pin: None,
        subsequent_pin: None,
        markers: BTreeMap::new(),
        bundles: BTreeMap::new(),
        trace: RefCell::new(Trace::default()),
    };
    let mut previous = GENESIS_NEXT;
    for height in 1..=count {
        let bundle = bundle(previous, height, 8);
        previous = bundle.next();
        store.markers.insert(height, bundle.id());
        store.bundles.insert(bundle.id(), bundle.bytes().to_vec());
        store.pin = Some(pin(&bundle).encode());
    }
    store
}

fn request(after_height: u64) -> PublishedRange {
    PublishedRange {
        after_height,
        expected_predecessor: None,
        max_bundles: MAX_PUBLISHED_PAGE_BUNDLES,
        max_bytes: MAX_PUBLISHED_PAGE_BYTES,
    }
}

fn journal(store: ReadOnlyStore) -> Journal<ReadOnlyStore> {
    Journal::new("unused-no-filesystem", store)
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-published-read-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn publish_fixture(&self, store: &ReadOnlyStore) {
        fs::create_dir_all(self.0.join(crate::BUNDLES)).unwrap();
        fs::create_dir_all(self.0.join(crate::HEIGHTS)).unwrap();
        for (id, bytes) in &store.bundles {
            fs::write(FsStore::bundle_path(&self.0, *id), bytes).unwrap();
        }
        for (height, id) in &store.markers {
            fs::write(FsStore::height_path(&self.0, *height), id).unwrap();
        }
        if let Some(bytes) = &store.pin {
            fs::write(self.0.join(crate::HEAD_FILE), bytes).unwrap();
        }
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn unpublished_markers_bundles_and_temp_stay_invisible_and_untouched() {
    let temp = Temp::new();
    let mut store = chain(2);
    let first = Bundle::decode(&store.bundles[&store.markers[&1]]).unwrap();
    let future = store.pin.take().unwrap();
    store.pin = Some(pin(&first).encode());
    temp.publish_fixture(&store);
    fs::write(temp.0.join(crate::HEAD_TMP), &future).unwrap();
    let page = Journal::new(&temp.0, FsStore)
        .read_published_range(request(0))
        .unwrap();
    assert_eq!(page.observed_head().height, 1);
    assert_eq!(page.bundles().len(), 1);
    assert_eq!(page.next_after(), 1);
    assert!(!page.has_more());
    assert_eq!(fs::read(temp.0.join(crate::HEAD_TMP)).unwrap(), future);
    assert!(FsStore::height_path(&temp.0, 2).exists());
    assert!(FsStore::bundle_path(&temp.0, store.markers[&2]).exists());
    assert!(!temp.0.join(crate::LOCK_FILE).exists());

    fs::remove_file(temp.0.join(crate::HEAD_FILE)).unwrap();
    let empty = Journal::new(&temp.0, FsStore)
        .read_published_range(request(0))
        .unwrap();
    assert_eq!(empty.observed_head().height, 0);
    assert!(empty.bundles().is_empty());
    assert!(temp.0.join(crate::HEAD_TMP).exists());
    assert!(FsStore::height_path(&temp.0, 1).exists());
}

#[test]
fn reading_absent_journal_does_not_create_a_directory() {
    let temp = Temp::new();
    let absent = temp.0.join("absent");
    let page = Journal::new(&absent, FsStore)
        .read_published_range(request(0))
        .unwrap();
    assert_eq!(page.next_after(), 0);
    assert_eq!(page.bytes(), 0);
    assert!(!absent.exists());
}

#[test]
fn one_head_snapshot_and_no_enumeration_or_mutating_store_calls() {
    let mut store = chain(3);
    let second = Bundle::decode(&store.bundles[&store.markers[&2]]).unwrap();
    store.subsequent_pin = store.pin.take();
    store.pin = Some(pin(&second).encode());
    let reader = journal(store);
    let page = reader.read_published_range(request(0)).unwrap();
    assert_eq!(page.observed_head().height, 2);
    assert_eq!(
        page.bundles()
            .iter()
            .map(Bundle::height)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let trace = reader.store.trace.borrow();
    assert_eq!(trace.pin_reads, 1);
    assert!(!trace.marker_reads.contains(&3));
    assert_eq!(trace.bundle_reads, 2); // cached tip reused, no second tip read
}

#[test]
fn head_tip_id_height_predecessor_and_next_must_all_agree() {
    for field in 0..5 {
        let mut store = chain(2);
        let mut head = Pin::decode(store.pin.as_ref().unwrap()).unwrap();
        match field {
            0 => {
                store.markers.insert(2, [9; 32]);
            }
            1 => {
                head.height = 1;
                store.markers.insert(1, head.bundle);
            }
            2 => {
                head.predecessor[0] ^= 1;
            }
            3 => {
                head.next[0] ^= 1;
            }
            _ => {
                head.bundle = ZERO;
            }
        }
        store.pin = Some(head.encode());
        assert!(matches!(
            journal(store).read_published_range(request(0)),
            Err(PublishedReadError::CorruptHead)
        ));
    }
    let mut store = chain(2);
    store.pin = Some(b"broken head".to_vec());
    assert!(journal(store).read_published_range(request(0)).is_err());
    let mut store = chain(1);
    let mut head = Pin::decode(store.pin.as_ref().unwrap()).unwrap();
    head.height = 0;
    store.pin = Some(head.encode());
    assert!(matches!(
        journal(store).read_published_range(request(0)),
        Err(PublishedReadError::CorruptHead)
    ));
}

#[test]
fn tip_content_substitution_and_missing_published_indexes_fail_closed() {
    let mut store = chain(2);
    let tip_id = store.markers[&2];
    store
        .bundles
        .insert(tip_id, store.bundles[&store.markers[&1]].clone());
    assert!(journal(store).read_published_range(request(0)).is_err());
    let mut store = chain(3);
    store.markers.remove(&1);
    assert!(matches!(
        journal(store).read_published_range(request(0)),
        Err(PublishedReadError::MissingHeight { height: 1 })
    ));
    let mut store = chain(3);
    store.markers.insert(1, store.markers[&2]);
    assert!(matches!(
        journal(store).read_published_range(request(0)),
        Err(PublishedReadError::Discontinuous { height: 1 })
    ));
}

#[test]
fn exact_predecessor_anchor_and_internal_continuity_are_checked() {
    let reader = journal(chain(3));
    let mut wanted = request(1);
    wanted.expected_predecessor = Some(frontier(1));
    assert_eq!(
        reader.read_published_range(wanted).unwrap().bundles().len(),
        2
    );
    wanted.expected_predecessor = Some([7; 32]);
    assert!(matches!(
        reader.read_published_range(wanted),
        Err(PublishedReadError::FrontierMismatch { height: 2 })
    ));
    let mut genesis = request(0);
    genesis.expected_predecessor = Some([7; 32]);
    assert!(matches!(
        reader.read_published_range(genesis),
        Err(PublishedReadError::FrontierMismatch { height: 1 })
    ));
    let mut at_head = request(3);
    at_head.expected_predecessor = Some([7; 32]);
    assert!(matches!(
        reader.read_published_range(at_head),
        Err(PublishedReadError::FrontierMismatch { height: 3 })
    ));

    let mut store = chain(3);
    let broken = bundle([7; 32], 2, 8);
    store.bundles.insert(broken.id(), broken.bytes().to_vec());
    store.markers.insert(2, broken.id());
    assert!(matches!(
        journal(store).read_published_range(request(0)),
        Err(PublishedReadError::Discontinuous { height: 2 })
    ));
}

#[test]
fn invalid_count_and_byte_limits_fail_before_any_disk_read() {
    for (max_bundles, max_bytes) in [
        (0, 1),
        (MAX_PUBLISHED_PAGE_BUNDLES + 1, 1),
        (1, 0),
        (1, MAX_PUBLISHED_PAGE_BYTES + 1),
        (usize::MAX, usize::MAX),
    ] {
        let reader = journal(chain(1));
        let mut wanted = request(0);
        wanted.max_bundles = max_bundles;
        wanted.max_bytes = max_bytes;
        assert!(matches!(
            reader.read_published_range(wanted),
            Err(PublishedReadError::Limits)
        ));
        assert_eq!(reader.store.trace.borrow().pin_reads, 0);
    }
}

#[test]
fn byte_budget_gives_progress_or_explicit_first_bundle_requirement() {
    let store = chain(3);
    let size = store.bundles[&store.markers[&1]].len();
    let reader = journal(store);
    let mut wanted = request(0);
    wanted.max_bytes = size - 1;
    assert!(matches!(
        reader.read_published_range(wanted),
        Err(PublishedReadError::BudgetTooSmall { required }) if required == size
    ));
    wanted.max_bytes = size;
    let page = reader.read_published_range(wanted).unwrap();
    assert_eq!(page.bundles().len(), 1);
    assert_eq!(page.bytes(), size);
    assert_eq!(page.next_after(), 1);
    assert!(page.has_more());
    wanted.after_height = page.next_after();
    wanted.expected_predecessor = Some(page.bundles()[0].next());
    assert_eq!(reader.read_published_range(wanted).unwrap().next_after(), 2);
}

#[test]
fn continuation_crosses_1024_without_inventory_truncation_or_orphan_scan() {
    let reader = journal(chain(1_057));
    let mut after = 0;
    let mut expected = GENESIS_NEXT;
    let mut pages = 0;
    while after < 1_057 {
        let mut wanted = request(after);
        wanted.expected_predecessor = Some(expected);
        let page = reader.read_published_range(wanted).unwrap();
        assert!(!page.bundles().is_empty());
        assert!(page.bundles().len() <= MAX_PUBLISHED_PAGE_BUNDLES);
        assert!(page.bytes() <= MAX_PUBLISHED_PAGE_BYTES);
        for bundle in page.bundles() {
            assert_eq!(bundle.height(), after + 1);
            assert_eq!(bundle.predecessor(), expected);
            after = bundle.height();
            expected = bundle.next();
        }
        assert_eq!(page.next_after(), after);
        pages += 1;
    }
    assert_eq!(pages, 34);
    assert_eq!(reader.store.trace.borrow().pin_reads, pages);
    assert_eq!(after, 1_057);
}

#[test]
fn maximum_height_continuation_never_wraps() {
    let last = bundle(frontier(u64::MAX - 1), u64::MAX, 8);
    let mut store = chain(0);
    store.pin = Some(pin(&last).encode());
    store.markers.insert(u64::MAX, last.id());
    store.bundles.insert(last.id(), last.bytes().to_vec());
    let reader = journal(store);
    let mut wanted = request(u64::MAX - 1);
    wanted.expected_predecessor = Some(last.predecessor());
    let page = reader.read_published_range(wanted).unwrap();
    assert_eq!(page.next_after(), u64::MAX);
    assert!(!page.has_more());
    let mut wanted = request(u64::MAX);
    wanted.expected_predecessor = Some(last.next());
    let page = reader.read_published_range(wanted).unwrap();
    assert!(page.bundles().is_empty());
    assert_eq!(page.next_after(), u64::MAX);
    assert!(matches!(
        journal(chain(2)).read_published_range(request(u64::MAX)),
        Err(PublishedReadError::CursorAhead {
            requested: u64::MAX,
            observed: 2
        })
    ));
}

#[test]
fn filesystem_corrupt_head_and_wrong_marker_are_preserved() {
    let temp = Temp::new();
    let store = chain(2);
    temp.publish_fixture(&store);
    let head_path = temp.0.join(crate::HEAD_FILE);
    fs::write(&head_path, b"corrupt").unwrap();
    assert!(Journal::new(&temp.0, FsStore)
        .read_published_range(request(0))
        .is_err());
    assert_eq!(fs::read(&head_path).unwrap(), b"corrupt");
    fs::write(&head_path, store.pin.as_ref().unwrap()).unwrap();
    let marker = FsStore::height_path(&temp.0, 2);
    fs::write(&marker, [9; 32]).unwrap();
    assert!(Journal::new(&temp.0, FsStore)
        .read_published_range(request(0))
        .is_err());
    assert_eq!(fs::read(marker).unwrap(), [9; 32]);
}
