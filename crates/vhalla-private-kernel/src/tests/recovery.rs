use super::*;
use crate::recovery::*;
use std::{
    future::Future,
    task::{Context as TaskContext, Poll},
};

impl ArchiveStore for Memory {
    async fn accounting(
        &mut self,
        context: Context,
    ) -> std::result::Result<Accounting, StoreError> {
        let image = self.load(context).await?;
        let disk = self.0.borrow();
        if disk.records.keys().copied().collect::<BTreeSet<_>>() != disk.published {
            return Err(StoreError::Corrupt);
        }
        let bytes = disk.records.values().try_fold(0u64, |n, record| {
            n.checked_add(record.as_bytes().len() as u64)
                .ok_or(StoreError::Corrupt)
        })?;
        Ok(Accounting {
            image,
            records: disk.records.len() as u64,
            bytes,
            max_records: 1_000_000,
            max_bytes: 1 << 30,
        })
    }
}

struct Archive {
    context: Context,
    id: [u8; 32],
    pages: Vec<Vec<u8>>,
    first_record: usize,
}
impl Archive {
    async fn capture(disk: Memory, key: &StorageKey, context: Context) -> Self {
        let mut export = ArchiveExport::open(disk, key, context).await.unwrap();
        let id = export.archive_id();
        // This bounded fixture keeps its small synthetic archive in memory. The
        // production API emits one page and does not collect lifetime history.
        let mut pages = Vec::new();
        while let Some(page) = export.next_page().await.unwrap() {
            assert!(page.encrypted_bytes().len() <= MAX_ARCHIVE_PAGE_BYTES);
            pages.push(page.encrypted_bytes().to_vec());
            assert!(pages.len() < 128);
        }
        let mut result = Self {
            context,
            id,
            pages,
            first_record: 0,
        };
        let (_, first_record) = result.source(key);
        result.first_record = first_record;
        result
    }
    fn source(&self, key: &StorageKey) -> (ArchiveSource, usize) {
        let mut reader = ArchiveSourceReader::new(key, self.context, self.id).unwrap();
        for (index, page) in self.pages.iter().enumerate() {
            if reader.push(page).unwrap() {
                return (reader.finish().unwrap(), index + 1);
            }
        }
        panic!("fixture has no complete image")
    }
    fn final_page(&self) -> &[u8] {
        self.pages.last().unwrap()
    }
    fn seal(&self, key: &StorageKey) -> ArchiveSeal {
        ArchiveSeal::from_final_page(key, self.context, self.id, self.final_page()).unwrap()
    }
    async fn begin(&self, disk: Memory, key: &StorageKey) -> ArchiveImport<Memory> {
        ArchiveImport::begin(disk, key, self.source(key).0)
            .await
            .unwrap()
    }
    async fn append_all(&self, import: &mut ArchiveImport<Memory>) {
        for page in &self.pages[self.first_record..self.pages.len() - 1] {
            import.append(page).await.unwrap();
        }
    }
}

async fn rich() -> Pair {
    let mut pair = joined().await;
    let to_member = pair
        .owner
        .test_send(op(10), b"owner text", pair.now)
        .await
        .unwrap();
    pair.member
        .receive(to_member.bytes(), pair.now)
        .await
        .unwrap();
    let to_owner = pair
        .member
        .test_send(op(11), b"member text", pair.now)
        .await
        .unwrap();
    pair.owner
        .receive(to_owner.bytes(), pair.now)
        .await
        .unwrap();
    pair.owner
        .create_contact_offer(
            op(12),
            pair.member.status().context.account,
            validity(pair.now),
            pair.now,
        )
        .await
        .unwrap();
    pair
}

#[test]
fn recovery_complete_read_only_archive_retains_exact_records_and_redacts_offers() {
    block_on(async {
        let mut pair = rich().await;
        let context = pair.owner.status().context;
        let original = pair.owner_disk.snapshot();
        let status = pair.owner.status();
        let expected = pair.owner.outbox(0, 16).await.unwrap();
        let archive = Archive::capture(pair.owner_disk.clone(), &pair.owner_key, context).await;
        let destination = Memory::default();
        let mut import = archive.begin(destination.clone(), &pair.owner_key).await;
        assert!(Kernel::open(destination.clone(), &pair.owner_key, context)
            .await
            .is_err());
        archive.append_all(&mut import).await;
        assert!(Kernel::open(destination.clone(), &pair.owner_key, context)
            .await
            .is_err());
        let mut view = import.finish(archive.final_page()).await.unwrap();
        assert_eq!(view.membership().await.unwrap().status(), status);
        let actual = view.outbox(0, 16).await.unwrap();
        assert_eq!(actual.head, expected.head);
        assert_eq!(actual.records.len(), expected.records.len());
        for (a, b) in actual.records.iter().zip(&expected.records) {
            assert_eq!(
                (a.sequence(), a.operation(), a.kind()),
                (b.sequence(), b.operation(), b.kind())
            );
            assert_eq!(
                a.artifact().map(CommittedOutbox::bytes),
                b.artifact().map(CommittedOutbox::bytes)
            );
        }
        assert!(matches!(
            actual.records.last(),
            Some(OutboxEntry::ConfidentialOffer { .. })
        ));
        let inbox = view.inbox(0, 16).await.unwrap();
        assert_eq!(inbox.records.len(), 1);
        assert_eq!(inbox.records[0].body(), b"member text");
        assert!(Kernel::open(destination.clone(), &pair.owner_key, context)
            .await
            .is_err());
        assert!(destination.0.borrow().records == original.1);
        assert!(pair.owner_disk.snapshot() == original);
        let mut reopened =
            ArchiveView::open(destination, &pair.owner_key, archive.seal(&pair.owner_key))
                .await
                .unwrap();
        assert_eq!(reopened.membership().await.unwrap().status(), status);
    });
}

#[test]
fn recovery_member_control_suffix_and_empty_history_are_complete() {
    block_on(async {
        let mut pair = joined().await;
        let renewal = pair
            .owner
            .owner_renewal_request(validity(pair.now + 1))
            .unwrap();
        let signed = renewal.sign(&pair.owner_account).unwrap();
        let update = pair
            .owner
            .renew_owner(op(20), signed, pair.now + 1)
            .await
            .unwrap();
        pair.member
            .apply_control(update.bytes(), pair.now + 1)
            .await
            .unwrap();
        let archive = Archive::capture(
            pair.member_disk.clone(),
            &pair.member_key,
            pair.member.status().context,
        )
        .await;
        let dest = Memory::default();
        let mut import = archive.begin(dest.clone(), &pair.member_key).await;
        archive.append_all(&mut import).await;
        let mut view = import.finish(archive.final_page()).await.unwrap();
        assert_eq!(
            view.membership().await.unwrap().status(),
            pair.member.status()
        );
        assert!(dest.0.borrow().records == pair.member_disk.0.borrow().records);
        let fresh = fresh().await;
        let empty = Archive::capture(
            fresh.owner_disk.clone(),
            &fresh.owner_key,
            fresh.owner.status().context,
        )
        .await;
        assert_eq!(empty.first_record + 1, empty.pages.len());
        let mut view = empty
            .begin(Memory::default(), &fresh.owner_key)
            .await
            .finish(empty.final_page())
            .await
            .unwrap();
        assert_eq!(view.outbox(0, 16).await.unwrap().head, 0);
    });
}

#[test]
fn recovery_uncertain_append_reopen_and_exact_last_page_retry_preserve_bytes() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        for fault in [Fault::Before, Fault::After, Fault::HangAfter] {
            let disk = Memory::default();
            let mut import = archive.begin(disk.clone(), &pair.owner_key).await;
            let before = disk.snapshot();
            disk.fault(fault);
            let raw = &archive.pages[archive.first_record];
            if matches!(fault, Fault::HangAfter) {
                let mut pending = Box::pin(import.append(raw));
                let mut cx = TaskContext::from_waker(futures::task::noop_waker_ref());
                assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
                drop(pending);
            } else {
                assert!(import.append(raw).await.is_err());
            }
            assert!(import.needs_reopen());
            assert!(matches!(import.progress(), Err(Error::NeedsReopen)));
            if matches!(fault, Fault::Before) {
                assert!(disk.snapshot() == before);
            }
            drop(import);
            let mut resumed = ArchiveImport::resume(
                disk.clone(),
                &pair.owner_key,
                archive.source(&pair.owner_key).0,
            )
            .await
            .unwrap();
            let after = resumed.append(raw).await.unwrap();
            let retained = disk.snapshot();
            assert_eq!(resumed.append(raw).await.unwrap(), after);
            assert!(disk.snapshot() == retained);
            for page in &archive.pages[archive.first_record + 1..archive.pages.len() - 1] {
                resumed.append(page).await.unwrap();
            }
            resumed.finish(archive.final_page()).await.unwrap();
        }
    });
}

#[test]
fn recovery_uncertain_finish_reopens_archive_without_live_restore() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        for fault in [Fault::After, Fault::HangAfter] {
            let disk = Memory::default();
            let mut import = archive.begin(disk.clone(), &pair.owner_key).await;
            archive.append_all(&mut import).await;
            disk.fault(fault);
            if matches!(fault, Fault::HangAfter) {
                let mut pending = Box::pin(import.finish(archive.final_page()));
                let mut cx = TaskContext::from_waker(futures::task::noop_waker_ref());
                assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
                drop(pending);
            } else {
                assert!(import.finish(archive.final_page()).await.is_err());
            }
            let retained = disk.snapshot();
            assert!(ArchiveImport::resume(
                disk.clone(),
                &pair.owner_key,
                archive.source(&pair.owner_key).0
            )
            .await
            .is_err());
            let mut view =
                ArchiveView::open(disk.clone(), &pair.owner_key, archive.seal(&pair.owner_key))
                    .await
                    .unwrap();
            assert_eq!(
                view.membership().await.unwrap().status(),
                pair.owner.status()
            );
            assert!(Kernel::open(disk.clone(), &pair.owner_key, archive.context)
                .await
                .is_err());
            assert!(disk.snapshot() == retained);
        }
    });
}

#[test]
fn recovery_pages_pin_full_context_id_order_size_and_authentication() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        let raw = &archive.pages[0];
        let mut variants = Vec::new();
        for index in [0, 8, 136, 168, 176, raw.len() - 1] {
            let mut changed = raw.clone();
            changed[index] ^= 1;
            variants.push(changed);
        }
        let mut oversized = raw.clone();
        oversized[208..212].copy_from_slice(&u32::MAX.to_be_bytes());
        variants.push(oversized);
        variants.push(vec![0; MAX_ARCHIVE_PAGE_BYTES + 1]);
        variants.push(raw[..raw.len() - 1].to_vec());
        let mut suffix = raw.clone();
        suffix.push(0);
        variants.push(suffix);
        for changed in variants {
            let mut reader =
                ArchiveSourceReader::new(&pair.owner_key, archive.context, archive.id).unwrap();
            assert!(reader.push(&changed).is_err());
            assert!(matches!(reader.push(raw), Err(Error::NeedsReopen)));
        }
        let mut reader =
            ArchiveSourceReader::new(&pair.owner_key, pair.member.status().context, archive.id)
                .unwrap();
        assert!(reader.push(raw).is_err());
        let mut reader =
            ArchiveSourceReader::new(&storage_key(), archive.context, archive.id).unwrap();
        assert!(reader.push(raw).is_err());
        let mut reader =
            ArchiveSourceReader::new(&pair.owner_key, archive.context, [7; 32]).unwrap();
        assert!(reader.push(raw).is_err());
        assert!(ArchiveSourceReader::new(&pair.owner_key, archive.context, [0; 32]).is_err());
    });
}

#[test]
fn recovery_gap_early_final_duplicate_and_different_stream_do_not_advance() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        let other =
            Archive::capture(pair.owner_disk.clone(), &pair.owner_key, archive.context).await;
        assert_ne!(archive.id, other.id);
        let disk = Memory::default();
        let mut import = archive.begin(disk.clone(), &pair.owner_key).await;
        let before = disk.snapshot();
        assert!(import
            .append(&archive.pages[archive.first_record + 1])
            .await
            .is_err());
        assert!(disk.snapshot() == before);
        let mut import = ArchiveImport::resume(
            disk.clone(),
            &pair.owner_key,
            archive.source(&pair.owner_key).0,
        )
        .await
        .unwrap();
        assert!(import
            .append(&other.pages[other.first_record])
            .await
            .is_err());
        assert!(disk.snapshot() == before);
        let import = ArchiveImport::resume(
            disk.clone(),
            &pair.owner_key,
            archive.source(&pair.owner_key).0,
        )
        .await
        .unwrap();
        assert!(import.finish(archive.final_page()).await.is_err());
        assert!(disk.snapshot() == before);
        assert!(
            ArchiveView::open(disk.clone(), &pair.owner_key, archive.seal(&pair.owner_key))
                .await
                .is_err()
        );
        assert!(ArchiveImport::begin(
            disk.clone(),
            &pair.owner_key,
            archive.source(&pair.owner_key).0
        )
        .await
        .is_err());
        assert!(disk.snapshot() == before);
    });
}

#[test]
fn recovery_missing_or_extra_record_and_index_mismatch_refuse_completeness() {
    block_on(async {
        for variant in 0..4 {
            let pair = rich().await;
            let context = pair.owner.status().context;
            {
                let mut disk = pair.owner_disk.0.borrow_mut();
                match variant {
                    0 => {
                        disk.records.remove(&RecordKey::Outbox(1));
                    }
                    1 => {
                        let key = RecordKey::Operation(op(999));
                        let record = StoredRecord::from_bytes(key, &[1; 40]).unwrap();
                        disk.records.insert(key, record);
                        disk.published.insert(key);
                    }
                    2 => {
                        let key = RecordKey::Operation(op(1));
                        let mut purpose = b"record/".to_vec();
                        purpose.extend(key.encode());
                        let raw = codec::seal(
                            &pair.owner_key,
                            context,
                            &purpose,
                            &99u64.to_be_bytes(),
                            MAX_STORED_RECORD_BYTES,
                        )
                        .unwrap();
                        disk.records
                            .insert(key, StoredRecord::from_bytes(key, &raw).unwrap());
                    }
                    _ => {
                        let key = RecordKey::Control(1);
                        let record = disk.records.get(&key).unwrap();
                        let mut raw = record.as_bytes().to_vec();
                        raw[40] ^= 1;
                        disk.records
                            .insert(key, StoredRecord::from_bytes(key, &raw).unwrap());
                    }
                }
            }
            let retained = pair.owner_disk.snapshot();
            if let Ok(mut export) =
                ArchiveExport::open(pair.owner_disk.clone(), &pair.owner_key, context).await
            {
                let mut refused = false;
                for _ in 0..128 {
                    match export.next_page().await {
                        Err(_) => {
                            refused = true;
                            break;
                        }
                        Ok(Some(_)) => (),
                        Ok(None) => panic!("damaged archive was marked complete"),
                    }
                }
                assert!(refused);
                assert!(export.needs_reopen());
            }
            assert!(pair.owner_disk.snapshot() == retained);
        }
    });
}

#[test]
fn recovery_source_advance_and_stale_import_owner_are_refused() {
    block_on(async {
        let mut pair = rich().await;
        let context = pair.owner.status().context;
        let mut export = ArchiveExport::open(pair.owner_disk.clone(), &pair.owner_key, context)
            .await
            .unwrap();
        export.next_page().await.unwrap().unwrap();
        pair.owner
            .test_send(op(90), b"new source revision", pair.now)
            .await
            .unwrap();
        assert!(export.next_page().await.is_err());
        assert!(export.needs_reopen());
        let archive = Archive::capture(pair.owner_disk.clone(), &pair.owner_key, context).await;
        let disk = Memory::default();
        let mut first = archive.begin(disk.clone(), &pair.owner_key).await;
        let mut stale = ArchiveImport::resume(
            disk.clone(),
            &pair.owner_key,
            archive.source(&pair.owner_key).0,
        )
        .await
        .unwrap();
        first
            .append(&archive.pages[archive.first_record])
            .await
            .unwrap();
        let retained = disk.snapshot();
        assert!(stale
            .append(&archive.pages[archive.first_record])
            .await
            .is_err());
        assert!(stale.needs_reopen());
        assert!(disk.snapshot() == retained);
    });
}

#[derive(Clone)]
struct BudgetStore {
    inner: Memory,
    max_records: u64,
    max_bytes: u64,
    block_accounting: Rc<std::cell::Cell<bool>>,
}
impl BudgetStore {
    fn new(inner: Memory, max_records: u64, max_bytes: u64) -> Self {
        Self {
            inner,
            max_records,
            max_bytes,
            block_accounting: Rc::new(std::cell::Cell::new(false)),
        }
    }
}
impl Store for BudgetStore {
    async fn load(&mut self, context: Context) -> std::result::Result<Option<Image>, StoreError> {
        self.inner.load(context).await
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> std::result::Result<Option<StoredRecord>, StoreError> {
        self.inner.read(context, key).await
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> std::result::Result<(), StoreError> {
        self.inner.publish(context, expected, next, records).await
    }
}
impl ArchiveStore for BudgetStore {
    async fn accounting(
        &mut self,
        context: Context,
    ) -> std::result::Result<Accounting, StoreError> {
        if self.block_accounting.get() {
            return std::future::pending().await;
        }
        let mut value = self.inner.accounting(context).await?;
        value.max_records = self.max_records;
        value.max_bytes = self.max_bytes;
        Ok(value)
    }
}

#[test]
fn recovery_capacity_is_checked_before_destination_write_and_orphans_never_reset() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        for (records, bytes) in [(0, 1 << 30), (1_000_000, 0)] {
            let disk = Memory::default();
            let store = BudgetStore::new(disk.clone(), records, bytes);
            assert!(matches!(
                ArchiveImport::begin(store, &pair.owner_key, archive.source(&pair.owner_key).0)
                    .await,
                Err(Error::Bounds)
            ));
            let state = disk.0.borrow();
            assert!(
                state.image.is_none() && state.records.is_empty() && state.published.is_empty()
            );
        }
        let disk = Memory::default();
        {
            let record = pair
                .owner_disk
                .0
                .borrow()
                .records
                .values()
                .next()
                .unwrap()
                .clone();
            let mut state = disk.0.borrow_mut();
            state.context = Some(archive.context);
            state.published.insert(record.key());
            state.records.insert(record.key(), record);
        }
        assert!(ArchiveImport::begin(
            disk.clone(),
            &pair.owner_key,
            archive.source(&pair.owner_key).0
        )
        .await
        .is_err());
        let state = disk.0.borrow();
        assert!(state.image.is_none());
        assert_eq!(state.records.len(), 1);
    });
}

#[test]
fn recovery_canceled_source_and_read_only_access_latch_before_first_await() {
    block_on(async {
        let pair = rich().await;
        let context = pair.owner.status().context;
        let store = BudgetStore::new(pair.owner_disk.clone(), 1_000_000, 1 << 30);
        let blocked = store.block_accounting.clone();
        let mut export = ArchiveExport::open(store, &pair.owner_key, context)
            .await
            .unwrap();
        blocked.set(true);
        let mut pending = Box::pin(export.next_page());
        let mut cx = TaskContext::from_waker(futures::task::noop_waker_ref());
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
        drop(pending);
        blocked.set(false);
        assert!(export.needs_reopen());
        assert!(matches!(export.next_page().await, Err(Error::NeedsReopen)));
        let archive = Archive::capture(pair.owner_disk.clone(), &pair.owner_key, context).await;
        let disk = Memory::default();
        let mut import = archive.begin(disk.clone(), &pair.owner_key).await;
        archive.append_all(&mut import).await;
        import.finish(archive.final_page()).await.unwrap();
        let store = BudgetStore::new(disk.clone(), 1_000_000, 1 << 30);
        let blocked = store.block_accounting.clone();
        let mut view = ArchiveView::open(store, &pair.owner_key, archive.seal(&pair.owner_key))
            .await
            .unwrap();
        let retained = disk.snapshot();
        blocked.set(true);
        let mut pending = Box::pin(view.membership());
        assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Pending));
        drop(pending);
        blocked.set(false);
        assert!(view.needs_reopen());
        assert!(matches!(view.membership().await, Err(Error::NeedsReopen)));
        assert!(disk.snapshot() == retained);
    });
}

#[test]
fn recovery_missing_imported_evidence_and_wrong_final_seal_fail_closed() {
    block_on(async {
        let pair = rich().await;
        let archive = Archive::capture(
            pair.owner_disk.clone(),
            &pair.owner_key,
            pair.owner.status().context,
        )
        .await;
        let other =
            Archive::capture(pair.owner_disk.clone(), &pair.owner_key, archive.context).await;
        let disk = Memory::default();
        let mut import = archive.begin(disk.clone(), &pair.owner_key).await;
        archive.append_all(&mut import).await;
        import.finish(archive.final_page()).await.unwrap();
        let retained = disk.snapshot();
        assert!(
            ArchiveView::open(disk.clone(), &pair.owner_key, other.seal(&pair.owner_key))
                .await
                .is_err()
        );
        assert!(
            ArchiveView::open(disk.clone(), &storage_key(), archive.seal(&pair.owner_key))
                .await
                .is_err()
        );
        assert!(disk.snapshot() == retained);
        disk.0.borrow_mut().records.remove(&RecordKey::Outbox(1));
        assert!(
            ArchiveView::open(disk.clone(), &pair.owner_key, archive.seal(&pair.owner_key))
                .await
                .is_err()
        );
        assert!(disk.0.borrow().published.contains(&RecordKey::Outbox(1)));
    });
}

#[test]
fn recovery_source_token_cannot_change_custody_before_destination_publication() {
    block_on(async {
        for populated in [false, true] {
            let pair = if populated {
                rich().await
            } else {
                fresh().await
            };
            let archive = Archive::capture(
                pair.owner_disk.clone(),
                &pair.owner_key,
                pair.owner.status().context,
            )
            .await;
            let other = storage_key();
            let disk = Memory::default();
            assert!(
                ArchiveImport::begin(disk.clone(), &other, archive.source(&pair.owner_key).0)
                    .await
                    .is_err()
            );
            {
                let state = disk.0.borrow();
                assert!(
                    state.image.is_none() && state.records.is_empty() && state.published.is_empty()
                );
            }
            let _valid = archive.begin(disk.clone(), &pair.owner_key).await;
            let retained = disk.snapshot();
            assert!(
                ArchiveImport::resume(disk.clone(), &other, archive.source(&pair.owner_key).0)
                    .await
                    .is_err()
            );
            assert!(disk.snapshot() == retained);
        }
    });
}
