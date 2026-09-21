#![cfg(all(unix, feature = "client"))]
//! Real account custody, MLS, archive codec and SQLite; no fake backend success.
use futures::executor::block_on;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    Context, OperationId, OutboxEntry,
};
use vhalla_private_native::{
    archive::{ArchiveExporter, ArchiveInput, ArchiveSession},
    bridge::KernelStore,
    client::{Error, RoomCreation, RoomSession},
    private_rooms::Limits,
};

struct Fixture {
    root: PathBuf,
    context: Context,
}
fn limits() -> Limits {
    Limits {
        max_records: 64,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn validity() -> Validity {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Validity::new(time - 1, time + 3600).unwrap()
}
impl Fixture {
    async fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vhalla-native-archive-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let identity = Identity::create_new(root.join("account")).unwrap();
        let authority = validity();
        let creation = RoomCreation::owner(identity, authority).unwrap();
        let context = creation.context();
        let mut room = creation
            .commit(root.join("source"), limits())
            .await
            .unwrap();
        let other = Identity::create_new(root.join("other-account")).unwrap();
        room.create_contact_offer(
            OperationId::from_bytes([1; 16]).unwrap(),
            Key::from_bytes(other.public_key()).unwrap(),
            authority,
        )
        .await
        .unwrap();
        let draft = room.prepare_message(b"archive inert text").unwrap();
        room.send(OperationId::from_bytes([2; 16]).unwrap(), &draft)
            .await
            .unwrap();
        room.lock();
        Self { root, context }
    }
    fn identity(&self) -> Identity {
        Identity::open(self.root.join("account")).unwrap()
    }
    async fn export(&self) -> ([u8; 32], Vec<Vec<u8>>) {
        let mut export =
            ArchiveExporter::open(self.identity(), self.root.join("source"), self.context)
                .await
                .unwrap();
        let id = export.archive_id().unwrap();
        assert!(Identity::open(self.root.join("account")).is_err());
        assert!(KernelStore::open(self.root.join("source"), self.context).is_err());
        let mut pages = Vec::new();
        while let Some(page) = export.next_page().await.unwrap() {
            assert!(pages.len() < 24); // Small fixture only; production streams.
            pages.push(page.encrypted_bytes().to_vec());
        }
        export.lock();
        assert!(matches!(export.archive_id(), Err(Error::Locked)));
        assert!(export.next_page().await.is_err());
        (id, pages)
    }
    fn input(&self, id: [u8; 32], pages: &[Vec<u8>]) -> (ArchiveInput, usize) {
        let mut input = ArchiveInput::new(self.identity(), self.context, id).unwrap();
        for (index, page) in pages.iter().enumerate() {
            if input.push_source(page).unwrap() {
                return (input, index + 1);
            }
        }
        panic!("complete synthetic prefix missing")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn archive_receiving_reopen_exact_retry_final_reopen_and_account_lock() {
    block_on(async {
        let f = Fixture::new().await;
        let (id, pages) = f.export().await;
        let dest = f.root.join("archive");
        let (input, start) = f.input(id, &pages);
        let mut receiver = input.create(&dest, limits()).await.unwrap();
        receiver.append(&pages[start]).await.unwrap();
        let retained = receiver.progress().unwrap();
        receiver.lock(); // Simulates process lifetime ending after actual commit.
        assert!(receiver.needs_reopen());
        assert!(RoomSession::open(f.identity(), &dest, f.context)
            .await
            .is_err());
        let (input, again) = f.input(id, &pages);
        assert_eq!(again, start);
        let mut receiver = input.resume(&dest).await.unwrap();
        assert_eq!(receiver.progress().unwrap(), retained);
        assert_eq!(receiver.append(&pages[start]).await.unwrap(), retained);
        for page in &pages[start + 1..pages.len() - 1] {
            receiver.append(page).await.unwrap();
        }
        let mut view = receiver.finish(pages.last().unwrap()).await.unwrap();
        assert!(Identity::open(f.root.join("account")).is_err());
        assert!(KernelStore::open(&dest, f.context).is_err());
        let original = view.membership().await.unwrap();
        let page = view.outbox(0, 16).await.unwrap();
        assert_eq!(page.records.len(), 2);
        assert!(matches!(
            page.records[0],
            OutboxEntry::ConfidentialOffer { .. }
        ));
        assert!(page.records[0].artifact().is_none());
        assert!(page.records[1].artifact().is_some());
        let revision = view.seal().unwrap().source_revision();
        view.lock();
        assert!(view.membership().await.is_err());
        // A lost finish response is reconciled only through explicit archive open.
        let mut reopened =
            ArchiveSession::open(f.identity(), &dest, f.context, id, pages.last().unwrap())
                .await
                .unwrap();
        assert_eq!(reopened.seal().unwrap().source_revision(), revision);
        assert_eq!(
            reopened.membership().await.unwrap().status(),
            original.status()
        );
        drop(reopened);
        assert!(RoomSession::open(f.identity(), &dest, f.context)
            .await
            .is_err());
        let (input, _) = f.input(id, &pages);
        assert!(input.resume(&dest).await.is_err());
        let mut source = RoomSession::open(f.identity(), f.root.join("source"), f.context)
            .await
            .unwrap();
        assert_eq!(source.outbox(0, 16).await.unwrap().head, 2);
    });
}

#[test]
fn unauthenticated_prefix_cannot_create_and_incomplete_state_is_never_reset() {
    block_on(async {
        let f = Fixture::new().await;
        let (id, pages) = f.export().await;
        assert!(ArchiveInput::new(
            Identity::open(f.root.join("other-account")).unwrap(),
            f.context,
            id
        )
        .is_err());
        let mut input = ArchiveInput::new(f.identity(), f.context, id).unwrap();
        let mut damaged = pages[0].clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(input.push_source(&damaged).is_err());
        assert!(input.create(f.root.join("bad"), limits()).await.is_err());
        assert!(!f.root.join("bad").exists());
        let mut changed = f.context;
        changed.device = Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[81; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let mut input = ArchiveInput::new(f.identity(), changed, id).unwrap();
        assert!(input.push_source(&pages[0]).is_err());
        drop(input);
        let empty = f.root.join("format-only");
        drop(KernelStore::create_new(&empty, f.context, limits()).unwrap());
        let format = fs::read(empty.join("FORMAT")).unwrap();
        let (input, _) = f.input(id, &pages);
        assert!(input.resume(&empty).await.is_err());
        assert_eq!(fs::read(empty.join("FORMAT")).unwrap(), format);
        let (input, _) = f.input(id, &pages);
        assert!(input.create(&empty, limits()).await.is_err());
    });
}

#[test]
fn changed_page_latches_without_advancing_progress_and_quota_refusal_keeps_source() {
    block_on(async {
        let f = Fixture::new().await;
        let (id, pages) = f.export().await;
        let (input, start) = f.input(id, &pages);
        let dest = f.root.join("receiving");
        let mut receiver = input.create(&dest, limits()).await.unwrap();
        let before = receiver.progress().unwrap();
        let mut changed = pages[start].clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(receiver.append(&changed).await.is_err());
        assert!(receiver.needs_reopen());
        assert!(receiver.append(&pages[start]).await.is_err());
        drop(receiver);
        let (input, _) = f.input(id, &pages);
        let receiver = input.resume(&dest).await.unwrap();
        assert_eq!(receiver.progress().unwrap(), before);
        drop(receiver);
        let (input, _) = f.input(id, &pages);
        assert!(input
            .create(
                f.root.join("small"),
                Limits {
                    max_records: 1,
                    ..limits()
                }
            )
            .await
            .is_err());
        // A refused destination remains allocated evidence, never auto-deleted.
        assert!(f.root.join("small").exists());
        assert!(
            RoomSession::open(f.identity(), f.root.join("source"), f.context)
                .await
                .is_ok()
        );
    });
}
