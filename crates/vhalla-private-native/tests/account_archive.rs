#![cfg(all(any(unix, windows), feature = "client"))]
//! Shared account ownership never turns recovered history into a live device.

use futures::executor::block_on;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::StoreError,
    CommittedOutbox, Context, Error as KernelError, MessageDraft, OperationId,
};
use vhalla_private_native::{
    archive::{ArchiveExporter, ArchiveInput},
    bridge::KernelStore,
    client::{AccountController, Error, RoomSession},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-account-archive-{}-{}-{serial}",
            std::process::id(),
            stamp.as_nanos()
        ));
        drop(vhalla_custody::create_private_directory(&path).unwrap());
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn validity() -> Validity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Validity::new(now - 1, now + 3600).unwrap()
}
fn limits() -> Limits {
    Limits {
        max_records: 64,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn op(value: u8) -> OperationId {
    OperationId::from_bytes([value; 16]).unwrap()
}
fn account_busy(path: &Path) {
    assert!(matches!(Identity::open(path), Err(IdentityError::Busy)));
}

async fn source(
    account: &AccountController,
    path: &Path,
) -> (RoomSession, Context, MessageDraft, CommittedOutbox) {
    let creation = account.prepare_owner(validity()).unwrap();
    let context = creation.context();
    let mut room = creation.commit(path, limits()).await.unwrap();
    let first_draft = room.prepare_message(b"retained before archive").unwrap();
    let first = room.send(op(1), &first_draft).await.unwrap();
    let second = room.prepare_message(b"another retained operation").unwrap();
    room.send(op(2), &second).await.unwrap();
    (room, context, first_draft, first)
}

async fn collect(exporter: &mut ArchiveExporter) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    while let Some(page) = exporter.next_page().await.unwrap() {
        assert!(pages.len() < 16); // This fixture contains only two small messages.
        pages.push(page.encrypted_bytes().to_vec());
    }
    pages
}

async fn export(
    account: &AccountController,
    path: &Path,
    context: Context,
) -> ([u8; 32], Vec<Vec<u8>>) {
    let mut exporter = account.open_archive_export(path, context).await.unwrap();
    let id = exporter.archive_id().unwrap();
    let pages = collect(&mut exporter).await;
    (id, pages)
}

fn input(
    account: &AccountController,
    context: Context,
    id: [u8; 32],
    pages: &[Vec<u8>],
) -> (ArchiveInput, usize) {
    let mut input = account.prepare_archive_import(context, id).unwrap();
    for (index, page) in pages.iter().enumerate() {
        if input.push_source(page).unwrap() {
            return (input, index + 1);
        }
    }
    panic!("complete fixture source prefix missing");
}

#[test]
fn export_keeps_account_and_source_locked_while_sibling_room_continues() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let source_path = temp.0.join("source");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let (mut room, context, draft, original) = source(&account, &source_path).await;
        let before = room.status().unwrap();
        let mut sibling = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("sibling"), limits())
            .await
            .unwrap();
        assert!(matches!(
            account.open_archive_export(&source_path, context).await,
            Err(Error::Storage(StoreError::Refused))
        ));
        assert_eq!(room.status().unwrap(), before);
        room.lock();
        let mut exporter = account
            .open_archive_export(&source_path, context)
            .await
            .unwrap();
        assert_eq!(exporter.context(), context);
        assert_eq!(exporter.limits().max_records, limits().max_records);
        assert!(matches!(
            account.open_room(&source_path, context).await,
            Err(Error::Storage(StoreError::Refused))
        ));
        let sibling_draft = sibling.prepare_message(b"sibling during export").unwrap();
        assert_eq!(
            sibling
                .send(op(1), &sibling_draft)
                .await
                .unwrap()
                .sequence(),
            1
        );
        let pages = collect(&mut exporter).await;
        assert!(pages.len() >= 4);
        drop(account);
        sibling.lock();
        account_busy(&account_path);
        assert!(matches!(
            KernelStore::open(&source_path, context),
            Err(StoreError::Refused)
        ));
        exporter.lock();
        assert!(exporter.needs_reopen());
        assert!(matches!(exporter.archive_id(), Err(Error::Locked)));
        assert!(matches!(exporter.next_page().await, Err(Error::Locked)));

        let account = AccountController::new(Identity::open(&account_path).unwrap());
        let mut reopened = account.open_room(&source_path, context).await.unwrap();
        assert_eq!(reopened.status().unwrap(), before);
        assert_eq!(
            reopened.send(op(1), &draft).await.unwrap().bytes(),
            original.bytes()
        );
        let next = reopened
            .prepare_message(b"source continues after export")
            .unwrap();
        assert_eq!(reopened.send(op(3), &next).await.unwrap().sequence(), 3);
    });
}

#[test]
fn input_receiver_and_completed_view_each_retain_the_last_account_hold() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let source_path = temp.0.join("source");
        let destination = temp.0.join("archive");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let (mut room, context, _, _) = source(&account, &source_path).await;
        room.lock();
        let (id, pages) = export(&account, &source_path, context).await;
        let (prefix, start) = input(&account, context, id, &pages);
        drop(account);
        account_busy(&account_path);
        assert!(!destination.exists());
        let mut receiver = prefix.create(&destination, limits()).await.unwrap();
        account_busy(&account_path);
        assert!(matches!(
            KernelStore::open(&destination, context),
            Err(StoreError::Refused)
        ));
        let retained = receiver.append(&pages[start]).await.unwrap();
        receiver.lock();
        assert!(receiver.needs_reopen());

        let account = AccountController::new(Identity::open(&account_path).unwrap());
        assert!(matches!(
            account.open_room(&destination, context).await,
            Err(Error::Kernel(_))
        ));
        let (prefix, again) = input(&account, context, id, &pages);
        assert_eq!(again, start);
        let mut receiver = prefix.resume(&destination).await.unwrap();
        assert_eq!(receiver.progress().unwrap(), retained);
        assert_eq!(receiver.append(&pages[start]).await.unwrap(), retained);
        for page in &pages[start + 1..pages.len() - 1] {
            receiver.append(page).await.unwrap();
        }
        drop(account);
        account_busy(&account_path);
        let mut view = receiver.finish(pages.last().unwrap()).await.unwrap();
        account_busy(&account_path);
        assert!(matches!(
            KernelStore::open(&destination, context),
            Err(StoreError::Refused)
        ));
        assert_eq!(view.outbox(0, 16).await.unwrap().head, 2);
        view.lock();
        assert!(view.needs_reopen());
        assert!(matches!(view.membership().await, Err(Error::Locked)));

        // Reconcile completion from the retained final page, without needing the
        // returned view or treating its historical device state as live custody.
        let account = AccountController::new(Identity::open(&account_path).unwrap());
        let mut reopened = account
            .open_archive(&destination, context, id, pages.last().unwrap())
            .await
            .unwrap();
        assert_eq!(reopened.seal().unwrap().archive_id(), id);
        assert_eq!(
            reopened.membership().await.unwrap().status().context,
            context
        );
        reopened.lock();
        assert!(matches!(
            account.open_room(&destination, context).await,
            Err(Error::Kernel(_))
        ));
        let (prefix, _) = input(&account, context, id, &pages);
        assert!(prefix.resume(&destination).await.is_err());
        let (prefix, _) = input(&account, context, id, &pages);
        assert!(matches!(
            prefix.create(&destination, limits()).await,
            Err(Error::Storage(StoreError::Refused))
        ));
        drop(account);
        assert!(Identity::open(&account_path).is_ok());
    });
}

#[test]
fn wrong_account_and_unauthenticated_pages_refuse_before_backend_access() {
    block_on(async {
        let temp = Temp::new();
        let account = AccountController::new(Identity::create_new(temp.0.join("account")).unwrap());
        let other = AccountController::new(Identity::create_new(temp.0.join("other")).unwrap());
        let source_path = temp.0.join("source");
        let (mut room, context, _, _) = source(&account, &source_path).await;
        let before = room.status().unwrap();
        // Account refusal precedes the source's otherwise-busy store lock.
        assert!(matches!(
            other.open_archive_export(&source_path, context).await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        assert!(matches!(
            other.prepare_archive_import(context, [1; 32]),
            Err(Error::Kernel(KernelError::Scope))
        ));
        room.lock();
        let (id, pages) = export(&account, &source_path, context).await;
        let reopened = account.open_room(&source_path, context).await.unwrap();
        assert!(matches!(
            other
                .open_archive(&source_path, context, id, pages.last().unwrap())
                .await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        let mut damaged_final = pages.last().unwrap().clone();
        *damaged_final.last_mut().unwrap() ^= 1;
        assert!(matches!(
            account
                .open_archive(&source_path, context, id, &damaged_final)
                .await,
            Err(Error::Kernel(_))
        ));
        // A valid final seal proceeds to the same busy backend, proving that
        // the damaged seal above was refused before native open/recovery.
        assert!(matches!(
            account
                .open_archive(&source_path, context, id, pages.last().unwrap())
                .await,
            Err(Error::Storage(StoreError::Refused))
        ));
        assert_eq!(reopened.status().unwrap(), before);
        let missing = temp.0.join("missing");
        assert!(account
            .open_archive(&missing, context, id, &damaged_final)
            .await
            .is_err());
        assert!(!missing.exists());

        let destination = temp.0.join("unauthenticated");
        let mut prefix = account.prepare_archive_import(context, id).unwrap();
        let mut damaged_source = pages[0].clone();
        *damaged_source.last_mut().unwrap() ^= 1;
        assert!(prefix.push_source(&damaged_source).is_err());
        assert!(prefix.create(&destination, limits()).await.is_err());
        assert!(!destination.exists());
        let incomplete = account.prepare_archive_import(context, id).unwrap();
        assert!(incomplete.create(&destination, limits()).await.is_err());
        assert!(!destination.exists());
        let changed = Context {
            device: Key::from_bytes(other.public_key()).unwrap(),
            ..context
        };
        let mut prefix = account.prepare_archive_import(changed, id).unwrap();
        assert!(prefix.push_source(&pages[0]).is_err());
        assert!(prefix.create(&destination, limits()).await.is_err());
        assert!(!destination.exists());
        assert_eq!(reopened.status().unwrap(), before);
    });
}

#[test]
fn receiving_retries_preserve_progress_and_never_reset_another_stream_or_store() {
    block_on(async {
        let temp = Temp::new();
        let account = AccountController::new(Identity::create_new(temp.0.join("account")).unwrap());
        let source_path = temp.0.join("source");
        let (mut room, context, _, _) = source(&account, &source_path).await;
        let source_status = room.status().unwrap();
        room.lock();
        let (id, pages) = export(&account, &source_path, context).await;
        let destination = temp.0.join("receiving");
        let (prefix, start) = input(&account, context, id, &pages);
        assert!(start + 2 < pages.len());
        let mut receiver = prefix.create(&destination, limits()).await.unwrap();
        let initial = receiver.progress().unwrap();
        assert!(receiver.append(&pages[start + 1]).await.is_err());
        assert!(receiver.needs_reopen());
        drop(receiver);
        let (prefix, _) = input(&account, context, id, &pages);
        let mut receiver = prefix.resume(&destination).await.unwrap();
        assert_eq!(receiver.progress().unwrap(), initial);
        let retained = receiver.append(&pages[start]).await.unwrap();
        assert_eq!(receiver.append(&pages[start]).await.unwrap(), retained);
        let mut changed = pages[start].clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(receiver.append(&changed).await.is_err());
        assert!(receiver.needs_reopen());
        assert!(receiver.append(&pages[start]).await.is_err());
        drop(receiver);

        let (other_id, other_pages) = export(&account, &source_path, context).await;
        assert_ne!(id, other_id);
        let (wrong, _) = input(&account, context, other_id, &other_pages);
        assert!(wrong.resume(&destination).await.is_err());
        let (prefix, _) = input(&account, context, id, &pages);
        let receiver = prefix.resume(&destination).await.unwrap();
        assert_eq!(receiver.progress().unwrap(), retained);
        drop(receiver);

        let partial = temp.0.join("format-only");
        drop(KernelStore::create_new(&partial, context, limits()).unwrap());
        let format = fs::read(partial.join("FORMAT")).unwrap();
        let (prefix, _) = input(&account, context, id, &pages);
        assert!(prefix.resume(&partial).await.is_err());
        let (prefix, _) = input(&account, context, id, &pages);
        assert!(prefix.create(&partial, limits()).await.is_err());
        assert_eq!(fs::read(partial.join("FORMAT")).unwrap(), format);
        let (prefix, _) = input(&account, context, id, &pages);
        assert!(prefix.resume(&source_path).await.is_err());
        let source = account.open_room(&source_path, context).await.unwrap();
        assert_eq!(source.status().unwrap(), source_status);
    });
}

#[test]
fn archive_view_lock_releases_only_its_store_and_sibling_room_keeps_working() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let source_path = temp.0.join("source");
        let (mut room, context, _, _) = source(&account, &source_path).await;
        room.lock();
        let (id, pages) = export(&account, &source_path, context).await;
        let destination = temp.0.join("archive");
        let (prefix, start) = input(&account, context, id, &pages);
        let mut receiver = prefix.create(&destination, limits()).await.unwrap();
        for page in &pages[start..pages.len() - 1] {
            receiver.append(page).await.unwrap();
        }
        let mut view = receiver.finish(pages.last().unwrap()).await.unwrap();
        let mut sibling = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("sibling"), limits())
            .await
            .unwrap();
        let draft = sibling
            .prepare_message(b"sibling beside archive view")
            .unwrap();
        assert_eq!(sibling.send(op(1), &draft).await.unwrap().sequence(), 1);
        let membership = view.membership().await.unwrap().status();
        view.lock();
        account_busy(&account_path);
        let mut reopened = account
            .open_archive(&destination, context, id, pages.last().unwrap())
            .await
            .unwrap();
        assert_eq!(reopened.membership().await.unwrap().status(), membership);
        let next = sibling
            .prepare_message(b"sibling after archive lock")
            .unwrap();
        assert_eq!(sibling.send(op(2), &next).await.unwrap().sequence(), 2);
        drop(account);
        reopened.lock();
        account_busy(&account_path);
        sibling.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}
