//! Closed synthetic fixture over real MLS, archive authentication and IndexedDB.
//! The seed is deterministically public fixture data, never a product account.
use crate::namespace::{destination, LEGACY};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use vhalla_browser_storage::{
    browser::private_rooms::{IndexedPrivateStore, Limits},
    Namespace,
};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId, Validity},
    recovery::{
        ArchiveExport, ArchiveImport, ArchiveSeal, ArchiveSource, ArchiveSourceReader, ArchiveView,
        MAX_ARCHIVE_PAGE_BYTES,
    },
    storage::ArchiveStore,
    Context, Kernel, OperationId, OwnerDraft, StorageKey,
};
use wasm_bindgen::prelude::*;

const MAX_FIXTURE: usize = 2 * 1024 * 1024;
const MAX_PAGES: usize = 16;
fn error(e: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("archive recovery spike: {e:?}"))
}
fn check(value: bool, message: &str) -> Result<(), JsValue> {
    if value {
        Ok(())
    } else {
        Err(error(message))
    }
}
fn hook(control: &js_sys::Function, name: &str) -> Result<(), JsValue> {
    control.call1(&JsValue::NULL, &name.into()).map(|_| ())
}
fn limits() -> Limits {
    Limits {
        max_records: 32,
        max_record_bytes: MAX_FIXTURE as u64,
    }
}
fn account(namespace: [u8; 32]) -> SigningKey {
    let mut hash = Sha256::new();
    hash.update(b"PUBLIC SYNTHETIC ARCHIVE RECOVERY FIXTURE ONLY\0");
    hash.update(namespace);
    SigningKey::from_bytes(&hash.finalize().into())
}
fn operation(n: u8) -> OperationId {
    OperationId::from_bytes([n; 16]).unwrap()
}
struct Archive {
    id: [u8; 32],
    pages: Vec<Vec<u8>>,
}
struct Fixture {
    namespace: [u8; 32],
    context: Context,
    a: Archive,
    b: Archive,
}
impl Fixture {
    fn key(&self) -> Result<StorageKey, JsValue> {
        StorageKey::derive_for_account(&account(self.namespace), self.context).map_err(error)
    }
    fn source(&self, archive: &Archive) -> Result<(ArchiveSource, usize), JsValue> {
        let key = self.key()?;
        let mut reader = ArchiveSourceReader::new(&key, self.context, archive.id).map_err(error)?;
        for (index, page) in archive.pages.iter().enumerate() {
            if reader.push(page).map_err(error)? {
                return Ok((reader.finish().map_err(error)?, index + 1));
            }
        }
        Err(error("missing authenticated source"))
    }
    async fn begin(
        &self,
        archive: &Archive,
    ) -> Result<(ArchiveImport<IndexedPrivateStore>, usize), JsValue> {
        let (source, first) = self.source(archive)?;
        // Only authenticated source fields choose a destination. Malformed
        // container hints never create even an empty database.
        let namespace = destination(source.context(), source.archive_id());
        let store = IndexedPrivateStore::create_new(namespace, source.context(), limits())
            .await
            .map_err(error)?;
        Ok((
            ArchiveImport::begin(store, &self.key()?, source)
                .await
                .map_err(error)?,
            first,
        ))
    }
    async fn resume(
        &self,
        archive: &Archive,
    ) -> Result<(ArchiveImport<IndexedPrivateStore>, usize), JsValue> {
        let (source, first) = self.source(archive)?;
        let store = IndexedPrivateStore::open(
            destination(source.context(), source.archive_id()),
            source.context(),
        )
        .await
        .map_err(error)?;
        Ok((
            ArchiveImport::resume(store, &self.key()?, source)
                .await
                .map_err(error)?,
            first,
        ))
    }
    async fn view(
        &self,
        archive: &Archive,
        namespace: Namespace,
        head: u64,
    ) -> Result<(), JsValue> {
        let key = self.key()?;
        let seal = ArchiveSeal::from_final_page(
            &key,
            self.context,
            archive.id,
            archive.pages.last().ok_or_else(|| error("missing seal"))?,
        )
        .map_err(error)?;
        let store = IndexedPrivateStore::open(namespace, self.context)
            .await
            .map_err(error)?;
        let mut view = ArchiveView::open(store, &key, seal).await.map_err(error)?;
        check(
            view.membership().await.map_err(error)?.status().outbox_head == head,
            "snapshot head changed",
        )?;
        check(
            view.outbox(0, 16).await.map_err(error)?.records.len() as u64 == head,
            "snapshot records changed",
        )
    }
}
async fn finish(
    mut import: ArchiveImport<IndexedPrivateStore>,
    archive: &Archive,
    from: usize,
) -> Result<(), JsValue> {
    for page in &archive.pages[from..archive.pages.len() - 1] {
        import.append(page).await.map_err(error)?;
    }
    import
        .finish(archive.pages.last().unwrap())
        .await
        .map_err(error)?;
    Ok(())
}
async fn export(
    namespace: Namespace,
    context: Context,
    key: &StorageKey,
) -> Result<Archive, JsValue> {
    let store = IndexedPrivateStore::open(namespace, context)
        .await
        .map_err(error)?;
    let mut export = ArchiveExport::open(store, key, context)
        .await
        .map_err(error)?;
    let id = export.archive_id();
    let mut pages = Vec::new();
    let mut bytes = 0;
    while let Some(page) = export.next_page().await.map_err(error)? {
        bytes += page.encrypted_bytes().len();
        check(
            pages.len() < MAX_PAGES && bytes <= MAX_FIXTURE,
            "fixture export bound",
        )?;
        pages.push(page.encrypted_bytes().to_vec());
    }
    Ok(Archive { id, pages })
}
fn encode(f: &Fixture) -> Vec<u8> {
    let mut out = b"VHARS001".to_vec();
    for value in [
        &f.namespace,
        f.context.scope.room.as_bytes(),
        f.context.scope.anchor.as_bytes(),
        f.context.account.as_bytes(),
        f.context.device.as_bytes(),
    ] {
        out.extend(value);
    }
    for archive in [&f.a, &f.b] {
        out.extend(archive.id);
        out.extend((archive.pages.len() as u32).to_be_bytes());
        for page in &archive.pages {
            out.extend((page.len() as u32).to_be_bytes());
            out.extend(page);
        }
    }
    out
}
fn decode(raw: &[u8]) -> Result<Fixture, JsValue> {
    check(
        raw.len() <= MAX_FIXTURE && raw.get(..8) == Some(b"VHARS001"),
        "fixture frame bound",
    )?;
    let mut offset: usize = 8;
    let mut take = |n: usize| -> Result<&[u8], JsValue> {
        let end = offset
            .checked_add(n)
            .ok_or_else(|| error("fixture overflow"))?;
        let part = raw
            .get(offset..end)
            .ok_or_else(|| error("fixture truncation"))?;
        offset = end;
        Ok(part)
    };
    let namespace = take(32)?.try_into().unwrap();
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(take(32)?.try_into().unwrap()).map_err(error)?,
            anchor: AnchorId::from_bytes(take(32)?.try_into().unwrap()).map_err(error)?,
        },
        account: Key::from_bytes(take(32)?.try_into().unwrap()).map_err(error)?,
        device: Key::from_bytes(take(32)?.try_into().unwrap()).map_err(error)?,
    };
    let mut archives = Vec::new();
    for _ in 0..2 {
        let id = take(32)?.try_into().unwrap();
        let count = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
        check((3..=MAX_PAGES).contains(&count), "fixture page count")?;
        let mut pages = Vec::new();
        for _ in 0..count {
            let length = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
            check(
                length > 0 && length <= MAX_ARCHIVE_PAGE_BYTES,
                "fixture page bound",
            )?;
            pages.push(take(length)?.to_vec());
        }
        archives.push(Archive { id, pages });
    }
    check(offset == raw.len(), "fixture trailing bytes")?;
    let b = archives.pop().unwrap();
    let a = archives.pop().unwrap();
    Ok(Fixture {
        namespace,
        context,
        a,
        b,
    })
}

/// Create two real archived revisions and a retained legacy snapshot, all synthetic.
#[wasm_bindgen]
pub async fn setup(raw_namespace: Vec<u8>) -> Result<Vec<u8>, JsValue> {
    let namespace: [u8; 32] = raw_namespace
        .try_into()
        .map_err(|_| error("namespace length"))?;
    let account = account(namespace);
    let account_key = Key::from_bytes(account.verifying_key().to_bytes()).map_err(error)?;
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let draft = OwnerDraft::new(
        account_key,
        Validity::new(now - 1, now + 3600).map_err(error)?,
    )
    .map_err(error)?;
    let anchor = draft.anchor_request().sign(&account).map_err(error)?;
    let enrollment = draft.enrollment_request().sign(&account).map_err(error)?;
    let context = draft.context(&anchor).map_err(error)?;
    let key = StorageKey::derive_for_account(&account, context).map_err(error)?;
    let store = IndexedPrivateStore::create_new(Namespace::new(namespace), context, limits())
        .await
        .map_err(error)?;
    let mut kernel: Kernel<_> = Box::pin(draft.create(store, &key, enrollment, anchor, now))
        .await
        .map_err(error)?;
    let draft = kernel
        .prepare_message(b"synthetic snapshot A")
        .map_err(error)?;
    Box::pin(kernel.send(operation(1), &draft, now))
        .await
        .map_err(error)?;
    let a = Box::pin(export(Namespace::new(namespace), context, &key)).await?;
    let draft = kernel
        .prepare_message(b"synthetic snapshot B")
        .map_err(error)?;
    Box::pin(kernel.send(operation(2), &draft, now))
        .await
        .map_err(error)?;
    let b = Box::pin(export(Namespace::new(namespace), context, &key)).await?;
    let fixture = Fixture {
        namespace,
        context,
        a,
        b,
    };
    let (source, first) = fixture.source(&fixture.a)?;
    let legacy =
        IndexedPrivateStore::create_new(Namespace::new(LEGACY), source.context(), limits())
            .await
            .map_err(error)?;
    let import = ArchiveImport::begin(legacy, &key, source)
        .await
        .map_err(error)?;
    finish(import, &fixture.a, first).await?;
    let (import, first) = fixture.begin(&fixture.a).await?;
    finish(import, &fixture.a, first).await?;
    fixture.view(&fixture.a, Namespace::new(LEGACY), 1).await?;
    fixture
        .view(&fixture.a, destination(context, fixture.a.id), 1)
        .await?;
    Ok(encode(&fixture))
}

/// Stop after a durable first B record but before returning a completed import.
/// The harness terminates this actual dedicated worker, not only a Rust handle.
#[wasm_bindgen]
pub async fn interrupt(raw: Vec<u8>, committed: js_sys::Function) -> Result<(), JsValue> {
    let fixture = decode(&raw)?;
    let (mut import, first) = fixture.begin(&fixture.b).await?;
    let progress = import
        .append(&fixture.b.pages[first])
        .await
        .map_err(error)?;
    check(progress.records > 0, "no record committed before teardown")?;
    committed.call1(
        &JsValue::NULL,
        &JsValue::from_f64(progress.next_page as f64),
    )?;
    std::future::pending::<()>().await;
    Ok(())
}

/// Reopen after worker death, retry exactly, fault one transaction, finish both snapshots.
#[wasm_bindgen]
pub async fn verify(raw: Vec<u8>, control: js_sys::Function) -> Result<String, JsValue> {
    let fixture = decode(&raw)?;
    hook(&control, "require-strict")?;
    let mut wrong = decode(&raw)?;
    wrong.b.id[0] ^= 1;
    check(
        wrong.begin(&wrong.b).await.is_err(),
        "substituted archive ID accepted",
    )?;
    let mut wrong = decode(&raw)?;
    let mut room = *wrong.context.scope.room.as_bytes();
    room[0] ^= 1;
    wrong.context.scope.room = RoomId::from_bytes(room).map_err(error)?;
    check(
        wrong.begin(&wrong.b).await.is_err(),
        "substituted context accepted",
    )?;
    hook(&control, "assert-no-mutation")?;
    let namespace = destination(fixture.context, fixture.b.id);
    let (mut import, first) = fixture.resume(&fixture.b).await?;
    let before = import.progress().map_err(error)?;
    check(
        before.next_page == (first + 1) as u64 && before.records > 0,
        "durable cursor lost after worker teardown",
    )?;
    let retry = import
        .append(&fixture.b.pages[first])
        .await
        .map_err(error)?;
    check(
        (retry.next_page, retry.records, retry.bytes)
            == (before.next_page, before.records, before.bytes),
        "exact retry changed progress",
    )?;
    let mut observer = IndexedPrivateStore::open(namespace, fixture.context)
        .await
        .map_err(error)?;
    let retained = observer.accounting(fixture.context).await.map_err(error)?;
    drop(observer);
    hook(&control, "deny-writes")?;
    let failed = import.append(&fixture.b.pages[first + 1]).await;
    hook(&control, "require-strict")?;
    check(
        failed.is_err() && import.needs_reopen(),
        "quota refusal did not require reopen",
    )?;
    drop(import);
    let mut observer = IndexedPrivateStore::open(namespace, fixture.context)
        .await
        .map_err(error)?;
    let after = observer.accounting(fixture.context).await.map_err(error)?;
    check(
        after.image == retained.image
            && after.records == retained.records
            && after.bytes == retained.bytes,
        "quota refusal changed retained image or records",
    )?;
    drop(observer);
    let (import, _) = fixture.resume(&fixture.b).await?;
    finish(import, &fixture.b, first + 1).await?;
    fixture.view(&fixture.a, Namespace::new(LEGACY), 1).await?;
    fixture
        .view(&fixture.a, destination(fixture.context, fixture.a.id), 1)
        .await?;
    fixture.view(&fixture.b, namespace, 2).await?;
    Ok("authenticated A/B coexist; legacy A unchanged; substituted ID/context refused before mutation; worker teardown exact retry; quota refusal unchanged; B resumed complete".into())
}
