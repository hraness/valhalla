//! Real MLS and strict IndexedDB. Only post-completion fault delivery is synthetic.
use ed25519_dalek::SigningKey;
use std::{cell::Cell, future::Future, rc::Rc, task::Poll};
use vhalla_browser_storage::{
    browser::private_rooms::{qualification::archive as negative, IndexedPrivateStore, Limits},
    Namespace,
};
use vhalla_private_kernel::{
    protocol::{Key, SignedDeviceEnrollment, SignedRoomAnchor, Validity},
    recovery::{
        ArchiveExport, ArchiveImport, ArchiveSeal, ArchiveSource, ArchiveSourceReader, ArchiveView,
        MAX_ARCHIVE_PAGE_BYTES,
    },
    storage::{Accounting, ArchiveStore, Image, RecordKey, Store, StoreError, StoredRecord},
    Context, Error, Kernel, MemberDraft, OperationId, OutboxEntry, OutboxKind, OwnerDraft, Status,
    StorageKey,
};
use wasm_bindgen::{JsCast, JsValue};

const MAX_FIXTURE_PAGES: usize = 24;
const MAX_FIXTURE_BYTES: usize = 4 * 1024 * 1024;
fn fail(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!(
        "private archive IndexedDB qualification: {error:?}"
    ))
}
fn ensure(value: bool, message: &str) -> Result<(), JsValue> {
    if value {
        Ok(())
    } else {
        Err(fail(message))
    }
}
fn hook(control: &js_sys::Function, mode: &str) -> Result<(), JsValue> {
    control.call1(&JsValue::NULL, &mode.into()).map(|_| ())
}
fn operation(n: u64) -> OperationId {
    let mut raw = [0; 16];
    raw[8..].copy_from_slice(&n.to_be_bytes());
    OperationId::from_bytes(raw).expect("nonzero fixture operation")
}
fn sibling(namespace: Namespace, tag: u8) -> Namespace {
    let mut raw = *namespace.identifier();
    raw[0] ^= tag;
    Namespace::new(raw)
}
fn random() -> Result<[u8; 32], JsValue> {
    let crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into())?;
    let get =
        js_sys::Reflect::get(&crypto, &"getRandomValues".into())?.dyn_into::<js_sys::Function>()?;
    let bytes = js_sys::Uint8Array::new_with_length(32);
    get.call1(&crypto, &bytes)?;
    let mut raw = [0; 32];
    bytes.copy_to(&mut raw);
    Ok(raw)
}
fn account() -> Result<SigningKey, JsValue> {
    Ok(SigningKey::from_bytes(&random()?))
}
fn public(account: &SigningKey) -> Result<Key, JsValue> {
    Key::from_bytes(account.verifying_key().to_bytes()).map_err(fail)
}
fn validity(now: u64) -> Result<Validity, JsValue> {
    Validity::new(now - 30, now + 7200).map_err(fail)
}
fn limits() -> Limits {
    Limits {
        max_records: 64,
        max_record_bytes: 8 * 1024 * 1024,
    }
}

struct Device {
    kernel: Kernel<IndexedPrivateStore>,
    key: StorageKey,
    context: Context,
}
struct Owner {
    device: Device,
    account: SigningKey,
    anchor: SignedRoomAnchor,
    enrollment: SignedDeviceEnrollment,
    now: u64,
}
async fn owner(namespace: Namespace) -> Result<Owner, JsValue> {
    let account = account()?;
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let draft = OwnerDraft::new(public(&account)?, validity(now)?).map_err(fail)?;
    let anchor = draft.anchor_request().sign(&account).map_err(fail)?;
    let enrollment = draft.enrollment_request().sign(&account).map_err(fail)?;
    let context = draft.context(&anchor).map_err(fail)?;
    let key = StorageKey::derive_for_account(&account, context).map_err(fail)?;
    let store = IndexedPrivateStore::create_new(namespace, context, limits())
        .await
        .map_err(fail)?;
    let kernel = Box::pin(draft.create(store, &key, enrollment.clone(), anchor.clone(), now))
        .await
        .map_err(fail)?;
    Ok(Owner {
        device: Device {
            kernel,
            key,
            context,
        },
        account,
        anchor,
        enrollment,
        now,
    })
}
async fn member(namespace: Namespace, owner: &Owner) -> Result<Device, JsValue> {
    let account = account()?;
    let draft = MemberDraft::new(
        owner.device.context.scope,
        owner.anchor.clone(),
        owner.enrollment.clone(),
        public(&account)?,
        validity(owner.now)?,
        owner.now,
    )
    .map_err(fail)?;
    let enrollment = draft.enrollment_request().sign(&account).map_err(fail)?;
    let context = draft.context();
    let key = StorageKey::derive_for_account(&account, context).map_err(fail)?;
    let store = IndexedPrivateStore::create_new(namespace, context, limits())
        .await
        .map_err(fail)?;
    let kernel = Box::pin(draft.initialize(store, &key, enrollment, owner.now))
        .await
        .map_err(fail)?;
    Ok(Device {
        kernel,
        key,
        context,
    })
}
async fn join(owner: &mut Owner, member: &mut Device) -> Result<(), JsValue> {
    let secret = Box::pin(owner.device.kernel.create_contact_offer(
        operation(1),
        member.context.account,
        validity(owner.now)?,
        owner.now,
    ))
    .await
    .map_err(fail)?;
    let request = Box::pin(member.kernel.contact_request(
        operation(1),
        secret.confidential_bytes(),
        owner.now,
    ))
    .await
    .map_err(fail)?;
    let response = Box::pin(owner.device.kernel.accept_contact(
        operation(2),
        request.bytes(),
        validity(owner.now)?,
        owner.now,
    ))
    .await
    .map_err(fail)?;
    Box::pin(member.kernel.join_contact(response.bytes(), owner.now))
        .await
        .map_err(fail)?;
    ensure(
        owner.device.kernel.status().members == 2
            && owner.device.kernel.status().roster == member.kernel.status().roster,
        "real confidential join did not establish both members",
    )
}
async fn traffic(owner: &mut Owner, member: &mut Device) -> Result<(), JsValue> {
    let draft = owner
        .device
        .kernel
        .prepare_message(b"synthetic archive owner message")
        .map_err(fail)?;
    let sent = Box::pin(owner.device.kernel.send(operation(3), &draft, owner.now))
        .await
        .map_err(fail)?;
    Box::pin(member.kernel.receive(sent.bytes(), owner.now))
        .await
        .map_err(fail)?;
    let draft = member
        .kernel
        .prepare_message(b"synthetic archive member message")
        .map_err(fail)?;
    let sent = Box::pin(member.kernel.send(operation(2), &draft, owner.now))
        .await
        .map_err(fail)?;
    Box::pin(owner.device.kernel.receive(sent.bytes(), owner.now))
        .await
        .map_err(fail)?;
    let enrollment = owner
        .device
        .kernel
        .owner_renewal_request(validity(owner.now + 1)?)
        .map_err(fail)?
        .sign(&owner.account)
        .map_err(fail)?;
    let update = Box::pin(
        owner
            .device
            .kernel
            .renew_owner(operation(4), enrollment, owner.now + 1),
    )
    .await
    .map_err(fail)?;
    Box::pin(member.kernel.apply_control(update.bytes(), owner.now + 1))
        .await
        .map_err(fail)?;
    ensure(
        owner.device.kernel.status().control_floor == member.kernel.status().control_floor,
        "renewed control not accepted by actual member",
    )
}

struct Case {
    namespace: Namespace,
    context: Context,
    foreign: Context,
    key: StorageKey,
    status: Status,
    image: Image,
    count: u64,
    bytes: u64,
    id: [u8; 32],
    pages: Vec<Vec<u8>>,
    first_record: usize,
    expected: Vec<OutboxEntry>,
}
impl Case {
    fn source(&self) -> Result<ArchiveSource, JsValue> {
        let mut reader =
            ArchiveSourceReader::new(&self.key, self.context, self.id).map_err(fail)?;
        for page in &self.pages[..self.first_record] {
            reader.push(page).map_err(fail)?;
        }
        reader.finish().map_err(fail)
    }
    fn final_page(&self) -> &[u8] {
        self.pages.last().expect("checked complete fixture")
    }
    fn seal(&self) -> Result<ArchiveSeal, JsValue> {
        ArchiveSeal::from_final_page(&self.key, self.context, self.id, self.final_page())
            .map_err(fail)
    }
    async fn store(&self, namespace: Namespace) -> Result<IndexedPrivateStore, JsValue> {
        IndexedPrivateStore::open(namespace, self.context)
            .await
            .map_err(fail)
    }
    async fn begin(
        &self,
        namespace: Namespace,
        limits: Limits,
    ) -> Result<ArchiveImport<Backend>, JsValue> {
        let inner = IndexedPrivateStore::create_new(namespace, self.context, limits)
            .await
            .map_err(fail)?;
        ArchiveImport::begin(Backend::new(inner), &self.key, self.source()?)
            .await
            .map_err(fail)
    }
    async fn resume(&self, namespace: Namespace) -> Result<ArchiveImport<Backend>, JsValue> {
        ArchiveImport::resume(
            Backend::new(self.store(namespace).await?),
            &self.key,
            self.source()?,
        )
        .await
        .map_err(fail)
    }
    async fn append_all(
        &self,
        import: &mut ArchiveImport<Backend>,
        from: usize,
    ) -> Result<(), JsValue> {
        for page in &self.pages[from..self.pages.len() - 1] {
            import.append(page).await.map_err(fail)?;
        }
        Ok(())
    }
}
async fn source(namespace: Namespace) -> Result<Case, JsValue> {
    let mut owner = Box::pin(owner(namespace)).await?;
    let mut member = Box::pin(member(namespace, &owner)).await?;
    Box::pin(join(&mut owner, &mut member)).await?;
    Box::pin(traffic(&mut owner, &mut member)).await?;
    let foreign = member.context;
    drop(member);
    let expected = owner
        .device
        .kernel
        .outbox(0, 16)
        .await
        .map_err(fail)?
        .records;
    ensure(
        matches!(
            expected.first(),
            Some(OutboxEntry::ConfidentialOffer { .. })
        ),
        "source secret offer not redacted",
    )?;
    ensure(
        expected.len() == 4 && expected[3].kind() == OutboxKind::OwnerUpdate,
        "source artifact sequence",
    )?;
    let status = owner.device.kernel.status();
    let Owner {
        device: Device {
            kernel,
            key,
            context,
        },
        ..
    } = owner;
    let mut store = kernel.into_store();
    let accounting = store.accounting(context).await.map_err(fail)?;
    let image = accounting
        .image
        .ok_or_else(|| fail("source image absent"))?;
    ensure(
        accounting.records == 13,
        "source record/index/control accounting",
    )?;
    let mut export = ArchiveExport::open(store, &key, context)
        .await
        .map_err(fail)?;
    let id = export.archive_id();
    let mut pages = Vec::new();
    let mut total = 0usize;
    while let Some(page) = export.next_page().await.map_err(fail)? {
        ensure(
            page.encrypted_bytes().len() <= MAX_ARCHIVE_PAGE_BYTES,
            "oversized page",
        )?;
        total = total
            .checked_add(page.encrypted_bytes().len())
            .ok_or_else(|| fail("fixture bytes overflow"))?;
        ensure(
            total <= MAX_FIXTURE_BYTES && pages.len() < MAX_FIXTURE_PAGES,
            "synthetic fixture exceeded bounded evidence",
        )?;
        pages.push(page.encrypted_bytes().to_vec());
    }
    drop(export);
    let mut reader = ArchiveSourceReader::new(&key, context, id).map_err(fail)?;
    let mut first_record = None;
    for (index, page) in pages.iter().enumerate() {
        if reader.push(page).map_err(fail)? {
            first_record = Some(index + 1);
            break;
        }
    }
    reader.finish().map_err(fail)?;
    let first_record = first_record.ok_or_else(|| fail("missing image completion"))?;
    ensure(
        first_record + 2 < pages.len(),
        "fixture lacks record pages and final",
    )?;
    Ok(Case {
        namespace,
        context,
        foreign,
        key,
        status,
        image,
        count: accounting.records,
        bytes: accounting.bytes,
        id,
        pages,
        first_record,
        expected,
    })
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    After,
    PendingAfter,
}
/// Forward every operation to the actual adapter. Uncertainty/cancellation is
/// delivered only after a confirmed strict IDB commit, never instead of one.
struct Backend {
    inner: IndexedPrivateStore,
    fault: Rc<Cell<Fault>>,
    committed: Rc<Cell<bool>>,
}
impl Backend {
    fn new(inner: IndexedPrivateStore) -> Self {
        Self {
            inner,
            fault: Rc::new(Cell::new(Fault::None)),
            committed: Rc::new(Cell::new(false)),
        }
    }
}
impl Store for Backend {
    async fn load(&mut self, context: Context) -> Result<Option<Image>, StoreError> {
        self.inner.load(context).await
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> Result<Option<StoredRecord>, StoreError> {
        self.inner.read(context, key).await
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> Result<(), StoreError> {
        self.inner.publish(context, expected, next, records).await?;
        self.committed.set(true);
        match self.fault.replace(Fault::None) {
            Fault::After => Err(StoreError::Uncertain),
            Fault::PendingAfter => std::future::pending().await,
            Fault::None => Ok(()),
        }
    }
}
impl ArchiveStore for Backend {
    async fn accounting(&mut self, context: Context) -> Result<Accounting, StoreError> {
        self.inner.accounting(context).await
    }
}
async fn cancel_after_commit<T>(
    future: impl Future<Output = T>,
    committed: Rc<Cell<bool>>,
) -> Result<(), JsValue> {
    let mut pending = Box::pin(future);
    std::future::poll_fn(|cx| match pending.as_mut().poll(cx) {
        Poll::Pending if committed.get() => Poll::Ready(Ok(())),
        Poll::Pending => Poll::Pending,
        Poll::Ready(_) => Poll::Ready(Err(fail(
            "cancellation fixture returned instead of holding after real commit",
        ))),
    })
    .await?;
    drop(pending);
    Ok(())
}
async fn no_live(case: &Case, namespace: Namespace) -> Result<(), JsValue> {
    ensure(
        Kernel::open(case.store(namespace).await?, &case.key, case.context)
            .await
            .is_err(),
        "inert/archive image reopened as live kernel",
    )
}
async fn retained(
    case: &Case,
    namespace: Namespace,
    image: &Image,
    count: u64,
    bytes: u64,
) -> Result<(), JsValue> {
    let value = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        value.image.as_ref() == Some(image) && value.records == count && value.bytes == bytes,
        "exact retained image/accounting changed",
    )
}
async fn view(case: &Case, namespace: Namespace) -> Result<(), JsValue> {
    let mut view = ArchiveView::open(
        Backend::new(case.store(namespace).await?),
        &case.key,
        case.seal()?,
    )
    .await
    .map_err(fail)?;
    ensure(
        view.membership().await.map_err(fail)?.status() == case.status,
        "archive membership differs",
    )?;
    let first = view.outbox(0, 1).await.map_err(fail)?;
    ensure(
        first.head == 4
            && first.next == Some(1)
            && first.records.len() == 1
            && first.records[0].artifact().is_none(),
        "archive secret issuance was omitted or exposed",
    )?;
    let rest = view.outbox(1, 16).await.map_err(fail)?;
    ensure(
        rest.records.len() == 3 && rest.next.is_none(),
        "archive outbox continuation",
    )?;
    for (actual, expected) in rest.records.iter().zip(&case.expected[1..]) {
        ensure(
            actual.sequence() == expected.sequence()
                && actual.operation() == expected.operation()
                && actual.kind() == expected.kind()
                && actual.artifact().map(|a| a.bytes()) == expected.artifact().map(|a| a.bytes()),
            "archive changed retained ciphertext",
        )?;
    }
    let inbox = view.inbox(0, 16).await.map_err(fail)?;
    ensure(
        inbox.head == 1
            && inbox.records.len() == 1
            && inbox.records[0].body() == b"synthetic archive member message",
        "archive lost retained plaintext inbox",
    )?;
    drop(view);
    no_live(case, namespace).await
}

async fn complete(case: &Case, namespace: Namespace) -> Result<(), JsValue> {
    let mut import = case.begin(namespace, limits()).await?;
    no_live(case, namespace).await?;
    case.append_all(&mut import, case.first_record).await?;
    no_live(case, namespace).await?;
    drop(import.finish(case.final_page()).await.map_err(fail)?);
    view(case, namespace).await?;
    let snapshot = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        snapshot.records == case.count && snapshot.bytes == case.bytes,
        "complete archive lost exact accounting",
    )?;
    retained(case, case.namespace, &case.image, case.count, case.bytes).await
}

async fn faults(
    case: &Case,
    namespace: Namespace,
    fault: Fault,
    control: &js_sys::Function,
) -> Result<(), JsValue> {
    let inner = IndexedPrivateStore::create_new(namespace, case.context, limits())
        .await
        .map_err(fail)?;
    let backend = Backend::new(inner);
    let injected = backend.fault.clone();
    let committed = backend.committed.clone();
    let mut import = ArchiveImport::begin(backend, &case.key, case.source()?)
        .await
        .map_err(fail)?;
    let pristine = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    committed.set(false);
    injected.set(fault);
    let first = &case.pages[case.first_record];
    match fault {
        Fault::After => ensure(
            import.append(first).await.is_err(),
            "post-commit append uncertainty accepted",
        )?,
        Fault::PendingAfter => cancel_after_commit(import.append(first), committed.clone()).await?,
        Fault::None => return Err(fail("fault scenario has no fault")),
    }
    ensure(
        committed.get() && import.needs_reopen(),
        "append fault preceded actual strict completion or failed to latch",
    )?;
    ensure(
        matches!(import.progress(), Err(Error::NeedsReopen)),
        "poisoned import returned healthy progress",
    )?;
    drop(import);
    let after = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        after.image != pristine.image && after.records == 2 && after.bytes > 0,
        "append did not durably publish actual pair",
    )?;
    let backend = Backend::new(case.store(namespace).await?);
    let injected = backend.fault.clone();
    let committed = backend.committed.clone();
    let mut import = ArchiveImport::resume(backend, &case.key, case.source()?)
        .await
        .map_err(fail)?;
    let before_retry = import.progress().map_err(fail)?;
    hook(control, "deny-writes")?;
    ensure(
        import.append(first).await.map_err(fail)? == before_retry,
        "exact append retry changed cursor",
    )?;
    hook(control, "assert-no-write")?;
    hook(control, "require-strict")?;
    retained(
        case,
        namespace,
        after.image.as_ref().ok_or_else(|| fail("append image"))?,
        after.records,
        after.bytes,
    )
    .await?;
    case.append_all(&mut import, case.first_record + 1).await?;
    no_live(case, namespace).await?;
    let before_finish = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    committed.set(false);
    injected.set(fault);
    match fault {
        Fault::After => ensure(
            import.finish(case.final_page()).await.is_err(),
            "post-commit finish uncertainty accepted",
        )?,
        Fault::PendingAfter => {
            cancel_after_commit(import.finish(case.final_page()), committed.clone()).await?
        }
        Fault::None => return Err(fail("finish scenario has no fault")),
    }
    ensure(
        committed.get(),
        "finish fault preceded actual strict completion",
    )?;
    let after_finish = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        after_finish.image != before_finish.image
            && after_finish.records == case.count
            && after_finish.bytes == case.bytes,
        "finish did not cross exact actual archive publication",
    )?;
    ensure(
        case.resume(namespace).await.is_err(),
        "final archive reopened as receiving state",
    )?;
    view(case, namespace).await?;
    retained(
        case,
        namespace,
        after_finish
            .image
            .as_ref()
            .ok_or_else(|| fail("finished image"))?,
        case.count,
        case.bytes,
    )
    .await
}

async fn custody_and_bounds(
    case: &Case,
    namespace: Namespace,
    control: &js_sys::Function,
) -> Result<(), JsValue> {
    let inner = IndexedPrivateStore::create_new(namespace, case.context, limits())
        .await
        .map_err(fail)?;
    let other = StorageKey::from_secret(random()?).map_err(fail)?;
    hook(control, "deny-writes")?;
    ensure(
        matches!(
            ArchiveImport::begin(Backend::new(inner), &other, case.source()?).await,
            Err(Error::Authentication)
        ),
        "wrong source key did not refuse before publication",
    )?;
    let mut foreign = ArchiveSourceReader::new(&case.key, case.foreign, case.id).map_err(fail)?;
    ensure(
        foreign.push(&case.pages[0]).is_err(),
        "foreign full context accepted source",
    )?;
    let mut changed = case.pages[0].clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let mut reader = ArchiveSourceReader::new(&case.key, case.context, case.id).map_err(fail)?;
    ensure(
        reader.push(&changed).is_err(),
        "tampered page authenticated",
    )?;
    ensure(
        matches!(reader.push(&case.pages[0]), Err(Error::NeedsReopen)),
        "failed source reader reused",
    )?;
    let pristine = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        pristine.image.is_none() && pristine.records == 0 && pristine.bytes == 0,
        "wrong-key source created destination state",
    )?;
    hook(control, "assert-no-write")?;
    hook(control, "require-strict")?;

    let wrong_order = sibling(case.namespace, 11);
    let mut import = case.begin(wrong_order, limits()).await?;
    let before = case
        .store(wrong_order)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    ensure(
        import
            .append(&case.pages[case.first_record + 1])
            .await
            .is_err(),
        "record gap accepted",
    )?;
    drop(import);
    let import = case.resume(wrong_order).await?;
    ensure(
        import.finish(case.final_page()).await.is_err(),
        "incomplete prefix accepted final seal",
    )?;
    retained(
        case,
        wrong_order,
        before
            .image
            .as_ref()
            .ok_or_else(|| fail("receiving image"))?,
        0,
        0,
    )
    .await?;
    no_live(case, wrong_order).await
}

async fn durability_refusal(
    case: &Case,
    namespace: Namespace,
    control: &js_sys::Function,
) -> Result<(), JsValue> {
    let mut import = case.begin(namespace, limits()).await?;
    let before = case
        .store(namespace)
        .await?
        .accounting(case.context)
        .await
        .map_err(fail)?;
    // The maintained harness makes the actual IDB transaction report relaxed
    // durability. The real adapter must abort before queuing any mutation.
    hook(control, "ignored-options")?;
    ensure(
        import.append(&case.pages[case.first_record]).await.is_err(),
        "relaxed durability claimed archive publication",
    )?;
    ensure(
        import.needs_reopen(),
        "durability refusal did not latch archive owner",
    )?;
    hook(control, "assert-no-mutation")?;
    hook(control, "require-strict")?;
    drop(import);
    retained(
        case,
        namespace,
        before
            .image
            .as_ref()
            .ok_or_else(|| fail("pre-refusal image"))?,
        0,
        0,
    )
    .await?;
    let mut import = case.resume(namespace).await?;
    case.append_all(&mut import, case.first_record).await?;
    drop(import.finish(case.final_page()).await.map_err(fail)?);
    view(case, namespace).await
}

async fn quotas(case: &Case, control: &js_sys::Function) -> Result<(), JsValue> {
    for (tag, limit) in [
        (
            7,
            Limits {
                max_records: case.count - 1,
                max_record_bytes: case.bytes,
            },
        ),
        (
            8,
            Limits {
                max_records: case.count,
                max_record_bytes: case.bytes - 1,
            },
        ),
    ] {
        let namespace = sibling(case.namespace, tag);
        let inner = IndexedPrivateStore::create_new(namespace, case.context, limit)
            .await
            .map_err(fail)?;
        hook(control, "deny-writes")?;
        ensure(
            matches!(
                ArchiveImport::begin(Backend::new(inner), &case.key, case.source()?).await,
                Err(Error::Bounds)
            ),
            "source capacity was not checked before writes",
        )?;
        let unused = case
            .store(namespace)
            .await?
            .accounting(case.context)
            .await
            .map_err(fail)?;
        ensure(
            unused.image.is_none() && unused.records == 0 && unused.bytes == 0,
            "quota refusal changed pristine destination",
        )?;
        hook(control, "assert-no-write")?;
        hook(control, "require-strict")?;
    }
    let namespace = sibling(case.namespace, 9);
    let limit = Limits {
        max_records: case.count,
        max_record_bytes: case.bytes,
    };
    let mut import = case.begin(namespace, limit).await?;
    case.append_all(&mut import, case.first_record).await?;
    drop(import.finish(case.final_page()).await.map_err(fail)?);
    view(case, namespace).await?;
    let mut store = case.store(namespace).await?;
    let full = store.accounting(case.context).await.map_err(fail)?;
    let image = full
        .image
        .as_ref()
        .ok_or_else(|| fail("quota archive image"))?;
    let extra =
        StoredRecord::from_bytes(RecordKey::Operation(operation(999)), &[19; 40]).map_err(fail)?;
    ensure(
        matches!(
            store
                .publish(case.context, Some(image), image, &[extra])
                .await,
            Err(StoreError::Refused)
        ),
        "full archive quota accepted additional record",
    )?;
    drop(store);
    retained(case, namespace, image, case.count, case.bytes).await
}

async fn missing_and_extra(case: &Case) -> Result<(), JsValue> {
    // Preserve each negative fixture separately. Never repair or erase its damage.
    negative::missing_record_refuses_export(case.namespace, case.context, &case.key).await?;
    let extra_namespace = sibling(case.namespace, 12);
    let extra = Box::pin(owner(extra_namespace)).await?;
    let context = extra.device.context;
    let key = extra.device.key;
    drop(extra.device.kernel);
    negative::extra_record_refuses_export(extra_namespace, context, &key).await
}

/// Closed fixture path; the caller is the maintained loopback-only runner with
/// a fresh Chromium profile and cryptographically random namespace per realm.
/// Only bounded synthetic page ciphertext is retained here; production export
/// itself never accumulates a lifetime store or gains a live restore operation.
pub async fn run(namespace: Namespace, control: js_sys::Function) -> Result<String, JsValue> {
    hook(&control, "require-strict")?;
    let case = Box::pin(source(namespace)).await?;
    Box::pin(complete(&case, sibling(namespace, 1))).await?;
    Box::pin(faults(&case, sibling(namespace, 2), Fault::After, &control)).await?;
    Box::pin(faults(
        &case,
        sibling(namespace, 3),
        Fault::PendingAfter,
        &control,
    ))
    .await?;
    Box::pin(custody_and_bounds(&case, sibling(namespace, 4), &control)).await?;
    Box::pin(durability_refusal(&case, sibling(namespace, 5), &control)).await?;
    Box::pin(quotas(&case, &control)).await?;
    retained(&case, case.namespace, &case.image, case.count, case.bytes).await?;
    Box::pin(missing_and_extra(&case)).await?;
    hook(&control, "finish")?;
    Ok("real MLS/IndexedDB archive: confidential group source, secret-offer metadata, signed controls, exact paged import/read-only view, live-open refusal, wrong source custody/context, strict-durability refusal, real post-commit uncertainty/cancellation and exact reopen, missing/extra evidence, and exact capacity passed".into())
}
