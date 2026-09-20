//! Real cryptography and real IndexedDB. Only fault delivery is synthetic.
use ed25519_dalek::SigningKey;
use std::{cell::Cell, future::Future, rc::Rc, task::Poll};
use vhalla_browser_storage::{
    browser::private_rooms::{IndexedPrivateStore, Limits},
    Namespace,
};
use vhalla_private_kernel::{
    protocol::{ControlFloor, Key, SignedDeviceEnrollment, SignedRoomAnchor, Validity},
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    CommittedOutbox, ConfidentialContactOffer, ContactBootstrap, Context, Error, Kernel,
    MemberDraft, OperationId, OutboxKind, OwnerDraft, Phase, StorageKey,
};
use wasm_bindgen::JsValue;
use zeroize::Zeroizing;

fn fail(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("private MLS IndexedDB qualification: {error:?}"))
}
fn ensure(value: bool, message: &str) -> Result<(), JsValue> {
    if value {
        Ok(())
    } else {
        Err(fail(message))
    }
}
fn op(n: u64) -> OperationId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&n.to_be_bytes());
    OperationId::from_bytes(bytes).unwrap()
}
fn key(account: &SigningKey) -> Key {
    Key::from_bytes(account.verifying_key().to_bytes()).unwrap()
}
fn validity(now: u64) -> Validity {
    Validity::new(now - 30, now + 7200).unwrap()
}
fn limits(records: u64) -> Limits {
    Limits {
        max_records: records,
        max_record_bytes: 16 * 1024 * 1024,
    }
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Before,
    After,
    PendingAfter,
}
/// Test-only wrapper around the actual typed backend. No injected callback runs
/// inside an IDB transaction. After faults occur only after its strict completion.
struct Backend {
    inner: IndexedPrivateStore,
    fault: Rc<Cell<Fault>>,
    committed: Rc<Cell<bool>>,
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
        let fault = self.fault.replace(Fault::None);
        if matches!(fault, Fault::Before) {
            return Err(StoreError::Refused);
        }
        self.inner.publish(context, expected, next, records).await?;
        self.committed.set(true);
        match fault {
            Fault::After => Err(StoreError::Uncertain),
            Fault::PendingAfter => std::future::pending().await,
            _ => Ok(()),
        }
    }
}
struct Device {
    session: Option<Kernel<Backend>>,
    namespace: Namespace,
    context: Context,
    key: StorageKey,
    fault: Rc<Cell<Fault>>,
    committed: Rc<Cell<bool>>,
}
impl Device {
    fn session(&mut self) -> &mut Kernel<Backend> {
        self.session.as_mut().unwrap()
    }
    fn set_fault(&self, fault: Fault) {
        self.fault.set(fault);
        self.committed.set(false);
    }
    async fn reopen(&mut self) -> Result<(), JsValue> {
        // End actual connection custody before opening the retained namespace.
        drop(self.session.take().map(Kernel::into_store));
        let inner = IndexedPrivateStore::open(self.namespace, self.context)
            .await
            .map_err(fail)?;
        self.set_fault(Fault::None);
        let backend = Backend {
            inner,
            fault: self.fault.clone(),
            committed: self.committed.clone(),
        };
        self.session = Some(
            Kernel::open(backend, &self.key, self.context)
                .await
                .map_err(fail)?,
        );
        Ok(())
    }
    async fn image(&self) -> Result<Image, JsValue> {
        let mut store = IndexedPrivateStore::open(self.namespace, self.context)
            .await
            .map_err(fail)?;
        store
            .load(self.context)
            .await
            .map_err(fail)?
            .ok_or_else(|| fail("missing current image"))
    }
    async fn absent(&self, key: RecordKey) -> Result<bool, JsValue> {
        let mut store = IndexedPrivateStore::open(self.namespace, self.context)
            .await
            .map_err(fail)?;
        Ok(store.read(self.context, key).await.map_err(fail)?.is_none())
    }
    async fn send(&mut self, id: u64, body: &[u8], now: u64) -> Result<CommittedOutbox, Error> {
        let draft = self.session().prepare_message(body)?;
        self.session().send(op(id), &draft, now).await
    }
}

struct Pair {
    owner: Device,
    member: Device,
    anchor: SignedRoomAnchor,
    owner_enrollment: SignedDeviceEnrollment,
    now: u64,
}
impl Pair {
    async fn fresh(namespace: Namespace, owner_records: u64) -> Result<Self, JsValue> {
        let now = (js_sys::Date::now() / 1000.0) as u64;
        // Fixed synthetic accounts/wrapping secrets remain only in this test.
        // Device and MLS randomness come from actual browser CSPRNG paths.
        let account = SigningKey::from_bytes(&[71; 32]);
        let draft = OwnerDraft::new(key(&account), validity(now)).map_err(fail)?;
        let anchor = draft.anchor_request().sign(&account).map_err(fail)?;
        let enrollment = draft.enrollment_request().sign(&account).map_err(fail)?;
        let context = draft.context(&anchor).map_err(fail)?;
        let wrapping = StorageKey::from_secret([81; 32]).map_err(fail)?;
        let fault = Rc::new(Cell::new(Fault::None));
        let committed = Rc::new(Cell::new(false));
        let inner = IndexedPrivateStore::create_new(namespace, context, limits(owner_records))
            .await
            .map_err(fail)?;
        let backend = Backend {
            inner,
            fault: fault.clone(),
            committed: committed.clone(),
        };
        let session = draft
            .create(backend, &wrapping, enrollment.clone(), anchor.clone(), now)
            .await
            .map_err(fail)?;
        let owner = Device {
            session: Some(session),
            namespace,
            context,
            key: wrapping,
            fault,
            committed,
        };
        let member = Self::new_member(namespace, &anchor, &enrollment, 72, now).await?;
        Ok(Self {
            owner,
            member,
            anchor,
            owner_enrollment: enrollment,
            now,
        })
    }
    async fn new_member(
        namespace: Namespace,
        anchor: &SignedRoomAnchor,
        owner: &SignedDeviceEnrollment,
        seed: u8,
        now: u64,
    ) -> Result<Device, JsValue> {
        let account = SigningKey::from_bytes(&[seed; 32]);
        let draft = MemberDraft::new(
            anchor.verify().map_err(fail)?.scope(),
            anchor.clone(),
            owner.clone(),
            key(&account),
            validity(now),
            now,
        )
        .map_err(fail)?;
        let enrollment = draft.enrollment_request().sign(&account).map_err(fail)?;
        let context = draft.context();
        let wrapping = StorageKey::from_secret([seed + 10; 32]).map_err(fail)?;
        let fault = Rc::new(Cell::new(Fault::None));
        let committed = Rc::new(Cell::new(false));
        let inner = IndexedPrivateStore::create_new(namespace, context, limits(1000))
            .await
            .map_err(fail)?;
        let backend = Backend {
            inner,
            fault: fault.clone(),
            committed: committed.clone(),
        };
        let session = draft
            .initialize(backend, &wrapping, enrollment, now)
            .await
            .map_err(fail)?;
        Ok(Device {
            session: Some(session),
            namespace,
            context,
            key: wrapping,
            fault,
            committed,
        })
    }
    async fn join(&mut self) -> Result<(Vec<u8>, Vec<u8>, ControlFloor), JsValue> {
        let package = self
            .member
            .session()
            .key_package(op(1), self.now)
            .await
            .map_err(fail)?;
        let invitation = self
            .owner
            .session()
            .invite(op(1), package.bytes(), validity(self.now), self.now)
            .await
            .map_err(fail)?;
        self.member
            .session()
            .join(invitation.bytes(), self.now)
            .await
            .map_err(fail)?;
        let page = self
            .owner
            .session()
            .encrypted_controls(ControlFloor::new(0, None).map_err(fail)?, 1)
            .await
            .map_err(fail)?;
        ensure(page.records.len() == 1, "initial control not indexed")?;
        Ok((
            package.bytes().to_vec(),
            invitation.bytes().to_vec(),
            page.head,
        ))
    }
}

// Keep each real scenario small enough for the standard 1 MiB WASM stack.
// Boxing these bounded phases prevents the entry future from embedding every
// phase's large unoptimized poll temporary at once. No test or budget is removed.
async fn lifecycle(namespace: Namespace) -> Result<(), JsValue> {
    let mut pair = Box::pin(Pair::fresh(namespace, 1000)).await?;
    let first_floor = Box::pin(lifecycle_join(&mut pair)).await?;
    let reply = Box::pin(lifecycle_traffic(&mut pair)).await?;
    let (mut third, third_floor) =
        Box::pin(lifecycle_add(&mut pair, namespace, first_floor)).await?;
    Box::pin(lifecycle_remove(&mut pair, &mut third, third_floor, &reply)).await
}

async fn lifecycle_join(pair: &mut Pair) -> Result<ControlFloor, JsValue> {
    let now = pair.now;
    let (package, invitation, first_floor) = pair.join().await?;
    pair.owner.reopen().await?;
    pair.member.reopen().await?;
    ensure(
        pair.owner
            .session()
            .invite(op(1), &package, validity(now), now)
            .await
            .map_err(fail)?
            .bytes()
            == invitation,
        "invite retry changed after reopen",
    )?;
    ensure(
        pair.member
            .session()
            .key_package(op(1), now)
            .await
            .map_err(fail)?
            .bytes()
            == package,
        "key package retry changed",
    )?;
    ensure(
        pair.member
            .session()
            .join(&invitation, now)
            .await
            .map_err(fail)?
            .phase
            == Phase::MemberJoined,
        "join retry failed",
    )?;

    Ok(first_floor)
}

async fn lifecycle_traffic(pair: &mut Pair) -> Result<CommittedOutbox, JsValue> {
    let now = pair.now;
    let draft = pair
        .owner
        .session()
        .prepare_message(b"inert private puzzle")
        .map_err(fail)?;
    let sent = pair
        .owner
        .session()
        .send(op(2), &draft, now)
        .await
        .map_err(fail)?;
    let got = pair
        .member
        .session()
        .receive(sent.bytes(), now)
        .await
        .map_err(fail)?;
    ensure(
        got.body() == b"inert private puzzle" && got.sender() == pair.owner.context.device,
        "inbound body/sender differs",
    )?;
    pair.owner.reopen().await?;
    pair.member.reopen().await?;
    ensure(
        pair.owner
            .session()
            .send(op(2), &draft, now)
            .await
            .map_err(fail)?
            .bytes()
            == sent.bytes(),
        "sender regenerated retry ciphertext",
    )?;
    ensure(
        pair.member
            .session()
            .receive(sent.bytes(), now)
            .await
            .map_err(fail)?
            .sequence()
            == got.sequence(),
        "receiver advanced duplicate",
    )?;
    let reply = pair
        .member
        .send(2, b"inert private answer", now)
        .await
        .map_err(fail)?;
    ensure(
        pair.owner
            .session()
            .receive(reply.bytes(), now)
            .await
            .map_err(fail)?
            .body()
            == b"inert private answer",
        "bidirectional reply failed",
    )?;

    Ok(reply)
}

async fn lifecycle_add(
    pair: &mut Pair,
    namespace: Namespace,
    first_floor: ControlFloor,
) -> Result<(Device, ControlFloor), JsValue> {
    let now = pair.now;
    // A third member consumes a Welcome checkpoint; an existing member consumes
    // only the exact next retained owner control, never the new member's Welcome.
    let stale_draft = pair
        .owner
        .session()
        .prepare_message(b"old roster intent")
        .map_err(fail)?;
    let mut third =
        Pair::new_member(namespace, &pair.anchor, &pair.owner_enrollment, 73, now).await?;
    let third_package = third
        .session()
        .key_package(op(1), now)
        .await
        .map_err(fail)?;
    let third_invite = pair
        .owner
        .session()
        .invite(op(3), third_package.bytes(), validity(now), now)
        .await
        .map_err(fail)?;
    third
        .session()
        .join(third_invite.bytes(), now)
        .await
        .map_err(fail)?;
    let controls = pair
        .owner
        .session()
        .encrypted_controls(first_floor, 1)
        .await
        .map_err(fail)?;
    ensure(controls.records.len() == 1, "third member control missing")?;
    pair.member
        .session()
        .apply_control(controls.records[0].bytes(), now)
        .await
        .map_err(fail)?;
    ensure(
        pair.member.session().status().members == 3 && third.session().status().members == 3,
        "roster did not converge",
    )?;
    let before = pair.owner.image().await?;
    ensure(
        pair.owner
            .session()
            .send(op(4), &stale_draft, now)
            .await
            .is_err(),
        "old roster draft silently rebound",
    )?;
    ensure(
        pair.owner.image().await? == before
            && pair.owner.absent(RecordKey::Operation(op(4))).await?,
        "refused draft changed storage",
    )?;
    pair.owner.reopen().await?;

    Ok((third, controls.head))
}

async fn lifecycle_remove(
    pair: &mut Pair,
    third: &mut Device,
    third_floor: ControlFloor,
    reply: &CommittedOutbox,
) -> Result<(), JsValue> {
    let now = pair.now;
    let target = pair.member.context.device;
    let removal = pair
        .owner
        .session()
        .remove(op(4), target, now)
        .await
        .map_err(fail)?;
    let removed_controls = pair
        .owner
        .session()
        .encrypted_controls(third_floor, 1)
        .await
        .map_err(fail)?;
    ensure(
        removed_controls.records.len() == 1,
        "removal control missing",
    )?;
    let control = removed_controls.records[0].bytes().to_vec();
    pair.member
        .session()
        .apply_control(&control, now)
        .await
        .map_err(fail)?;
    third
        .session()
        .apply_control(&control, now)
        .await
        .map_err(fail)?;
    pair.owner.reopen().await?;
    pair.member.reopen().await?;
    third.reopen().await?;
    ensure(
        pair.owner
            .session()
            .remove(op(4), target, now)
            .await
            .map_err(fail)?
            .bytes()
            == removal.bytes(),
        "removal retry changed",
    )?;
    ensure(
        pair.member
            .session()
            .apply_control(&control, now)
            .await
            .map_err(fail)?
            .phase
            == Phase::Removed,
        "removed state/retry lost",
    )?;
    ensure(
        pair.member
            .session()
            .inbox(0, 16)
            .await
            .map_err(fail)?
            .records[0]
            .body()
            == b"inert private puzzle",
        "removal lost retained history",
    )?;
    let history = pair.member.session().outbox(1, 1).await.map_err(fail)?;
    ensure(
        history.records.len() == 1
            && history.records[0]
                .artifact()
                .ok_or_else(|| fail("ordinary artifact missing"))?
                .bytes()
                == reply.bytes(),
        "outbox history changed",
    )?;
    ensure(
        pair.member.send(3, b"must refuse", now).await.is_err(),
        "removed member sent",
    )?;
    pair.member.reopen().await?;
    let after = pair
        .owner
        .send(5, b"after removal", now)
        .await
        .map_err(fail)?;
    ensure(
        third
            .session()
            .receive(after.bytes(), now)
            .await
            .map_err(fail)?
            .body()
            == b"after removal",
        "remaining member cannot decrypt",
    )?;
    ensure(
        pair.member
            .session()
            .receive(after.bytes(), now)
            .await
            .is_err(),
        "removed member accepted new epoch",
    )?;
    Ok(())
}

async fn uncertain(namespace: Namespace) -> Result<(), JsValue> {
    let mut pair = Pair::fresh(namespace, 1000).await?;
    pair.join().await?;
    let now = pair.now;
    let draft = pair
        .owner
        .session()
        .prepare_message(b"commit before release")
        .map_err(fail)?;
    pair.owner.set_fault(Fault::After);
    ensure(
        matches!(
            pair.owner.session().send(op(2), &draft, now).await,
            Err(Error::NeedsReopen)
        ),
        "uncertain sender released output",
    )?;
    ensure(
        pair.owner.committed.get() && pair.owner.session().needs_reopen(),
        "fault did not cross actual commit",
    )?;
    pair.owner.reopen().await?;
    let retained = pair
        .owner
        .session()
        .outbox(1, 1)
        .await
        .map_err(fail)?
        .records
        .remove(0);
    let exact = pair
        .owner
        .session()
        .send(op(2), &draft, now)
        .await
        .map_err(fail)?;
    ensure(
        retained
            .artifact()
            .ok_or_else(|| fail("ordinary artifact missing"))?
            .bytes()
            == exact.bytes(),
        "uncertain send retry regenerated",
    )?;

    let before = pair.member.image().await?;
    pair.member.set_fault(Fault::Before);
    ensure(
        matches!(
            pair.member.session().receive(exact.bytes(), now).await,
            Err(Error::Refused)
        ),
        "before-commit failure released plaintext",
    )?;
    ensure(
        pair.member.image().await? == before,
        "refused receive advanced ratchet",
    )?;
    pair.member.reopen().await?;
    pair.member.set_fault(Fault::After);
    ensure(
        matches!(
            pair.member.session().receive(exact.bytes(), now).await,
            Err(Error::NeedsReopen)
        ),
        "after-commit failure released plaintext",
    )?;
    ensure(
        pair.member.committed.get(),
        "inbox failure preceded real commit",
    )?;
    pair.member.reopen().await?;
    let got = pair
        .member
        .session()
        .receive(exact.bytes(), now)
        .await
        .map_err(fail)?;
    ensure(
        got.body() == b"commit before release" && got.sequence() == 1,
        "uncertain inbox retry differs",
    )?;
    ensure(
        pair.member
            .session()
            .inbox(0, 16)
            .await
            .map_err(fail)?
            .records
            .len()
            == 1,
        "retry duplicated inbox",
    )?;
    Ok(())
}

async fn canceled(namespace: Namespace) -> Result<(), JsValue> {
    let mut pair = Pair::fresh(namespace, 1000).await?;
    pair.join().await?;
    let now = pair.now;
    let draft = pair
        .owner
        .session()
        .prepare_message(b"cancel after IDB completion")
        .map_err(fail)?;
    pair.owner.set_fault(Fault::PendingAfter);
    let committed = pair.owner.committed.clone();
    let mut operation = Box::pin(pair.owner.session().send(op(2), &draft, now));
    std::future::poll_fn(|cx| match operation.as_mut().poll(cx) {
        Poll::Ready(_) => Poll::Ready(Err(fail("canceled operation unexpectedly completed"))),
        Poll::Pending if committed.get() => Poll::Ready(Ok(())),
        Poll::Pending => Poll::Pending,
    })
    .await?;
    drop(operation);
    ensure(
        pair.owner.session().needs_reopen(),
        "canceled kernel became usable",
    )?;
    ensure(
        matches!(
            pair.owner.session().send(op(2), &draft, now).await,
            Err(Error::NeedsReopen)
        ),
        "canceled kernel retried before reopen",
    )?;
    pair.owner.reopen().await?;
    let retained = pair
        .owner
        .session()
        .outbox(1, 1)
        .await
        .map_err(fail)?
        .records
        .remove(0);
    let exact = pair
        .owner
        .session()
        .send(op(2), &draft, now)
        .await
        .map_err(fail)?;
    ensure(
        retained
            .artifact()
            .ok_or_else(|| fail("ordinary artifact missing"))?
            .bytes()
            == exact.bytes()
            && pair.owner.session().status().outbox_head == 2,
        "cancel recovery resigned or advanced",
    )?;
    Ok(())
}

async fn stale_and_capacity(namespace: Namespace) -> Result<(), JsValue> {
    let mut pair = Pair::fresh(namespace, 1000).await?;
    pair.join().await?;
    let now = pair.now;
    // A real second IDB connection carries a stale independently authenticated
    // image; exact whole-image comparison refuses its obsolete sender ratchet.
    let inner = IndexedPrivateStore::open(namespace, pair.owner.context)
        .await
        .map_err(fail)?;
    let mut stale = Kernel::open(inner, &pair.owner.key, pair.owner.context)
        .await
        .map_err(fail)?;
    let draft = stale.prepare_message(b"stale writer").map_err(fail)?;
    pair.owner
        .send(2, b"first writer", now)
        .await
        .map_err(fail)?;
    let current = pair.owner.image().await?;
    ensure(
        matches!(stale.send(op(3), &draft, now).await, Err(Error::Conflict)),
        "stale writer accepted",
    )?;
    ensure(
        stale.needs_reopen()
            && pair.owner.image().await? == current
            && pair.owner.absent(RecordKey::Operation(op(3))).await?,
        "stale writer changed evidence",
    )?;
    drop(stale);
    let mut store = IndexedPrivateStore::open(namespace, pair.owner.context)
        .await
        .map_err(fail)?;
    ensure(
        store.load(pair.member.context).await.is_err(),
        "wrong scope loaded",
    )?;
    drop(store);
    let wrong_key = StorageKey::from_secret([99; 32]).map_err(fail)?;
    let store = IndexedPrivateStore::open(namespace, pair.owner.context)
        .await
        .map_err(fail)?;
    ensure(
        matches!(
            Kernel::open(store, &wrong_key, pair.owner.context).await,
            Err(Error::Authentication)
        ),
        "wrong custody key restored MLS",
    )?;
    ensure(
        pair.owner.image().await? == current,
        "wrong-key open changed evidence",
    )?;

    let mut bounded = Pair::fresh(namespace, 3).await?;
    let now = bounded.now;
    let (package, invitation, _) = bounded.join().await?;
    let before = bounded.owner.image().await?;
    ensure(
        matches!(
            bounded.owner.send(2, b"over capacity", now).await,
            Err(Error::Refused)
        ),
        "lifetime capacity ignored",
    )?;
    ensure(
        bounded.owner.session().needs_reopen()
            && bounded.owner.image().await? == before
            && bounded.owner.absent(RecordKey::Operation(op(2))).await?,
        "capacity failure changed evidence",
    )?;
    bounded.owner.reopen().await?;
    ensure(
        bounded
            .owner
            .session()
            .invite(op(1), &package, validity(now), now)
            .await
            .map_err(fail)?
            .bytes()
            == invitation,
        "capacity lost prior exact retry",
    )?;
    Ok(())
}

async fn renewal(namespace: Namespace) -> Result<(), JsValue> {
    let mut pair = Box::pin(Pair::fresh(namespace, 1000)).await?;
    pair.join().await?;
    let now = pair.now;
    let context = pair.owner.context;
    let old = pair
        .owner
        .session()
        .prepare_message(b"old roster consent")
        .map_err(fail)?;
    let enrollment = pair
        .owner
        .session()
        .owner_renewal_request(Validity::new(now, now + 14400).map_err(fail)?)
        .map_err(fail)?
        .sign(&SigningKey::from_bytes(&[71; 32]))
        .map_err(fail)?;
    pair.owner.set_fault(Fault::After);
    ensure(
        matches!(
            pair.owner
                .session()
                .renew_owner(op(10), enrollment.clone(), now)
                .await,
            Err(Error::NeedsReopen)
        ),
        "uncertain renewal released output",
    )?;
    ensure(
        pair.owner.committed.get(),
        "renewal fault preceded real commit",
    )?;
    pair.owner.reopen().await?;
    let committed = pair.owner.image().await?;
    let update = pair
        .owner
        .session()
        .renew_owner(op(10), enrollment.clone(), now)
        .await
        .map_err(fail)?;
    ensure(
        pair.owner.image().await? == committed && pair.owner.context == context,
        "renewal retry changed retained custody",
    )?;
    pair.member.set_fault(Fault::PendingAfter);
    let marker = pair.member.committed.clone();
    {
        let mut pending = Box::pin(pair.member.session().apply_control(update.bytes(), now));
        std::future::poll_fn(|cx| {
            if pending.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(fail("canceled renewal returned")));
            }
            if marker.get() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
    }
    pair.member.reopen().await?;
    pair.member
        .session()
        .apply_control(update.bytes(), now)
        .await
        .map_err(fail)?;
    ensure(
        pair.member.session().status().roster == pair.owner.session().status().roster,
        "renewed roster did not converge",
    )?;
    ensure(
        pair.owner.session().send(op(11), &old, now).await.is_err(),
        "renewal reused old consent",
    )?;
    ensure(
        pair.owner.image().await? == committed,
        "refused draft changed renewal",
    )?;
    pair.owner.reopen().await?;
    ensure(
        pair.owner
            .session()
            .renew_owner(op(10), enrollment, now)
            .await
            .map_err(fail)?
            .bytes()
            == update.bytes(),
        "reopened renewal changed ciphertext",
    )?;
    let fresh = pair
        .owner
        .send(11, b"current roster consent", now)
        .await
        .map_err(fail)?;
    ensure(
        pair.member
            .session()
            .receive(fresh.bytes(), now)
            .await
            .map_err(fail)?
            .body()
            == b"current roster consent",
        "renewed group cannot exchange traffic",
    )?;
    Ok(())
}

async fn contact_bootstrap(namespace: Namespace) -> Result<(), JsValue> {
    // A separate harness-owned synthetic namespace; no existing phase uses this
    // offset. Full fresh room/device contexts still come from actual CSPRNGs.
    let mut identifier = *namespace.identifier();
    identifier[0] ^= 0x40;
    let mut pair = Box::pin(Pair::fresh(Namespace::new(identifier), 1000)).await?;
    let offer = Box::pin(contact_offer(&mut pair)).await?;
    let (request, response) = Box::pin(contact_join(&mut pair, &offer)).await?;
    Box::pin(contact_recovery(&mut pair, &offer, &request, &response)).await
}

async fn contact_offer(pair: &mut Pair) -> Result<ConfidentialContactOffer, JsValue> {
    let now = pair.now;
    let recipient = pair.member.context.account;
    let offer = pair
        .owner
        .session()
        .create_contact_offer(op(1), recipient, validity(now), now)
        .await
        .map_err(fail)?;
    let bootstrap = ContactBootstrap::inspect(
        offer.confidential_bytes(),
        pair.owner.context.account,
        recipient,
        now,
    )
    .map_err(fail)?;
    ensure(
        bootstrap.scope() == pair.member.context.scope,
        "contact bootstrap changed pinned room",
    )?;
    let page = pair.owner.session().outbox(0, 1).await.map_err(fail)?;
    ensure(
        page.head == 1
            && page.next.is_none()
            && page.records.len() == 1
            && page.records[0].sequence() == 1
            && page.records[0].operation() == op(1)
            && page.records[0].kind() == OutboxKind::ContactOffer
            && page.records[0].artifact().is_none(),
        "secret contact offer escaped generic outbox metadata",
    )?;
    let before = pair.member.image().await?;
    let mut tampered = Zeroizing::new(offer.confidential_bytes().to_vec());
    *tampered
        .last_mut()
        .ok_or_else(|| fail("empty signed contact offer"))? ^= 1;
    ensure(
        matches!(
            pair.member
                .session()
                .contact_request(op(1), &tampered, now)
                .await,
            Err(Error::Authentication)
        ),
        "tampered owner signature released a contact request",
    )?;
    ensure(
        pair.member.image().await? == before
            && pair.member.absent(RecordKey::Operation(op(1))).await?
            && pair.member.absent(RecordKey::Outbox(1)).await?,
        "tampered offer changed member evidence",
    )?;
    Ok(offer)
}

async fn contact_join(
    pair: &mut Pair,
    offer: &ConfidentialContactOffer,
) -> Result<(CommittedOutbox, CommittedOutbox), JsValue> {
    let now = pair.now;
    let request = pair
        .member
        .session()
        .contact_request(op(1), offer.confidential_bytes(), now)
        .await
        .map_err(fail)?;
    ensure(
        request.kind() == OutboxKind::ContactRequest,
        "contact request has the wrong retained kind",
    )?;
    pair.member.reopen().await?;
    let before = pair.member.image().await?;
    ensure(
        pair.member
            .session()
            .contact_request(op(1), offer.confidential_bytes(), now)
            .await
            .map_err(fail)?
            .bytes()
            == request.bytes()
            && pair.member.image().await? == before,
        "contact request retry changed retained KeyPackage or ciphertext",
    )?;
    let response = pair
        .owner
        .session()
        .accept_contact(op(2), request.bytes(), validity(now), now)
        .await
        .map_err(fail)?;
    ensure(
        response.kind() == OutboxKind::ContactInvitation,
        "contact response has the wrong retained kind",
    )?;
    let joined = pair
        .member
        .session()
        .join_contact(response.bytes(), now)
        .await
        .map_err(fail)?;
    let owner = pair.owner.session().status();
    ensure(
        joined.phase == Phase::MemberJoined
            && joined.members == 2
            && owner.members == 2
            && joined.roster == owner.roster
            && joined.control_floor == owner.control_floor,
        "contact admission did not converge on the exact roster/control",
    )?;
    Ok((request, response))
}

async fn contact_recovery(
    pair: &mut Pair,
    offer: &ConfidentialContactOffer,
    request: &CommittedOutbox,
    response: &CommittedOutbox,
) -> Result<(), JsValue> {
    let now = pair.now;
    pair.owner.reopen().await?;
    pair.member.reopen().await?;
    let owner_before = pair.owner.image().await?;
    let member_before = pair.member.image().await?;
    let owner_status = pair.owner.session().status();
    let member_status = pair.member.session().status();
    let recipient = pair.member.context.account;
    let recovered = pair
        .owner
        .session()
        .create_contact_offer(op(1), recipient, validity(now), now)
        .await
        .map_err(fail)?;
    ensure(
        recovered.confidential_bytes() == offer.confidential_bytes(),
        "contact issuance retry regenerated secret keys",
    )?;
    ensure(
        pair.owner
            .session()
            .accept_contact(op(2), request.bytes(), validity(now), now)
            .await
            .map_err(fail)?
            .bytes()
            == response.bytes()
            && pair
                .member
                .session()
                .join_contact(response.bytes(), now)
                .await
                .map_err(fail)?
                == member_status,
        "contact acceptance/join retry changed retained results",
    )?;
    ensure(
        pair.owner.image().await? == owner_before && pair.member.image().await? == member_before,
        "exact contact recovery advanced durable state",
    )?;
    ensure(
        matches!(
            pair.owner
                .session()
                .accept_contact(op(3), request.bytes(), validity(now), now)
                .await,
            Err(Error::Missing)
        ),
        "recovered secret issuance reactivated consumed admission",
    )?;
    ensure(
        pair.owner.image().await? == owner_before
            && pair.owner.absent(RecordKey::Operation(op(3))).await?,
        "consumed offer refusal changed owner evidence",
    )?;
    pair.owner.reopen().await?;
    ensure(
        pair.owner.session().status() == owner_status,
        "consumed authority changed after final reopen",
    )?;
    Ok(())
}

/// Execute only synthetic, fresh custody contexts in the isolated fixture.
pub async fn run(namespace: Namespace, hook: js_sys::Function) -> Result<String, JsValue> {
    hook.call1(&JsValue::NULL, &"require-strict".into())?;
    Box::pin(lifecycle(namespace)).await?;
    Box::pin(uncertain(namespace)).await?;
    Box::pin(canceled(namespace)).await?;
    Box::pin(stale_and_capacity(namespace)).await?;
    Box::pin(renewal(namespace)).await?;
    Box::pin(contact_bootstrap(namespace)).await?;
    hook.call1(&JsValue::NULL, &"finish".into())?;
    Ok("real MLS/IndexedDB: 3-device control, encrypted bidirectional traffic, removal, owner renewal, exact reopen, post-commit uncertainty/cancellation, stale writer, wrong key/scope, capacity and one-use confidential contact bootstrap passed".into())
}
