//! Stateful two-device delivery over one ordered in-memory mailbox. Every
//! device owns the production sync engine over a real kernel and durable
//! image; the model injects controls, messages, foreign bootstrap items and
//! clock regressions. A live cursor must always reach the mailbox head and no
//! ordinary command sequence may end a device's custody.
#![cfg(feature = "private-rooms")]
// The shared model and engine also carry paths only the worker transport
// uses (hostile replies, identity changes); the model does not drive them.
#[path = "../src/private/admission.rs"]
mod admission;
#[allow(dead_code)]
#[path = "../src/private/delivery_engine.rs"]
mod engine;
#[allow(dead_code)]
#[path = "../src/private/delivery_model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/private/wire.rs"]
pub mod private_wire;

use ed25519_dalek::SigningKey;
use engine::{Engine, Failure, Host, Summary, TransportError};
use futures::executor::block_on;
use hegel::{generators as gs, TestCase};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    Context, Kernel, MemberDraft, OperationId, OutboxKind, OwnerDraft, Phase, StorageKey,
};
use vhalla_private_relay::{codec, PositionedItem, RelayItem, RelayNamespace, RelayPage};

fn op(value: u64) -> OperationId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    OperationId::from_bytes(bytes).unwrap()
}
fn account(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn device_key(account: &SigningKey) -> Key {
    Key::from_bytes(account.verifying_key().to_bytes()).unwrap()
}

/// In-memory kernel store honoring the exact CAS contract; counts strict
/// image transactions for the batching report.
#[derive(Default)]
struct Disk {
    context: Option<Context>,
    image: Option<Image>,
    records: BTreeMap<RecordKey, StoredRecord>,
    publishes: usize,
}
#[derive(Clone, Default)]
struct Mem(Rc<RefCell<Disk>>);
impl Mem {
    fn publishes(&self) -> usize {
        self.0.borrow().publishes
    }
}
impl Store for Mem {
    async fn load(&mut self, context: Context) -> Result<Option<Image>, StoreError> {
        let disk = self.0.borrow();
        if disk.context.is_some_and(|old| old != context) {
            return Err(StoreError::Corrupt);
        }
        if disk.image.is_none() && !disk.records.is_empty() {
            return Err(StoreError::Corrupt);
        }
        Ok(disk.image.clone())
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> Result<Option<StoredRecord>, StoreError> {
        let disk = self.0.borrow();
        if disk.context != Some(context) {
            return Err(StoreError::Corrupt);
        }
        Ok(disk.records.get(&key).cloned())
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> Result<(), StoreError> {
        let mut disk = self.0.borrow_mut();
        if disk.context.is_some_and(|old| old != context) {
            return Err(StoreError::Corrupt);
        }
        if disk.image.as_ref() != expected
            || (expected.is_none() && !disk.records.is_empty())
            || records.iter().any(|r| disk.records.contains_key(&r.key()))
        {
            return Err(StoreError::Conflict);
        }
        for record in records {
            disk.records.insert(record.key(), record.clone());
        }
        disk.context = Some(context);
        disk.image = Some(next.clone());
        disk.publishes += 1;
        Ok(())
    }
}

/// One shared mailbox appending whole relay items in arrival order.
#[derive(Default)]
struct Mailbox {
    items: Vec<RelayItem>,
}
impl Mailbox {
    fn head(&self) -> u64 {
        self.items.len() as u64
    }
    fn put(&mut self, item: RelayItem) -> Vec<u8> {
        let digest = item.digest();
        let (position, duplicate) = match self.items.iter().position(|old| old.digest() == digest) {
            Some(at) => (at as u64 + 1, true),
            None => {
                self.items.push(item);
                (self.items.len() as u64, false)
            }
        };
        let mut body = position.to_be_bytes().to_vec();
        body.extend_from_slice(&digest);
        body.push(u8::from(duplicate));
        codec::frame(codec::STATUS_OK, &body)
    }
    fn page(&self, after: u64, limit: usize) -> Vec<u8> {
        let head = self.head();
        let records: Vec<PositionedItem> = self
            .items
            .iter()
            .enumerate()
            .skip(after as usize)
            .take(limit)
            .map(|(index, item)| PositionedItem {
                position: index as u64 + 1,
                item: item.clone(),
            })
            .collect();
        let next = records
            .last()
            .filter(|last| last.position < head)
            .map(|last| last.position);
        codec::frame(
            codec::STATUS_OK,
            &codec::encode_page(&RelayPage {
                head,
                next,
                records,
            })
            .unwrap(),
        )
    }
}

/// One member or owner device: kernel custody, the durable delivery image and
/// retained bootstrap items, plus a per-device wall-clock skew.
struct Device {
    kernel: Option<Kernel<Mem>>,
    disk: Mem,
    key: StorageKey,
    image: Option<Vec<u8>>,
    retained: BTreeMap<u64, Vec<u8>>,
    image_writes: usize,
    mailbox: Rc<RefCell<Mailbox>>,
    clock: Rc<Cell<u64>>,
    skew: u64,
    /// Fail one exact retained-item transaction before or after its commit.
    retention_fault: u8,
}
impl Host for Device {
    type Store = Mem;
    fn now(&self) -> engine::Result<u64> {
        Ok(self.clock.get().saturating_sub(self.skew))
    }
    fn canceled(&self) -> bool {
        false
    }
    fn kernel(&mut self) -> engine::Result<&mut Kernel<Mem>> {
        self.kernel.as_mut().ok_or(Failure::State)
    }
    async fn reopen_kernel(&mut self, context: Context) -> engine::Result<()> {
        let store = self.kernel.take().ok_or(Failure::State)?.into_store();
        self.kernel = Some(Kernel::open(store, &self.key, context).await?);
        Ok(())
    }
    async fn revalidate(&mut self) -> engine::Result<()> {
        Ok(())
    }
    async fn load(&mut self) -> engine::Result<Option<Vec<u8>>> {
        Ok(self.image.clone())
    }
    async fn publish(
        &mut self,
        expected: Option<&[u8]>,
        next: &[u8],
        retain: Option<(u64, &[u8])>,
        discard: Option<u64>,
    ) -> engine::Result<()> {
        if self.image.as_deref() != expected {
            return Err(Failure::Storage);
        }
        let fault = if retain.is_some() {
            std::mem::take(&mut self.retention_fault)
        } else {
            0
        };
        if fault == 1 {
            return Err(Failure::Storage);
        }
        if retain.is_some_and(|(position, _)| self.retained.contains_key(&position))
            || discard.is_some_and(|position| !self.retained.contains_key(&position))
        {
            return Err(Failure::Storage);
        }
        if let Some((position, bytes)) = retain {
            if self.retained.insert(position, bytes.to_vec()).is_some() {
                return Err(Failure::Storage);
            }
        }
        if let Some(position) = discard {
            if self.retained.remove(&position).is_none() {
                return Err(Failure::Storage);
            }
        }
        self.image = Some(next.to_vec());
        self.image_writes += 1;
        if fault == 2 {
            return Err(Failure::Storage);
        }
        Ok(())
    }
    async fn load_retained(&mut self, position: u64) -> engine::Result<Option<Vec<u8>>> {
        Ok(self.retained.get(&position).cloned())
    }
    async fn exchange(
        &mut self,
        frame: &[u8],
        _maximum: usize,
    ) -> core::result::Result<Vec<u8>, TransportError> {
        let (op, body) =
            codec::decode_frame(frame, codec::MAX_REQUEST).map_err(|_| TransportError::Refused)?;
        let mut mailbox = self.mailbox.borrow_mut();
        Ok(match op {
            codec::OP_PUT => {
                mailbox.put(RelayItem::decode(body).map_err(|_| TransportError::Refused)?)
            }
            codec::OP_PAGE => {
                if body.len() != 10 {
                    return Err(TransportError::Refused);
                }
                let after = u64::from_be_bytes(body[..8].try_into().expect("bounded"));
                let limit = u16::from_be_bytes(body[8..10].try_into().expect("bounded")) as usize;
                mailbox.page(after, limit)
            }
            _ => return Err(TransportError::Refused),
        })
    }
}

struct World {
    owner: Device,
    member: Device,
    owner_engine: Engine,
    member_engine: Engine,
    mailbox: Rc<RefCell<Mailbox>>,
    clock: Rc<Cell<u64>>,
    account: SigningKey,
    member_device: Key,
    member_removed: bool,
    namespace: RelayNamespace,
    op: u64,
}
impl World {
    fn operation(&mut self) -> OperationId {
        self.op += 1;
        op(self.op)
    }
    fn device(&mut self, index: usize) -> (&mut Engine, &mut Device) {
        match index {
            0 => (&mut self.owner_engine, &mut self.owner),
            _ => (&mut self.member_engine, &mut self.member),
        }
    }
    fn phase(&self, index: usize) -> Phase {
        self.device_ref(index)
            .kernel
            .as_ref()
            .unwrap()
            .status()
            .phase
    }
    fn device_ref(&self, index: usize) -> &Device {
        match index {
            0 => &self.owner,
            _ => &self.member,
        }
    }
    fn admitted(phase: Phase) -> bool {
        matches!(
            phase,
            Phase::OwnerGenesis
                | Phase::OwnerJoined
                | Phase::MemberJoined
                | Phase::OwnerAfterRemoval
        )
    }
    /// Compose one application message at the device's current epoch. The
    /// artifact is committed now; it is only relayed by a later sync.
    async fn send(&mut self, index: usize) {
        if matches!(self.phase(index), Phase::AwaitingWelcome | Phase::Removed) {
            return;
        }
        let operation = self.operation();
        let now = self.clock.get();
        let kernel = self.device(index).1.kernel.as_mut().unwrap();
        let body = format!("body-{operation:?}");
        let draft = kernel.prepare_message(body.as_bytes()).unwrap();
        kernel.send(operation, &draft, now).await.unwrap();
    }
    /// The owner renews its enrollment; the replacement control travels to
    /// members only through the mailbox on the owner's next sync.
    async fn renew(&mut self) {
        let now = self.clock.get();
        self.op += 1;
        let horizon = now + 30 * 86400 + self.op * 3600;
        let unsigned = self
            .owner
            .kernel
            .as_mut()
            .unwrap()
            .owner_renewal_request(Validity::new(now - 30, horizon).unwrap())
            .unwrap();
        let enrollment = unsigned.sign(&self.account).unwrap();
        self.owner
            .kernel
            .as_mut()
            .unwrap()
            .renew_owner(op(self.op), enrollment, now)
            .await
            .unwrap();
    }
    /// The owner removes the member device; the removal control is only
    /// published by a later owner sync. The owner's roster already dropped the
    /// member even though the member only learns that through the mailbox, so
    /// the model remembers the removal itself.
    async fn remove(&mut self) {
        if self.member_removed {
            return;
        }
        let operation = self.operation();
        let now = self.clock.get();
        let target = self.member_device;
        self.owner
            .kernel
            .as_mut()
            .unwrap()
            .remove(operation, target, now)
            .await
            .unwrap();
        self.member_removed = true;
    }
    /// A foreign sender deposits one bootstrap item any token holder could
    /// publish; receivers must retain it for explicit admission, never apply.
    fn inject(&mut self, kind: OutboxKind) {
        let operation = self.operation();
        let item = RelayItem::new(
            self.namespace,
            1_000_000 + self.op,
            operation,
            kind,
            b"foreign opaque bootstrap ciphertext",
        )
        .unwrap();
        self.mailbox.borrow_mut().items.push(item);
    }
    /// One bounded sync. A device whose phase no longer admits syncing refuses
    /// locally; nothing else may fail for ordinary mailbox traffic.
    async fn sync(&mut self, index: usize) -> Option<Summary> {
        let phase = self.phase(index);
        let (engine, device) = self.device(index);
        match engine.sync(device).await {
            Ok(summary) => {
                assert!(Self::admitted(phase), "sync ran under {phase:?}");
                Some(summary)
            }
            Err(Failure::State) => {
                assert!(!Self::admitted(phase), "sync refused under {phase:?}");
                None
            }
            Err(error) => panic!("fatal sync for device {index}: {error:?}"),
        }
    }
    /// Explicitly discard the oldest retained bootstrap item.
    async fn discard(&mut self, index: usize) {
        let position = {
            let (engine, _) = self.device(index);
            let Some(position) = engine.admissions().first().map(|a| a.position) else {
                return;
            };
            position
        };
        let (engine, device) = self.device(index);
        engine.discard(device, position).await.unwrap();
    }
    /// After healing every clock, repeated syncs must converge every live
    /// cursor to the mailbox head without a fatal outcome.
    async fn converge(&mut self) {
        self.owner.skew = 0;
        self.member.skew = 0;
        for _ in 0..40 {
            let mut pending = false;
            for index in 0..2 {
                if !Self::admitted(self.phase(index)) {
                    continue;
                }
                let Some(summary) = self.sync(index).await else {
                    continue;
                };
                if summary.blocked == model::blocked::ADMISSIONS_FULL {
                    self.discard(index).await;
                    pending = true;
                }
                if summary.pending
                    || summary.cursor < self.mailbox.borrow().head()
                    || (summary.blocked != 0 && summary.stop == 0)
                {
                    pending = true;
                }
                assert_eq!(summary.stop, 0, "device {index} stopped");
            }
            if !pending {
                break;
            }
        }
        let head = self.mailbox.borrow().head();
        for index in 0..2 {
            if !Self::admitted(self.phase(index)) {
                continue;
            }
            let (engine, _) = self.device(index);
            let summary = engine.summary(false);
            assert_eq!(
                summary.cursor, head,
                "device {index} cursor {} never reached mailbox head {head}",
                summary.cursor
            );
            assert_eq!(summary.stop, 0);
        }
    }
}

async fn build() -> World {
    // OpenMLS validates leaf lifetimes against real time, so the model's
    // epoch is the real wall clock; per-device skew still comes from `skew`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let clock = Rc::new(Cell::new(now));
    let mailbox = Rc::new(RefCell::new(Mailbox::default()));
    let owner_account = account(5);
    let member_account = account(6);
    // Stay inside the MLS leaf-node lifetime bound (about three months).
    let validity = Validity::new(now - 30, now + 28 * 86400).unwrap();
    let draft = OwnerDraft::new(device_key(&owner_account), validity).unwrap();
    let anchor = draft.anchor_request().sign(&owner_account).unwrap();
    let enrollment = draft.enrollment_request().sign(&owner_account).unwrap();
    let scope = anchor.verify().unwrap().scope();
    let member_draft = MemberDraft::new(
        scope,
        anchor.clone(),
        enrollment.clone(),
        device_key(&member_account),
        validity,
        now,
    )
    .unwrap();
    let member_enrollment = member_draft
        .enrollment_request()
        .sign(&member_account)
        .unwrap();
    let owner_disk = Mem::default();
    let member_disk = Mem::default();
    let owner_key = StorageKey::from_secret([11; 32]).unwrap();
    let member_key = StorageKey::from_secret([12; 32]).unwrap();
    let mut owner_kernel = draft
        .create(owner_disk.clone(), &owner_key, enrollment, anchor, now)
        .await
        .unwrap();
    let mut member_kernel = member_draft
        .initialize(member_disk.clone(), &member_key, member_enrollment, now)
        .await
        .unwrap();
    let package = member_kernel.key_package(op(1), now).await.unwrap();
    let invitation = owner_kernel
        .invite(op(1), package.bytes(), validity, now)
        .await
        .unwrap();
    member_kernel.join(invitation.bytes(), now).await.unwrap();
    let member_device = member_kernel.status().context.device;
    let namespace = RelayNamespace::from_bytes([3; 32]).unwrap();
    let mut owner = Device {
        kernel: Some(owner_kernel),
        disk: owner_disk,
        key: owner_key,
        image: None,
        retained: BTreeMap::new(),
        image_writes: 0,
        mailbox: mailbox.clone(),
        clock: clock.clone(),
        skew: 0,
        retention_fault: 0,
    };
    let mut member = Device {
        kernel: Some(member_kernel),
        disk: member_disk,
        key: member_key,
        image: None,
        retained: BTreeMap::new(),
        image_writes: 0,
        mailbox: mailbox.clone(),
        clock: clock.clone(),
        skew: 0,
        retention_fault: 0,
    };
    let _owner_engine = Engine::open(&mut owner, namespace, [9; 32], [7; 16], 0, true)
        .await
        .unwrap();
    let _member_engine = Engine::open(&mut member, namespace, [9; 32], [7; 16], 0, true)
        .await
        .unwrap();
    // This delivery fixture begins after the bootstrap control was explicitly
    // exchanged by the invitation above. Pin that shared initial full floor;
    // subsequent additions/renewals must use the independent control stream.
    for device in [&mut owner, &mut member] {
        let mut state = model::State::decode(device.image.as_ref().unwrap()).unwrap();
        state.control_sent = Some(device.kernel.as_ref().unwrap().status().control_floor);
        device.image = Some(state.encode().unwrap());
    }
    let owner_engine = Engine::open(&mut owner, namespace, [9; 32], [7; 16], 0, false)
        .await
        .unwrap();
    let member_engine = Engine::open(&mut member, namespace, [9; 32], [7; 16], 0, false)
        .await
        .unwrap();
    World {
        owner,
        member,
        owner_engine,
        member_engine,
        mailbox,
        clock,
        account: owner_account,
        member_device,
        member_removed: false,
        namespace,
        op: 10,
    }
}

/// A future-epoch message precedes the control that admits it. Keep its exact
/// bytes across a worker restart, fetch the later control, then apply once.
#[test]
fn future_message_before_control_survives_restart_and_is_applied_once() {
    block_on(async {
        let mut world = build().await;
        world.renew().await;
        world.send(0).await;
        world.sync(0).await;
        world.mailbox.borrow_mut().items.swap(0, 1);
        let exact = world.mailbox.borrow().items[0].encode().unwrap();
        let first = world.sync(1).await.unwrap();
        assert!(first.review);
        assert_eq!(first.refused, 0, "future ciphertext is retryable");
        assert_eq!(first.received, 0);
        assert_eq!(first.cursor, 0, "unresolved position remains visible");
        assert_eq!(world.member.retained.get(&1), Some(&exact));
        let context = world.member.kernel.as_ref().unwrap().status().context;
        world.member.reopen_kernel(context).await.unwrap();
        world.member_engine = Engine::open(
            &mut world.member,
            world.namespace,
            [9; 32],
            [8; 16],
            0,
            false,
        )
        .await
        .unwrap();
        let second = world.sync(1).await.unwrap();
        assert_eq!(second.received, 1);
        assert_eq!(second.refused, 0);
        assert_eq!(second.cursor, 2);
        assert!(!world.member.retained.contains_key(&1));
        let again = world.sync(1).await.unwrap();
        assert_eq!(again.received, 1, "retained replay cannot double-accept");
    });
}

/// Arrange one genuine future-epoch message without its control. Its bytes must
/// remain retryable; forwarding that control is a separate test concern.
async fn future_only(world: &mut World) -> Vec<u8> {
    world.renew().await;
    world.send(0).await;
    let kernel = world.owner.kernel.as_mut().unwrap();
    let head = kernel.status().outbox_head;
    let page = kernel.outbox(head - 1, 1).await.unwrap();
    let item =
        RelayItem::from_artifact(world.namespace, page.records[0].artifact().unwrap()).unwrap();
    let raw = item.encode().unwrap();
    world.mailbox.borrow_mut().items.push(item);
    raw
}

#[test]
fn deferred_ciphertext_and_cursor_publish_atomically_across_uncertain_completion() {
    block_on(async {
        for fault in [1, 2] {
            let mut world = build().await;
            let exact = future_only(&mut world).await;
            world.member.retention_fault = fault;
            assert!(world.member_engine.sync(&mut world.member).await.is_err());
            let persisted = model::State::decode(world.member.image.as_ref().unwrap()).unwrap();
            if fault == 1 {
                assert_eq!(persisted.cursor, 0);
                assert!(persisted.deferred.is_empty());
                assert!(world.member.retained.is_empty());
            } else {
                assert_eq!(persisted.cursor, 1);
                assert_eq!(persisted.resolved(), 0);
                assert_eq!(world.member.retained.get(&1), Some(&exact));
            }
            world.member_engine = Engine::open(
                &mut world.member,
                world.namespace,
                [9; 32],
                [8; 16],
                0,
                false,
            )
            .await
            .unwrap();
            let summary = world.sync(1).await.unwrap();
            assert_eq!(summary.cursor, 0);
            assert_eq!(summary.fetched, 1);
            assert_eq!(summary.deferred, 1);
            assert_eq!(summary.refused, 0);
            assert_eq!(world.member.retained.get(&1), Some(&exact));
        }
    });
}

#[test]
fn missing_or_changed_deferred_bytes_refuse_reopen_without_repair() {
    block_on(async {
        for missing in [true, false] {
            let mut world = build().await;
            future_only(&mut world).await;
            world.sync(1).await;
            let image = world.member.image.clone();
            if missing {
                world.member.retained.remove(&1);
            } else {
                world.member.retained.get_mut(&1).unwrap()[40] ^= 1;
            }
            assert!(Engine::open(
                &mut world.member,
                world.namespace,
                [9; 32],
                [8; 16],
                0,
                false
            )
            .await
            .is_err());
            assert_eq!(
                world.member.image, image,
                "reopen never repairs a missing publication half"
            );
        }
    });
}

#[test]
fn stale_engine_cannot_overwrite_another_workers_deferred_progress() {
    block_on(async {
        let mut world = build().await;
        let exact = future_only(&mut world).await;
        let mut newer = Engine::open(
            &mut world.member,
            world.namespace,
            [9; 32],
            [8; 16],
            0,
            false,
        )
        .await
        .unwrap();
        newer.sync(&mut world.member).await.unwrap();
        let image = world.member.image.clone();
        assert!(world.member_engine.sync(&mut world.member).await.is_err());
        assert_eq!(world.member.image, image);
        assert_eq!(world.member.retained.get(&1), Some(&exact));
    });
}

#[test]
fn full_deferred_queue_holds_ninth_item_without_skipping_or_eviction() {
    block_on(async {
        let mut world = build().await;
        future_only(&mut world).await;
        for _ in 1..=model::MAX_DEFERRED {
            world.send(0).await;
            let kernel = world.owner.kernel.as_mut().unwrap();
            let head = kernel.status().outbox_head;
            let page = kernel.outbox(head - 1, 1).await.unwrap();
            world.mailbox.borrow_mut().items.push(
                RelayItem::from_artifact(world.namespace, page.records[0].artifact().unwrap())
                    .unwrap(),
            );
        }
        for _ in 0..3 {
            world.sync(1).await;
        }
        let summary = world.member_engine.summary(false);
        assert_eq!(summary.blocked, model::blocked::DEFERRED_FULL);
        assert_eq!(summary.cursor, 0);
        assert_eq!(summary.fetched, model::MAX_DEFERRED as u64);
        assert_eq!(summary.deferred, model::MAX_DEFERRED as u64);
        assert_eq!(summary.refused, 0);
        assert_eq!(world.member.retained.len(), model::MAX_DEFERRED);
        let state = model::State::decode(world.member.image.as_ref().unwrap()).unwrap();
        let staged = codec::decode_page(&state.staged, state.staged_after, model::PAGE).unwrap();
        assert_eq!(staged.records[state.applied as usize].position, 9);
    });
}

async fn admit_third(world: &mut World) -> Kernel<Mem> {
    let now = world.clock.get();
    let third_account = account(7);
    let view = world
        .owner
        .kernel
        .as_mut()
        .unwrap()
        .membership()
        .await
        .unwrap();
    let validity = Validity::new(now - 30, now + 7200).unwrap();
    let draft = MemberDraft::new(
        view.status().context.scope,
        view.anchor().clone(),
        view.owner().clone(),
        device_key(&third_account),
        validity,
        now,
    )
    .unwrap();
    let enrollment = draft.enrollment_request().sign(&third_account).unwrap();
    let third_key = StorageKey::from_secret([13; 32]).unwrap();
    let mut third = draft
        .initialize(Mem::default(), &third_key, enrollment, now)
        .await
        .unwrap();
    let issue = world.operation();
    let offer = world
        .owner
        .kernel
        .as_mut()
        .unwrap()
        .create_contact_offer(issue, device_key(&third_account), validity, now)
        .await
        .unwrap();
    let request = third
        .contact_request(op(1), offer.confidential_bytes(), now)
        .await
        .unwrap();
    let admit = world.operation();
    let response = world
        .owner
        .kernel
        .as_mut()
        .unwrap()
        .accept_contact(admit, request.bytes(), validity, now)
        .await
        .unwrap();
    third.join_contact(response.bytes(), now).await.unwrap();
    third
}

#[test]
fn confidential_third_member_admission_relays_control_to_existing_offline_member() {
    block_on(async {
        let mut world = build().await;
        let third = admit_third(&mut world).await;
        world.send(0).await;
        world.sync(0).await;
        world.sync(0).await;
        let control = world
            .mailbox
            .borrow()
            .items
            .iter()
            .position(|item| item.kind() == vhalla_private_relay::RelayKind::Control)
            .unwrap();
        let message = world
            .mailbox
            .borrow()
            .items
            .iter()
            .position(|item| item.kind() == OutboxKind::Application)
            .unwrap();
        world.mailbox.borrow_mut().items.swap(control, message);
        let first = world.sync(1).await.unwrap();
        assert!(first.review);
        assert_eq!(first.deferred, 1);
        assert_eq!(world.member.kernel.as_ref().unwrap().status().members, 3);
        world.member_engine = Engine::open(
            &mut world.member,
            world.namespace,
            [9; 32],
            [8; 16],
            0,
            false,
        )
        .await
        .unwrap();
        let second = world.sync(1).await.unwrap();
        assert_eq!(second.received, 1);
        assert_eq!(second.deferred, 0);
        assert_eq!(second.refused, 0);
        assert_eq!(
            third.status().roster,
            world.member.kernel.as_ref().unwrap().status().roster
        );
    });
}

#[test]
fn committed_old_message_precedes_own_membership_control_and_new_message() {
    block_on(async {
        let mut world = build().await;
        world.send(0).await;
        let _third = admit_third(&mut world).await;
        world.send(0).await;
        for _ in 0..4 {
            world.sync(0).await;
        }
        let kinds: Vec<_> = world
            .mailbox
            .borrow()
            .items
            .iter()
            .map(|item| item.kind())
            .collect();
        let messages: Vec<_> = kinds
            .iter()
            .enumerate()
            .filter_map(|(at, kind)| (*kind == OutboxKind::Application).then_some(at))
            .collect();
        let control = kinds
            .iter()
            .position(|kind| *kind == vhalla_private_relay::RelayKind::Control)
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert!(
            messages[0] < control,
            "membership control overtook earlier committed application"
        );
        assert!(
            control < messages[1],
            "new-epoch application overtook its required control"
        );
        let first = world.sync(1).await.unwrap();
        assert!(first.review);
        assert_eq!(first.received, 1);
        assert_eq!(first.refused, 0);
        world.member_engine = Engine::open(
            &mut world.member,
            world.namespace,
            [9; 32],
            [8; 16],
            0,
            false,
        )
        .await
        .unwrap();
        let second = world.sync(1).await.unwrap();
        assert_eq!(second.received, 2);
        assert_eq!(second.refused, 0);
        assert_eq!(second.deferred, 0);
        assert_eq!(world.member.kernel.as_ref().unwrap().status().members, 3);
    });
}

#[test]
fn later_control_does_not_block_fetching_its_predecessor() {
    block_on(async {
        let mut world = build().await;
        world.renew().await;
        world.renew().await;
        world.sync(0).await;
        assert_eq!(world.mailbox.borrow().items.len(), 2);
        world.mailbox.borrow_mut().items.swap(0, 1);
        let first = world.sync(1).await.unwrap();
        assert!(first.review);
        assert_eq!(first.deferred, 1);
        assert_eq!(first.cursor, 0);
        assert_eq!(first.fetched, 2);
        let second = world.sync(1).await.unwrap();
        assert!(second.review);
        assert_eq!(second.deferred, 0);
        assert_eq!(second.cursor, 2);
        assert_eq!(
            world.member.kernel.as_ref().unwrap().status().control_floor,
            world.owner.kernel.as_ref().unwrap().status().control_floor
        );
    });
}

#[test]
fn ahead_sender_ratchet_is_retained_until_an_earlier_message_arrives() {
    block_on(async {
        let mut world = build().await;
        let mut sent = Vec::new();
        for _ in 0..34 {
            world.send(0).await;
            let kernel = world.owner.kernel.as_mut().unwrap();
            let head = kernel.status().outbox_head;
            let page = kernel.outbox(head - 1, 1).await.unwrap();
            sent.push(
                RelayItem::from_artifact(world.namespace, page.records[0].artifact().unwrap())
                    .unwrap(),
            );
        }
        world.mailbox.borrow_mut().items.push(sent[33].clone());
        let first = world.sync(1).await.unwrap();
        assert_eq!(first.deferred, 1);
        assert_eq!(first.blocked, model::blocked::RATCHET);
        assert_eq!(first.refused, 0);
        world.mailbox.borrow_mut().items.push(sent[0].clone());
        let second = world.sync(1).await.unwrap();
        assert_eq!(second.deferred, 0);
        assert_eq!(second.received, 2);
        assert_eq!(second.refused, 0);
        assert_eq!(world.member.kernel.as_ref().unwrap().status().inbox_head, 2);
    });
}

#[test]
fn relay_retention_never_fabricates_member_acceptance_and_verified_claims_survive_reopen() {
    block_on(async {
        let mut world = build().await;
        world.send(0).await;
        let output = world.owner.kernel.as_ref().unwrap().status().outbox_head;
        world.sync(0).await;
        assert!(world
            .owner
            .kernel
            .as_mut()
            .unwrap()
            .acceptances(output)
            .await
            .unwrap()
            .is_empty());
        world.sync(1).await;
        world.sync(0).await;
        let claims = world
            .owner
            .kernel
            .as_mut()
            .unwrap()
            .acceptances(output)
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].recipient(), world.member_device);
        let context = world.owner.kernel.as_ref().unwrap().status().context;
        world.owner.reopen_kernel(context).await.unwrap();
        assert_eq!(
            world
                .owner
                .kernel
                .as_mut()
                .unwrap()
                .acceptances(output)
                .await
                .unwrap(),
            claims
        );
    });
}

/// A member artifact composed at epoch N reaches the owner's mailbox after an
/// owner renewal moved the room to N+1: the classic Renew/send race. The
/// stale record must be durably refused, skipped and reported while the
/// fresh record behind it still applies.
#[test]
fn stale_member_message_after_owner_renewal_is_recorded_and_delivery_continues() {
    block_on(async {
        let mut world = build().await;
        world.send(1).await; // member commits an epoch-N artifact
        world.renew().await; // owner commits the renewal control
        world.sync(0).await; // owner publishes the control at position 1
                             // The member applies the control (a review stop ends this sync early)
                             // and composes a fresh message at the new epoch.
        assert!(world.sync(1).await.unwrap().review);
        world.send(1).await;
        // Forwarding the exact retained control consumes one bounded outgoing
        // slot (the relay deduplicates it). Then publish both member artifacts.
        world.sync(1).await;
        world.sync(1).await;
        assert_eq!(world.mailbox.borrow().head(), 3);
        let summary = world.sync(0).await.unwrap();
        assert_eq!(summary.stop, 0);
        assert_eq!(summary.refused, 1, "stale epoch record must be retained");
        assert_eq!(summary.received, 1, "the fresh record must still apply");
        assert_eq!(summary.cursor, 3);
        world.converge().await;
    });
}

/// An owner-side removal committed while a member message is already retained
/// in the mailbox leaves the owner's epoch ahead: the late record is refused
/// and skipped, the removal control still reaches the member, and the
/// owner's cursor still reaches the head.
#[test]
fn removal_committed_before_late_member_message_is_skipped_not_wedged() {
    block_on(async {
        let mut world = build().await;
        world.send(1).await;
        world.sync(1).await; // member publishes its epoch-N artifact first
        world.remove().await; // owner removal moves the owner to epoch N+1
        let summary = world.sync(0).await.unwrap();
        assert_eq!(summary.stop, 0);
        assert_eq!(summary.refused, 1);
        assert_eq!(summary.cursor, 1);
        // The removal control is now at position 2; the member applies it as
        // a review and can no longer sync, by design.
        assert!(world.sync(1).await.unwrap().review);
        assert!(world.sync(1).await.is_none());
        world.converge().await;
    });
}

/// Relay-delivered contact bootstrap items are never applied. They are
/// retained byte-exact with their index and released only through the
/// explicit admission path or an explicit discard.
#[test]
fn relay_bootstrap_items_are_retained_for_explicit_admission() {
    block_on(async {
        let mut world = build().await;
        world.inject(OutboxKind::ContactRequest);
        world.inject(OutboxKind::ContactInvitation);
        let summary = world.sync(0).await.unwrap();
        assert_eq!(summary.admissions, 2);
        assert_eq!(summary.refused, 0);
        assert_eq!(summary.received, 0);
        let position = {
            let (engine, _) = world.device(0);
            let admissions = engine.admissions();
            assert_eq!(admissions.len(), 2);
            admissions[0].position
        };
        let (engine, device) = world.device(0);
        let item = engine.retained(device, position).await.unwrap();
        assert_eq!(item.kind(), OutboxKind::ContactRequest);
        let summary = engine.discard(device, position).await.unwrap();
        assert_eq!(summary.admissions, 1);
        world.converge().await;
    });
}

/// Applying a full inbound page batches the durable cursor write but never
/// record durability. For four applied records the image sees one staging
/// write, one reservation and one page commit; the kernel still publishes an
/// inbox record and a retained acceptance for every single message.
#[test]
fn a_full_page_batches_the_cursor_write_but_not_record_durability() {
    block_on(async {
        let mut world = build().await;
        for _ in 0..4 {
            world.send(0).await;
        }
        world.sync(0).await;
        world.sync(0).await;
        assert_eq!(world.mailbox.borrow().head(), 4);
        let writes = world.member.image_writes;
        let publishes = world.member.disk.publishes();
        let summary = world.sync(1).await.unwrap();
        // One write staging the member's non-relay outbox entry, one page
        // reservation, one staged-page write and one batched commit for all
        // four applied records, then two outbound PUTs at three writes each.
        // Persisting the cursor per record needed thirteen, not ten.
        assert_eq!(world.member.image_writes - writes, 10);
        // Two kernel transactions per received record: inbox commit and
        // retained member-acceptance commit.
        assert_eq!(world.member.disk.publishes() - publishes, 8);
        assert_eq!(summary.received, 4);
        assert_eq!(summary.cursor, 4);
        world.converge().await;
    });
}

/// Three hundred successful small-page exchanges charge only their exact
/// bytes through the real reservation/settle path. Holding the pessimistic
/// 4 MiB page reservation forever would have exhausted the 1 GiB lifetime
/// wire budget around the 250th cycle.
#[test]
fn three_hundred_small_page_cycles_charge_only_actual_bytes() {
    block_on(async {
        let mut world = build().await;
        for _ in 0..300 {
            let summary = world.sync(1).await.unwrap();
            assert_eq!(summary.stop, 0);
        }
        let (engine, _) = world.device(1);
        let summary = engine.summary(false);
        assert_eq!(summary.attempts, 300);
        assert!(
            summary.wire_bytes < 1_000_000,
            "wire_bytes {} charged pessimistically",
            summary.wire_bytes
        );
    });
}

#[hegel::test(test_cases = 64)]
fn two_devices_converge_through_controls_messages_and_bootstrap_items(tc: TestCase) {
    block_on(async {
        let mut world = build().await;
        let steps = tc.draw(gs::integers::<usize>().max_value(23)) + 1;
        for _ in 0..steps {
            match tc.draw(gs::integers::<u8>().max_value(7)) {
                0 => {
                    let index = tc.draw(gs::integers::<u8>().max_value(1)) as usize;
                    world.send(index).await;
                }
                1 => world.renew().await,
                2 => world.remove().await,
                3 => {
                    let index = tc.draw(gs::integers::<u8>().max_value(1)) as usize;
                    world.sync(index).await;
                }
                4 => {
                    let kind = if tc.draw(gs::integers::<u8>().max_value(1)) == 0 {
                        OutboxKind::ContactRequest
                    } else {
                        OutboxKind::ContactInvitation
                    };
                    world.inject(kind);
                }
                5 => {
                    let index = tc.draw(gs::integers::<u8>().max_value(1)) as usize;
                    world.discard(index).await;
                }
                6 => {
                    let hours = tc.draw(gs::integers::<u64>().max_value(5)) + 1;
                    world.clock.set(world.clock.get() + 3600 * hours);
                }
                _ => {
                    let index = tc.draw(gs::integers::<u8>().max_value(1)) as usize;
                    world.device(index).1.skew = 3600;
                }
            }
        }
        world.converge().await;
    });
}

async fn admission_fixture(world: &mut World, seed: u8) -> (Kernel<Mem>, Vec<u8>, RelayItem, Key) {
    let now = world.clock.get();
    let account = account(seed);
    let recipient = device_key(&account);
    let membership = world
        .owner
        .kernel
        .as_mut()
        .unwrap()
        .membership()
        .await
        .unwrap();
    let validity = Validity::new(now - 30, now + 1800).unwrap();
    let draft = MemberDraft::new(
        membership.status().context.scope,
        membership.anchor().clone(),
        membership.owner().clone(),
        recipient,
        validity,
        now,
    )
    .unwrap();
    let enrollment = draft.enrollment_request().sign(&account).unwrap();
    let mut member = draft
        .initialize(
            Mem::default(),
            &StorageKey::from_secret([seed; 32]).unwrap(),
            enrollment,
            now,
        )
        .await
        .unwrap();
    let operation = world.operation();
    let offer = world
        .owner
        .kernel
        .as_mut()
        .unwrap()
        .create_contact_offer(operation, recipient, validity, now)
        .await
        .unwrap();
    let request = member
        .contact_request(op(1), offer.confidential_bytes(), now)
        .await
        .unwrap();
    let item = RelayItem::from_artifact(world.namespace, &request).unwrap();
    (member, offer.confidential_bytes().to_vec(), item, recipient)
}

#[test]
fn admission_review_is_read_only_and_confirm_consumes_exact_request_once() {
    block_on(async {
        let mut world = build().await;
        let (mut member, offer, item, recipient) = admission_fixture(&mut world, 9).await;
        let now = world.clock.get();
        let mut admission = admission::Admission::new([1; 16]).unwrap();
        let writes = world.owner.disk.publishes();
        let consent = admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        assert_eq!(writes, world.owner.disk.publishes());
        assert_eq!(consent.device, member.status().context.device);
        // The panel displays the returned metadata without another worker call.
        // Exercise the actual wire round trip before the explicit confirmation.
        let raw = private_wire::Response::AdmissionReview(Box::new(consent.clone()))
            .encode()
            .unwrap();
        let private_wire::Response::AdmissionReview(shown) =
            private_wire::Response::decode(&raw).unwrap()
        else {
            panic!("review reply")
        };
        assert!(*shown == consent);
        let operation = world.operation();
        let command = private_wire::Request::ConfirmAdmission {
            operation,
            consent: shown,
        };
        admission.before(&command);
        let output = admission
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &consent,
                &item,
                now,
            )
            .await
            .unwrap();
        assert_eq!(output.kind(), OutboxKind::ContactInvitation);
        member.join_contact(output.bytes(), now).await.unwrap();
        let writes = world.owner.disk.publishes();
        assert!(admission
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &consent,
                &item,
                now
            )
            .await
            .is_err());
        assert_eq!(writes, world.owner.disk.publishes());
    });
}

#[test]
fn admission_wrong_recipient_and_expired_offer_never_publish() {
    block_on(async {
        let mut world = build().await;
        let (_, offer, item, recipient) = admission_fixture(&mut world, 9).await;
        let now = world.clock.get();
        let writes = world.owner.disk.publishes();
        let mut admission = admission::Admission::new([1; 16]).unwrap();
        assert!(admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                device_key(&account(10)),
                now
            )
            .await
            .is_err());
        assert!(admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now + 1801
            )
            .await
            .is_err());
        let consent = admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        let operation = world.operation();
        assert!(admission
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &consent,
                &item,
                now + 1801
            )
            .await
            .is_err());
        assert_eq!(writes, world.owner.disk.publishes());
    });
}

#[test]
fn admission_sync_read_and_reload_invalidate_worker_held_consent() {
    block_on(async {
        let mut world = build().await;
        let (_, offer, item, recipient) = admission_fixture(&mut world, 9).await;
        let now = world.clock.get();
        let writes = world.owner.disk.publishes();
        let operation = world.operation();
        let mut admission = admission::Admission::new([1; 16]).unwrap();
        for request in [
            private_wire::Request::DeliverySync,
            private_wire::Request::Membership,
        ] {
            let consent = admission
                .review(
                    world.owner.kernel.as_mut().unwrap(),
                    1,
                    &item,
                    &offer,
                    recipient,
                    now,
                )
                .await
                .unwrap();
            admission.before(&request);
            assert!(admission
                .confirm(
                    world.owner.kernel.as_mut().unwrap(),
                    operation,
                    &consent,
                    &item,
                    now
                )
                .await
                .is_err());
        }
        let prior = admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        drop(admission);
        let mut reopened = admission::Admission::new([2; 16]).unwrap();
        assert!(reopened
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &prior,
                &item,
                now
            )
            .await
            .is_err());
        let current = reopened
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        assert_ne!(prior.session, current.session);
        assert!(reopened
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &prior,
                &item,
                now
            )
            .await
            .is_err());
        assert_eq!(writes, world.owner.disk.publishes());
    });
}

#[test]
fn admission_modified_confirmation_or_retained_item_cannot_rebind_review() {
    block_on(async {
        let mut world = build().await;
        let (_, offer, item, recipient) = admission_fixture(&mut world, 9).await;
        let (_, _, replacement, _) = admission_fixture(&mut world, 10).await;
        let now = world.clock.get();
        let writes = world.owner.disk.publishes();
        let operation = world.operation();
        let mut admission = admission::Admission::new([1; 16]).unwrap();
        for field in 0..10 {
            let mut consent = admission
                .review(
                    world.owner.kernel.as_mut().unwrap(),
                    1,
                    &item,
                    &offer,
                    recipient,
                    now,
                )
                .await
                .unwrap();
            match field {
                0 => consent.recipient = device_key(&account(11)),
                1 => consent.device = device_key(&account(11)),
                2 => consent.position += 1,
                3 => consent.digest[0] ^= 1,
                4 => consent.context = world.member.kernel.as_ref().unwrap().status().context,
                5 => consent.epoch += 1,
                6 => consent.roster[0] ^= 1,
                7 => consent.validity = Validity::new(now, now + 10).unwrap(),
                8 => consent.session[0] ^= 1,
                _ => {
                    consent.control_floor =
                        vhalla_private_kernel::protocol::ControlFloor::new(0, None).unwrap()
                }
            }
            assert!(admission
                .confirm(
                    world.owner.kernel.as_mut().unwrap(),
                    operation,
                    &consent,
                    &item,
                    now
                )
                .await
                .is_err());
        }
        let consent = admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        assert!(admission
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &consent,
                &replacement,
                now
            )
            .await
            .is_err());
        assert_eq!(writes, world.owner.disk.publishes());
    });
}

#[test]
fn admission_membership_change_after_review_requires_fresh_consent() {
    block_on(async {
        let mut world = build().await;
        let (_, offer, item, recipient) = admission_fixture(&mut world, 9).await;
        let (_, _, other, _) = admission_fixture(&mut world, 10).await;
        let now = world.clock.get();
        let mut admission = admission::Admission::new([1; 16]).unwrap();
        let consent = admission
            .review(
                world.owner.kernel.as_mut().unwrap(),
                1,
                &item,
                &offer,
                recipient,
                now,
            )
            .await
            .unwrap();
        let operation = world.operation();
        world
            .owner
            .kernel
            .as_mut()
            .unwrap()
            .accept_contact(
                operation,
                other.payload(),
                Validity::new(now, now + 600).unwrap(),
                now,
            )
            .await
            .unwrap();
        let writes = world.owner.disk.publishes();
        let operation = world.operation();
        assert!(admission
            .confirm(
                world.owner.kernel.as_mut().unwrap(),
                operation,
                &consent,
                &item,
                now
            )
            .await
            .is_err());
        assert_eq!(writes, world.owner.disk.publishes());
    });
}
