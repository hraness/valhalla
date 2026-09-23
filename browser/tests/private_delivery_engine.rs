//! Stateful two-device delivery over one ordered in-memory mailbox. Every
//! device owns the production sync engine over a real kernel and durable
//! image; the model injects controls, messages, foreign bootstrap items and
//! clock regressions. A live cursor must always reach the mailbox head and no
//! ordinary command sequence may end a device's custody.
#![cfg(feature = "private-rooms")]
// The shared model and engine also carry paths only the worker transport
// uses (hostile replies, identity changes); the model does not drive them.
#[allow(dead_code)]
#[path = "../src/private/delivery_engine.rs"]
mod engine;
#[allow(dead_code)]
#[path = "../src/private/delivery_model.rs"]
mod model;

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
    };
    let owner_engine = Engine::open(&mut owner, namespace, [9; 32], [7; 16], 0, true)
        .await
        .unwrap();
    let member_engine = Engine::open(&mut member, namespace, [9; 32], [7; 16], 0, true)
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
        // Both member artifacts publish: the stale ciphertext, then the fresh.
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
