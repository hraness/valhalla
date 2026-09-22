use crate::Error;
use crate::{protocol::*, storage::*, *};
use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Before,
    After,
    HangAfter,
}
#[derive(Default)]
struct Disk {
    context: Option<Context>,
    image: Option<Image>,
    records: BTreeMap<RecordKey, StoredRecord>,
    published: BTreeSet<RecordKey>,
    fault: Fault,
}
#[derive(Clone, Default)]
struct Memory(Rc<RefCell<Disk>>);
impl Memory {
    fn image(&self) -> Image {
        self.0.borrow().image.clone().unwrap()
    }
    fn fault(&self, fault: Fault) {
        self.0.borrow_mut().fault = fault;
    }
    fn snapshot(&self) -> (Image, BTreeMap<RecordKey, StoredRecord>) {
        (self.image(), self.0.borrow().records.clone())
    }
}
impl Store for Memory {
    async fn load(&mut self, context: Context) -> std::result::Result<Option<Image>, StoreError> {
        let disk = self.0.borrow();
        if disk.context.is_some_and(|old| old != context) {
            return Err(StoreError::Corrupt);
        }
        if disk.image.is_none() && (!disk.records.is_empty() || !disk.published.is_empty()) {
            return Err(StoreError::Corrupt);
        }
        Ok(disk.image.clone())
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> std::result::Result<Option<StoredRecord>, StoreError> {
        let disk = self.0.borrow();
        if disk.context != Some(context) {
            return Err(StoreError::Corrupt);
        }
        let result = disk.records.get(&key).cloned();
        if result.is_some() != disk.published.contains(&key) {
            return Err(StoreError::Corrupt);
        }
        Ok(result)
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> std::result::Result<(), StoreError> {
        let fault = {
            let mut disk = self.0.borrow_mut();
            if disk.context.is_some_and(|old| old != context) {
                return Err(StoreError::Corrupt);
            }
            if disk.image.as_ref() != expected
                || (expected.is_none() && (!disk.records.is_empty() || !disk.published.is_empty()))
            {
                return Err(StoreError::Conflict);
            }
            if records.len() > MAX_TRANSACTION_RECORDS {
                return Err(StoreError::Refused);
            }
            let mut offered = BTreeSet::new();
            for record in records {
                if !offered.insert(record.key()) || disk.published.contains(&record.key()) {
                    return Err(StoreError::Conflict);
                }
            }
            let fault = std::mem::take(&mut disk.fault);
            if matches!(fault, Fault::Before) {
                return Err(StoreError::Refused);
            }
            for record in records {
                disk.records.insert(record.key(), record.clone());
                disk.published.insert(record.key());
            }
            disk.context = Some(context);
            disk.image = Some(next.clone());
            fault
        };
        match fault {
            Fault::After => Err(StoreError::Uncertain),
            Fault::HangAfter => std::future::pending().await,
            _ => Ok(()),
        }
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn validity(now: u64) -> Validity {
    Validity::new(now - 30, now + 7200).unwrap()
}
fn account() -> SigningKey {
    SigningKey::from_bytes(&codec::random().unwrap())
}
fn key(account: &SigningKey) -> Key {
    Key::from_bytes(account.verifying_key().to_bytes()).unwrap()
}
fn storage_key() -> StorageKey {
    StorageKey::from_secret(codec::random().unwrap()).unwrap()
}
fn retained_work(disk: &Memory, key: &StorageKey, context: Context) -> model::Working {
    let image = disk.image();
    let clear = codec::unseal(
        key,
        context,
        b"current-state",
        image.as_bytes(),
        MAX_IMAGE_BYTES,
    )
    .unwrap();
    model::Working::hydrate(model::State::decode(&clear, context).unwrap()).unwrap()
}
fn op(value: u64) -> OperationId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    OperationId::from_bytes(bytes).unwrap()
}
// Legacy lifecycle regressions explicitly prepare the current release at each
// call. Group-specific tests below retain MessageDraft across epoch changes.
impl Kernel<Memory> {
    async fn test_send(
        &mut self,
        operation: OperationId,
        body: &[u8],
        now: u64,
    ) -> Result<CommittedOutbox> {
        let draft = self.prepare_message(body)?;
        self.send(operation, &draft, now).await
    }
}
struct Pair {
    owner: Kernel<Memory>,
    member: Kernel<Memory>,
    owner_disk: Memory,
    member_disk: Memory,
    owner_key: StorageKey,
    owner_account: SigningKey,
    member_key: StorageKey,
    now: u64,
}
async fn fresh() -> Pair {
    fresh_with_lifetimes(7200, 7200).await
}
async fn fresh_with_lifetimes(owner_life: u64, member_life: u64) -> Pair {
    let now = now();
    let owner_account = account();
    let member_account = account();
    let draft = OwnerDraft::new(
        key(&owner_account),
        Validity::new(now - 30, now + owner_life).unwrap(),
    )
    .unwrap();
    let anchor = draft.anchor_request().sign(&owner_account).unwrap();
    let enrollment = draft.enrollment_request().sign(&owner_account).unwrap();
    let scope = anchor.verify().unwrap().scope();
    let member_draft = MemberDraft::new(
        scope,
        anchor.clone(),
        enrollment.clone(),
        key(&member_account),
        Validity::new(now - 30, now + member_life).unwrap(),
        now,
    )
    .unwrap();
    let member_enrollment = member_draft
        .enrollment_request()
        .sign(&member_account)
        .unwrap();
    let owner_key = storage_key();
    let member_key = storage_key();
    let owner_disk = Memory::default();
    let member_disk = Memory::default();
    let owner = draft
        .create(owner_disk.clone(), &owner_key, enrollment, anchor, now)
        .await
        .unwrap();
    let member = member_draft
        .initialize(member_disk.clone(), &member_key, member_enrollment, now)
        .await
        .unwrap();
    Pair {
        owner,
        member,
        owner_disk,
        member_disk,
        owner_key,
        owner_account,
        member_key,
        now,
    }
}
async fn joined() -> Pair {
    let mut pair = fresh().await;
    let package = pair.member.key_package(op(1), pair.now).await.unwrap();
    let invitation = pair
        .owner
        .invite(op(1), package.bytes(), validity(pair.now), pair.now)
        .await
        .unwrap();
    pair.member
        .join(invitation.bytes(), pair.now)
        .await
        .unwrap();
    pair
}
impl Pair {
    async fn reopen_owner(&mut self) {
        self.owner = Kernel::open(
            self.owner_disk.clone(),
            &self.owner_key,
            self.owner.status().context,
        )
        .await
        .unwrap();
    }
    async fn reopen_member(&mut self) {
        self.member = Kernel::open(
            self.member_disk.clone(),
            &self.member_key,
            self.member.status().context,
        )
        .await
        .unwrap();
    }
}

#[test]
fn owner_invite_join_messages_remove_and_exact_reopen_retries() {
    block_on(async {
        let mut pair = fresh().await;
        assert_eq!(pair.owner.status().phase, Phase::OwnerGenesis);
        assert_eq!(pair.member.status().phase, Phase::AwaitingWelcome);
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let invitation = pair
            .owner
            .invite(op(1), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        pair.reopen_owner().await;
        assert_eq!(
            pair.owner
                .invite(op(1), package.bytes(), validity(pair.now), pair.now + 1)
                .await
                .unwrap()
                .bytes(),
            invitation.bytes()
        );
        pair.member
            .join(invitation.bytes(), pair.now)
            .await
            .unwrap();
        pair.reopen_member().await;
        assert_eq!(
            pair.member
                .join(invitation.bytes(), pair.now + 1)
                .await
                .unwrap()
                .phase,
            Phase::MemberJoined
        );
        assert_eq!(
            pair.member
                .key_package(op(1), pair.now)
                .await
                .unwrap()
                .bytes(),
            package.bytes()
        );
        let sent = pair
            .owner
            .test_send(op(2), b"inert puzzle request", pair.now)
            .await
            .unwrap();
        let received = pair.member.receive(sent.bytes(), pair.now).await.unwrap();
        assert_eq!(received.sender(), pair.owner.status().context.device);
        assert_eq!(received.body(), b"inert puzzle request");
        pair.reopen_owner().await;
        pair.reopen_member().await;
        assert_eq!(
            pair.owner
                .test_send(op(2), b"inert puzzle request", pair.now + 2)
                .await
                .unwrap()
                .bytes(),
            sent.bytes()
        );
        assert_eq!(
            pair.member
                .receive(sent.bytes(), pair.now + 2)
                .await
                .unwrap()
                .sequence(),
            received.sequence()
        );
        let reply = pair
            .member
            .test_send(op(2), b"inert result", pair.now)
            .await
            .unwrap();
        assert_eq!(
            pair.owner
                .receive(reply.bytes(), pair.now)
                .await
                .unwrap()
                .body(),
            b"inert result"
        );
        let removal = pair
            .owner
            .remove(op(3), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        assert_eq!(pair.owner.status().phase, Phase::OwnerAfterRemoval);
        assert_eq!(
            pair.member
                .apply_removal(removal.bytes(), pair.now)
                .await
                .unwrap()
                .phase,
            Phase::Removed
        );
        pair.reopen_member().await;
        assert_eq!(
            pair.member
                .apply_removal(removal.bytes(), pair.now)
                .await
                .unwrap()
                .phase,
            Phase::Removed
        );
        assert!(matches!(
            pair.member.test_send(op(3), b"forbidden", pair.now).await,
            Err(Error::Policy)
        ));
        pair.reopen_member().await;
        assert!(pair
            .member
            .join(invitation.bytes(), pair.now)
            .await
            .is_err());
        pair.reopen_member().await;
        let later = pair
            .owner
            .test_send(op(4), b"after removal", pair.now)
            .await
            .unwrap();
        assert!(pair.member.receive(later.bytes(), pair.now).await.is_err());
    });
}

#[test]
fn commit_refusal_and_uncertainty_preserve_exact_sender_and_receiver_results() {
    block_on(async {
        let mut pair = joined().await;
        let before = pair.owner_disk.snapshot();
        pair.owner_disk.fault(Fault::Before);
        assert!(matches!(
            pair.owner.test_send(op(2), b"must commit", pair.now).await,
            Err(Error::Refused)
        ));
        assert!(pair.owner.needs_reopen());
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        pair.owner_disk.fault(Fault::After);
        assert!(matches!(
            pair.owner.test_send(op(2), b"must commit", pair.now).await,
            Err(Error::NeedsReopen)
        ));
        assert!(pair.owner.needs_reopen());
        pair.reopen_owner().await;
        let output = pair
            .owner
            .test_send(op(2), b"must commit", pair.now)
            .await
            .unwrap();
        assert_eq!(output.sequence(), 2);
        let confirmed = pair.owner_disk.snapshot();
        assert_eq!(
            pair.owner
                .test_send(op(2), b"must commit", pair.now)
                .await
                .unwrap()
                .bytes(),
            output.bytes()
        );
        assert!(pair.owner_disk.snapshot() == confirmed);
        let before = pair.member_disk.snapshot();
        pair.member_disk.fault(Fault::Before);
        assert!(matches!(
            pair.member.receive(output.bytes(), pair.now).await,
            Err(Error::Refused)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member_disk.fault(Fault::After);
        assert!(matches!(
            pair.member.receive(output.bytes(), pair.now).await,
            Err(Error::NeedsReopen)
        ));
        pair.reopen_member().await;
        let received = pair.member.receive(output.bytes(), pair.now).await.unwrap();
        assert_eq!(received.body(), b"must commit");
        assert_eq!(received.sequence(), 1);
    });
}

#[test]
fn cancellation_latches_and_competing_custody_cannot_reuse_ratchet() {
    block_on(async {
        let mut pair = joined().await;
        let context = pair.owner.status().context;
        let mut stale = Kernel::open(pair.owner_disk.clone(), &pair.owner_key, context)
            .await
            .unwrap();
        pair.owner_disk.fault(Fault::HangAfter);
        {
            let pending = pair
                .owner
                .test_send(op(2), b"committed before cancellation", pair.now);
            futures::pin_mut!(pending);
            assert!(futures::poll!(pending.as_mut()).is_pending());
        }
        assert!(pair.owner.needs_reopen());
        assert!(matches!(
            pair.owner
                .test_send(op(3), b"cannot continue", pair.now)
                .await,
            Err(Error::NeedsReopen)
        ));
        assert!(matches!(
            stale.test_send(op(2), b"different bytes", pair.now).await,
            Err(Error::Conflict)
        ));
        pair.reopen_owner().await;
        let output = pair
            .owner
            .test_send(op(2), b"committed before cancellation", pair.now)
            .await
            .unwrap();
        assert_eq!(
            pair.member
                .receive(output.bytes(), pair.now)
                .await
                .unwrap()
                .body(),
            b"committed before cancellation"
        );
    });
}

#[test]
fn one_time_package_join_failure_and_invalid_bindings_do_not_publish() {
    block_on(async {
        let mut pair = fresh().await;
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let before = pair.member_disk.snapshot();
        assert!(pair.member.key_package(op(2), pair.now).await.is_err());
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let invitation = pair
            .owner
            .invite(op(1), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let mut tampered = invitation.bytes().to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(pair.member.join(&tampered, pair.now).await.is_err());
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member_disk.fault(Fault::Before);
        assert!(matches!(
            pair.member.join(invitation.bytes(), pair.now).await,
            Err(Error::Refused)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .join(invitation.bytes(), pair.now)
            .await
            .unwrap();
        let joined = pair.member_disk.snapshot();
        // A cryptographically valid enrollment from another account/device does not
        // substitute for the exact recipient credential selected before joining.
        let mut packet = packets::InvitePacket::decode(invitation.bytes()).unwrap();
        let account = account();
        let other = OwnerDraft::new(key(&account), validity(pair.now)).unwrap();
        packet.member = other
            .enrollment_request()
            .sign(&account)
            .unwrap()
            .verify()
            .unwrap();
        assert!(pair
            .member
            .join(&packet.encode().unwrap(), pair.now)
            .await
            .is_err());
        assert!(pair.member_disk.snapshot() == joined);
    });
}

#[test]
fn wrong_context_ciphertext_operation_collision_and_missing_index_fail_closed() {
    block_on(async {
        let mut pair = joined().await;
        let context = pair.owner.status().context;
        let mut wrong = context;
        wrong.scope.anchor = AnchorId::from_bytes(codec::random().unwrap()).unwrap();
        assert!(
            Kernel::open(pair.owner_disk.clone(), &pair.owner_key, wrong)
                .await
                .is_err()
        );
        assert!(
            Kernel::open(pair.owner_disk.clone(), &storage_key(), context)
                .await
                .is_err()
        );
        pair.owner
            .test_send(op(2), b"original", pair.now)
            .await
            .unwrap();
        let original = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner.test_send(op(2), b"replacement", pair.now).await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == original);
        pair.reopen_owner().await;
        pair.owner_disk
            .0
            .borrow_mut()
            .records
            .remove(&RecordKey::Operation(op(2)));
        assert!(matches!(
            pair.owner.test_send(op(2), b"original", pair.now).await,
            Err(Error::NeedsReopen)
        ));
        assert_eq!(pair.owner.status().outbox_head, 2);
    });
}

#[test]
fn bounded_pages_exceed_sixty_four_messages_and_clock_rejects_without_effects() {
    block_on(async {
        let mut pair = joined().await;
        for index in 2u64..=71 {
            let message = pair
                .owner
                .test_send(op(index), &index.to_be_bytes(), pair.now + index)
                .await
                .unwrap();
            assert_eq!(
                pair.member
                    .receive(message.bytes(), pair.now + index)
                    .await
                    .unwrap()
                    .body(),
                &index.to_be_bytes()
            );
        }
        pair.reopen_owner().await;
        let mut after = 0;
        let mut count = 0;
        loop {
            let page = pair.owner.outbox(after, 7).await.unwrap();
            assert_eq!(page.head, 71);
            assert!(page.records.len() <= 7);
            count += page.records.len();
            if let Some(next) = page.next {
                assert!(next > after);
                after = next;
            } else {
                break;
            }
        }
        assert_eq!(count, 71);
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .test_send(op(72), b"clock regressed", pair.now)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        assert!(matches!(
            pair.owner
                .test_send(op(72), b"expired", pair.now + 7200)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.owner_disk.snapshot() == before);
    });
}

#[test]
fn bounds_and_nonsecret_backend_records_are_enforced() {
    block_on(async {
        let mut pair = joined().await;
        let body = b"SYNTHETIC private record marker never stored as cleartext";
        let message = pair.owner.test_send(op(2), body, pair.now).await.unwrap();
        pair.member
            .receive(message.bytes(), pair.now)
            .await
            .unwrap();
        for store in [&pair.owner_disk, &pair.member_disk] {
            let disk = store.0.borrow();
            assert!(!disk
                .image
                .as_ref()
                .unwrap()
                .as_bytes()
                .windows(body.len())
                .any(|window| window == body));
            for record in disk.records.values() {
                assert!(!record
                    .as_bytes()
                    .windows(body.len())
                    .any(|window| window == body));
            }
        }
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .test_send(op(3), &[1; MAX_BODY_BYTES + 1], pair.now)
                .await,
            Err(Error::Bounds)
        ));
        assert!(!pair.owner.needs_reopen());
        assert!(pair.owner_disk.snapshot() == before);
        assert!(matches!(
            pair.member
                .receive(&vec![1; MAX_WIRE_BYTES + 1], pair.now)
                .await,
            Err(Error::Bounds)
        ));
        assert!(Image::from_bytes(&[1; 39]).is_err());
        assert!(StoredRecord::from_bytes(RecordKey::Outbox(0), &[1; 40]).is_err());
    });
}

#[test]
fn cryptographically_valid_foreign_control_and_wrong_recipient_refuse_before_welcome() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = fresh().await;
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let original = pair
            .owner
            .invite(op(1), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let before = pair.member_disk.snapshot();
        let mut malformed = packets::InvitePacket::decode(original.bytes()).unwrap();
        malformed.commit = b"not an MLS Commit".to_vec();
        let mut claims = malformed.control.claims().clone();
        claims.commit = CommitDigest::of_bytes(&malformed.commit).unwrap();
        let unsigned = UnsignedOwnerControl::new(claims).unwrap();
        let owner = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        let signature = owner
            .signer()
            .unwrap()
            .sign(&unsigned.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        malformed.control = unsigned.attach(signature).unwrap().verify().unwrap();
        assert!(matches!(
            pair.member
                .join(&malformed.encode().unwrap(), pair.now)
                .await,
            Err(Error::Encoding)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let attacker = account();
        let mut packet = packets::InvitePacket::decode(original.bytes()).unwrap();
        let mut claims = packet.control.claims().clone();
        claims.owner_device = key(&attacker);
        packet.control = UnsignedOwnerControl::new(claims)
            .unwrap()
            .sign(&attacker)
            .unwrap()
            .verify()
            .unwrap();
        assert!(matches!(
            pair.member.join(&packet.encode().unwrap(), pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let mut packet = packets::InvitePacket::decode(original.bytes()).unwrap();
        let wrong = OwnerDraft::new(key(&attacker), validity(pair.now)).unwrap();
        packet.member = wrong
            .enrollment_request()
            .sign(&attacker)
            .unwrap()
            .verify()
            .unwrap();
        assert!(matches!(
            pair.member.join(&packet.encode().unwrap(), pair.now).await,
            Err(Error::Scope)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member.join(original.bytes(), pair.now).await.unwrap();
        let removal = pair
            .owner
            .remove(op(2), pair.member.status().context.device, pair.now)
            .await
            .unwrap();
        let mut packet = decode_for_member(&pair, removal.bytes());
        let mut claims = packet.control.claims().clone();
        claims.owner_device = key(&attacker);
        packet.control = UnsignedOwnerControl::new(claims)
            .unwrap()
            .sign(&attacker)
            .unwrap()
            .verify()
            .unwrap();
        let forged_wire = wrap_for_member(&pair, &packet);
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_removal(&forged_wire, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
    });
}

#[test]
fn actual_key_package_secret_is_consumed_only_after_committed_welcome() {
    use openmls::prelude::*;
    use openmls_traits::OpenMlsProvider;
    use tls_codec::Deserialize as _;
    block_on(async {
        let mut pair = fresh().await;
        let package = pair.member.key_package(op(1), pair.now).await.unwrap();
        let join = packets::JoinRequest::decode(package.bytes()).unwrap();
        let context = pair.member.status().context;
        let work = retained_work(&pair.member_disk, &pair.member_key, context);
        let parsed = KeyPackageIn::tls_deserialize_exact(&join.package)
            .unwrap()
            .validate(work.provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let package_ref = parsed.hash_ref(work.provider.crypto()).unwrap();
        let retained: Option<KeyPackageBundle> =
            openmls_traits::storage::StorageProvider::key_package(
                work.provider.storage(),
                &package_ref,
            )
            .unwrap();
        assert!(retained.is_some());
        let invitation = pair
            .owner
            .invite(op(1), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        pair.member_disk.fault(Fault::Before);
        assert!(pair
            .member
            .join(invitation.bytes(), pair.now)
            .await
            .is_err());
        let work = retained_work(&pair.member_disk, &pair.member_key, context);
        let retained: Option<KeyPackageBundle> =
            openmls_traits::storage::StorageProvider::key_package(
                work.provider.storage(),
                &package_ref,
            )
            .unwrap();
        assert!(retained.is_some());
        pair.reopen_member().await;
        pair.member
            .join(invitation.bytes(), pair.now)
            .await
            .unwrap();
        let work = retained_work(&pair.member_disk, &pair.member_key, context);
        let retained: Option<KeyPackageBundle> =
            openmls_traits::storage::StorageProvider::key_package(
                work.provider.storage(),
                &package_ref,
            )
            .unwrap();
        assert!(retained.is_none());
    });
}

#[test]
fn uncertain_initialization_reopens_exact_retained_context_and_never_resets() {
    block_on(async {
        let now = now();
        let account = account();
        let key = storage_key();
        let disk = Memory::default();
        let draft = OwnerDraft::new(crate::tests::key(&account), validity(now)).unwrap();
        let anchor = draft.anchor_request().sign(&account).unwrap();
        let enrollment = draft.enrollment_request().sign(&account).unwrap();
        let context = draft.context(&anchor).unwrap();
        disk.fault(Fault::After);
        assert!(matches!(
            draft
                .create(disk.clone(), &key, enrollment.clone(), anchor.clone(), now)
                .await,
            Err(Error::NeedsReopen)
        ));
        let kernel = Kernel::open(disk.clone(), &key, context).await.unwrap();
        assert_eq!(kernel.status().phase, Phase::OwnerGenesis);
        let old = disk.snapshot();
        let replacement = OwnerDraft::new(crate::tests::key(&account), validity(now)).unwrap();
        let replaced_anchor = replacement.anchor_request().sign(&account).unwrap();
        let replaced_enrollment = replacement.enrollment_request().sign(&account).unwrap();
        assert!(replacement
            .create(
                disk.clone(),
                &key,
                replaced_enrollment,
                replaced_anchor,
                now
            )
            .await
            .is_err());
        assert!(disk.snapshot() == old);
    });
}

#[test]
fn control_key_and_three_record_transaction_are_canonical_atomic_and_bounded() {
    block_on(async {
        let pair = fresh().await;
        let context = pair.owner.status().context;
        let mut store = Memory::default();
        let first = Image::from_bytes(&[1; 40]).unwrap();
        let next = Image::from_bytes(&[2; 40]).unwrap();
        let last = Image::from_bytes(&[3; 40]).unwrap();
        store.publish(context, None, &first, &[]).await.unwrap();
        assert!(RecordKey::Control(0).validate().is_err());
        assert!(StoredRecord::from_bytes(RecordKey::Control(0), &[1; 40]).is_err());
        assert_eq!(
            RecordKey::Control(0x0102030405060708).encode(),
            [5, 1, 2, 3, 4, 5, 6, 7, 8]
        );
        let record = |key| StoredRecord::from_bytes(key, &[9; 40]).unwrap();
        let batch = [
            record(RecordKey::Control(1)),
            record(RecordKey::Outbox(1)),
            record(RecordKey::Operation(op(1))),
        ];
        store.fault(Fault::Before);
        assert_eq!(
            store.publish(context, Some(&first), &next, &batch).await,
            Err(StoreError::Refused)
        );
        assert!(store.image() == first);
        assert!(store.0.borrow().records.is_empty());
        store.fault(Fault::After);
        assert_eq!(
            store.publish(context, Some(&first), &next, &batch).await,
            Err(StoreError::Uncertain)
        );
        assert!(store.image() == next);
        for expected in &batch {
            assert!(store.read(context, expected.key()).await.unwrap().as_ref() == Some(expected));
        }
        let before = store.snapshot();
        let collision = [
            record(RecordKey::Outbox(2)),
            record(RecordKey::Operation(op(2))),
            record(RecordKey::Control(1)),
        ];
        assert_eq!(
            store.publish(context, Some(&next), &last, &collision).await,
            Err(StoreError::Conflict)
        );
        assert!(store.snapshot() == before);
        let too_many = [
            record(RecordKey::Outbox(2)),
            record(RecordKey::Operation(op(2))),
            record(RecordKey::Control(2)),
            record(RecordKey::Inbox(1)),
        ];
        assert_eq!(
            store.publish(context, Some(&next), &last, &too_many).await,
            Err(StoreError::Refused)
        );
        assert!(store.snapshot() == before);
    });
}

async fn pending_device(pair: &Pair, account: &SigningKey) -> (Kernel<Memory>, Memory, StorageKey) {
    let owner = retained_work(
        &pair.owner_disk,
        &pair.owner_key,
        pair.owner.status().context,
    );
    let chain: Vec<OwnerSuccessionProof> = owner.state.successions.clone();
    let draft = if chain.is_empty() {
        MemberDraft::new(
            pair.owner.status().context.scope,
            owner.state.anchor.signed().clone(),
            owner.state.owner.signed().clone(),
            key(account),
            validity(pair.now),
            pair.now,
        )
        .unwrap()
    } else {
        MemberDraft::new_succeeded(
            pair.owner.status().context.scope,
            owner.state.anchor.signed().clone(),
            owner.state.owner.signed().clone(),
            chain,
            key(account),
            validity(pair.now),
            pair.now,
        )
        .unwrap()
    };
    let enrollment = draft.enrollment_request().sign(account).unwrap();
    let disk = Memory::default();
    let secret = storage_key();
    let kernel = draft
        .initialize(disk.clone(), &secret, enrollment, pair.now)
        .await
        .unwrap();
    (kernel, disk, secret)
}
async fn add_device(pair: &mut Pair, member: &mut Kernel<Memory>, operation: u64) -> Vec<u8> {
    let before = pair.owner.status().control_floor;
    let package = member.key_package(op(1), pair.now).await.unwrap();
    let invitation = pair
        .owner
        .invite(op(operation), package.bytes(), validity(pair.now), pair.now)
        .await
        .unwrap();
    member.join(invitation.bytes(), pair.now).await.unwrap();
    let page = pair.owner.encrypted_controls(before, 1).await.unwrap();
    assert_eq!(page.records.len(), 1);
    page.records[0].bytes().to_vec()
}

#[test]
fn four_devices_late_join_ordered_catchup_and_explicit_new_device_rejoin() {
    block_on(async {
        let mut pair = joined().await;
        let account = account();
        let (mut third, third_disk, third_key) = pending_device(&pair, &account).await;
        let control2 = add_device(&mut pair, &mut third, 10).await;
        assert_eq!(third.status().history_base.sequence(), 1);
        assert!(matches!(
            third.controls(ControlFloor::new(0, None).unwrap(), 1).await,
            Err(Error::Missing)
        ));
        third = Kernel::open(third_disk.clone(), &third_key, third.status().context)
            .await
            .unwrap();
        let (mut fourth, _, _) = pending_device(&pair, &account).await;
        let control3 = add_device(&mut pair, &mut fourth, 11).await;
        assert_ne!(
            third.status().context.device,
            fourth.status().context.device
        );
        assert_eq!(
            third.status().context.account,
            fourth.status().context.account
        );
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_control(&control3, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .apply_control(&control2, pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(&control3, pair.now)
            .await
            .unwrap();
        third.apply_control(&control3, pair.now).await.unwrap();
        assert_eq!(pair.owner.status().members, 4);
        assert_eq!(pair.owner.status().roster, fourth.status().roster);
        let draft = fourth
            .prepare_message(b"explicit four-device release")
            .unwrap();
        let sent = fourth.send(op(2), &draft, pair.now).await.unwrap();
        assert_eq!(
            third.receive(sent.bytes(), pair.now).await.unwrap().body(),
            draft.body()
        );
        let before = pair.owner.status().control_floor;
        pair.owner
            .remove(op(12), third.status().context.device, pair.now)
            .await
            .unwrap();
        let removal = pair
            .owner
            .encrypted_controls(before, 1)
            .await
            .unwrap()
            .records
            .remove(0);
        pair.member
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        fourth
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        third
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        assert_eq!(third.status().phase, Phase::Removed);
        assert_eq!(fourth.status().members, 3);
        assert!(third.prepare_message(b"cannot rejoin by reset").is_err());
        let (mut replacement, _, _) = pending_device(&pair, &account).await;
        let control5 = add_device(&mut pair, &mut replacement, 13).await;
        fourth.apply_control(&control5, pair.now).await.unwrap();
        pair.member
            .apply_control(&control5, pair.now)
            .await
            .unwrap();
        assert_eq!(replacement.status().history_base.sequence(), 4);
        assert_eq!(replacement.status().members, 4);
        assert!(matches!(
            third.apply_control(&control5, pair.now).await,
            Err(Error::Policy)
        ));
        third = Kernel::open(third_disk, &third_key, third.status().context)
            .await
            .unwrap();
        assert_eq!(third.status().phase, Phase::Removed);
        assert!(third.inbox(0, 16).await.unwrap().records.len() == 1);
    });
}

#[test]
fn typed_release_refuses_new_epoch_author_and_roster_but_retains_exact_old_ciphertext() {
    block_on(async {
        let mut pair = joined().await;
        let draft = pair
            .owner
            .prepare_message(b"for the original two devices only")
            .unwrap();
        let sent = pair.owner.send(op(20), &draft, pair.now).await.unwrap();
        let (mut third, _, _) = pending_device(&pair, &account()).await;
        let control = add_device(&mut pair, &mut third, 21).await;
        pair.member.apply_control(&control, pair.now).await.unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner.send(op(22), &draft, pair.now).await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        assert_eq!(
            pair.owner
                .send(op(20), &draft, pair.now)
                .await
                .unwrap()
                .bytes(),
            sent.bytes()
        );
        assert!(matches!(
            third.send(op(20), &draft, pair.now).await,
            Err(Error::Scope)
        ));
        // The old epoch is never re-encrypted or silently re-shared with third.
        assert!(third.receive(sent.bytes(), pair.now).await.is_err());
        let explicit = pair.owner.prepare_message(draft.body()).unwrap();
        let new = pair.owner.send(op(22), &explicit, pair.now).await.unwrap();
        assert_ne!(new.bytes(), sent.bytes());
        assert_eq!(pair.owner.status().outbox_head, 4);
    });
}

#[test]
fn sixteen_device_capacity_and_bounded_control_pages_do_not_scan_lifetime_history() {
    block_on(async {
        let mut pair = joined().await;
        let mut last = None;
        for index in 2..MAX_MEMBERS {
            let (mut member, _, _) = pending_device(&pair, &account()).await;
            add_device(&mut pair, &mut member, 100 + index as u64).await;
            last = Some(member);
        }
        assert_eq!(pair.owner.status().members, MAX_MEMBERS);
        assert_eq!(
            last.as_ref().unwrap().status().roster,
            pair.owner.status().roster
        );
        let (mut excess, _, _) = pending_device(&pair, &account()).await;
        let package = excess.key_package(op(1), pair.now).await.unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner
                .invite(op(200), package.bytes(), validity(pair.now), pair.now)
                .await,
            Err(Error::Bounds)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        let mut cursor = ControlFloor::new(0, None).unwrap();
        let mut count = 0;
        loop {
            let page = pair.owner.controls(cursor, 3).await.unwrap();
            assert!(page.records.len() <= 3);
            count += page.records.len();
            if let Some(next) = page.next {
                cursor = next;
            } else {
                break;
            }
        }
        assert_eq!(count, MAX_MEMBERS - 1);
        let clear = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        assert!(clear.state.roster.len() == 16);
        assert!(pair.owner_disk.image().as_bytes().len() < MAX_IMAGE_BYTES);
    });
}

fn control_proof(pair: &Pair, raw: &[u8]) -> VerifiedOwnerControl {
    if let Ok(signed) = SignedOwnerControl::decode(raw) {
        return signed.verify().unwrap();
    }
    let frame = transport::Envelope::decode(raw).unwrap();
    let key = RecordKey::Control(frame.sequence);
    let record = pair.owner_disk.0.borrow().records[&key].clone();
    let mut purpose = b"record/".to_vec();
    purpose.extend(key.encode());
    let clear = codec::unseal(
        &pair.owner_key,
        pair.owner.status().context,
        &purpose,
        record.as_bytes(),
        MAX_STORED_RECORD_BYTES,
    )
    .unwrap();
    transport::RetainedControl::decode(&clear).unwrap().control
}
fn decode_for_member(pair: &Pair, raw: &[u8]) -> packets::ControlPacket {
    let work = retained_work(
        &pair.member_disk,
        &pair.member_key,
        pair.member.status().context,
    );
    transport::open(&work, &transport::Envelope::decode(raw).unwrap()).unwrap()
}
fn wrap_for_member(pair: &Pair, packet: &packets::ControlPacket) -> Vec<u8> {
    let work = retained_work(
        &pair.member_disk,
        &pair.member_key,
        pair.member.status().context,
    );
    transport::seal(&work, &work.group().unwrap(), packet).unwrap()
}
fn conflicting_control(pair: &Pair, raw: &[u8]) -> Vec<u8> {
    use openmls_traits::signatures::Signer;
    let mut claims = control_proof(pair, raw).claims().clone();
    claims.change = ControlChange::Membership {
        additions: Vec::new(),
        removals: vec![pair.owner.status().context.device],
    };
    let unsigned = UnsignedOwnerControl::new(claims).unwrap();
    let owner = retained_work(
        &pair.owner_disk,
        &pair.owner_key,
        pair.owner.status().context,
    );
    unsigned
        .attach(
            owner
                .signer()
                .unwrap()
                .sign(&unsigned.signing_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
        .encode()
}

#[test]
fn owner_fork_is_durable_quarantine_and_failed_publication_preserves_observation() {
    block_on(async {
        for fault in [Fault::None, Fault::Before, Fault::After] {
            let mut pair = joined().await;
            let page = pair
                .owner
                .controls(ControlFloor::new(0, None).unwrap(), 1)
                .await
                .unwrap();
            let fork = conflicting_control(&pair, page.records[0].bytes());
            let before = pair.member_disk.snapshot();
            pair.member_disk.fault(fault);
            let result = pair.member.observe_owner_control(&fork, pair.now).await;
            match fault {
                Fault::None => {
                    assert!(matches!(result, Err(Error::Quarantined)));
                    assert!(pair.member.status().quarantined);
                    assert!(pair.member.pending_fork_evidence().is_none());
                }
                Fault::Before => {
                    assert!(matches!(result, Err(Error::Refused)));
                    assert!(pair.member.needs_reopen());
                    assert!(pair.member.pending_fork_evidence().is_some());
                    assert!(pair.member_disk.snapshot() == before);
                }
                Fault::After => {
                    assert!(matches!(result, Err(Error::NeedsReopen)));
                    assert!(pair.member.pending_fork_evidence().is_some());
                }
                _ => unreachable!(),
            }
            pair.reopen_member().await;
            if matches!(fault, Fault::Before) {
                assert!(!pair.member.status().quarantined); // no impossible persistence claim
                assert!(matches!(
                    pair.member.observe_owner_control(&fork, pair.now).await,
                    Err(Error::Quarantined)
                ));
            }
            assert!(pair.member.status().quarantined);
            let proof = pair.member.fork_evidence().await.unwrap().unwrap();
            assert_eq!(proof.accepted, page.records[0].floor());
            assert_ne!(
                proof.conflicting.verify().unwrap().id(),
                proof.accepted.id().unwrap()
            );
            assert!(matches!(
                pair.member.prepare_message(b"never after fork"),
                Err(Error::Quarantined)
            ));
            assert!(matches!(
                pair.member
                    .observe_owner_control(page.records[0].bytes(), pair.now)
                    .await,
                Err(Error::Quarantined)
            ));
            assert_eq!(
                pair.member
                    .controls(pair.member.status().history_base, 16)
                    .await
                    .unwrap()
                    .records
                    .len(),
                1
            );
        }
    });
}

#[test]
fn later_join_checks_owner_endorsement_against_actual_mls_roster_before_committing() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let (mut third, disk, secret) = pending_device(&pair, &account()).await;
        let package = third.key_package(op(1), pair.now).await.unwrap();
        let invitation = pair
            .owner
            .invite(op(10), package.bytes(), validity(pair.now), pair.now)
            .await
            .unwrap();
        let mut packet = packets::InvitePacket::decode(invitation.bytes()).unwrap();
        let (_, replacement_disk, replacement_secret) = pending_device(&pair, &account()).await;
        let replacement_context = replacement_disk.0.borrow().context.unwrap();
        let replacement =
            retained_work(&replacement_disk, &replacement_secret, replacement_context)
                .state
                .local;
        let mut claims = packet.checkpoint.claims().clone();
        let original = pair.member.status().context.device;
        let index = claims
            .roster
            .iter()
            .position(|e| e.claims().device == original)
            .unwrap();
        claims.roster[index] = replacement;
        claims.roster.sort_by_key(|e| e.claims().device);
        let unsigned = checkpoint::UnsignedCheckpoint::new(claims).unwrap();
        let owner = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        packet.checkpoint = unsigned
            .attach(
                owner
                    .signer()
                    .unwrap()
                    .sign(&unsigned.signing_bytes().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        let before = disk.snapshot();
        assert!(matches!(
            third.join(&packet.encode().unwrap(), pair.now).await,
            Err(Error::Policy)
        ));
        assert!(disk.snapshot() == before);
        third = Kernel::open(disk, &secret, third.status().context)
            .await
            .unwrap();
        third.join(invitation.bytes(), pair.now).await.unwrap();
        assert_eq!(third.status().members, 3);
    });
}

#[test]
fn missing_precheckpoint_history_cannot_quarantine_but_known_checkpoint_floor_can() {
    block_on(async {
        let mut pair = joined().await;
        let first = pair
            .owner
            .controls(ControlFloor::new(0, None).unwrap(), 1)
            .await
            .unwrap()
            .records
            .remove(0);
        let (mut third, _, _) = pending_device(&pair, &account()).await;
        let second = add_device(&mut pair, &mut third, 10).await;
        let (mut fourth, disk, secret) = pending_device(&pair, &account()).await;
        add_device(&mut pair, &mut fourth, 11).await;
        assert_eq!(fourth.status().history_base.sequence(), 2);
        let before = disk.snapshot();
        assert!(matches!(
            fourth
                .observe_owner_control(&conflicting_control(&pair, first.bytes()), pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(disk.snapshot() == before);
        fourth = Kernel::open(disk.clone(), &secret, fourth.status().context)
            .await
            .unwrap();
        assert!(matches!(
            fourth
                .observe_owner_control(&conflicting_control(&pair, &second), pair.now)
                .await,
            Err(Error::Quarantined)
        ));
        fourth = Kernel::open(disk, &secret, fourth.status().context)
            .await
            .unwrap();
        let evidence = fourth.fork_evidence().await.unwrap().unwrap();
        assert!(evidence.accepted_from_checkpoint);
        let proof = checkpoint::Checkpoint::decode(&evidence.accepted_proof).unwrap();
        assert_eq!(proof.claims().parent, evidence.accepted);
        assert_ne!(
            evidence.conflicting.verify().unwrap().id(),
            evidence.accepted.id().unwrap()
        );
    });
}

#[test]
fn canceled_fork_commit_requires_reopen_and_exact_group_control_retry_does_not_write() {
    block_on(async {
        let mut pair = joined().await;
        let control = pair
            .owner
            .controls(ControlFloor::new(0, None).unwrap(), 1)
            .await
            .unwrap()
            .records
            .remove(0);
        let before = pair.member_disk.snapshot();
        pair.member
            .observe_owner_control(control.bytes(), pair.now + 8000)
            .await
            .unwrap();
        assert!(pair.member_disk.snapshot() == before); // history retry, not expired admission
        pair.member_disk.fault(Fault::HangAfter);
        let fork = conflicting_control(&pair, control.bytes());
        {
            let pending = pair.member.observe_owner_control(&fork, pair.now);
            futures::pin_mut!(pending);
            assert!(futures::poll!(pending).is_pending());
        }
        assert!(pair.member.needs_reopen());
        assert!(pair.member.pending_fork_evidence().is_some());
        pair.reopen_member().await;
        assert!(pair.member.status().quarantined);
        assert!(pair.member.fork_evidence().await.unwrap().is_some());
    });
}

#[test]
fn observing_unsupported_owner_claim_cannot_admit_future_state_but_records_known_fork() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let page = pair
            .owner
            .controls(ControlFloor::new(0, None).unwrap(), 1)
            .await
            .unwrap();
        let proof = SignedOwnerControl::decode(page.records[0].bytes())
            .unwrap()
            .verify()
            .unwrap();
        let owner = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        let sign = |claims| {
            let unsigned = UnsignedOwnerControl::new(claims).unwrap();
            unsigned
                .attach(
                    owner
                        .signer()
                        .unwrap()
                        .sign(&unsigned.signing_bytes())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )
                .unwrap()
        };
        let mut future = proof.claims().clone();
        future.parent = pair.owner.status().control_floor;
        future.prior_epoch = 1;
        future.next_epoch = 2;
        future.change = ControlChange::OwnerUpdate;
        let future = sign(future);
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member
                .observe_owner_control(&future.encode(), pair.now)
                .await,
            Err(Error::Missing)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        let mut claims = proof.claims().clone();
        claims.change = ControlChange::OwnerUpdate;
        let known = sign(claims);
        assert!(matches!(
            pair.member
                .observe_owner_control(&known.encode(), pair.now)
                .await,
            Err(Error::Quarantined)
        ));
        pair.reopen_member().await;
        assert!(pair.member.status().quarantined);
        assert_eq!(
            pair.member
                .fork_evidence()
                .await
                .unwrap()
                .unwrap()
                .conflicting,
            known
        );
    });
}

fn renewal(pair: &Pair, validity: Validity) -> SignedDeviceEnrollment {
    pair.owner
        .owner_renewal_request(validity)
        .unwrap()
        .sign(&pair.owner_account)
        .unwrap()
}
async fn join_pending(pair: &mut Pair) {
    let package = pair.member.key_package(op(1), pair.now).await.unwrap();
    let invitation = pair
        .owner
        .invite(op(1), package.bytes(), validity(pair.now), pair.now)
        .await
        .unwrap();
    pair.member
        .join(invitation.bytes(), pair.now)
        .await
        .unwrap();
}

#[test]
fn owner_renewal_preserves_fixed_identity_invalidates_drafts_and_joins_with_new_credential() {
    block_on(async {
        let mut pair = joined().await;
        let context = pair.owner.status().context;
        let old_roster = pair.owner.status().roster;
        let old = pair
            .owner
            .prepare_message(b"consent before owner credential update")
            .unwrap();
        let enrollment = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
        let updated = pair
            .owner
            .renew_owner(op(10), enrollment.clone(), pair.now + 1)
            .await
            .unwrap();
        assert_eq!(updated.kind(), OutboxKind::OwnerUpdate);
        assert_eq!(pair.owner.status().context, context);
        assert_eq!(pair.owner.status().members, 2);
        assert_ne!(pair.owner.status().roster, old_roster);
        pair.member
            .apply_control(updated.bytes(), pair.now + 1)
            .await
            .unwrap();
        pair.reopen_owner().await;
        pair.reopen_member().await;
        assert_eq!(pair.owner.status().roster, pair.member.status().roster);
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner.send(op(11), &old, pair.now + 1).await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == before);
        pair.reopen_owner().await;
        assert_eq!(
            pair.owner
                .renew_owner(op(10), enrollment, pair.now + 2)
                .await
                .unwrap()
                .bytes(),
            updated.bytes()
        );
        assert!(pair.owner_disk.snapshot() == before);
        let fresh = pair
            .owner
            .prepare_message(b"new exact roster release")
            .unwrap();
        let message = pair.owner.send(op(11), &fresh, pair.now + 2).await.unwrap();
        assert_eq!(
            pair.member
                .receive(message.bytes(), pair.now + 2)
                .await
                .unwrap()
                .body(),
            fresh.body()
        );
        pair.now += 3;
        let (mut third, disk, secret) = pending_device(&pair, &account()).await;
        let add = add_device(&mut pair, &mut third, 12).await;
        pair.member.apply_control(&add, pair.now).await.unwrap();
        third = Kernel::open(disk, &secret, third.status().context)
            .await
            .unwrap();
        assert_eq!(third.status().roster, pair.owner.status().roster);
        assert_eq!(third.status().history_base.sequence(), 2);
        assert_eq!(
            pair.member
                .controls(pair.member.status().history_base, 16)
                .await
                .unwrap()
                .records
                .len(),
            3
        );
    });
}

#[test]
fn expired_owner_requires_current_same_device_account_attestation_and_keeps_ordinary_checks() {
    block_on(async {
        let mut pair = fresh_with_lifetimes(60, 7200).await;
        join_pending(&mut pair).await;
        let later = pair.now + 61;
        assert!(matches!(
            pair.owner
                .test_send(op(10), b"old credential cannot send", later)
                .await,
            Err(Error::Time)
        ));
        assert!(matches!(
            pair.member
                .test_send(op(10), b"old owner blocks ordinary admission", later)
                .await,
            Err(Error::Time)
        ));
        pair.reopen_owner().await;
        pair.reopen_member().await;
        let enrollment = renewal(
            &pair,
            Validity::new(pair.now + 60, pair.now + 14400).unwrap(),
        );
        let update = pair
            .owner
            .renew_owner(op(10), enrollment, later)
            .await
            .unwrap();
        pair.member
            .apply_control(update.bytes(), later)
            .await
            .unwrap();
        pair.reopen_owner().await;
        pair.reopen_member().await;
        let draft = pair
            .member
            .prepare_message(b"admitted after explicit owner renewal")
            .unwrap();
        let message = pair.member.send(op(10), &draft, later).await.unwrap();
        assert_eq!(
            pair.owner
                .receive(message.bytes(), later)
                .await
                .unwrap()
                .body(),
            draft.body()
        );
        assert!(
            pair.owner.status().context.device
                == pair
                    .owner
                    .owner_renewal_request(Validity::new(later, later + 20000).unwrap())
                    .unwrap()
                    .claims()
                    .device
        );
    });
}

#[test]
fn renewal_wrong_account_device_interval_and_operation_collision_preserve_all_state() {
    block_on(async {
        let mut pair = joined().await;
        assert!(matches!(
            pair.member.owner_renewal_request(validity(pair.now)),
            Err(Error::Policy)
        ));
        let context = pair.owner.status().context;
        let attacker = account();
        let cases = [
            (
                context.account,
                key(&attacker),
                Validity::new(pair.now, pair.now + 14400).unwrap(),
                false,
            ),
            (
                key(&attacker),
                context.device,
                Validity::new(pair.now, pair.now + 14400).unwrap(),
                true,
            ),
            (context.account, context.device, validity(pair.now), false),
            (
                context.account,
                context.device,
                Validity::new(pair.now - 31, pair.now + 14400).unwrap(),
                false,
            ),
            (
                context.account,
                context.device,
                Validity::new(pair.now + 1, pair.now + 14400).unwrap(),
                false,
            ),
        ];
        for (account, device, validity, foreign) in cases {
            let record = UnsignedDeviceEnrollment::new(DeviceEnrollmentClaims {
                account,
                device,
                validity,
            })
            .unwrap()
            .sign(if foreign {
                &attacker
            } else {
                &pair.owner_account
            })
            .unwrap();
            let before = pair.owner_disk.snapshot();
            assert!(pair
                .owner
                .renew_owner(op(10), record, pair.now)
                .await
                .is_err());
            assert!(pair.owner_disk.snapshot() == before);
            pair.reopen_owner().await;
        }
        let first = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
        pair.owner
            .renew_owner(op(10), first, pair.now)
            .await
            .unwrap();
        let next = renewal(&pair, Validity::new(pair.now, pair.now + 20000).unwrap());
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            pair.owner.renew_owner(op(10), next, pair.now).await,
            Err(Error::Conflict)
        ));
        assert!(pair.owner_disk.snapshot() == before);
    });
}

#[test]
fn owner_renewal_and_member_admission_are_atomic_under_refusal_uncertainty_and_cancellation() {
    block_on(async {
        for fault in [Fault::Before, Fault::After, Fault::HangAfter] {
            let mut pair = joined().await;
            let enrollment = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
            let before = pair.owner_disk.snapshot();
            pair.owner_disk.fault(fault);
            if matches!(fault, Fault::HangAfter) {
                let pending = pair.owner.renew_owner(op(10), enrollment.clone(), pair.now);
                futures::pin_mut!(pending);
                assert!(futures::poll!(pending).is_pending());
            } else {
                assert!(pair
                    .owner
                    .renew_owner(op(10), enrollment.clone(), pair.now)
                    .await
                    .is_err());
            }
            assert!(pair.owner.needs_reopen());
            if matches!(fault, Fault::Before) {
                assert!(pair.owner_disk.snapshot() == before);
            }
            pair.reopen_owner().await;
            let update = pair
                .owner
                .renew_owner(op(10), enrollment.clone(), pair.now)
                .await
                .unwrap();
            assert_eq!(pair.owner.status().control_sequence, 2);
            assert_eq!(pair.owner.status().outbox_head, 2);
            let before = pair.member_disk.snapshot();
            pair.member_disk.fault(fault);
            if matches!(fault, Fault::HangAfter) {
                let pending = pair.member.apply_control(update.bytes(), pair.now);
                futures::pin_mut!(pending);
                assert!(futures::poll!(pending).is_pending());
            } else {
                assert!(pair
                    .member
                    .apply_control(update.bytes(), pair.now)
                    .await
                    .is_err());
            }
            assert!(pair.member.needs_reopen());
            if matches!(fault, Fault::Before) {
                assert!(pair.member_disk.snapshot() == before);
            }
            pair.reopen_member().await;
            pair.member
                .apply_control(update.bytes(), pair.now)
                .await
                .unwrap();
            assert_eq!(pair.member.status().control_sequence, 2);
            assert_eq!(pair.member.status().roster, pair.owner.status().roster);
        }
    });
}

#[test]
fn valid_owner_renewal_label_cannot_hide_membership_proposals_or_a_different_path_credential() {
    use openmls_traits::signatures::Signer;
    block_on(async {
        let mut pair = joined().await;
        let enrollment = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
        let (mut third, _, _) = pending_device(&pair, &account()).await;
        let addition = add_device(&mut pair, &mut third, 10).await;
        let mut packet = decode_for_member(&pair, &addition);
        let mut claims = packet.control.claims().clone();
        claims.change = ControlChange::OwnerUpdate;
        let unsigned = UnsignedOwnerControl::new(claims).unwrap();
        let owner = retained_work(
            &pair.owner_disk,
            &pair.owner_key,
            pair.owner.status().context,
        );
        packet.control = unsigned
            .attach(
                owner
                    .signer()
                    .unwrap()
                    .sign(&unsigned.signing_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap()
            .verify()
            .unwrap();
        packet.invitation = None;
        packet.enrollment = Some(enrollment.verify().unwrap());
        let forged_wire = wrap_for_member(&pair, &packet);
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_control(&forged_wire, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .apply_control(&addition, pair.now)
            .await
            .unwrap();
        let actual = pair
            .owner
            .renew_owner(op(11), enrollment, pair.now)
            .await
            .unwrap();
        let other = renewal(&pair, Validity::new(pair.now, pair.now + 20000).unwrap());
        let mut packet = decode_for_member(&pair, actual.bytes());
        packet.enrollment = Some(other.verify().unwrap());
        let forged_wire = wrap_for_member(&pair, &packet);
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_control(&forged_wire, pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .apply_control(actual.bytes(), pair.now)
            .await
            .unwrap();
    });
}

#[test]
fn renewal_controls_cannot_skip_parent_floor_or_reactivate_expired_local_member() {
    block_on(async {
        let mut pair = joined().await;
        let first = renewal(&pair, Validity::new(pair.now, pair.now + 14400).unwrap());
        let update1 = pair
            .owner
            .renew_owner(op(10), first, pair.now)
            .await
            .unwrap();
        let second = renewal(&pair, Validity::new(pair.now, pair.now + 20000).unwrap());
        let update2 = pair
            .owner
            .renew_owner(op(11), second, pair.now)
            .await
            .unwrap();
        let before = pair.member_disk.snapshot();
        assert!(matches!(
            pair.member.apply_control(update2.bytes(), pair.now).await,
            Err(Error::Policy)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        assert!(matches!(
            pair.member
                .apply_control(update1.bytes(), pair.now + 7201)
                .await,
            Err(Error::Time)
        ));
        assert!(pair.member_disk.snapshot() == before);
        pair.reopen_member().await;
        pair.member
            .apply_control(update1.bytes(), pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(update2.bytes(), pair.now)
            .await
            .unwrap();
        pair.reopen_member().await;
        assert_eq!(pair.member.status().roster, pair.owner.status().roster);
    });
}

mod acceptance;
mod confidential;

mod contact;

mod recovery;

mod succession;
