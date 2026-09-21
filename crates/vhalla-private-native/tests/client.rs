#![cfg(all(unix, feature = "client"))]
//! Actual account, MLS and SQLite custody with one local session lifetime.
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
    protocol::Validity, storage::Store, Error as KernelError, OperationId, Phase,
};
use vhalla_private_native::{
    agent::{Budget, LocalGrant, Permissions},
    bridge::KernelStore,
    client::{Error, RoomCreation, RoomSession},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        // Wall-clock reads can coincide across parallel tests.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-private-client-{}-{}-{ordinal}",
            std::process::id(),
            stamp.as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

#[test]
fn agent_conversion_consumes_client_and_keeps_both_custodies_until_lock() {
    block_on(async {
        let temp = Temp::new();
        let account = temp.0.join("account");
        let room = temp.0.join("room");
        let creation =
            RoomCreation::owner(Identity::create_new(&account).unwrap(), validity()).unwrap();
        let client = creation.commit(&room, limits()).await.unwrap();
        let status = client.status().unwrap();
        let (grant, _revoke) = LocalGrant::for_status(
            status,
            std::time::Duration::from_secs(60),
            Permissions {
                queue: true,
                ..Permissions::default()
            },
            Budget {
                preparations: 1,
                messages: 1,
                body_bytes: 64,
                ..Budget::default()
            },
        )
        .unwrap();
        let mut agent = client.into_agent(grant).unwrap();
        let draft = agent.prepare(b"fixed-room agent content").unwrap();
        let queued = agent.queue(op(9), draft).await.unwrap();
        assert_eq!(queued.sequence, 1);
        agent.lock();
        assert!(agent.is_locked());
        assert!(matches!(agent.status(), Err(Error::Locked)));
        assert!(Identity::open(&account).is_ok());
        drop(agent);
    });
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
        max_records: 128,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn op(value: u8) -> OperationId {
    OperationId::from_bytes([value; 16]).unwrap()
}

#[test]
fn lock_releases_both_custodians_and_exact_reopen_preserves_the_device() {
    block_on(async {
        let temp = Temp::new();
        let account = temp.0.join("account");
        let room = temp.0.join("room");
        let creation =
            RoomCreation::owner(Identity::create_new(&account).unwrap(), validity()).unwrap();
        let context = creation.context();
        let anchor = creation.anchor().clone();
        let mut client = creation.commit(&room, limits()).await.unwrap();
        assert!(Identity::open(&account).is_err());
        assert!(KernelStore::open(&room, context).is_err());
        let snapshot = client.membership().await.unwrap();
        assert_eq!(snapshot.anchor(), &anchor);
        assert_eq!(snapshot.status().context, context);
        assert_eq!(snapshot.members().len(), 1);
        assert_eq!(snapshot.owner().claims().device, context.device);
        assert_eq!(snapshot.local(), snapshot.owner());
        let draft = client.prepare_message(b"retained exact release").unwrap();
        let sent = client.send(op(1), &draft).await.unwrap();
        let before = client.status().unwrap();
        client.lock();
        assert!(client.is_locked());
        assert!(matches!(client.status(), Err(Error::Locked)));
        assert!(matches!(client.membership().await, Err(Error::Locked)));
        assert!(matches!(
            client.send(op(2), &draft).await,
            Err(Error::Locked)
        ));
        let identity = Identity::open(&account).unwrap();
        let mut reopened = RoomSession::open(identity, &room, context).await.unwrap();
        assert_eq!(reopened.status().unwrap(), before);
        let retry = reopened.send(op(1), &draft).await.unwrap();
        assert_eq!(retry.bytes(), sent.bytes());
        assert_eq!(reopened.status().unwrap(), before);
        drop(reopened);
        let identity = Identity::open(&account).unwrap();
        let mut store = KernelStore::open(&room, context).unwrap();
        assert!(store.load(context).await.unwrap().is_some());
        drop(store);
        drop(identity);
    });
}

#[test]
fn recipient_snapshot_and_renewal_preserve_explicit_roster_consent() {
    block_on(async {
        let temp = Temp::new();
        let owner_account = temp.0.join("owner-account");
        let member_account = temp.0.join("member-account");
        let creation =
            RoomCreation::owner(Identity::create_new(&owner_account).unwrap(), validity()).unwrap();
        let owner_context = creation.context();
        let mut owner = creation
            .commit(temp.0.join("owner-room"), limits())
            .await
            .unwrap();
        let before = owner.membership().await.unwrap();
        let member = RoomCreation::member(
            Identity::create_new(&member_account).unwrap(),
            owner_context.scope,
            before.anchor().clone(),
            before.owner().clone(),
            validity(),
        )
        .unwrap();
        let member_context = member.context();
        let mut member = member
            .commit(temp.0.join("member-room"), limits())
            .await
            .unwrap();
        let request = member.key_package(op(1)).await.unwrap();
        let invite = owner
            .invite(op(1), request.bytes(), validity())
            .await
            .unwrap();
        member.join(invite.bytes()).await.unwrap();
        let snapshot = owner.membership().await.unwrap();
        let joined = member.membership().await.unwrap();
        assert_eq!(snapshot.members(), joined.members());
        assert_eq!(snapshot.status().roster, joined.status().roster);
        assert_eq!(snapshot.members().len(), 2);
        assert!(snapshot
            .members()
            .iter()
            .any(|e| e.claims().device == member_context.device));
        let draft = member.prepare_message(b"old roster disclosure").unwrap();
        let floor = member.status().unwrap().control_floor;
        let previous_validity = snapshot.owner().claims().validity;
        let renewal = Validity::new(
            previous_validity.not_before(),
            previous_validity.expires_at() + 3600,
        )
        .unwrap();
        owner.renew_owner(op(2), renewal).await.unwrap();
        let controls = owner.encrypted_controls(floor, 16).await.unwrap();
        assert_eq!(controls.records.len(), 1);
        member
            .apply_control(controls.records[0].bytes())
            .await
            .unwrap();
        assert_ne!(member.status().unwrap().roster, joined.status().roster);
        assert!(matches!(
            member.send(op(2), &draft).await,
            Err(Error::Kernel(KernelError::Conflict))
        ));
        // A failed operation requires explicit close/open, not a hidden retry.
        member.lock();
        member = RoomSession::open(
            Identity::open(&member_account).unwrap(),
            temp.0.join("member-room"),
            member_context,
        )
        .await
        .unwrap();
        let fresh = member
            .prepare_message(b"current recipients approved")
            .unwrap();
        let sent = member.send(op(3), &fresh).await.unwrap();
        assert_eq!(
            owner.receive(sent.bytes()).await.unwrap().body(),
            b"current recipients approved"
        );
        let floor = member.status().unwrap().control_floor;
        owner.remove(op(3), member_context.device).await.unwrap();
        let controls = owner.encrypted_controls(floor, 16).await.unwrap();
        member
            .apply_control(controls.records[0].bytes())
            .await
            .unwrap();
        let removed = member.membership().await.unwrap();
        assert_eq!(removed.status().phase, Phase::Removed);
        assert_eq!(removed.local().claims().device, member_context.device);
        assert!(!removed
            .members()
            .iter()
            .any(|e| e.claims().device == member_context.device));
        assert!(member.prepare_message(b"must refuse").is_err());
        drop(member);
        drop(owner);
    });
}

#[test]
fn wrong_account_and_missing_image_never_initialize_or_replace_state() {
    block_on(async {
        let temp = Temp::new();
        let account = temp.0.join("account");
        let other = temp.0.join("other");
        let room = temp.0.join("room");
        let creation =
            RoomCreation::owner(Identity::create_new(&account).unwrap(), validity()).unwrap();
        let context = creation.context();
        let mut client = creation.commit(&room, limits()).await.unwrap();
        let status = client.status().unwrap();
        client.lock();
        let mut store = KernelStore::open(&room, context).unwrap();
        let image = store.load(context).await.unwrap().unwrap();
        drop(store);
        let result = RoomSession::open(Identity::create_new(&other).unwrap(), &room, context).await;
        assert!(matches!(result, Err(Error::Kernel(KernelError::Scope))));
        let mut store = KernelStore::open(&room, context).unwrap();
        assert!(store.load(context).await.unwrap().as_ref() == Some(&image));
        drop(store);
        let reopened = RoomSession::open(Identity::open(&account).unwrap(), &room, context)
            .await
            .unwrap();
        assert_eq!(reopened.status().unwrap(), status);
        drop(reopened);
        let empty = temp.0.join("empty");
        drop(KernelStore::create_new(&empty, context, limits()).unwrap());
        let result = RoomSession::open(Identity::open(&account).unwrap(), &empty, context).await;
        assert!(matches!(result, Err(Error::Kernel(KernelError::Missing))));
        let mut store = KernelStore::open(&empty, context).unwrap();
        assert!(store.load(context).await.unwrap().is_none());
        drop(store);
    });
}

#[test]
fn one_confidential_offer_bootstraps_a_recipient_and_never_reactivates_on_retry() {
    block_on(async {
        use vhalla_private_kernel::{protocol::Key, OutboxKind};
        let temp = Temp::new();
        let owner_account = temp.0.join("owner-account");
        let member_account = temp.0.join("member-account");
        let owner_room = temp.0.join("owner-room");
        let member_room = temp.0.join("member-room");
        let validity = validity();
        let creation =
            RoomCreation::owner(Identity::create_new(&owner_account).unwrap(), validity).unwrap();
        let owner_context = creation.context();
        let mut owner = creation.commit(&owner_room, limits()).await.unwrap();
        let recipient = Identity::create_new(&member_account).unwrap();
        let recipient_key = Key::from_bytes(recipient.public_key()).unwrap();
        drop(recipient);
        let offer = owner
            .create_contact_offer(op(1), recipient_key, validity)
            .await
            .unwrap();
        let page = owner.outbox(0, 16).await.unwrap();
        assert_eq!(page.head, 1);
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].kind(), OutboxKind::ContactOffer);
        assert!(page.records[0].artifact().is_none());
        assert!(matches!(
            RoomCreation::from_contact(
                Identity::open(&member_account).unwrap(),
                offer.confidential_bytes(),
                recipient_key,
                validity
            ),
            Err(Error::Kernel(KernelError::Scope))
        ));
        assert!(!member_room.exists());
        let creation = RoomCreation::from_contact(
            Identity::open(&member_account).unwrap(),
            offer.confidential_bytes(),
            owner_context.account,
            validity,
        )
        .unwrap();
        assert_eq!(creation.context().scope, owner_context.scope);
        let member_context = creation.context();
        let mut member = creation.commit(&member_room, limits()).await.unwrap();
        let request = member
            .contact_request(op(1), offer.confidential_bytes())
            .await
            .unwrap();
        assert_eq!(request.kind(), OutboxKind::ContactRequest);
        owner.lock();
        let mut owner = RoomSession::open(
            Identity::open(&owner_account).unwrap(),
            &owner_room,
            owner_context,
        )
        .await
        .unwrap();
        let response = owner
            .accept_contact(op(2), request.bytes(), validity)
            .await
            .unwrap();
        assert_eq!(response.kind(), OutboxKind::ContactInvitation);
        member.join_contact(response.bytes()).await.unwrap();
        assert_eq!(
            member.membership().await.unwrap().members(),
            owner.membership().await.unwrap().members()
        );
        let before = owner.status().unwrap();
        let recovered = owner
            .create_contact_offer(op(1), recipient_key, validity)
            .await
            .unwrap();
        assert_eq!(recovered.confidential_bytes(), offer.confidential_bytes());
        assert_eq!(
            owner
                .accept_contact(op(2), request.bytes(), validity)
                .await
                .unwrap()
                .bytes(),
            response.bytes()
        );
        assert_eq!(owner.status().unwrap(), before);
        assert!(matches!(
            owner.accept_contact(op(3), request.bytes(), validity).await,
            Err(Error::Kernel(KernelError::Missing))
        ));
        owner.lock();
        let mut owner = RoomSession::open(
            Identity::open(&owner_account).unwrap(),
            &owner_room,
            owner_context,
        )
        .await
        .unwrap();
        assert_eq!(owner.status().unwrap(), before);
        member.lock();
        let mut member = RoomSession::open(
            Identity::open(&member_account).unwrap(),
            &member_room,
            member_context,
        )
        .await
        .unwrap();
        member.join_contact(response.bytes()).await.unwrap();
        let draft = member
            .prepare_message(b"explicitly invited private member")
            .unwrap();
        let sent = member.send(op(2), &draft).await.unwrap();
        assert_eq!(
            owner.receive(sent.bytes()).await.unwrap().body(),
            b"explicitly invited private member"
        );
    });
}
