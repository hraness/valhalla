#![cfg(all(unix, feature = "client"))]
//! Actual account, MLS and SQLite custody with one local session lifetime.
use futures::executor::block_on;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::Validity, storage::Store, Error as KernelError, OperationId, Phase,
};
use vhalla_private_native::{
    bridge::KernelStore,
    client::{Error, RoomCreation, RoomSession},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-private-client-{}-{}",
            std::process::id(),
            stamp.as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
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
