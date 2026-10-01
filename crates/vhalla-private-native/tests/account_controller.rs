#![cfg(all(unix, feature = "client"))]
//! One account lock, independent durable rooms, and no room-writer sharing.

use futures::executor::block_on;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::{Store, StoreError},
    Error as KernelError, OperationId,
};
use vhalla_private_native::{
    agent::{Budget, Error as AgentError, LocalGrant, Permissions},
    bridge::KernelStore,
    client::{AccountController, Error},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-account-controller-{}-{}-{ordinal}",
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
fn account_busy(path: &Path) {
    assert!(matches!(Identity::open(path), Err(IdentityError::Busy)));
}

#[test]
fn two_rooms_send_and_reopen_independently_under_one_account() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let first = account.prepare_owner(validity()).unwrap();
        let second = account.prepare_owner(validity()).unwrap();
        let first_context = first.context();
        let second_context = second.context();
        assert_eq!(*first_context.account.as_bytes(), account.public_key());
        assert_eq!(first_context.account, second_context.account);
        assert_ne!(first_context.scope, second_context.scope);
        assert_ne!(first_context.device, second_context.device);
        let first_path = temp.0.join("first");
        let second_path = temp.0.join("second");
        let mut first = first.commit(&first_path, limits()).await.unwrap();
        let mut second = second.commit(&second_path, limits()).await.unwrap();
        account_busy(&account_path);

        let first_draft = first.prepare_message(b"first room").unwrap();
        let second_draft = second.prepare_message(b"second room").unwrap();
        let (sent_first, sent_second) = futures::join!(
            first.send(op(1), &first_draft),
            second.send(op(1), &second_draft)
        );
        let sent_first = sent_first.unwrap();
        let sent_second = sent_second.unwrap();
        assert_ne!(sent_first.bytes(), sent_second.bytes());
        let first_status = first.status().unwrap();
        let second_status = second.status().unwrap();

        first.lock();
        assert!(first.is_locked());
        account_busy(&account_path);
        let mut reopened = account.open_room(&first_path, first_context).await.unwrap();
        assert_eq!(reopened.status().unwrap(), first_status);
        assert_eq!(
            reopened.send(op(1), &first_draft).await.unwrap().bytes(),
            sent_first.bytes()
        );
        assert_eq!(second.status().unwrap(), second_status);
        let draft = second.prepare_message(b"second remains live").unwrap();
        second.send(op(2), &draft).await.unwrap();
        assert_eq!(reopened.status().unwrap(), first_status);

        drop(account);
        reopened.lock();
        account_busy(&account_path);
        second.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}

#[test]
fn controller_and_uncommitted_creation_each_retain_account_custody() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let first = account.prepare_owner(validity()).unwrap();
        drop(first);
        // Even with no room or unpublished device, the controller owns custody.
        account_busy(&account_path);
        let pending = account.prepare_owner(validity()).unwrap();
        let session = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("live"), limits())
            .await
            .unwrap();
        drop(account);
        account_busy(&account_path);
        drop(session);
        account_busy(&account_path);
        // The creation can commit after its controller has gone away.
        let mut session = pending
            .commit(temp.0.join("pending"), limits())
            .await
            .unwrap();
        account_busy(&account_path);
        session.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}

#[test]
fn shared_account_never_allows_competing_room_writers_or_recreation() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let room_path = temp.0.join("room");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let creation = account.prepare_owner(validity()).unwrap();
        let context = creation.context();
        let mut session = creation.commit(&room_path, limits()).await.unwrap();
        let before = session.status().unwrap();
        assert!(matches!(
            account.open_room(&room_path, context).await,
            Err(Error::Storage(StoreError::Refused))
        ));
        assert!(matches!(
            account
                .prepare_owner(validity())
                .unwrap()
                .commit(&room_path, limits())
                .await,
            Err(Error::Storage(StoreError::Refused))
        ));
        assert_eq!(session.status().unwrap(), before);
        session.lock();
        let reopened = account.open_room(&room_path, context).await.unwrap();
        assert_eq!(reopened.status().unwrap(), before);
        account_busy(&account_path);
        drop(reopened);
        drop(account);
        assert!(Identity::open(&account_path).is_ok());
    });
}

#[test]
fn wrong_account_refuses_before_store_access_and_preserves_existing_state() {
    block_on(async {
        let temp = Temp::new();
        let account = AccountController::new(Identity::create_new(temp.0.join("account")).unwrap());
        let other = AccountController::new(Identity::create_new(temp.0.join("other")).unwrap());
        let room_path = temp.0.join("room");
        let creation = account.prepare_owner(validity()).unwrap();
        let context = creation.context();
        let mut session = creation.commit(&room_path, limits()).await.unwrap();
        let status = session.status().unwrap();
        // Scope rejection precedes the otherwise-busy backend lock.
        assert!(matches!(
            other.open_room(&room_path, context).await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        session.lock();
        let mut store = KernelStore::open(&room_path, context).unwrap();
        let before = store.load(context).await.unwrap().unwrap();
        drop(store);
        assert!(matches!(
            other.open_room(&room_path, context).await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        let absent = temp.0.join("absent");
        assert!(matches!(
            other.open_room(&absent, context).await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        assert!(!absent.exists());
        let mut store = KernelStore::open(&room_path, context).unwrap();
        assert!(store.load(context).await.unwrap().as_ref() == Some(&before));
        drop(store);
        let reopened = account.open_room(&room_path, context).await.unwrap();
        assert_eq!(reopened.status().unwrap(), status);
    });
}

#[test]
fn member_preparation_and_contact_join_share_one_recipient_account() {
    block_on(async {
        let temp = Temp::new();
        // Offers and invitations cannot outlive their issuing credentials.
        // Share an interval rather than extending it at each wall-clock read.
        let validity = validity();
        let owner = AccountController::new(Identity::create_new(temp.0.join("owner")).unwrap());
        let recipient_path = temp.0.join("recipient");
        let recipient = AccountController::new(Identity::create_new(&recipient_path).unwrap());
        let mut first_owner = owner
            .prepare_owner(validity)
            .unwrap()
            .commit(temp.0.join("first-owner"), limits())
            .await
            .unwrap();
        let first_membership = first_owner.membership().await.unwrap();
        let mut first_member = recipient
            .prepare_member(
                first_membership.status().context.scope,
                first_membership.anchor().clone(),
                first_membership.owner().clone(),
                validity,
            )
            .unwrap()
            .commit(temp.0.join("first-member"), limits())
            .await
            .unwrap();
        let request = first_member.key_package(op(1)).await.unwrap();
        let invitation = first_owner
            .invite(op(1), request.bytes(), validity)
            .await
            .unwrap();
        first_member.join(invitation.bytes()).await.unwrap();

        let mut second_owner = owner
            .prepare_owner(validity)
            .unwrap()
            .commit(temp.0.join("second-owner"), limits())
            .await
            .unwrap();
        let before_offer = second_owner.status().unwrap();
        let recipient_key = Key::from_bytes(recipient.public_key()).unwrap();
        let beyond_owner = Validity::new(validity.not_before(), validity.expires_at() + 1).unwrap();
        assert!(matches!(
            second_owner
                .create_contact_offer(op(1), recipient_key, beyond_owner)
                .await,
            Err(Error::Kernel(KernelError::Scope))
        ));
        assert_eq!(second_owner.status().unwrap(), before_offer);
        assert_eq!(second_owner.outbox(0, 1).await.unwrap().head, 0);
        // Refusal does not consume the operation or weaken the expiry check.
        let offer = second_owner
            .create_contact_offer(op(1), recipient_key, validity)
            .await
            .unwrap();
        let mut second_member = recipient
            .prepare_contact_member(
                offer.confidential_bytes(),
                Key::from_bytes(owner.public_key()).unwrap(),
                validity,
            )
            .unwrap()
            .commit(temp.0.join("second-member"), limits())
            .await
            .unwrap();
        let request = second_member
            .contact_request(op(1), offer.confidential_bytes())
            .await
            .unwrap();
        let invitation = second_owner
            .accept_contact(op(2), request.bytes(), validity)
            .await
            .unwrap();
        second_member
            .join_contact(invitation.bytes())
            .await
            .unwrap();

        for (member, owner, message) in [
            (
                &mut first_member,
                &mut first_owner,
                b"first joined room".as_slice(),
            ),
            (
                &mut second_member,
                &mut second_owner,
                b"second joined room".as_slice(),
            ),
        ] {
            let draft = member.prepare_message(message).unwrap();
            let sent = member.send(op(2), &draft).await.unwrap();
            assert_eq!(owner.receive(sent.bytes()).await.unwrap().body(), message);
        }
        drop(recipient);
        first_member.lock();
        account_busy(&recipient_path);
        second_member.lock();
        assert!(Identity::open(&recipient_path).is_ok());
    });
}

#[test]
fn narrowed_agent_holds_account_custody_after_controller_and_other_room_drop() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let room_path = temp.0.join("agent-room");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let session = account
            .prepare_owner(validity())
            .unwrap()
            .commit(&room_path, limits())
            .await
            .unwrap();
        let other = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("other-room"), limits())
            .await
            .unwrap();
        let status = session.status().unwrap();
        let (grant, _revoke) = LocalGrant::for_status(
            status,
            Duration::from_secs(60),
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
        let mut agent = session.into_agent(grant).unwrap();
        drop(account);
        drop(other);
        account_busy(&account_path);
        assert!(matches!(
            KernelStore::open(&room_path, status.context),
            Err(StoreError::Refused)
        ));
        let draft = agent.prepare(b"fixed-room shared-account agent").unwrap();
        assert_eq!(agent.queue(op(1), draft).await.unwrap().sequence, 1);
        agent.lock();
        assert!(agent.is_locked());
        assert!(matches!(agent.status(), Err(Error::Locked)));
        assert!(Identity::open(&account_path).is_ok());
        assert!(KernelStore::open(&room_path, status.context).is_ok());
    });
}

#[test]
fn maintenance_keeps_account_and_room_locked_until_its_own_drop() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let room_path = temp.0.join("maintenance-room");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let creation = account.prepare_owner(validity()).unwrap();
        let context = creation.context();
        let session = creation.commit(&room_path, limits()).await.unwrap();
        let other = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("other-room"), limits())
            .await
            .unwrap();
        let maintenance = session.into_delivery_maintenance().unwrap();
        drop(account);
        drop(other);
        account_busy(&account_path);
        assert!(matches!(
            KernelStore::open(&room_path, context),
            Err(StoreError::Refused)
        ));
        drop(maintenance);
        assert!(Identity::open(&account_path).is_ok());
        assert!(KernelStore::open(&room_path, context).is_ok());
    });
}

#[test]
fn wrong_room_grant_rejects_and_releases_only_the_consumed_room() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let first_path = temp.0.join("first");
        let mut first = account
            .prepare_owner(validity())
            .unwrap()
            .commit(&first_path, limits())
            .await
            .unwrap();
        let second_path = temp.0.join("second");
        let second = account
            .prepare_owner(validity())
            .unwrap()
            .commit(&second_path, limits())
            .await
            .unwrap();
        let first_status = first.status().unwrap();
        let second_status = second.status().unwrap();
        let (grant, _revoke) = LocalGrant::for_status(
            first_status,
            Duration::from_secs(60),
            Permissions::default(),
            Budget::default(),
        )
        .unwrap();
        assert!(matches!(
            second.into_agent(grant),
            Err(Error::Agent(AgentError::AuthorityChanged))
        ));
        let reopened = account
            .open_room(&second_path, second_status.context)
            .await
            .unwrap();
        assert_eq!(reopened.status().unwrap(), second_status);
        assert!(matches!(
            KernelStore::open(&first_path, first_status.context),
            Err(StoreError::Refused)
        ));
        let draft = first.prepare_message(b"first remains authorized").unwrap();
        first.send(op(1), &draft).await.unwrap();
        drop(account);
        drop(reopened);
        account_busy(&account_path);
        first.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}

#[test]
fn sibling_reopen_never_renews_spent_grant_or_bypasses_revocation() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let first = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("first"), limits())
            .await
            .unwrap();
        let sibling_path = temp.0.join("sibling");
        let mut sibling = account
            .prepare_owner(validity())
            .unwrap()
            .commit(&sibling_path, limits())
            .await
            .unwrap();
        let sibling_context = sibling.status().unwrap().context;
        let (grant, revoke) = LocalGrant::for_status(
            first.status().unwrap(),
            Duration::from_secs(60),
            Permissions {
                queue: true,
                ..Permissions::default()
            },
            Budget {
                preparations: 2,
                messages: 1,
                body_bytes: 64,
                ..Budget::default()
            },
        )
        .unwrap();
        let mut agent = first.into_agent(grant).unwrap();
        let draft = agent.prepare(b"one allowed message").unwrap();
        agent.queue(op(1), draft).await.unwrap();
        let remaining = agent.status().unwrap().remaining;
        assert_eq!(remaining.messages, 0);
        assert_eq!(remaining.preparations, 1);
        assert!(remaining.body_bytes < 64);
        sibling.lock();
        assert_eq!(agent.status().unwrap().remaining, remaining);
        let mut sibling = account
            .open_room(&sibling_path, sibling_context)
            .await
            .unwrap();
        assert_eq!(agent.status().unwrap().remaining, remaining);
        let draft = agent.prepare(b"no second send allowance").unwrap();
        assert!(matches!(
            agent.queue(op(2), draft).await,
            Err(Error::Agent(AgentError::Quota))
        ));
        revoke.revoke();
        assert!(matches!(
            agent.status(),
            Err(Error::Agent(AgentError::Revoked))
        ));
        assert!(matches!(
            agent.prepare(b"revoked"),
            Err(Error::Agent(AgentError::Revoked))
        ));
        let draft = sibling
            .prepare_message(b"sibling still authorized")
            .unwrap();
        sibling.send(op(1), &draft).await.unwrap();
        drop(account);
        sibling.lock();
        account_busy(&account_path);
        agent.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}
