#![cfg(all(any(unix, windows), feature = "client"))]
//! Native room custody outlives transient agent adapters and their grants.

use futures::executor::block_on;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_kernel::{protocol::Validity, OperationId};
use vhalla_private_native::{
    agent::{AgentAccess, Budget, Error as AgentError, LocalGrant, Permissions, RevocationHandle},
    client::{AccountController, Error, RoomSession},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-scoped-agent-{}-{}-{}",
            std::process::id(),
            stamp.as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
fn access(room: &RoomSession) -> (AgentAccess, RevocationHandle) {
    let (grant, authority) = LocalGrant::for_status(
        room.status().unwrap(),
        Duration::from_secs(600),
        Permissions {
            inbox: true,
            queue: true,
            outbox_status: true,
        },
        Budget {
            preparations: 2,
            messages: 1,
            body_bytes: 128,
            read_records: 2,
            read_bytes: 65_536,
        },
    )
    .unwrap();
    (room.agent_access(grant).unwrap(), authority)
}

#[test]
fn separate_scopes_keep_their_grants_across_rebind_and_room_reopen() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let creation = account.prepare_owner(validity()).unwrap();
        let context = creation.context();
        let room_path = temp.0.join("room");
        let mut room = creation.commit(&room_path, limits()).await.unwrap();
        let (mut first, first_authority) = access(&room);
        let (mut second, second_authority) = access(&room);
        let first_draft = room
            .scoped_agent(&mut first)
            .unwrap()
            .prepare(b"first agent")
            .unwrap();
        let second_draft = room
            .scoped_agent(&mut second)
            .unwrap()
            .prepare(b"second agent")
            .unwrap();
        assert!(matches!(
            room.scoped_agent(&mut first)
                .unwrap()
                .queue(op(1), second_draft)
                .await,
            Err(Error::Agent(AgentError::StaleDraft))
        ));
        assert_eq!(
            room.scoped_agent(&mut first)
                .unwrap()
                .status()
                .unwrap()
                .pending,
            Some(first_draft)
        );
        let queued = room
            .scoped_agent(&mut first)
            .unwrap()
            .queue(op(1), first_draft)
            .await
            .unwrap();
        assert_eq!(queued.sequence, 1);
        let second_status = room.scoped_agent(&mut second).unwrap().status().unwrap();
        assert_eq!(second_status.pending, Some(second_draft));
        assert_eq!(second_status.remaining.messages, 1);
        assert_eq!(second_status.remaining.preparations, 1);
        let next = room
            .scoped_agent(&mut first)
            .unwrap()
            .prepare(b"spent authorization")
            .unwrap();
        assert!(matches!(
            room.scoped_agent(&mut first)
                .unwrap()
                .queue(op(2), next)
                .await,
            Err(Error::Agent(AgentError::Quota))
        ));
        let queued = room
            .scoped_agent(&mut second)
            .unwrap()
            .queue(op(3), second_draft)
            .await
            .unwrap();
        assert_eq!(queued.sequence, 2);
        // Trusted ciphertext reconciliation does not consume an agent allowance.
        assert_eq!(room.outbox(0, 8).await.unwrap().head, 2);
        assert!(!room.scoped_agent(&mut first).unwrap().latched());
        room.lock();
        let mut room = account.open_room(&room_path, context).await.unwrap();
        let remaining = room.scoped_agent(&mut first).unwrap().status().unwrap();
        assert_eq!(remaining.remaining.messages, 0);
        assert_eq!(remaining.remaining.preparations, 0);
        assert_eq!(remaining.pending, Some(next));
        assert!(matches!(
            room.scoped_agent(&mut first)
                .unwrap()
                .queue(op(2), next)
                .await,
            Err(Error::Agent(AgentError::Quota))
        ));
        assert_eq!(
            room.scoped_agent(&mut second)
                .unwrap()
                .status()
                .unwrap()
                .remaining
                .messages,
            0
        );

        first_authority.revoke();
        second_authority.revoke();
        assert!(matches!(
            room.scoped_agent(&mut first),
            Err(Error::Agent(AgentError::Revoked))
        ));
        assert!(matches!(
            room.scoped_agent(&mut second),
            Err(Error::Agent(AgentError::Revoked))
        ));
        let trusted = room.prepare_message(b"trusted local controller").unwrap();
        assert_eq!(room.send(op(4), &trusted).await.unwrap().sequence(), 3);
        assert_eq!(room.outbox(0, 8).await.unwrap().head, 3);
        drop(account);
        assert!(matches!(
            Identity::open(&account_path),
            Err(IdentityError::Busy)
        ));
        room.lock();
        // Retaining spent accesses does not retain signing/account custody.
        assert!(Identity::open(&account_path).is_ok());
        assert!(matches!(room.scoped_agent(&mut first), Err(Error::Locked)));
    });
}

#[test]
fn a_same_account_sibling_room_cannot_use_or_reset_an_existing_access() {
    block_on(async {
        let temp = Temp::new();
        let account = AccountController::new(Identity::create_new(temp.0.join("account")).unwrap());
        let mut first_room = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("first"), limits())
            .await
            .unwrap();
        let mut sibling = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("sibling"), limits())
            .await
            .unwrap();
        let (mut access, authority) = access(&first_room);
        let draft = first_room
            .scoped_agent(&mut access)
            .unwrap()
            .prepare(b"only first room")
            .unwrap();
        let before = first_room
            .scoped_agent(&mut access)
            .unwrap()
            .status()
            .unwrap();
        assert!(matches!(
            sibling.scoped_agent(&mut access),
            Err(Error::Agent(AgentError::AuthorityChanged))
        ));
        let retained = first_room
            .scoped_agent(&mut access)
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(retained.pending, before.pending);
        assert_eq!(retained.remaining, before.remaining);
        assert_eq!(retained.accepted, before.accepted);
        first_room
            .scoped_agent(&mut access)
            .unwrap()
            .queue(op(1), draft)
            .await
            .unwrap();
        assert_eq!(first_room.status().unwrap().outbox_head, 1);
        assert_eq!(sibling.status().unwrap().outbox_head, 0);
        authority.revoke();
        assert!(matches!(
            first_room.scoped_agent(&mut access),
            Err(Error::Agent(AgentError::Revoked))
        ));
        let trusted = sibling
            .prepare_message(b"sibling remains independently usable")
            .unwrap();
        sibling.send(op(1), &trusted).await.unwrap();
    });
}
