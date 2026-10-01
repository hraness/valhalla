#![cfg(all(unix, feature = "client"))]
//! Trusted borrowed recovery reads keep existing account and room custody.

use futures::executor::block_on;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_kernel::{protocol::Validity, MemberAcceptance, OperationId, Phase};
use vhalla_private_native::{
    client::{AccountController, Error, RoomSession},
    private_rooms::Limits,
};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-retained-delivery-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
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

fn limits() -> Limits {
    Limits {
        max_records: 128,
        max_record_bytes: 8 * 1024 * 1024,
    }
}
fn op(value: u8) -> OperationId {
    OperationId::from_bytes([value; 16]).unwrap()
}
fn validity() -> Validity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Validity::new(now - 1, now + 3600).unwrap()
}

async fn joined(
    temp: &Temp,
) -> (
    AccountController,
    AccountController,
    RoomSession,
    RoomSession,
) {
    let validity = validity();
    let owner = AccountController::new(Identity::create_new(temp.0.join("owner")).unwrap());
    let member = AccountController::new(Identity::create_new(temp.0.join("member")).unwrap());
    let mut owner_room = owner
        .prepare_owner(validity)
        .unwrap()
        .commit(temp.0.join("owner-room"), limits())
        .await
        .unwrap();
    let membership = owner_room.membership().await.unwrap();
    let mut member_room = member
        .prepare_member(
            membership.status().context.scope,
            membership.anchor().clone(),
            membership.owner().clone(),
            validity,
        )
        .unwrap()
        .commit(temp.0.join("member-room"), limits())
        .await
        .unwrap();
    let request = member_room.key_package(op(1)).await.unwrap();
    let invitation = owner_room
        .invite(op(1), request.bytes(), validity)
        .await
        .unwrap();
    member_room.join(invitation.bytes()).await.unwrap();
    (owner, member, owner_room, member_room)
}

#[test]
fn retained_delivery_reads_authenticate_real_history_and_survive_reopen() {
    block_on(async {
        let temp = Temp::new();
        let (owner, member, mut owner_room, mut member_room) = joined(&temp).await;
        let binding = owner_room.status().unwrap();
        let member_context = member_room.status().unwrap().context;
        let draft = owner_room.prepare_message(b"original delivery").unwrap();
        let sent = owner_room.send(op(2), &draft).await.unwrap();
        let received = member_room.receive(sent.bytes()).await.unwrap();
        let receipt = member_room
            .issue_acceptance(op(2), sent.bytes())
            .await
            .unwrap();
        owner_room.receive(receipt.bytes()).await.unwrap();
        let hash = MemberAcceptance::ciphertext_commitment(sent.bytes());
        let owner_before = owner_room.status().unwrap();
        let member_before = member_room.status().unwrap();
        assert_eq!(
            owner_room.original(&hash).await.unwrap().unwrap().bytes(),
            sent.bytes()
        );
        assert!(member_room.original(&hash).await.unwrap().is_none());
        let retained = member_room
            .retained_received(sent.bytes())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.sequence(), received.sequence());
        assert_eq!(retained.sender(), received.sender());
        assert_eq!(retained.body(), received.body());
        let claims = owner_room.acceptances(sent.sequence()).await.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].recipient(), member_context.device);
        assert_eq!(claims[0].received_sequence(), received.sequence());
        assert_eq!(owner_room.status().unwrap(), owner_before);
        assert_eq!(member_room.status().unwrap(), member_before);

        let removal = owner_room
            .remove(op(3), member_context.device)
            .await
            .unwrap();
        assert!(!member_room.retained_control(removal.bytes()).await.unwrap());
        member_room.apply_control(removal.bytes()).await.unwrap();
        assert!(owner_room.retained_control(removal.bytes()).await.unwrap());
        assert!(member_room.retained_control(removal.bytes()).await.unwrap());
        assert_eq!(member_room.status().unwrap().phase, Phase::Removed);
        owner_room.lock();
        member_room.lock();
        owner_room = owner
            .open_room(temp.0.join("owner-room"), binding.context)
            .await
            .unwrap();
        member_room = member
            .open_room(temp.0.join("member-room"), member_context)
            .await
            .unwrap();
        let owner_before = owner_room.status().unwrap();
        let member_before = member_room.status().unwrap();
        let recovered = owner_room
            .retained_send(op(2), binding.epoch, binding.roster, b"original delivery")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.bytes(), sent.bytes());
        assert_eq!(recovered.sequence(), sent.sequence());
        assert_eq!(
            owner_room.original(&hash).await.unwrap().unwrap().bytes(),
            sent.bytes()
        );
        assert!(owner_room
            .acceptances(sent.sequence())
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            member_room
                .retained_received(sent.bytes())
                .await
                .unwrap()
                .unwrap()
                .body(),
            b"original delivery"
        );
        assert!(member_room.retained_control(removal.bytes()).await.unwrap());
        assert_eq!(owner_room.status().unwrap(), owner_before);
        assert_eq!(member_room.status().unwrap(), member_before);
        assert!(member_room.prepare_message(b"not reauthorized").is_err());
    });
}

#[test]
fn locked_recovery_reads_refuse_while_another_room_keeps_the_account_live() {
    block_on(async {
        let temp = Temp::new();
        let account_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&account_path).unwrap());
        let mut first = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("first"), limits())
            .await
            .unwrap();
        let mut second = account
            .prepare_owner(validity())
            .unwrap()
            .commit(temp.0.join("second"), limits())
            .await
            .unwrap();
        let binding = first.status().unwrap();
        first.lock();
        drop(account);
        assert!(matches!(
            first
                .retained_send(op(1), binding.epoch, binding.roster, b"body")
                .await,
            Err(Error::Locked)
        ));
        assert!(matches!(
            first.retained_received(b"frame").await,
            Err(Error::Locked)
        ));
        assert!(matches!(
            first.retained_control(b"frame").await,
            Err(Error::Locked)
        ));
        assert!(matches!(first.original(&[1; 32]).await, Err(Error::Locked)));
        assert!(matches!(first.acceptances(1).await, Err(Error::Locked)));
        assert!(matches!(
            Identity::open(&account_path),
            Err(IdentityError::Busy)
        ));
        let second_binding = second.status().unwrap();
        let draft = second.prepare_message(b"unaffected room").unwrap();
        let sent = second.send(op(1), &draft).await.unwrap();
        assert_eq!(
            second
                .retained_send(
                    op(1),
                    second_binding.epoch,
                    second_binding.roster,
                    b"unaffected room"
                )
                .await
                .unwrap()
                .unwrap()
                .bytes(),
            sent.bytes()
        );
        second.lock();
        assert!(Identity::open(&account_path).is_ok());
    });
}
