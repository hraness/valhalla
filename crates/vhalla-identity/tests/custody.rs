#![cfg(unix)]
//! Native filesystem and command-line custody regressions.

use std::{
    fs,
    os::unix::fs::{symlink, DirBuilderExt, PermissionsExt},
    path::PathBuf,
};
use vhalla_core::{Epoch, EventId, PeerId, RealmId, RoomId, Sequence};
use vhalla_crypto::{peer_id_from_key, ReplayWindow, SessionId, VerificationContext, VerifyingKey};
use vhalla_identity::{Identity, IdentityError};
use vhalla_wire::Envelope;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-identity-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self) -> PathBuf {
        self.0.join("owner")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn create_reopen_and_sign_preserve_one_random_identity() {
    let dir = Temp::new();
    let identity = Identity::create_new(dir.child()).unwrap();
    let original = identity.public_key();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::Busy)
    ));
    assert!(Identity::create_new(dir.child()).is_err());
    assert_eq!(
        fs::metadata(dir.child()).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(dir.child().join("identity"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    drop(identity);
    let identity = Identity::open(dir.child()).unwrap();
    assert_eq!(identity.public_key(), original);
    let key = VerifyingKey::from_bytes(&original).unwrap();
    let ctx = VerificationContext {
        audience: PeerId(9),
        realm: RealmId(1),
        room: RoomId(2),
        epoch: Epoch(3),
        session: SessionId(4),
    };
    let message = Envelope::chat(
        peer_id_from_key(&key),
        ctx.realm,
        ctx.room,
        EventId(5),
        Sequence(1),
        b"hello",
    )
    .unwrap();
    let signed = identity.sign_envelope(message, ctx, 100).unwrap();
    let mut replay = ReplayWindow::new(ctx, 1).unwrap();
    assert_eq!(
        replay
            .verify_and_accept(signed, &key, 50)
            .unwrap()
            .envelope()
            .body(),
        b"hello"
    );
    let different = Identity::create_new(dir.0.join("other")).unwrap();
    assert_ne!(identity.public_key(), different.public_key());
}

#[test]
fn corrupt_partial_or_unknown_records_are_never_replaced() {
    for length in [0, 7, 39, 71, 72, 73, 1024] {
        let dir = Temp::new();
        drop(Identity::create_new(dir.child()).unwrap());
        let record = dir.child().join("identity");
        let invalid = vec![0u8; length];
        fs::write(&record, &invalid).unwrap();
        assert!(matches!(
            Identity::open(dir.child()),
            Err(IdentityError::Corrupt)
        ));
        assert!(Identity::create_new(dir.child()).is_err());
        assert_eq!(fs::read(&record).unwrap(), invalid);
    }
}

#[test]
fn missing_and_interrupted_publication_fail_without_repair() {
    let dir = Temp::new();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::Io(_))
    ));
    assert!(!dir.child().exists());
    drop(Identity::create_new(dir.child()).unwrap());
    fs::rename(
        dir.child().join("identity"),
        dir.child().join("identity.tmp"),
    )
    .unwrap();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::Corrupt)
    ));
    assert!(dir.child().join("identity.tmp").exists());
    // Also model publication having happened before temporary-name cleanup.
    fs::hard_link(
        dir.child().join("identity.tmp"),
        dir.child().join("identity"),
    )
    .unwrap();
    assert!(Identity::open(dir.child()).is_err());
    assert!(dir.child().join("identity.tmp").exists());
}

#[test]
fn symlinks_hardlinks_and_exposed_permissions_are_rejected() {
    let dir = Temp::new();
    drop(Identity::create_new(dir.child()).unwrap());
    let alias = dir.0.join("alias");
    symlink(dir.child(), &alias).unwrap();
    assert!(matches!(
        Identity::open(&alias),
        Err(IdentityError::UnsafePath)
    ));
    fs::remove_file(&alias).unwrap();
    let record = dir.child().join("identity");
    fs::hard_link(&record, &alias).unwrap();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::UnsafePath)
    ));
    fs::remove_file(&alias).unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::UnsafePath)
    ));
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&record, &alias).unwrap();
    symlink(&alias, &record).unwrap();
    assert!(matches!(
        Identity::open(dir.child()),
        Err(IdentityError::UnsafePath)
    ));
}

#[test]
fn reopen_keeps_identity_but_os_nonces_reject_old_handshake_and_chat() {
    use vhalla_session::{Pairing, Reject};
    let dir = Temp::new();
    let a = Identity::create_new(dir.child()).unwrap();
    let b_path = dir.0.join("peer");
    let b = Identity::create_new(&b_path).unwrap();
    let transport_a = ed25519_dalek::SigningKey::from_bytes(&[3; 32])
        .verifying_key()
        .to_bytes();
    let transport_b = ed25519_dalek::SigningKey::from_bytes(&[4; 32])
        .verifying_key()
        .to_bytes();
    let pair = Pairing {
        initiator: a.public_key(),
        responder: b.public_key(),
        initiator_transport: transport_a,
        responder_transport: transport_b,
        realm: RealmId(1),
        room: RoomId(2),
        epoch: Epoch(3),
        expires_at: 100,
    };
    let (pending_a, hello) = a
        .initiate_session(pair, transport_a, transport_b, 10, 20)
        .unwrap();
    let (pending_b, response) = b
        .respond_session(pair, transport_b, transport_a, &hello, 10, 20)
        .unwrap();
    let (mut session_a, confirmation) = a.confirm_session(pending_a, &response, 11).unwrap();
    let mut session_b = pending_b.finish(&confirmation, 11).unwrap();
    let message = session_a.prepare_chat(b"before restart", 12).unwrap();
    let raw = a
        .sign_envelope(message, session_a.outbound_context(), 99)
        .unwrap()
        .encode()
        .unwrap();
    session_b.receive(&raw, 12).unwrap();
    drop(b);
    let b = Identity::open(&b_path).unwrap();
    assert_eq!(b.public_key(), pair.responder);
    let (restarted, _) = b
        .respond_session(pair, transport_b, transport_a, &hello, 13, 20)
        .unwrap();
    assert!(matches!(
        restarted.finish(&confirmation, 14),
        Err(Reject::Context)
    ));
    let (pending_a, fresh_hello) = a
        .initiate_session(pair, transport_a, transport_b, 13, 20)
        .unwrap();
    let (pending_b, response) = b
        .respond_session(pair, transport_b, transport_a, &fresh_hello, 13, 20)
        .unwrap();
    let (mut fresh_a, confirmation) = a.confirm_session(pending_a, &response, 14).unwrap();
    let mut fresh_b = pending_b.finish(&confirmation, 14).unwrap();
    assert_ne!(
        fresh_a.outbound_context().session,
        session_a.outbound_context().session
    );
    assert!(matches!(
        fresh_b.receive(&raw, 15),
        Err(Reject::Verify(vhalla_crypto::VerifyError::SessionMismatch))
    ));
    let new = fresh_a.prepare_chat(b"after restart", 15).unwrap();
    let new = a
        .sign_envelope(new, fresh_a.outbound_context(), 99)
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        fresh_b.receive(&new, 15).unwrap().envelope().body(),
        b"after restart"
    );
}
