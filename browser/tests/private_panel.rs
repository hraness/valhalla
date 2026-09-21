//! Native canonical locator and disclosure classification regressions.
#![cfg(feature = "private-rooms")]
#[path = "../src/private/panel_model.rs"]
pub mod model;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, OutboxKind,
};
fn context() -> Context {
    let mut key = [0x66; 32];
    key[0] = 0x58;
    let key = Key::from_bytes(key).unwrap();
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: key,
        device: key,
    }
}
#[test]
fn locator_is_exact_full_context_and_refuses_truncation_trailing_and_weak_keys() {
    let context = context();
    let raw = model::locator(context);
    assert_eq!(raw.len(), model::LOCATOR_BYTES);
    assert_eq!(model::decode_locator(&raw).unwrap(), context);
    for n in 0..raw.len() {
        assert!(model::decode_locator(&raw[..n]).is_err());
    }
    let mut changed = raw.clone();
    changed.push(0);
    assert!(model::decode_locator(&changed).is_err());
    for offset in [0, 7] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert!(model::decode_locator(&changed).is_err());
    }
    for offset in [8, 40, 72, 104] {
        let mut changed = raw.clone();
        changed[offset..offset + 32].fill(0);
        assert!(model::decode_locator(&changed).is_err());
    }
    for offset in [8, 40] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert_ne!(model::decode_locator(&changed).unwrap(), context);
    }
}
#[test]
fn ordinary_export_never_labels_secret_or_legacy_bootstrap_as_ciphertext() {
    for kind in [
        OutboxKind::ContactOffer,
        OutboxKind::KeyPackage,
        OutboxKind::Invitation,
    ] {
        assert!(model::encrypted_export(kind).is_none());
    }
    for kind in [
        OutboxKind::Application,
        OutboxKind::ContactRequest,
        OutboxKind::ContactInvitation,
        OutboxKind::Removal,
        OutboxKind::OwnerUpdate,
    ] {
        assert!(model::encrypted_export(kind).is_some());
    }
}

#[test]
fn disclosure_refuses_every_scope_roster_epoch_or_text_switch() {
    let context = context();
    let original = model::Disclosure {
        context,
        epoch: 7,
        roster: [8; 32],
        body: b"private text",
    };
    let mut selected = model::Disclosure {
        context,
        epoch: 7,
        roster: [8; 32],
        body: b"private text",
    };
    assert!(original.matches(&selected));
    selected.body = b"private text ";
    assert!(!original.matches(&selected));
    selected.body = original.body;
    selected.epoch += 1;
    assert!(!original.matches(&selected));
    selected.epoch = original.epoch;
    selected.roster[31] ^= 1;
    assert!(!original.matches(&selected));
    selected.roster = original.roster;
    let other = Key::from_bytes([
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ])
    .unwrap();
    selected.context.account = other;
    assert!(!original.matches(&selected));
    selected.context = context;
    selected.context.device = other;
    assert!(!original.matches(&selected));
    selected.context = context;
    selected.context.scope.room = RoomId::from_bytes([9; 32]).unwrap();
    assert!(!original.matches(&selected));
    selected.context = context;
    selected.context.scope.anchor = AnchorId::from_bytes([9; 32]).unwrap();
    assert!(!original.matches(&selected));
}
