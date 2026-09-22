use super::*;
use crate::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

fn account() -> SigningKey {
    SigningKey::from_bytes(&core::array::from_fn(|i| i as u8))
}
fn context() -> Context {
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([17; 32]).unwrap(),
            anchor: AnchorId::from_bytes([34; 32]).unwrap(),
        },
        account: Key::from_bytes(account().verifying_key().to_bytes()).unwrap(),
        // RFC8032 test1 public key, only a public synthetic context label.
        device: Key::from_bytes([
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ])
        .unwrap(),
    }
}

#[test]
fn frozen_account_storage_hkdf_vector_and_exact_retry() {
    // Independently calculated with Python stdlib HMAC-SHA256:
    // PRK=HMAC(SALT, bytes(range(32)))
    // OKM=HMAC(PRK, INFO || room32 || anchor32 || account32 || device32 || 0x01).
    // The seed and all context values are public fixtures, never defaults.
    let expected = [
        0xc6, 0x86, 0x47, 0x57, 0xb3, 0x7b, 0x6a, 0x10, 0x7a, 0x46, 0x6b, 0x1e, 0xa3, 0x18, 0xec,
        0xf1, 0x9e, 0x3f, 0x32, 0x79, 0x90, 0x09, 0x23, 0x10, 0x1f, 0xf5, 0xbd, 0xd6, 0x1b, 0x20,
        0xc5, 0x78,
    ];
    let first = StorageKey::derive_for_account(&account(), context()).unwrap();
    assert_eq!(*first.0, expected);
    let second = StorageKey::derive_for_account(&account(), context()).unwrap();
    assert_eq!(*second.0, expected);
}

#[test]
fn account_gate_and_every_full_context_field_separate_storage_keys() {
    let account = account();
    let original = context();
    let expected = StorageKey::derive_for_account(&account, original).unwrap();
    let mut variants = [original; 3];
    variants[0].scope.room = RoomId::from_bytes([18; 32]).unwrap();
    variants[1].scope.anchor = AnchorId::from_bytes([35; 32]).unwrap();
    variants[2].device =
        Key::from_bytes(SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes()).unwrap();
    for changed in variants {
        let different = StorageKey::derive_for_account(&account, changed).unwrap();
        assert_ne!(*different.0, *expected.0);
    }
    let other = SigningKey::from_bytes(&[92; 32]);
    assert!(matches!(
        StorageKey::derive_for_account(&other, original),
        Err(Error::Scope)
    ));
    let mut changed = original;
    changed.account = Key::from_bytes(other.verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        StorageKey::derive_for_account(&account, changed),
        Err(Error::Scope)
    ));
    let different = StorageKey::derive_for_account(&other, changed).unwrap();
    assert_ne!(*different.0, *expected.0);
}
