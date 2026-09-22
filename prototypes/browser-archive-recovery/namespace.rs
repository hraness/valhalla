//! Prototype namespace selection only; callers must authenticate the source first.
use sha2::{Digest, Sha256};
use vhalla_browser_storage::Namespace;
use vhalla_private_kernel::Context;

/// Existing production archive namespace, preserved verbatim by the spike.
pub const LEGACY: [u8; 32] = *b"vhalla-browser-local-archive-v01";

/// Select a new immutable archive destination after source/seal authentication.
pub fn destination(context: Context, archive: [u8; 32]) -> Namespace {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/browser-private-archive-destination/v1\0");
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
        &archive,
    ] {
        hash.update(field);
    }
    Namespace::new(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vhalla_private_kernel::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

    #[test]
    fn archive_and_every_context_field_select_independent_destinations() {
        let key = Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let other = Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([3; 32]).unwrap(),
                anchor: AnchorId::from_bytes([4; 32]).unwrap(),
            },
            account: key,
            device: key,
        };
        let first = destination(context, [5; 32]);
        assert_eq!(
            first.identifier(),
            destination(context, [5; 32]).identifier()
        );
        assert_ne!(first.identifier(), &LEGACY);
        assert_ne!(
            first.identifier(),
            destination(context, [6; 32]).identifier()
        );
        for field in 0..4 {
            let mut changed = context;
            match field {
                0 => changed.scope.room = RoomId::from_bytes([7; 32]).unwrap(),
                1 => changed.scope.anchor = AnchorId::from_bytes([8; 32]).unwrap(),
                2 => changed.account = other,
                _ => changed.device = other,
            }
            assert_ne!(
                first.identifier(),
                destination(changed, [5; 32]).identifier()
            );
        }
    }
}
