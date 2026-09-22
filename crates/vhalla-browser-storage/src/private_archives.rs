//! Authenticated archive destinations and an append-only origin-wide reservation budget.
//! Reservations survive interrupted imports. No reset, eviction or deletion API exists.
use crate::{Error, Namespace};
use sha2::{Digest, Sha256};
use vhalla_private_kernel::{
    recovery::{ArchiveSeal, ArchiveSource},
    Context,
};

/// Existing fixed destination. Only explicit open/resume may use this namespace.
pub const LEGACY: Namespace = Namespace::new(*b"vhalla-browser-local-archive-v01");
/// Maximum newly reserved snapshots across all accounts in this browser origin.
pub const MAX_SNAPSHOTS: usize = 4;
/// Each reservation grants this finite encrypted-record payload budget.
/// Four reservations consume at most 1 GiB of payload; bounded image/index and
/// browser-engine overhead are additional. Physical quota can refuse earlier.
pub const SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
/// Immutable records, including indexes, per reserved snapshot.
pub const SNAPSHOT_RECORDS: u64 = 100_000;
const MAGIC: &[u8; 8] = b"VHPAC001";
pub(crate) const MAX_CATALOG_BYTES: usize = 9 + MAX_SNAPSHOTS * 32;

fn destination(context: Context, archive: [u8; 32]) -> Namespace {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/browser-private-archive-destination/v1\0");
    hash.update(crate::private_rooms::context_bytes(context));
    hash.update(archive);
    Namespace::new(hash.finalize().into())
}
/// Select only after the kernel authenticates the complete source image.
pub fn source_namespace(source: &ArchiveSource) -> Namespace {
    destination(source.context(), source.archive_id())
}
/// Select an existing destination only after authenticating its retained seal.
pub fn sealed_namespace(seal: &ArchiveSeal) -> Namespace {
    destination(seal.context(), seal.archive_id())
}
pub(crate) fn catalog_namespace() -> Namespace {
    Namespace::new(Sha256::digest(b"vhalla/browser-private-archive-catalog/v1\0").into())
}
/// Bounded canonical reservation set. Exact existing reservations remain usable
/// at capacity; a different archive cannot consume or replace one.
pub(crate) fn reserve(raw: Option<&[u8]>, namespace: Namespace) -> Result<Vec<u8>, Error> {
    let mut entries = Vec::<[u8; 32]>::new();
    if let Some(raw) = raw {
        if raw.len() < 9
            || raw.len() > MAX_CATALOG_BYTES
            || &raw[..8] != MAGIC
            || raw[8] as usize > MAX_SNAPSHOTS
            || raw.len() != 9 + raw[8] as usize * 32
        {
            return Err(Error::Corrupt);
        }
        for &entry in raw[9..].as_chunks::<32>().0 {
            if entries.last().is_some_and(|prior| *prior >= entry) {
                return Err(Error::Corrupt);
            }
            entries.push(entry);
        }
    }
    let entry = *namespace.identifier();
    if !entries.contains(&entry) {
        if entries.len() == MAX_SNAPSHOTS {
            return Err(Error::Bounds);
        }
        entries.push(entry);
        entries.sort_unstable();
    }
    let mut out = MAGIC.to_vec();
    out.push(entries.len() as u8);
    for entry in entries {
        out.extend(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_reservations_preserve_exact_retries_and_refuse_corruption() {
        let mut raw = None;
        for i in 1..=MAX_SNAPSHOTS {
            raw = Some(reserve(raw.as_deref(), Namespace::new([i as u8; 32])).unwrap());
        }
        let full = raw.unwrap();
        assert_eq!(reserve(Some(&full), Namespace::new([1; 32])).unwrap(), full);
        assert_eq!(
            reserve(Some(&full), Namespace::new([9; 32])),
            Err(Error::Bounds)
        );
        for end in 0..full.len() {
            assert!(reserve(Some(&full[..end]), Namespace::new([1; 32])).is_err());
        }
        let mut malformed = full.clone();
        malformed[9..41].fill(2);
        assert_eq!(
            reserve(Some(&malformed), Namespace::new([1; 32])),
            Err(Error::Corrupt)
        );
        assert_ne!(catalog_namespace().identifier(), LEGACY.identifier());
    }
    #[test]
    fn every_context_field_and_archive_id_selects_a_distinct_destination() {
        use vhalla_private_kernel::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};
        let key = |n| {
            Key::from_bytes(
                ed25519_dalek::SigningKey::from_bytes(&[n; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap()
        };
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([3; 32]).unwrap(),
                anchor: AnchorId::from_bytes([4; 32]).unwrap(),
            },
            account: key(1),
            device: key(2),
        };
        let original = destination(context, [5; 32]);
        for field in 0..5 {
            let mut next = context;
            let mut id = [5; 32];
            match field {
                0 => next.scope.room = RoomId::from_bytes([6; 32]).unwrap(),
                1 => next.scope.anchor = AnchorId::from_bytes([6; 32]).unwrap(),
                2 => next.account = key(7),
                3 => next.device = key(7),
                _ => id = [6; 32],
            }
            assert_ne!(original.identifier(), destination(next, id).identifier());
        }
        assert_ne!(original.identifier(), LEGACY.identifier());
    }
}
