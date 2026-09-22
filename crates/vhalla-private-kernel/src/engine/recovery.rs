//! Explicit encrypted archives. An archive is never a live device restore.
//!
//! Source images and immutable evidence remain exact; destination/progress and
//! final archive images use separate purposes that ordinary Kernel::open refuses.
//! This API does not export a provider map, key, generic sealer or live kernel.
use super::*;
use crate::protocol::ControlFloor;
use crate::storage::{Accounting, ArchiveStore};

mod destination;
mod frame;
mod records;
mod source;
pub use destination::{ArchiveImport, ArchiveSeal, ArchiveView, ImportProgress};
use frame::{Header, Page};
pub use source::{ArchiveExport, ArchiveSource, ArchiveSourceReader};

/// Hard limit for one encrypted archive page, unrelated to lifetime history.
pub const MAX_ARCHIVE_PAGE_BYTES: usize = 512 * 1024;
/// Maximum fragment of the bounded current image in one source page.
pub const IMAGE_FRAGMENT_BYTES: usize = 256 * 1024;

/// One checked source-produced encrypted page. This is confidential recovery
/// material, never an ordinary outbox artifact or network-delivery instruction.
pub struct ArchivePage(Vec<u8>);
impl ArchivePage {
    /// Exact encrypted framing for an explicitly selected private file sink.
    pub fn encrypted_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Snapshot {
    revision: u64,
    outbox: u64,
    inbox: u64,
    base: ControlFloor,
    floor: ControlFloor,
    anchor_owner: protocol::Key,
    /// (carrying control sequence, successor device) per accepted handoff.
    successions: Vec<(u64, protocol::Key)>,
}
impl Snapshot {
    fn of(state: &State) -> Self {
        Self {
            revision: state.revision,
            outbox: state.outbox,
            inbox: state.inbox,
            base: state.base,
            floor: state.floor,
            anchor_owner: state.anchor.claims().owner_device,
            successions: state
                .successions
                .iter()
                .map(|grant| {
                    (
                        grant.claims().sequence,
                        grant.claims().successor.claims().device,
                    )
                })
                .collect(),
        }
    }
    /// Owner generation authorized to sign the control at `sequence`.
    fn owner_at(&self, sequence: u64) -> protocol::Key {
        let mut owner = self.anchor_owner;
        for &(grant_sequence, successor) in &self.successions {
            if sequence <= grant_sequence {
                return owner;
            }
            owner = successor;
        }
        owner
    }
    fn units(&self) -> Result<u64> {
        self.outbox
            .checked_add(self.inbox)
            .and_then(|n| {
                self.floor
                    .sequence()
                    .checked_sub(self.base.sequence())
                    .and_then(|c| n.checked_add(c))
            })
            .ok_or(Error::Bounds)
    }
    fn records(&self) -> Result<u64> {
        self.outbox
            .checked_add(self.inbox)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| {
                self.floor
                    .sequence()
                    .checked_sub(self.base.sequence())
                    .and_then(|c| n.checked_add(c))
            })
            .ok_or(Error::Bounds)
    }
}
fn page_digest(bytes: &[u8]) -> [u8; 32] {
    codec::hash(b"vhalla/private-archive/page/v1\0", bytes)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    codec::hash(b"vhalla/private-archive/content/v1\0", bytes)
}
fn accounting(value: &Accounting, image: Option<&Image>, records: u64, bytes: u64) -> Result<()> {
    if value.image.as_ref() != image
        || value.records != records
        || value.bytes != bytes
        || records > value.max_records
        || bytes > value.max_bytes
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn record_clear(
    key: &StorageKey,
    context: Context,
    record: &StoredRecord,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut purpose = b"record/".to_vec();
    purpose.extend(record.key().encode());
    codec::unseal(
        key,
        context,
        &purpose,
        record.as_bytes(),
        MAX_STORED_RECORD_BYTES,
    )
}
fn canonical_state(
    key: &StorageKey,
    context: Context,
    image: &Image,
) -> Result<(Zeroizing<Vec<u8>>, State)> {
    let clear = codec::unseal(
        key,
        context,
        b"current-state",
        image.as_bytes(),
        MAX_IMAGE_BYTES,
    )?;
    let state = Working::hydrate(State::decode(&clear, context)?)?.capture()?;
    let encoded = Zeroizing::new(state.encode()?);
    if *clear != *encoded {
        return Err(Error::Encoding);
    }
    Ok((clear, state))
}
