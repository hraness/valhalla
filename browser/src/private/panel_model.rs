//! Portable file/disclosure helpers for the trusted private panel, not authority.
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, OutboxKind,
};
const LOCATOR: &[u8; 8] = b"VHPLOC1\0";
/// Exact nonsecret locator width: versioned prefix plus four full identifiers.
pub const LOCATOR_BYTES: usize = 136;
/// Every private text/file input shares lock cleanup and busy-state handling.
pub const PRIVATE_INPUTS: &[&str] = &[
    "private-delivery-profile",
    "private-generation-transition",
    "private-generation-head",
    "private-generation-fence",
    "private-generation-profile",
    "private-generation-attempts",
    "private-owner",
    "private-recipient",
    "private-remove-device",
    "private-succeed-device",
    "private-offer-file",
    "private-locator-file",
    "private-message-file",
    "private-request-file",
    "private-join-file",
    "private-control-file",
    "private-proof-file",
    "private-resume-offer-file",
    "private-archive-file",
];
/// Blob downloads temporarily retain Rust, JS and browser backing copies. Keep
/// all live download payloads within 16 MiB; the larger import format is unchanged.
pub const DOWNLOAD_BYTES_MAX: usize = 16 * 1024 * 1024;

/// Reserve the complete payload before allocating another download copy.
pub fn admit_download(retained: usize, incoming: usize) -> Result<(), &'static str> {
    if retained
        .checked_add(incoming)
        .is_none_or(|total| total > DOWNLOAD_BYTES_MAX)
    {
        return Err(
            "Browser downloads are limited to 16 MiB in total. Wait for earlier downloads to release, then retry. A larger archive needs a streaming export; retained room data is unchanged.",
        );
    }
    Ok(())
}

/// Account for a page's length prefix and the eventual container terminator
/// before buffering its bytes. `current` already includes the terminator.
pub fn archive_download_size(current: usize, page: usize) -> Result<usize, &'static str> {
    let next = current
        .checked_add(4)
        .and_then(|n| n.checked_add(page))
        .ok_or("Archive size overflow.")?;
    admit_download(0, next)?;
    Ok(next)
}

/// Borrowed exact message disclosure, used immediately before a worker request.
pub struct Disclosure<'a> {
    /// Full private room, anchor, account, and device selection.
    pub context: Context,
    /// Exact local MLS epoch reviewed by the user.
    pub epoch: u64,
    /// Exact roster commitment; display labels never substitute for this value.
    pub roster: [u8; 32],
    /// Exact inert UTF-8 message bytes; no implicit edit or room move.
    pub body: &'a [u8],
}
impl Disclosure<'_> {
    /// Refuse every scope, membership or body change before asynchronous work.
    pub fn matches(&self, other: &Disclosure<'_>) -> bool {
        self.context == other.context
            && self.epoch == other.epoch
            && self.roster == other.roster
            && self.body == other.body
    }
}
/// Encode the exact local store locator. This grants no membership or recovery authority.
pub fn locator(context: Context) -> Vec<u8> {
    let mut raw = Vec::with_capacity(LOCATOR_BYTES);
    raw.extend_from_slice(LOCATOR);
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ] {
        raw.extend_from_slice(field);
    }
    raw
}
/// Decode only the exact canonical locator. Missing stores must still refuse open.
pub fn decode_locator(raw: &[u8]) -> Result<Context, &'static str> {
    if raw.len() != LOCATOR_BYTES || &raw[..8] != LOCATOR {
        return Err(
            "Choose a complete .vhroom locator; unknown versions and extra bytes are refused.",
        );
    }
    let field = |offset| {
        raw[offset..offset + 32]
            .try_into()
            .expect("bounded fixed locator")
    };
    Ok(Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(field(8)).map_err(|_| "Invalid room identifier.")?,
            anchor: AnchorId::from_bytes(field(40)).map_err(|_| "Invalid anchor identifier.")?,
        },
        account: Key::from_bytes(field(72)).map_err(|_| "Invalid account key.")?,
        device: Key::from_bytes(field(104)).map_err(|_| "Invalid device key.")?,
    })
}
/// Canonical .vharchive container magic; byte-identical to the native CLI file
/// format so archives move between the browser panel and `vhalla private`.
pub const ARCHIVE_MAGIC: &[u8; 8] = b"VHARCHF1";
/// Archive header width: magic plus full context plus archive correlation ID.
pub const ARCHIVE_HEADER: usize = 8 + 128 + 32;
/// Structural page cap for the browser's fixed store budgets. This is a
/// container bound only; the kernel authenticates every page independently.
pub const ARCHIVE_PAGES_MAX: u64 = 100_000
    + (vhalla_private_kernel::MAX_IMAGE_BYTES as u64)
        .div_ceil(vhalla_private_kernel::recovery::IMAGE_FRAGMENT_BYTES as u64)
    + 1;
/// Structural whole-file byte cap under the same fixed budgets.
pub const ARCHIVE_FILE_MAX: u64 = ARCHIVE_HEADER as u64
    + 4
    + vhalla_private_kernel::MAX_IMAGE_BYTES as u64
    + 256 * 1024 * 1024
    + ARCHIVE_PAGES_MAX * 512
    + 100_000 * 41;

/// Write the unauthenticated container header; the kernel re-checks every field
/// against authenticated pages before any destination write.
pub fn archive_header(context: Context, archive_id: [u8; 32]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(ARCHIVE_HEADER);
    raw.extend_from_slice(ARCHIVE_MAGIC);
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
        &archive_id,
    ] {
        raw.extend_from_slice(field);
    }
    raw
}
/// Decode only the canonical header of a complete header-width prefix. Header
/// claims are hints; page authentication decides everything downstream.
pub fn decode_archive_header(raw: &[u8]) -> Result<(Context, [u8; 32]), &'static str> {
    if raw.len() != ARCHIVE_HEADER || &raw[..8] != ARCHIVE_MAGIC {
        return Err("Choose a complete .vharchive file; unknown versions are refused.");
    }
    let field = |offset| raw[offset..offset + 32].try_into().expect("bounded header");
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(field(8)).map_err(|_| "Invalid room identifier.")?,
            anchor: AnchorId::from_bytes(field(40)).map_err(|_| "Invalid anchor identifier.")?,
        },
        account: Key::from_bytes(field(72)).map_err(|_| "Invalid account key.")?,
        device: Key::from_bytes(field(104)).map_err(|_| "Invalid device key.")?,
    };
    let id: [u8; 32] = field(136);
    if id == [0; 32] {
        return Err("Invalid archive identity.");
    }
    Ok((context, id))
}
/// Explicit encrypted-artifact export allowlist; secret and legacy bootstrap forms refuse.
pub fn encrypted_export(kind: OutboxKind) -> Option<(&'static str, &'static str)> {
    match kind {
        OutboxKind::Application => Some(("Encrypted message", "vhmsg")),
        OutboxKind::ContactRequest => Some(("Encrypted join request", "vhrequest")),
        OutboxKind::ContactInvitation => Some(("Encrypted join response", "vhjoin")),
        OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession => {
            Some(("Encrypted owner control", "vhcontrol"))
        }
        OutboxKind::ContactOffer | OutboxKind::KeyPackage | OutboxKind::Invitation => None,
    }
}
