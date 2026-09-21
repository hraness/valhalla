//! Portable file/disclosure helpers for the trusted private panel, not authority.
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, OutboxKind,
};
const LOCATOR: &[u8; 8] = b"VHPLOC1\0";
/// Exact nonsecret locator width: versioned prefix plus four full identifiers.
pub const LOCATOR_BYTES: usize = 136;

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
/// Explicit encrypted-artifact export allowlist; secret and legacy bootstrap forms refuse.
pub fn encrypted_export(kind: OutboxKind) -> Option<(&'static str, &'static str)> {
    match kind {
        OutboxKind::Application => Some(("Encrypted message", "vhmsg")),
        OutboxKind::ContactRequest => Some(("Encrypted join request", "vhrequest")),
        OutboxKind::ContactInvitation => Some(("Encrypted join response", "vhjoin")),
        OutboxKind::Removal | OutboxKind::OwnerUpdate => {
            Some(("Encrypted owner control", "vhcontrol"))
        }
        OutboxKind::ContactOffer | OutboxKind::KeyPackage | OutboxKind::Invitation => None,
    }
}
