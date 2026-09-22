//! Exact retained-room lookup, independent of active-room listing pagination.
use vhalla_rooms::{registry::Registry, RoomGenesisId};

/// Resolve only a complete canonical ID in the caller's verified registry.
/// This includes archived rooms for recovery and grants no posting permission.
pub fn lookup(registry: &Registry, text: &str) -> Result<RoomGenesisId, &'static str> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "Enter exactly 64 lowercase hexadecimal characters for the recovery room genesis ID.",
        );
    }
    let mut raw = [0; 32];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "Invalid recovery room genesis ID.")?;
    }
    registry
        .room_by_genesis(RoomGenesisId::from_bytes(raw))
        .map(|room| room.genesis())
        .ok_or("This room ID is absent from the locally verified directory. Check the selected network and ID, or sync its certified history before recovery.")
}
