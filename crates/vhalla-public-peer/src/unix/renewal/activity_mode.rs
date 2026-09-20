//! Immutable opt-in mode for NEW publisher state, never a live migration.
use super::*;
use std::os::unix::ffi::OsStrExt;
pub(super) const MODE: &str = "activity-mode";
pub(super) const MODE_BYTES: usize = 5 + 32 + 32;

pub(super) fn capabilities(enabled: bool) -> Result<Capabilities, Error> {
    Capabilities::from_bits(
        Capabilities::READ.bits()
            | if enabled {
                Capabilities::PUBLISH.bits()
            } else {
                0
            },
    )
    .map_err(|_| Error::Config)
}
pub(super) fn config_digest(config: &ActivityConfig) -> Result<[u8; 32], Error> {
    if config.rooms.is_empty() || config.rooms.len() > MAX_ACTIVITY_ROOMS {
        return Err(Error::Config);
    }
    let mut rooms = config.rooms.iter().collect::<Vec<_>>();
    rooms.sort_by_key(|room| *room.room.as_bytes());
    if rooms.windows(2).any(|pair| pair[0].room == pair[1].room) {
        return Err(Error::Config);
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/public-peer-activity-config/v1\0");
    hash.update((rooms.len() as u32).to_be_bytes());
    for room in rooms {
        let path = custody::absolute(&room.directory).map_err(Error::Custody)?;
        let raw = path.as_os_str().as_bytes();
        hash.update(room.room.as_bytes());
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(raw);
        hash.update(room.limits.max_events.to_be_bytes());
        hash.update(room.limits.max_history_bytes.to_be_bytes());
    }
    Ok(hash.finalize().into())
}
fn encode(scope: &Scope, config: [u8; 32]) -> Vec<u8> {
    let mut raw = b"VHPM\x01".to_vec();
    raw.extend_from_slice(&config);
    let mut hash = Sha256::new();
    hash.update(b"vhalla/public-peer-activity-mode/v1\0");
    hash.update(scope.network);
    hash.update(scope.key);
    hash.update(scope.route_hash());
    hash.update(&raw);
    raw.extend_from_slice(&hash.finalize());
    raw
}
pub(super) fn read_mode(
    dir: &Path,
    uid: u32,
    scope: &Scope,
    expected: Option<[u8; 32]>,
) -> Result<Option<Vec<u8>>, Error> {
    let retained = read_optional(dir, uid, MODE, MODE_BYTES)?;
    let expected = expected.map(|config| encode(scope, config));
    if retained != expected {
        return Err(Error::State(
            "activity mode/configuration mismatch; preserve state",
        ));
    }
    if retained.is_some() {
        custody::open_private_file(&dir.join(MODE), uid, MODE_BYTES)
            .map_err(Error::Custody)?
            .sync_all()?;
    }
    Ok(retained)
}
impl Publisher {
    pub(super) fn create_activity_mode(&mut self, config: [u8; 32]) -> Result<(), Error> {
        // Only new state may enter this mode. A torn initial marker is retained
        // and refused; no reopen reconstructs it or resets a reservation.
        if self.reservation.sequence != 0
            || self.persisted.is_some()
            || self.activity_mode.is_some()
        {
            return Err(Error::State("activity requires new publisher state"));
        }
        self.poisoned = true;
        let raw = encode(&self.scope, config);
        let mut file =
            custody::create_private_file(&self.dir.join(MODE)).map_err(Error::Custody)?;
        file.write_all(&raw)?;
        file.sync_all()?;
        self.directory.sync_all()?;
        self.activity_mode = Some(raw);
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
