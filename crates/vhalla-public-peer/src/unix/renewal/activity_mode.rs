//! Immutable opt-in mode for NEW publisher state, never a live migration.
use super::*;
use std::os::unix::ffi::OsStrExt;
pub(super) const MODE: &str = "activity-mode";
pub(super) const MODE_BYTES: usize = 5 + 32 + 32;

#[derive(Clone, Copy)]
pub(super) enum Selection {
    Legacy([u8; 32]),
    Continuity([u8; 32]),
}
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
fn encode_selected(scope: &Scope, selected: Selection) -> Vec<u8> {
    let (config, version, domain): ([u8; 32], u8, &[u8]) = match selected {
        Selection::Legacy(config) => (config, 1, b"vhalla/public-peer-activity-mode/v1\0"),
        Selection::Continuity(config) => (config, 2, b"vhalla/public-peer-activity-mode/v2\0"),
    };
    let mut raw = b"VHPM".to_vec();
    raw.push(version);
    raw.extend_from_slice(&config);
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(scope.network);
    hash.update(scope.key);
    hash.update(scope.route_hash());
    hash.update(&raw);
    raw.extend_from_slice(&hash.finalize());
    raw
}
pub(super) fn read_selected_mode(
    dir: &Path,
    owner: Owner,
    scope: &Scope,
    expected: Option<Selection>,
) -> Result<Option<Vec<u8>>, Error> {
    let retained = read_optional(dir, owner, MODE, MODE_BYTES)?;
    let expected = expected.map(|config| encode_selected(scope, config));
    if retained != expected {
        return Err(Error::State(
            "activity mode/configuration mismatch; preserve state",
        ));
    }
    if retained.is_some() {
        custody::open_private_file(&dir.join(MODE), owner, MODE_BYTES)
            .map_err(Error::Custody)?
            .sync_all()?;
    }
    Ok(retained)
}
impl Publisher {
    pub(super) fn create_selected_mode(&mut self, config: Selection) -> Result<(), Error> {
        // Only new state may enter this mode. A torn initial marker is retained
        // and refused; no reopen reconstructs it or resets a reservation.
        if self.reservation.sequence != 0
            || self.persisted.is_some()
            || self.activity_mode.is_some()
        {
            return Err(Error::State("activity requires new publisher state"));
        }
        self.poisoned = true;
        let raw = encode_selected(&self.scope, config);
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

pub(super) fn continuity_digest(config: &ContinuityConfig) -> Result<[u8; 32], Error> {
    if config.rooms.is_empty() || config.rooms.len() > MAX_ACTIVITY_ROOMS {
        return Err(Error::Config);
    }
    let mut rooms = config.rooms.iter().collect::<Vec<_>>();
    rooms.sort_by_key(|room| *room.room.as_bytes());
    if rooms.windows(2).any(|pair| pair[0].room == pair[1].room) {
        return Err(Error::Config);
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/public-peer-continuity-config/v2\0VHCF2");
    hash.update((rooms.len() as u32).to_be_bytes());
    for room in rooms {
        let path = custody::absolute(&room.directory).map_err(Error::Custody)?;
        let raw = path.as_os_str().as_bytes();
        hash.update(room.room.as_bytes());
        hash.update((raw.len() as u64).to_be_bytes());
        hash.update(raw);
        let limits = room.limits;
        hash.update(limits.history.max_events.to_be_bytes());
        hash.update(limits.history.max_history_bytes.to_be_bytes());
        hash.update(limits.max_stage_slots.to_be_bytes());
        hash.update(limits.max_stage_events.to_be_bytes());
        hash.update(limits.max_stage_bytes.to_be_bytes());
        hash.update(limits.stage_ttl_seconds.to_be_bytes());
    }
    Ok(hash.finalize().into())
}
