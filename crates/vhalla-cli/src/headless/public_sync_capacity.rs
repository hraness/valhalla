//! Owner-selected growth of one sync store, preserving every cursor and fence.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::headless) enum StorageComponent {
    Replica {},
    Projection {},
    Follower { peer: Hash },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::headless) struct StorageLimits {
    max_records: u64,
    max_record_bytes: u64,
}
impl StorageLimits {
    fn checked(self, current: Limits) -> Result<Limits> {
        if self.max_records < current.max_records
            || self.max_record_bytes < current.max_record_bytes
            || self.max_records > 1_000_000
            || self.max_record_bytes > 8 * 1024 * 1024 * 1024
        {
            return Err(ErrorBody::new(
                ErrorCode::Usage,
                "Storage limits can only increase, up to 1000000 records and 8589934592 payload bytes.",
            ));
        }
        Ok(Limits {
            max_records: self.max_records,
            max_record_bytes: self.max_record_bytes,
        })
    }
}

fn accounting(value: disk::Accounting) -> Value {
    json!({"records":value.records,"bytes":value.bytes,"generation":value.generation,
        "tip":value.tip,"max_records":value.limits.max_records,
        "max_record_bytes":value.limits.max_record_bytes})
}

fn follower_error(source: &mut SourceRuntime, error: FollowerError) -> ErrorBody {
    source.fail(
        "The retained source history needs an explicit reopen.",
        false,
    );
    if follower_room_failure(error) {
        unavailable()
    } else {
        ErrorBody::new(
            ErrorCode::Conflict,
            "The selected source history could not be checked. Preserve its files and reopen the room before retrying.",
        )
    }
}

impl PublicSync {
    fn open_storage_follower(
        &mut self,
        slot: Id,
        peer: Hash,
        published: &Published,
        runtime: &mut Runtime,
    ) -> Result<()> {
        let source = runtime
            .sources
            .entry(peer)
            .or_insert_with(SourceRuntime::new);
        if source.follower.is_some() {
            return Ok(());
        }
        let path = runtime.followers_directory.path.join(peer.to_string());
        let Some(initial) = self.metadata.initial_target(slot, peer)? else {
            if !matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
            {
                source.fail(
                    "Source files exist without their initial target intent.",
                    false,
                );
            }
            return Ok(());
        };
        // A terminal capacity refusal releases its follower lock. Maintenance
        // may reopen that retained ledger without clearing the source refusal
        // or giving the network scheduler permission to run it again.
        let opened = Follower::open(
            &path,
            published.binding.genesis()?,
            peer.0,
            &mut runtime.replica,
        )
        .map_err(source_open_error)
        .and_then(|mut follower| {
            if follower.initial_target(&mut runtime.replica)? != initial {
                return Err(FollowerError::Store(disk::Error::Corrupt));
            }
            let status = follower.status(&mut runtime.replica)?;
            Ok((follower, status))
        });
        source.opened = true;
        match opened {
            Ok((follower, status)) => {
                source.follower = Some(follower);
                source.status = Some(status);
                Ok(())
            }
            Err(error) => {
                let error = follower_error(source, error);
                if error.code == ErrorCode::OwnerUnavailable {
                    Err(error)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub(in crate::headless) fn storage_status(
        &mut self,
        slot: Id,
        room: &mut RoomSession,
    ) -> Result<Value> {
        self.storage_operation(slot, room, None)
    }

    pub(in crate::headless) fn expand_storage(
        &mut self,
        slot: Id,
        room: &mut RoomSession,
        component: StorageComponent,
        limits: StorageLimits,
    ) -> Result<Value> {
        self.storage_operation(slot, room, Some((component, limits)))
    }

    fn storage_operation(
        &mut self,
        slot: Id,
        room: &mut RoomSession,
        change: Option<(StorageComponent, StorageLimits)>,
    ) -> Result<Value> {
        self.check()?;
        let published = self.metadata.slot(slot)?.clone();
        if published.ready.is_none() || self.fenced.contains_key(&slot) {
            return Err(unavailable());
        }
        if !self.runtime.contains_key(&slot) {
            let opened = Runtime::open(&self.path(slot), &published, self.metadata.source(), room);
            match opened {
                Ok(runtime) => {
                    self.runtime.insert(slot, runtime);
                }
                Err(error) => {
                    self.fence(slot, "Retained room sync state could not be opened.");
                    return Err(error);
                }
            }
        }
        let mut runtime = self.runtime.remove(&slot).ok_or_else(unavailable)?;
        let result = (|| {
            runtime.check()?;
            published.binding.check(room)?;
            for peer in published.selected.keys() {
                self.open_storage_follower(slot, *peer, &published, &mut runtime)?;
            }
            if self.fenced.contains_key(&slot) {
                return Err(unavailable());
            }
            let replica = runtime.replica.accounting().map_err(|_| unavailable())?;
            let projection = runtime
                .projection
                .accounting(room, &mut runtime.replica)
                .map_err(|_| unavailable())?;
            if let Some((component, limits)) = change {
                let grown = match component {
                    StorageComponent::Replica {} => runtime
                        .replica
                        .expand_limits(limits.checked(replica.limits)?)
                        .map_err(|_| unavailable())?,
                    StorageComponent::Projection {} => runtime
                        .projection
                        .expand_limits(
                            limits.checked(projection.limits)?,
                            room,
                            &mut runtime.replica,
                        )
                        .map_err(|_| unavailable())?,
                    StorageComponent::Follower { peer } => {
                        let source = runtime
                            .sources
                            .get_mut(&peer)
                            .filter(|_| published.selected.contains_key(&peer))
                            .ok_or_else(|| {
                                ErrorBody::new(
                                    ErrorCode::NotFound,
                                    "Select this source before changing its storage limits.",
                                )
                            })?;
                        let follower = source.follower.as_mut().ok_or_else(|| ErrorBody::new(
                            ErrorCode::Conflict, "This source has no open retained history. Check sync status and explicitly reopen the room if needed."))?;
                        let current = match follower.accounting(&mut runtime.replica) {
                            Ok(value) => value,
                            Err(error) => return Err(follower_error(source, error)),
                        };
                        match follower
                            .expand_limits(limits.checked(current.limits)?, &mut runtime.replica)
                        {
                            Ok(value) => value,
                            Err(error) => return Err(follower_error(source, error)),
                        }
                    }
                };
                runtime.check()?;
                // Growth does not remove a capacity stop, pending transfer,
                // source refusal, or safety fence. Explicit reopen retries it.
                return Ok(
                    json!({"room":slot,"component":component,"storage":accounting(grown),
                    "resume":"Reopen the room to retry stopped synchronization."}),
                );
            }
            let mut sources = Vec::new();
            for peer in published.selected.keys() {
                let source = runtime.sources.get_mut(peer).ok_or_else(unavailable)?;
                let storage = match source.follower.as_mut() {
                    Some(follower) => match follower.accounting(&mut runtime.replica) {
                        Ok(value) => Some(accounting(value)),
                        Err(error) => {
                            let error = follower_error(source, error);
                            if error.code == ErrorCode::OwnerUnavailable {
                                return Err(error);
                            }
                            None
                        }
                    },
                    None => None,
                };
                sources.push(json!({"peer":peer,"storage":storage,
                    "state":if source.blocked {"needs_reopen"} else if source.follower.is_some() {"open"} else {"awaiting_snapshot"}}));
            }
            let metadata = self.metadata.accounting()?;
            runtime.check()?;
            Ok(
                json!({"room":slot,"replica":accounting(replica),"projection":accounting(projection),
                "followers":sources,"metadata":accounting(metadata),"metadata_expandable":false}),
            )
        })();
        if result
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::OwnerUnavailable)
        {
            self.fence(
                slot,
                "Retained sync storage could not be checked; explicitly reopen the room.",
            );
        } else {
            self.runtime.insert(slot, runtime);
        }
        self.check()?;
        result
    }
}
