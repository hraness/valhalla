use crate::{codec::*, *};

impl RoomSession {
    /// Increase retained-data limits in place, then republish the exact frame in
    /// the emergency slot before clearing that slot. This never prunes records,
    /// changes cursors or resets owner-fork, overflow or lost-custody evidence.
    /// If the new allowance is still insufficient, the emergency slot survives.
    pub fn expand_limits(&mut self, target: Limits) -> Result<Status> {
        self.ready()?;
        if let Err(error) = self.store.expand_limits(target) {
            if matches!(
                error,
                vhalla_direct_store::Error::Uncertain | vhalla_direct_store::Error::Corrupt
            ) {
                self.poisoned = true;
            }
            return Err(error.into());
        }
        self.retain_blocked()?;
        self.apply_policies()?;
        self.status()
    }

    fn retain_blocked(&mut self) -> Result<()> {
        let Some(blocked) = self.image.blocked.clone() else {
            return Ok(());
        };
        let existing = self.store.read(blocked.key())?;
        if existing
            .as_ref()
            .is_some_and(|raw| raw.as_slice() != blocked.as_bytes())
        {
            return Err(Error::Corrupt);
        }
        let mut image = self.image.clone();
        let mut records = Vec::new();
        match blocked.key()[0] {
            EVENT => {
                let event = self.event_raw(blocked.as_bytes())?;
                if blocked.key() != raw_key(EVENT, *event.id().as_bytes()) {
                    return Err(Error::Corrupt);
                }
                if existing.is_none() {
                    records.push(blocked.clone());
                    if let Some(old) =
                        self.indexed_event(event.claims().author, event.claims().sequence)?
                    {
                        if old.id() != event.id()
                            && self
                                .store
                                .read(key(AUTHOR_FORK, &event.claims().author))?
                                .is_none()
                        {
                            let mut proof = event.claims().author.to_vec();
                            proof.extend_from_slice(&event.claims().sequence.to_be_bytes());
                            proof.extend_from_slice(old.id().as_bytes());
                            proof.extend_from_slice(event.id().as_bytes());
                            records.push(record(key(AUTHOR_FORK, &event.claims().author), &proof)?);
                        }
                    } else if let Some(index) = self.event_index_record(&event)? {
                        records.push(index);
                    }
                    if event.claims().author == self.author_key()
                        && !self.pending_matches(EVENT, *event.id().as_bytes())?
                    {
                        image.author_lost = true;
                        records.push(record(
                            raw_key(LOST_AUTHOR, *event.id().as_bytes()),
                            event.id().as_bytes(),
                        )?);
                    }
                }
                image.blocked = None;
                self.publish(image, &records, true)?;
                self.event_persisted(&event)?;
            }
            POLICY => {
                let policy = self.policy_raw(blocked.as_bytes())?;
                if blocked.key() != raw_key(POLICY, *policy.id().as_bytes()) {
                    return Err(Error::Corrupt);
                }
                if existing.is_none() {
                    records.push(blocked.clone());
                    if let Some(old) = self.indexed_policy(OBSERVED, policy.claims().revision)? {
                        if old.id() != policy.id() {
                            let mut proof = old.id().as_bytes().to_vec();
                            proof.extend_from_slice(policy.id().as_bytes());
                            records.push(record(key(OWNER_FORK, &proof), &proof)?);
                        }
                    } else if let Some(index) = self.observed_index_record(&policy)? {
                        records.push(index);
                    }
                    if self.created_here
                        && !self.pending_matches(POLICY, *policy.id().as_bytes())?
                    {
                        image.owner_lost = true;
                        records.push(record(
                            raw_key(LOST_OWNER, *policy.id().as_bytes()),
                            policy.id().as_bytes(),
                        )?);
                    }
                }
                image.blocked = None;
                self.publish(image, &records, true)?;
                self.observe_cached(policy)?;
            }
            _ => return Err(Error::Corrupt),
        }
        Ok(())
    }
}
