//! Partition-aware liveness and lease reference model.
//!
//! The model distinguishes observations from authority. Missing progress may
//! produce a bounded suspicion, but never transfers ownership or policy. Only
//! an explicit owner-signed transition (represented here by the owner token)
//! may renew or reattach a lease.

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Peer(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Active,
    Suspected,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub owner: Peer,
    pub epoch: u64,
    pub expires_at: u64,
    pub state: LeaseState,
    last_progress: Option<u64>,
    last_tick: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub peer: Peer,
    pub epoch: u64,
    pub progress: u64,
    pub observed_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongOwner,
    WrongEpoch,
    StaleProgress,
    Expired,
    InvalidDeadline,
}

impl Lease {
    pub fn new(owner: Peer, epoch: u64, expires_at: u64) -> Result<Self, Error> {
        if expires_at == 0 {
            return Err(Error::InvalidDeadline);
        }
        Ok(Self {
            owner,
            epoch,
            expires_at,
            state: LeaseState::Active,
            last_progress: None,
            last_tick: 0,
        })
    }

    pub fn renew(&mut self, owner: Peer, epoch: u64, expires_at: u64) -> Result<(), Error> {
        if owner != self.owner {
            return Err(Error::WrongOwner);
        }
        if epoch != self.epoch {
            return Err(Error::WrongEpoch);
        }
        if expires_at <= self.expires_at {
            return Err(Error::InvalidDeadline);
        }
        if self.state == LeaseState::Expired {
            return Err(Error::Expired);
        }
        self.expires_at = expires_at;
        self.state = LeaseState::Active;
        Ok(())
    }

    pub fn observe(&mut self, observation: Observation, now: u64) -> Result<(), Error> {
        if observation.peer != self.owner {
            return Err(Error::WrongOwner);
        }
        if observation.epoch != self.epoch {
            return Err(Error::WrongEpoch);
        }
        if observation.observed_at > now {
            return Err(Error::InvalidDeadline);
        }
        if observation.progress == 0
            || self
                .last_progress
                .is_some_and(|last| observation.progress <= last)
        {
            return Err(Error::StaleProgress);
        }
        self.last_progress = Some(observation.progress);
        if self.state != LeaseState::Expired {
            self.state = LeaseState::Active;
        }
        Ok(())
    }

    pub fn tick(&mut self, now: u64) {
        if now < self.last_tick {
            return;
        }
        self.last_tick = now;
        if now >= self.expires_at {
            self.state = LeaseState::Expired;
        } else if self.state == LeaseState::Active {
            self.state = LeaseState::Suspected;
        }
    }

    pub fn reattach(&mut self, owner: Peer, epoch: u64, now: u64) -> Result<(), Error> {
        if owner != self.owner {
            return Err(Error::WrongOwner);
        }
        if epoch != self.epoch {
            return Err(Error::WrongEpoch);
        }
        if now >= self.expires_at {
            return Err(Error::Expired);
        }
        self.state = LeaseState::Active;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_progress_causes_suspicion_but_not_authority_transfer() {
        let mut lease = Lease::new(Peer(1), 7, 10).unwrap();
        lease.tick(5);
        assert_eq!(lease.state, LeaseState::Suspected);
        assert_eq!(lease.owner, Peer(1));
        assert_eq!(lease.reattach(Peer(2), 7, 5), Err(Error::WrongOwner));
        lease.reattach(Peer(1), 7, 5).unwrap();
        assert_eq!(lease.state, LeaseState::Active);
    }

    #[test]
    fn expiry_does_not_create_a_new_owner() {
        let mut lease = Lease::new(Peer(1), 7, 10).unwrap();
        lease.tick(10);
        assert_eq!(lease.state, LeaseState::Expired);
        assert_eq!(lease.owner, Peer(1));
        assert_eq!(lease.renew(Peer(1), 7, 20), Err(Error::Expired));
        assert_eq!(lease.reattach(Peer(2), 7, 10), Err(Error::WrongOwner));
    }

    #[test]
    fn observations_are_epoch_and_progress_bound() {
        let mut lease = Lease::new(Peer(1), 2, 20).unwrap();
        assert_eq!(
            lease.observe(
                Observation {
                    peer: Peer(1),
                    epoch: 1,
                    progress: 1,
                    observed_at: 3,
                },
                3
            ),
            Err(Error::WrongEpoch)
        );
        assert_eq!(
            lease.observe(
                Observation {
                    peer: Peer(1),
                    epoch: 2,
                    progress: 0,
                    observed_at: 3,
                },
                3
            ),
            Err(Error::StaleProgress)
        );
        lease
            .observe(
                Observation {
                    peer: Peer(1),
                    epoch: 2,
                    progress: 4,
                    observed_at: 3,
                },
                3,
            )
            .unwrap();
        assert_eq!(lease.state, LeaseState::Active);
    }
}
