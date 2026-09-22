//! Deterministic ecology model for composition experiments.
//!
//! The state is intentionally tiny: organisms have typed abilities, resources,
//! and lineage. Each tick uses a seed-derived deterministic schedule so a
//! canonical transcript can be replayed on native and WASM implementations.

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Organism {
    pub id: u64,
    pub lineage: u64,
    pub abilities: Vec<u8>,
    pub resources: u64,
    pub alive: bool,
}

pub const MAX_ORGANISMS: usize = 128;
pub const MAX_ABILITIES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorldError {
    DuplicateOrganismId(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct World {
    pub seed: u64,
    pub tick: u64,
    pub organisms: Vec<Organism>,
}

impl World {
    /// Construct a world while rejecting duplicate organism identities before
    /// canonicalization or truncation. Inputs from an untrusted wire should
    /// use this fallible constructor.
    pub fn try_new(seed: u64, mut organisms: Vec<Organism>) -> Result<Self, WorldError> {
        organisms.sort_by_key(|organism| organism.id);
        for pair in organisms.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(WorldError::DuplicateOrganismId(pair[0].id));
            }
        }
        organisms.truncate(MAX_ORGANISMS);
        for organism in &mut organisms {
            organism.abilities.truncate(MAX_ABILITIES);
        }
        Ok(Self {
            seed,
            tick: 0,
            organisms,
        })
    }

    pub fn new(seed: u64, organisms: Vec<Organism>) -> Self {
        Self::try_new(seed, organisms).expect("duplicate organism ID")
    }

    pub fn step(&mut self) {
        let tick_seed = self
            .seed
            .wrapping_add(self.tick.wrapping_mul(0x9e3779b97f4a7c15));
        for organism in &mut self.organisms {
            if !organism.alive {
                continue;
            }
            let ability = organism.abilities.first().copied().unwrap_or(0);
            let gain = u64::from(ability) + (tick_seed ^ organism.lineage) % 3;
            organism.resources = organism.resources.saturating_add(gain);
            if organism.resources > 32 {
                organism.resources -= 8;
                organism.lineage = organism.lineage.wrapping_mul(31).wrapping_add(tick_seed);
            }
        }
        self.tick = self.tick.wrapping_add(1);
    }

    pub fn replay_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"valhalla/ecology/replay/v1\0");
        hasher.update(self.seed.to_be_bytes());
        hasher.update(self.tick.to_be_bytes());
        hasher.update((self.organisms.len() as u64).to_be_bytes());
        for organism in &self.organisms {
            hasher.update(organism.id.to_be_bytes());
            hasher.update(organism.lineage.to_be_bytes());
            hasher.update(organism.resources.to_be_bytes());
            hasher.update([u8::from(organism.alive)]);
            hasher.update((organism.abilities.len() as u64).to_be_bytes());
            for ability in &organism.abilities {
                hasher.update([*ability]);
            }
        }
        hasher.finalize().into()
    }

    pub fn composition_gain(&self) -> u64 {
        let coalition = self
            .organisms
            .iter()
            .filter(|organism| organism.alive)
            .fold(0u64, |sum, organism| sum.saturating_add(organism.resources));
        let best_isolated = self
            .organisms
            .iter()
            .filter(|organism| organism.alive)
            .map(|organism| organism.resources)
            .max()
            .unwrap_or(0);
        coalition.saturating_sub(best_isolated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world() -> World {
        World::new(
            4,
            vec![
                Organism {
                    id: 1,
                    lineage: 10,
                    abilities: vec![2],
                    resources: 0,
                    alive: true,
                },
                Organism {
                    id: 2,
                    lineage: 20,
                    abilities: vec![3],
                    resources: 0,
                    alive: true,
                },
            ],
        )
    }

    #[test]
    fn same_seed_and_transcript_replay_identically() {
        let mut left = world();
        let mut right = world();
        for _ in 0..10 {
            left.step();
            right.step();
        }
        assert_eq!(left, right);
        assert_eq!(left.replay_digest(), right.replay_digest());
    }

    #[test]
    fn composition_gain_is_measured_against_best_isolated_member() {
        let mut world = world();
        for _ in 0..4 {
            world.step();
        }
        assert!(world.composition_gain() > 0);
    }

    #[test]
    fn dead_lineages_do_not_receive_resources() {
        let mut world = world();
        world.organisms[0].alive = false;
        let before = world.organisms[0].resources;
        world.step();
        assert_eq!(world.organisms[0].resources, before);
    }

    #[test]
    fn duplicate_ids_are_rejected_before_truncation() {
        let duplicate = Organism {
            id: 9,
            lineage: 0,
            abilities: vec![],
            resources: 0,
            alive: true,
        };
        assert_eq!(
            World::try_new(0, vec![duplicate.clone(), duplicate]),
            Err(WorldError::DuplicateOrganismId(9))
        );
    }
}
