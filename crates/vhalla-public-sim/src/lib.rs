//! Deterministic, bounded model for public-room event propagation.
//!
//! This crate intentionally models the measurement substrate rather than the
//! production transport. It has no sockets, clocks, files, or provider
//! dependencies. A receipt is useful only when its seed and configuration are
//! retained with the experiment manifest.
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

pub const MAX_PEERS: usize = 512;
pub const MAX_EVENTS: usize = 10_000;
pub const MAX_STEPS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub seed: u64,
    pub peers: usize,
    pub events: usize,
    pub steps: usize,
    pub churn_percent: u8,
    pub partition_start: Option<usize>,
    pub partition_end: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            seed: 1,
            peers: 16,
            events: 32,
            steps: 64,
            churn_percent: 10,
            partition_start: Some(12),
            partition_end: Some(28),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), SimError> {
        if self.peers == 0 || self.peers > MAX_PEERS {
            return Err(SimError::Limit("peers"));
        }
        if self.events == 0 || self.events > MAX_EVENTS {
            return Err(SimError::Limit("events"));
        }
        if self.steps == 0 || self.steps > MAX_STEPS {
            return Err(SimError::Limit("steps"));
        }
        if self.churn_percent > 100 {
            return Err(SimError::Limit("churn_percent"));
        }
        match (self.partition_start, self.partition_end) {
            (Some(start), Some(end)) if start >= end || end > self.steps => {
                Err(SimError::Invalid("partition interval"))
            }
            (None, None) | (Some(_), Some(_)) => Ok(()),
            _ => Err(SimError::Invalid("partition interval")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: u64,
    pub author: usize,
    pub sequence: u64,
    pub parents: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub schema_version: u32,
    pub seed: u64,
    pub peers: usize,
    pub configured_events: usize,
    pub steps: usize,
    pub generated_events: usize,
    pub delivered_events: usize,
    pub converged_events: usize,
    pub convergence_rate_bps: u32,
    pub duplicate_suppressed: usize,
    pub orphan_references: usize,
    pub partition_steps: usize,
    pub churn_steps: usize,
    pub digest: u64,
}

impl Receipt {
    /// Stable JSON for a machine-local evidence artifact. The values are all
    /// integers so this avoids bringing a serializer into the workspace.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":{},\"seed\":{},\"peers\":{},\"configured_events\":{},\"steps\":{},\"generated_events\":{},\"delivered_events\":{},\"converged_events\":{},\"convergence_rate_bps\":{},\"duplicate_suppressed\":{},\"orphan_references\":{},\"partition_steps\":{},\"churn_steps\":{},\"digest\":{}}}",
            self.schema_version,
            self.seed,
            self.peers,
            self.configured_events,
            self.steps,
            self.generated_events,
            self.delivered_events,
            self.converged_events,
            self.convergence_rate_bps,
            self.duplicate_suppressed,
            self.orphan_references,
            self.partition_steps,
            self.churn_steps,
            self.digest
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimError {
    Limit(&'static str),
    Invalid(&'static str),
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit(field) => write!(f, "{field} exceeds simulator limit"),
            Self::Invalid(field) => write!(f, "invalid {field}"),
        }
    }
}

impl std::error::Error for SimError {}

#[derive(Clone, Debug)]
struct Peer {
    online: bool,
    events: BTreeSet<u64>,
}

#[derive(Clone, Debug)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9e3779b97f4a7c15 } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        self.0 = x;
        x
    }

    fn percent(&mut self, n: u8) -> bool {
        self.next() % 100 < u64::from(n)
    }
}

fn event_id(seed: u64, author: usize, sequence: u64, parents: &[u64]) -> u64 {
    let mut h = seed ^ 0x517cc1b727220a95;
    h = h.rotate_left(17) ^ author as u64;
    h = h.rotate_left(23) ^ sequence;
    for parent in parents {
        h = h.rotate_left(11) ^ *parent;
        h = h.wrapping_mul(0x9e3779b185ebca87);
    }
    h
}

pub fn run(config: Config) -> Result<Receipt, SimError> {
    config.validate()?;
    let mut rng = Rng::new(config.seed);
    let mut peers: Vec<Peer> = (0..config.peers)
        .map(|_| Peer {
            online: true,
            events: BTreeSet::new(),
        })
        .collect();
    let mut events = BTreeMap::<u64, Event>::new();
    let mut previous_by_author = vec![None; config.peers];
    let mut generated = Vec::with_capacity(config.events);
    for n in 0..config.events {
        let author = n % config.peers;
        let mut parents = Vec::with_capacity(2);
        if let Some(parent) = previous_by_author[author] {
            parents.push(parent);
        }
        if let Some(previous) = generated.last().map(|e: &Event| e.id) {
            if !parents.contains(&previous) {
                parents.push(previous);
            }
        }
        let event = Event {
            id: event_id(config.seed, author, n as u64, &parents),
            author,
            sequence: n as u64,
            parents,
        };
        previous_by_author[author] = Some(event.id);
        if events.insert(event.id, event.clone()).is_some() {
            return Err(SimError::Invalid("event id collision"));
        }
        generated.push(event);
    }
    // Seed each author's accepted event at its author peer. This gives the
    // model a realistic mix of local acceptance and remote propagation while
    // keeping the workload manifest independent of the simulation clock.
    for event in &generated {
        peers[event.author].events.insert(event.id);
    }

    let mut delivered_events = 0usize;
    let mut duplicate_suppressed = 0usize;
    let mut churn_steps = 0usize;
    let mut partition_steps = 0usize;
    for step in 0..config.steps {
        if config.churn_percent > 0 {
            let mut changed = false;
            for peer in &mut peers {
                if rng.percent(config.churn_percent) {
                    peer.online = !peer.online;
                    changed = true;
                }
            }
            if changed {
                churn_steps += 1;
            }
        }
        let partitioned = matches!((config.partition_start, config.partition_end), (Some(a), Some(b)) if step >= a && step < b);
        if partitioned {
            partition_steps += 1;
        }

        // A ring plus deterministic skip links approximates a sparse gossip
        // mesh without making topology generation depend on platform APIs.
        let mut transfers = Vec::new();
        for left in 0..config.peers {
            let right = (left + 1) % config.peers;
            let skip = (left + 1 + (rng.next() as usize % config.peers)) % config.peers;
            for neighbor in [right, skip] {
                if neighbor == left || !peers[left].online || !peers[neighbor].online {
                    continue;
                }
                if partitioned && (left < config.peers / 2) != (neighbor < config.peers / 2) {
                    continue;
                }
                let from: Vec<u64> = peers[left].events.iter().copied().collect();
                let to: Vec<u64> = peers[neighbor].events.iter().copied().collect();
                let have: BTreeSet<u64> = to.into_iter().collect();
                for id in from {
                    if have.contains(&id) {
                        duplicate_suppressed += 1;
                    } else {
                        transfers.push((neighbor, id));
                    }
                }
            }
        }
        for (peer, id) in transfers {
            if peers[peer].events.insert(id) {
                delivered_events += 1;
            }
        }
    }

    let converged_events = events
        .keys()
        .filter(|id| peers.iter().all(|peer| peer.events.contains(id)))
        .count();
    let orphan_references = peers
        .iter()
        .map(|peer| {
            peer.events
                .iter()
                .filter_map(|id| events.get(id))
                .flat_map(|event| event.parents.iter())
                .filter(|parent| !peer.events.contains(parent))
                .count()
        })
        .sum();
    let mut digest = config.seed ^ 0x6a09e667f3bcc909;
    for (id, event) in &events {
        digest = digest.rotate_left(9) ^ *id ^ event.author as u64 ^ event.sequence;
    }
    for peer in &peers {
        digest = digest.rotate_left(7) ^ peer.events.len() as u64 ^ u64::from(peer.online);
    }
    Ok(Receipt {
        schema_version: 1,
        seed: config.seed,
        peers: config.peers,
        configured_events: config.events,
        steps: config.steps,
        generated_events: events.len(),
        delivered_events,
        converged_events,
        convergence_rate_bps: if events.is_empty() {
            0
        } else {
            ((converged_events as u64 * 10_000) / events.len() as u64) as u32
        },
        duplicate_suppressed,
        orphan_references,
        partition_steps,
        churn_steps,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_runs_are_replayable() {
        let config = Config {
            churn_percent: 0,
            partition_start: None,
            partition_end: None,
            ..Config::default()
        };
        assert_eq!(run(config.clone()).unwrap(), run(config).unwrap());
    }

    #[test]
    fn healed_mesh_converges_without_churn() {
        let config = Config {
            churn_percent: 0,
            partition_start: Some(3),
            partition_end: Some(8),
            steps: 32,
            ..Config::default()
        };
        let receipt = run(config).unwrap();
        assert_eq!(receipt.generated_events, 32);
        assert_eq!(receipt.convergence_rate_bps, 10_000);
        assert!(receipt.partition_steps > 0);
    }

    #[test]
    fn bounds_are_fail_closed() {
        let config = Config {
            peers: MAX_PEERS + 1,
            ..Config::default()
        };
        assert_eq!(run(config), Err(SimError::Limit("peers")));
    }
}
