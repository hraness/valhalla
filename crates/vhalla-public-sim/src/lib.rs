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
/// Maximum forwarding candidates considered in one simulation step.
pub const MAX_STEP_TRANSFER_ATTEMPTS: usize = 1_000_000;
/// Maximum forwarding candidates considered in one complete simulation.
pub const MAX_TRANSFER_ATTEMPTS: usize = 50_000_000;
const FORWARDING_LINKS_PER_PEER: usize = 2;

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
        let attempts_per_step = self
            .peers
            .checked_mul(self.events)
            .and_then(|value| value.checked_mul(FORWARDING_LINKS_PER_PEER))
            .ok_or(SimError::Limit("transfer attempts per step"))?;
        if attempts_per_step > MAX_STEP_TRANSFER_ATTEMPTS {
            return Err(SimError::Limit("transfer attempts per step"));
        }
        let attempts = attempts_per_step
            .checked_mul(self.steps)
            .ok_or(SimError::Limit("transfer attempts"))?;
        if attempts > MAX_TRANSFER_ATTEMPTS {
            return Err(SimError::Limit("transfer attempts"));
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

const DIGEST_MULTIPLIER: u64 = 0x9e3779b185ebca87;
const DIGEST_DOMAIN: u64 = 0xd6e8feb86659fd93;
const DIGEST_OFFSET: u64 = 0x6a09e667f3bcc909;

fn mix_digest(digest: &mut u64, tag: u64, value: u64) {
    *digest = (*digest ^ tag.wrapping_mul(DIGEST_DOMAIN))
        .rotate_left(17)
        .wrapping_mul(DIGEST_MULTIPLIER)
        ^ value.wrapping_mul(DIGEST_DOMAIN);
    *digest = (*digest).rotate_left(29).wrapping_mul(DIGEST_MULTIPLIER);
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
        // A set makes duplicate forwarding attempts explicit and keeps the
        // pending batch bounded by the validated per-step transfer budget.
        let mut transfers = BTreeSet::new();
        for left in 0..config.peers {
            let right = (left + 1) % config.peers;
            // Reduce before converting to usize so 32-bit and 64-bit targets
            // choose the same topology for a given seed.
            let skip_offset = (rng.next() % config.peers as u64) as usize;
            let skip = (left + 1 + skip_offset) % config.peers;
            for neighbor in [right, skip] {
                if neighbor == left || !peers[left].online || !peers[neighbor].online {
                    continue;
                }
                if partitioned && (left < config.peers / 2) != (neighbor < config.peers / 2) {
                    continue;
                }
                for id in peers[left].events.iter().copied() {
                    if peers[neighbor].events.contains(&id) || !transfers.insert((neighbor, id)) {
                        duplicate_suppressed += 1;
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
    // Bind every manifest-controlled input, not only observed counters. For
    // example, one-peer partitions can produce identical counters at different
    // intervals, but those are still different experiments.
    let mut digest = DIGEST_OFFSET;
    mix_digest(&mut digest, 0, 2);
    mix_digest(&mut digest, 1, config.seed);
    mix_digest(&mut digest, 2, config.peers as u64);
    mix_digest(&mut digest, 3, config.events as u64);
    mix_digest(&mut digest, 4, config.steps as u64);
    mix_digest(&mut digest, 5, u64::from(config.churn_percent));
    match config.partition_start {
        Some(value) => {
            mix_digest(&mut digest, 6, 1);
            mix_digest(&mut digest, 7, value as u64);
        }
        None => mix_digest(&mut digest, 6, 0),
    }
    match config.partition_end {
        Some(value) => {
            mix_digest(&mut digest, 8, 1);
            mix_digest(&mut digest, 9, value as u64);
        }
        None => mix_digest(&mut digest, 8, 0),
    }
    for (event_index, (id, event)) in events.iter().enumerate() {
        mix_digest(&mut digest, 10, event_index as u64);
        mix_digest(&mut digest, 11, *id);
        mix_digest(&mut digest, 12, event.author as u64);
        mix_digest(&mut digest, 13, event.sequence);
        mix_digest(&mut digest, 14, event.parents.len() as u64);
        for (parent_index, parent) in event.parents.iter().enumerate() {
            mix_digest(&mut digest, 15, parent_index as u64);
            mix_digest(&mut digest, 16, *parent);
        }
    }
    for (peer_index, peer) in peers.iter().enumerate() {
        mix_digest(&mut digest, 17, peer_index as u64);
        mix_digest(&mut digest, 18, u64::from(peer.online));
        mix_digest(&mut digest, 19, peer.events.len() as u64);
        for id in &peer.events {
            mix_digest(&mut digest, 20, *id);
        }
    }
    for (tag, value) in [
        (21, delivered_events as u64),
        (22, duplicate_suppressed as u64),
        (23, orphan_references as u64),
        (24, partition_steps as u64),
        (25, churn_steps as u64),
    ] {
        mix_digest(&mut digest, tag, value);
    }
    Ok(Receipt {
        // Digest semantics changed in schema version 2 to bind the full
        // manifest, so old verifiers cannot silently accept a mismatched run.
        schema_version: 2,
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
        let first = run(config.clone()).unwrap();
        let second = run(config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.to_json(), second.to_json());
    }

    #[test]
    fn receipt_digest_binds_schedule_inputs() {
        let first = Config {
            peers: 1,
            events: 1,
            steps: 2,
            churn_percent: 0,
            partition_start: Some(0),
            partition_end: Some(1),
            ..Config::default()
        };
        let second = Config {
            partition_start: Some(1),
            partition_end: Some(2),
            ..first.clone()
        };
        let first_receipt = run(first).unwrap();
        let second_receipt = run(second).unwrap();
        assert_eq!(
            first_receipt.partition_steps,
            second_receipt.partition_steps
        );
        assert_eq!(
            first_receipt.delivered_events,
            second_receipt.delivered_events
        );
        assert_ne!(first_receipt.digest, second_receipt.digest);
    }

    #[test]
    fn digest_distinguishes_extreme_seeds() {
        let config = Config {
            peers: 1,
            events: 1,
            steps: 1,
            churn_percent: 0,
            partition_start: None,
            partition_end: None,
            ..Config::default()
        };
        let zero = run(Config {
            seed: 0,
            ..config.clone()
        })
        .unwrap();
        let maximum = run(Config {
            seed: u64::MAX,
            ..config
        })
        .unwrap();
        assert_ne!(zero.digest, maximum.digest);
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
    fn receipts_account_for_duplicates_and_orphans() {
        let duplicate_config = Config {
            peers: 2,
            events: 2,
            steps: 2,
            churn_percent: 0,
            partition_start: None,
            partition_end: None,
            ..Config::default()
        };
        let duplicate_receipt = run(duplicate_config).unwrap();
        assert!(duplicate_receipt.delivered_events > 0);
        assert!(duplicate_receipt.duplicate_suppressed > 0);

        let orphan_config = Config {
            peers: 4,
            events: 4,
            steps: 1,
            churn_percent: 0,
            partition_start: Some(0),
            partition_end: Some(1),
            ..Config::default()
        };
        let orphan_receipt = run(orphan_config).unwrap();
        assert_eq!(orphan_receipt.partition_steps, 1);
        assert!(orphan_receipt.orphan_references > 0);

        let churn_config = Config {
            peers: 2,
            events: 2,
            steps: 2,
            churn_percent: 100,
            partition_start: None,
            partition_end: None,
            ..Config::default()
        };
        let churn_receipt = run(churn_config).unwrap();
        assert_eq!(churn_receipt.churn_steps, 2);
    }

    #[test]
    fn bounds_are_fail_closed() {
        let config = Config {
            peers: MAX_PEERS + 1,
            ..Config::default()
        };
        assert_eq!(run(config), Err(SimError::Limit("peers")));

        let config = Config {
            peers: MAX_PEERS,
            events: MAX_EVENTS,
            steps: 1,
            ..Config::default()
        };
        assert_eq!(
            run(config),
            Err(SimError::Limit("transfer attempts per step"))
        );
    }
}
