//! Corpus helpers: the densest 64 KiB experiment and the `Replay`-kind game
//! manifest of a converted experiment.

use platonik_core::model as pk;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::WorkAllowance;

use crate::ids::RulesetId;
use crate::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};

use super::convert::Converted;

/// The densest 16-cell, 128-tick case that fits Platonik's 64 KiB input
/// bound: nine rules of eight satisfiable-then-failing conditions, then a
/// `Send` over two links, on a 32x32 grid with 8 beacons and 8 depots.
/// Restated from `prototypes/witness-restatement`.
#[must_use]
pub fn worst_case() -> pk::Experiment {
    let mut cells = Vec::new();
    let mut links = Vec::new();
    let mut link_id = 100;
    for index in 0..16u16 {
        let x = 10 + (index % 4) as u8;
        let y = 10 + (index / 4) as u8;
        let mut rules = Vec::new();
        for _ in 0..9 {
            let mut when = vec![
                pk::Condition::Heading {
                    direction: pk::Direction::East,
                };
                7
            ];
            when.push(pk::Condition::Carrying { value: true });
            rules.push(pk::Rule {
                when,
                action: pk::Action::Wait,
                remember: None,
            });
        }
        rules.push(pk::Rule {
            when: vec![],
            action: pk::Action::Send {
                port: 0,
                bit: pk::BitSource::Constant { value: true },
            },
            remember: Some(pk::MemoryWrite { slot: 0, value: 1 }),
        });
        cells.push(pk::Cell {
            id: index,
            position: pk::Point { x, y },
            heading: pk::Direction::East,
            mobile: false,
            memory: [0; 4],
            program: pk::Program { rules },
        });
    }
    for index in 0..16u16 {
        for target in [index + 1, index + 4] {
            if target < 16 && (index % 4 != 3 || target != index + 1) {
                links.push(pk::Link {
                    id: link_id,
                    from: pk::Endpoint::Cell { id: index, port: 0 },
                    to_cell: target,
                    to_port: (link_id % 4) as u8,
                    delay: 1,
                    enabled: true,
                });
                link_id += 1;
            }
        }
    }
    let beacons = (0..8u16)
        .map(|index| pk::Beacon {
            id: 200 + index,
            position: pk::Point {
                x: index as u8,
                y: 0,
            },
            accepts: index % 2 == 1,
            initial_charge: 10_000,
            drain_every: 1,
            drain_amount: 1,
            spark_charge: 1,
            required_deliveries: 0,
        })
        .collect();
    let depots = (0..8u16)
        .map(|index| pk::Depot {
            id: 300 + index,
            position: pk::Point {
                x: index as u8,
                y: 2,
            },
            capacity: 128,
        })
        .collect();
    let sources = (0..8u16)
        .map(|index| pk::Source {
            id: 400 + index,
            position: pk::Point {
                x: index as u8,
                y: 4,
            },
            sparks: (0..16)
                .map(|spark| pk::Spark {
                    id: u32::from(index) * 16 + spark,
                    bit: spark % 2 == 0,
                })
                .collect(),
        })
        .collect();
    pk::Experiment {
        version: pk::MODEL_VERSION,
        seed: 7,
        width: 32,
        height: 32,
        walls: (0..32u8).map(|x| pk::Point { x, y: 31 }).collect(),
        sources,
        depots,
        beacons,
        valves: vec![],
        cells,
        links,
        events: vec![],
        ticks: 128,
        fuel: pk::MAX_FUEL,
        activation_fuel: 1024,
        construction: None,
    }
}

/// The `Replay`-kind game manifest of a converted experiment: every slot
/// fixed, the world digest of the fixed template, one case, the experiment's
/// inner id, default limits, and `publisher` as given.
pub fn replay_manifest(converted: &Converted, publisher: [u8; 32]) -> GameManifest {
    let template = ValidManifest::validate(converted.template.clone()).expect("converted");
    GameManifest {
        ruleset: RulesetId::V1,
        world: template.hash(),
        slots: converted
            .programs
            .iter()
            .map(|(cell, _)| GameSlot {
                cell: *cell,
                role: SlotRole::Fixed,
            })
            .collect(),
        contract: converted.task.contract,
        loading_work: vec![converted.loading_work],
        artifacts: vec![converted.experiment],
        limits: SessionLimits {
            max_events: 64,
            max_segments: 8,
            replay: WorkAllowance {
                max_total: template.fuel_total(),
            },
            verification: VerificationAllowance {
                max_replays: 8,
                max_work: template.fuel_total() * 8,
                max_event_bytes: 64 * 24_576,
                max_artifact_bytes: MAX_ARTIFACT_BYTES,
            },
            missing_member: MissingMember::Pause,
            kind: SessionKind::Replay,
        },
        publisher,
    }
}
