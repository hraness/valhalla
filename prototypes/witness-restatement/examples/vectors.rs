//! Writes one vector file per corpus case into `vectors/`. Run from the crate
//! directory: `cargo run --example vectors --features std --locked`.

use std::fs;
use std::path::Path;

use witness_restatement::codec;
use witness_restatement::corpus::{convert, worst_case};
use witness_restatement::hash::ProgramHash;
use witness_restatement::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use witness_restatement::platform::{self, RunCapability, RunRole, WorkAllowance};
use witness_restatement::vectors::{render, Vector};

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors");
    fs::create_dir_all(&dir).unwrap();
    let mut cases: Vec<(String, platonik_core::model::Experiment)> = Vec::new();
    for name in platonik_core::fixtures::names() {
        cases.push((
            format!("fixture-{name}"),
            platonik_core::fixtures::experiment(name).unwrap(),
        ));
    }
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    for case in &report.cases {
        cases.push((
            format!("bridge-v1-{}", case.id),
            case.receipt.experiment.clone(),
        ));
    }
    cases.push(("worst-case".into(), worst_case()));
    for (id, experiment) in cases {
        let converted = convert(&experiment);
        let programs: Vec<(u16, _)> = converted
            .assignment
            .cells()
            .iter()
            .copied()
            .zip(converted.assignment.programs().iter().cloned())
            .collect();
        // First pass: run under an open contract to learn the quantities.
        let draft = TaskManifest {
            world: converted.world.spec().clone(),
            slots: programs
                .iter()
                .map(|(cell, _)| ProgramSlot {
                    cell: *cell,
                    fixed: None,
                })
                .collect(),
            cases: vec![converted.case.spec().clone()],
            contract: WorkContract {
                useful_floor: 0,
                total_ceiling: converted.case.fuel(),
                require_passed: false,
            },
        };
        let valid = ValidManifest::validate(draft.clone()).unwrap();
        let assignment = valid.assign(programs.clone()).unwrap();
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        let run = platform::run(
            &valid,
            &assignment,
            RunCapability::mint(
                valid.hash(),
                program,
                WorkAllowance {
                    max_total: valid.fuel_total(),
                },
                RunRole::Prove,
            ),
        )
        .unwrap();
        // Final manifest: the contract this run exactly satisfies.
        let manifest = TaskManifest {
            contract: WorkContract {
                useful_floor: run.useful(),
                total_ceiling: run.total(),
                require_passed: run.passed(),
            },
            ..draft
        };
        let valid = ValidManifest::validate(manifest.clone()).unwrap();
        let assignment = valid.assign(programs.clone()).unwrap();
        let run = platform::run(
            &valid,
            &assignment,
            RunCapability::mint(
                valid.hash(),
                program,
                WorkAllowance {
                    max_total: valid.fuel_total(),
                },
                RunRole::Prove,
            ),
        )
        .unwrap();
        let vector = Vector {
            id: id.clone(),
            manifest: codec::encode_manifest(&manifest),
            assignment: codec::encode_candidate(&programs),
            manifest_hash: valid.hash().0,
            program_hash: program.0,
            output_hash: run.output_hash().0,
            state_hashes: run.cases().iter().map(|case| case.final_state.0).collect(),
            useful: run.useful(),
            total: run.total(),
            passed: run.passed(),
        };
        fs::write(dir.join(format!("{id}.txt")), render(&vector)).unwrap();
        println!(
            "{id}: useful {} total {} passed {}",
            vector.useful, vector.total, vector.passed
        );
    }
}
