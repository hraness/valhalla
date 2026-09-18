//! The engine seam over the witness corpus: at the full through tick every
//! case's derived status equals the engine's own `RunStatus`, the state hash
//! equals the final state, the ledger total equals the case total, the
//! receipt matches the vector, and replays are deterministic.

use std::fs;
use std::path::Path;

use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_witness::codec;
use vhalla_witness::hash::ProgramHash;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vectors::parse;

#[test]
fn replay_at_the_full_tick_reproduces_every_witness_vector() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vhalla-witness/tests/vectors");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 28);
    let engine = PlatonikV1;
    for path in files {
        let vector = parse(&fs::read_to_string(&path).unwrap()).unwrap();
        let manifest =
            ValidManifest::validate(codec::decode_manifest(&vector.manifest).unwrap()).unwrap();
        let candidate = codec::decode_candidate(&vector.assignment).unwrap();
        let through = manifest
            .cases()
            .iter()
            .map(|case| case.ticks())
            .max()
            .unwrap();
        let binding = ReceiptBinding {
            challenge_id: [1; 32],
            subject_key: [2; 32],
        };
        let allowance = WorkAllowance {
            max_total: manifest.fuel_total(),
        };
        let first = engine
            .replay(
                manifest.hash(),
                &manifest,
                candidate.clone(),
                allowance,
                through,
                binding,
            )
            .unwrap();
        let second = engine
            .replay(
                manifest.hash(),
                &manifest,
                candidate.clone(),
                allowance,
                through,
                binding,
            )
            .unwrap();
        assert_eq!(first.cases, second.cases, "{}: deterministic", vector.id);
        assert_eq!(first.program.0, vector.program_hash, "{}", vector.id);
        assert_eq!(
            first.receipt.output().0,
            vector.output_hash,
            "{}",
            vector.id
        );
        assert_eq!(first.receipt.useful(), vector.useful, "{}", vector.id);
        assert_eq!(first.receipt.total(), vector.total, "{}", vector.id);
        assert_eq!(first.passed, vector.passed, "{}", vector.id);
        assert_eq!(
            first.work.total, vector.total,
            "{}: totals at the full tick",
            vector.id
        );
        // Reproduce the whole-case values through the plain run for comparison.
        let assignment = manifest.assign(candidate.clone()).unwrap();
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        assert_eq!(first.program, program);
        let plain = vhalla_witness::platform::run(
            &manifest,
            &assignment,
            #[allow(clippy::disallowed_methods)]
            vhalla_witness::platform::RunCapability::mint(
                manifest.hash(),
                program,
                allowance,
                vhalla_witness::platform::RunRole::Replay,
            ),
        )
        .unwrap();
        for (index, case) in first.cases.iter().enumerate() {
            let result = &plain.cases()[index];
            assert_eq!(
                case.status, result.status,
                "{} case {index}: status at the full tick equals RunStatus",
                vector.id
            );
            assert_eq!(
                case.state, result.final_state,
                "{} case {index}: state at the full tick",
                vector.id
            );
            assert_eq!(
                case.ledger_total,
                result.ledger.total().unwrap(),
                "{} case {index}: ledger total",
                vector.id
            );
            assert_eq!(
                case.state.0, vector.state_hashes[index],
                "{} case {index}",
                vector.id
            );
        }
        // An earlier through tick reads an earlier prefix: trace heads differ
        // for any case that ran past it, and totals never exceed the full run.
        if through > 1 {
            let early = engine
                .replay(
                    manifest.hash(),
                    &manifest,
                    candidate,
                    allowance,
                    through / 2,
                    binding,
                )
                .unwrap();
            for (index, case) in early.cases.iter().enumerate() {
                assert!(
                    case.ledger_total <= first.cases[index].ledger_total,
                    "{}",
                    vector.id
                );
                if plain.cases()[index].ticks_completed > through / 2 {
                    assert_ne!(
                        case.trace, first.cases[index].trace,
                        "{} case {index}: prefix",
                        vector.id
                    );
                }
            }
        }
    }
}
