//! Codec laws, byte bounds, and the manifest to receipt chain over the parity
//! corpus: every fixture, every bridge-v1 suite case, and random experiments.

mod common;

use common::{convert, random_experiment, worst_case, Converted, Rng};
use witness_restatement::codec::{
    self, CodecError, Field, MAX_ASSIGNMENT_BYTES, MAX_MANIFEST_BYTES, MAX_PROGRAM_BYTES,
    MAX_STATE_BYTES,
};
use witness_restatement::hash::{ManifestHash, ProgramHash};
use witness_restatement::manifest::{
    ManifestError, ProgramSlot, TaskManifest, ValidManifest, WorkContract,
};
use witness_restatement::model::Program;
use witness_restatement::platform::{
    self, ClaimedReceipt, ReceiptBinding, RunCapability, RunRefused, RunRole, WorkAllowance,
    RECEIPT_BYTES,
};

const _: () = assert!(MAX_MANIFEST_BYTES <= 32_768);

fn corpus() -> Vec<(String, platonik_core::model::Experiment)> {
    let mut out = Vec::new();
    for name in platonik_core::fixtures::names() {
        out.push((
            name.to_string(),
            platonik_core::fixtures::experiment(name).unwrap(),
        ));
    }
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    for case in &report.cases {
        out.push((case.id.clone(), case.receipt.experiment.clone()));
    }
    let mut rng = Rng::new(0xc0dec);
    for index in 0..120 {
        out.push((format!("random-{index}"), random_experiment(&mut rng)));
    }
    out.push(("worst-case".into(), worst_case()));
    out
}

fn pairs(converted: &Converted) -> Vec<(u16, Program)> {
    converted
        .assignment
        .cells()
        .iter()
        .copied()
        .zip(converted.assignment.programs().iter().cloned())
        .collect()
}

/// Every cell open, one case, the contract set from the actual run.
fn manifest_for(converted: &Converted, fixed_first: bool) -> TaskManifest {
    let programs = pairs(converted);
    TaskManifest {
        world: converted.world.spec().clone(),
        slots: programs
            .iter()
            .enumerate()
            .map(|(index, (cell, program))| ProgramSlot {
                cell: *cell,
                fixed: (fixed_first && index == 0).then(|| program.clone()),
            })
            .collect(),
        cases: vec![converted.case.spec().clone()],
        contract: WorkContract {
            useful_floor: 0,
            total_ceiling: converted.case.fuel(),
            require_passed: false,
        },
    }
}

#[test]
fn codec_laws_and_bounds_hold_over_the_corpus() {
    let mut max_program = 0;
    let mut max_assignment = 0;
    let mut max_manifest = 0;
    let mut max_state = 0;
    for (label, experiment) in corpus() {
        let converted = convert(&experiment);
        for program in converted.assignment.programs() {
            let raw = codec::encode_program(program);
            max_program = max_program.max(raw.len());
            assert!(raw.len() <= MAX_PROGRAM_BYTES, "{label}");
            let back = codec::decode_program(&raw).unwrap();
            assert_eq!(&back, program, "{label}: decode(encode(program))");
            assert_eq!(
                codec::encode_program(&back),
                raw,
                "{label}: encode(decode(raw))"
            );
        }
        let candidate = pairs(&converted);
        let raw = codec::encode_assignment(&converted.assignment);
        max_assignment = max_assignment.max(raw.len());
        assert!(raw.len() <= MAX_ASSIGNMENT_BYTES, "{label}");
        assert_eq!(
            codec::encode_candidate(&candidate),
            raw,
            "{label}: candidate bytes"
        );
        let back = codec::decode_candidate(&raw).unwrap();
        assert_eq!(back, candidate, "{label}: decode(encode(candidate))");
        assert_eq!(
            codec::encode_candidate(&back),
            raw,
            "{label}: encode(decode(raw))"
        );

        let manifest = manifest_for(&converted, false);
        let raw = codec::encode_manifest(&manifest);
        max_manifest = max_manifest.max(raw.len());
        assert!(
            raw.len() <= MAX_MANIFEST_BYTES,
            "{label}: {} bytes",
            raw.len()
        );
        let back = codec::decode_manifest(&raw).unwrap();
        assert_eq!(back, manifest, "{label}: decode(encode(manifest))");
        assert_eq!(
            codec::encode_manifest(&back),
            raw,
            "{label}: encode(decode(raw))"
        );

        let valid = ValidManifest::validate(manifest).unwrap();
        let assignment = valid.assign(candidate).unwrap();
        let result =
            witness_restatement::vm::run(valid.world(), &assignment, &valid.cases()[0], &mut ())
                .unwrap();
        let state = codec::encode_state(&result.final_state);
        max_state = max_state.max(state.len());
        assert!(
            state.len() <= MAX_STATE_BYTES,
            "{label}: state {} bytes",
            state.len()
        );
    }
    println!(
        "largest corpus encodings: program {max_program}/{MAX_PROGRAM_BYTES}, assignment \
         {max_assignment}/{MAX_ASSIGNMENT_BYTES}, manifest {max_manifest}/{MAX_MANIFEST_BYTES}, \
         state {max_state}/{MAX_STATE_BYTES}"
    );
}

#[test]
fn decoders_reject_malformed_bytes_without_panicking() {
    let converted = convert(&platonik_core::fixtures::experiment("opening-normal").unwrap());
    let raw = codec::encode_assignment(&converted.assignment);
    assert!(matches!(
        codec::decode_candidate(&raw[..raw.len() - 1]),
        Err(CodecError::Truncated { .. })
    ));
    let mut extra = raw.clone();
    extra.push(0);
    assert_eq!(
        codec::decode_candidate(&extra),
        Err(CodecError::TrailingBytes { count: 1 })
    );
    let mut version = raw.clone();
    version[0] = 2;
    assert_eq!(
        codec::decode_candidate(&version),
        Err(CodecError::UnsupportedVersion { found: 2 })
    );
    let mut language = raw.clone();
    language[1] = 2;
    assert_eq!(
        codec::decode_candidate(&language),
        Err(CodecError::UnsupportedLanguage { found: 2 })
    );
    let oversized = vec![0_u8; MAX_ASSIGNMENT_BYTES + 1];
    assert!(matches!(
        codec::decode_candidate(&oversized),
        Err(CodecError::TooLarge { .. })
    ));
    let mut rng = Rng::new(7);
    let mut seen_errors = 0_usize;
    for _ in 0..20_000 {
        let len = rng.below(64) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
        if codec::decode_program(&bytes).is_err() {
            seen_errors += 1;
        }
        let _ = codec::decode_candidate(&bytes);
        let _ = codec::decode_manifest(&bytes);
        let _ = codec::decode_output(&bytes);
        let _ = ClaimedReceipt::decode(&bytes);
    }
    assert!(seen_errors > 19_000);
    let mut flipped = raw.clone();
    flipped[2] = 200;
    assert_eq!(
        codec::decode_candidate(&flipped),
        Err(CodecError::Bound {
            field: Field::Count
        })
    );
}

#[test]
fn manifest_to_receipt_chain_is_deterministic_and_bound_to_its_inputs() {
    for name in platonik_core::fixtures::names() {
        let converted = convert(&platonik_core::fixtures::experiment(name).unwrap());
        for fixed_first in [false, true] {
            let manifest = manifest_for(&converted, fixed_first);
            let valid = ValidManifest::validate(manifest.clone()).unwrap();
            let all = pairs(&converted);
            let candidate: Vec<(u16, Program)> = all
                .iter()
                .filter(|(cell, _)| valid.open_slots().any(|open| open == *cell))
                .cloned()
                .collect();
            assert_eq!(candidate.len(), all.len() - usize::from(fixed_first));
            assert_eq!(
                valid.assign(all.clone()).err(),
                if fixed_first {
                    Some(ManifestError::Candidate)
                } else {
                    None
                }
                .filter(|_| fixed_first),
                "{name}: supplying a fixed slot is refused"
            );
            let assignment = valid.assign(candidate.clone()).unwrap();
            let program = ProgramHash::of(&codec::encode_assignment(&assignment));
            let allowance = WorkAllowance {
                max_total: valid.fuel_total(),
            };
            let cap = RunCapability::mint(valid.hash(), program, allowance, RunRole::Prove);
            let first = platform::run(&valid, &assignment, cap).unwrap();
            let cap = RunCapability::mint(valid.hash(), program, allowance, RunRole::Replay);
            let second = platform::run(&valid, &assignment, cap).unwrap();
            assert_eq!(first.cases(), second.cases(), "{name}: replay equals prove");
            assert_eq!(first.output_hash(), second.output_hash());
            assert_eq!(first.total(), first.cases()[0].ledger.total().unwrap());
            assert_eq!(
                first.useful(),
                u64::from(
                    witness_restatement::vm::run(
                        valid.world(),
                        &assignment,
                        &valid.cases()[0],
                        &mut ()
                    )
                    .unwrap()
                    .final_state
                    .beacons
                    .iter()
                    .map(|beacon| beacon.delivered)
                    .sum::<u32>()
                ),
                "{name}: useful is delivered sparks"
            );
            let output = first.output();
            assert_eq!(codec::decode_output(&output).unwrap(), first.cases());

            let binding = ReceiptBinding {
                challenge_id: [9; 32],
                subject_key: [4; 32],
            };
            let receipt = first.into_receipt(binding);
            let raw = receipt.encode();
            assert_eq!(raw.len(), RECEIPT_BYTES);
            let claimed = ClaimedReceipt::decode(&raw).unwrap();
            assert!(claimed.matches(&receipt));
            assert_eq!(claimed.encode(), raw);
            assert_eq!(receipt.hash(), second.into_receipt(binding).hash());
            let mut tampered = claimed;
            tampered.total += 1;
            assert!(!tampered.matches(&receipt), "{name}: ledger tamper visible");
            let mut tampered = claimed;
            tampered.challenge_id[0] ^= 1;
            assert!(!tampered.matches(&receipt), "{name}: rebinding visible");

            let wrong =
                RunCapability::mint(ManifestHash([0; 32]), program, allowance, RunRole::Prove);
            assert_eq!(
                platform::run(&valid, &assignment, wrong).err(),
                Some(RunRefused::Manifest)
            );
            let wrong = RunCapability::mint(
                valid.hash(),
                ProgramHash([0; 32]),
                allowance,
                RunRole::Prove,
            );
            assert_eq!(
                platform::run(&valid, &assignment, wrong).err(),
                Some(RunRefused::Program)
            );
            let short = RunCapability::mint(
                valid.hash(),
                program,
                WorkAllowance {
                    max_total: valid.fuel_total() - 1,
                },
                RunRole::Prove,
            );
            assert_eq!(
                platform::run(&valid, &assignment, short).err(),
                Some(RunRefused::Allowance)
            );
        }
    }
}

#[test]
fn manifest_validation_refuses_bad_slots_cases_and_contracts() {
    let converted = convert(&platonik_core::fixtures::experiment("opening-normal").unwrap());
    let good = manifest_for(&converted, false);
    assert!(ValidManifest::validate(good.clone()).is_ok());
    let mut bad = good.clone();
    bad.slots.pop();
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Slots)
    );
    let multi = manifest_for(
        &convert(&platonik_core::fixtures::experiment("ark-plan-a").unwrap()),
        false,
    );
    assert!(multi.slots.len() > 1);
    let mut bad = multi;
    bad.slots.reverse();
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Slots)
    );
    let mut bad = good.clone();
    bad.cases.clear();
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Cases)
    );
    let mut bad = good.clone();
    bad.cases = vec![good.cases[0].clone(); 9];
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Cases)
    );
    let mut bad = good.clone();
    bad.contract.total_ceiling = good.cases[0].fuel + 1;
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Contract)
    );
    let mut bad = good.clone();
    bad.contract.useful_floor = 128 * 8 + 1;
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Contract)
    );
    let mut bad = good.clone();
    bad.cases[0].loading_work = 0;
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::LoadingWork)
    );
    let mut bad = good.clone();
    bad.cases[0].loading_work = codec::encode_manifest(&good).len() as u64;
    assert!(ValidManifest::validate(bad).is_ok());
    let mut bad = good;
    bad.world.width = 2;
    assert!(matches!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::World(_))
    ));
}
