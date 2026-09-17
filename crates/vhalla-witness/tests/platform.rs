//! The manifest to receipt chain, refusals, tampering, and manifest
//! validation over the committed corpus.

mod common;

use vhalla_witness::codec;
use vhalla_witness::hash::{ManifestHash, ProgramHash};
use vhalla_witness::manifest::{ManifestError, ValidManifest};
use vhalla_witness::platform::{
    self, ClaimedReceipt, ReceiptBinding, RunCapability, RunRefused, RunRole, WorkAllowance,
    RECEIPT_BYTES,
};

#[test]
fn chain_is_deterministic_and_bound_to_its_inputs() {
    for (path, vector) in common::vectors() {
        let label = path.display();
        let valid =
            ValidManifest::validate(codec::decode_manifest(&vector.manifest).unwrap()).unwrap();
        assert_eq!(valid.hash().0, vector.manifest_hash, "{label}");
        let candidate = codec::decode_candidate(&vector.assignment).unwrap();
        let assignment = valid.assign(candidate.clone()).unwrap();
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        assert_eq!(program.0, vector.program_hash, "{label}");
        let allowance = WorkAllowance {
            max_total: valid.fuel_total(),
        };
        let prove = platform::run(
            &valid,
            &assignment,
            RunCapability::mint(valid.hash(), program, allowance, RunRole::Prove),
        )
        .unwrap();
        let replay = platform::run(
            &valid,
            &assignment,
            RunCapability::mint(valid.hash(), program, allowance, RunRole::Replay),
        )
        .unwrap();
        assert_eq!(prove.cases(), replay.cases(), "{label}");
        assert_eq!(prove.output_hash().0, vector.output_hash, "{label}");
        assert_eq!(prove.useful(), vector.useful, "{label}");
        assert_eq!(prove.total(), vector.total, "{label}");
        assert_eq!(prove.passed(), vector.passed, "{label}");
        assert_eq!(
            codec::decode_output(&prove.output()).unwrap(),
            prove.cases(),
            "{label}"
        );
        let contract = valid.contract();
        assert!(prove.useful() >= contract.useful_floor && prove.total() <= contract.total_ceiling);

        let binding = ReceiptBinding {
            challenge_id: [9; 32],
            subject_key: [4; 32],
        };
        let receipt = prove.into_receipt(binding);
        assert_eq!(receipt.binding(), binding);
        let raw = receipt.encode();
        assert_eq!(raw.len(), RECEIPT_BYTES);
        let claimed = ClaimedReceipt::decode(&raw).unwrap();
        assert!(claimed.matches(&receipt), "{label}");
        assert_eq!(
            receipt.hash(),
            replay.into_receipt(binding).hash(),
            "{label}"
        );
        for tamper in 0..raw.len() {
            let mut bytes = raw.clone();
            bytes[tamper] ^= 1;
            match ClaimedReceipt::decode(&bytes) {
                Ok(tampered) => assert!(!tampered.matches(&receipt), "{label}: byte {tamper}"),
                Err(_) => assert!(
                    tamper < 2 || tamper == raw.len() - 2,
                    "{label}: byte {tamper}"
                ),
            }
        }

        let wrong = RunCapability::mint(ManifestHash([0; 32]), program, allowance, RunRole::Prove);
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

#[test]
fn fixed_slots_are_not_supplied_by_the_candidate() {
    let vector = common::vector("fixture-ark-plan-a");
    let mut manifest = codec::decode_manifest(&vector.manifest).unwrap();
    let candidate = codec::decode_candidate(&vector.assignment).unwrap();
    assert!(candidate.len() > 1);
    manifest.slots[0].fixed = Some(candidate[0].1.clone());
    let valid = ValidManifest::validate(manifest).unwrap();
    assert_eq!(
        valid.assign(candidate.clone()).err(),
        Some(ManifestError::Candidate)
    );
    let open: Vec<_> = candidate[1..].to_vec();
    let assignment = valid.assign(open).unwrap();
    assert_eq!(
        ProgramHash::of(&codec::encode_assignment(&assignment)).0,
        vector.program_hash,
        "the merged assignment is the original one"
    );
    assert_ne!(
        valid.hash().0,
        vector.manifest_hash,
        "a fixed slot changes the manifest"
    );
}

#[test]
fn manifest_validation_refuses_bad_slots_cases_contracts_and_loading_work() {
    let good = codec::decode_manifest(&common::vector("fixture-ark-plan-a").manifest).unwrap();
    assert!(ValidManifest::validate(good.clone()).is_ok());
    let mut bad = good.clone();
    bad.slots.pop();
    assert_eq!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::Slots)
    );
    let mut bad = good.clone();
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
    let mut ok = good.clone();
    ok.cases[0].loading_work = codec::encode_manifest(&good).len() as u64;
    assert!(ValidManifest::validate(ok).is_ok());
    let mut bad = good;
    bad.world.width = 2;
    assert!(matches!(
        ValidManifest::validate(bad).err(),
        Some(ManifestError::World(_))
    ));
}

struct Counting {
    frames: u32,
    tick_zero: u32,
    last_tick: u32,
}

impl vhalla_witness::vm::Observer for Counting {
    fn frame(&mut self, frame: &vhalla_witness::vm::FrameView<'_>) {
        self.frames += 1;
        if frame.tick == 0 {
            self.tick_zero += 1;
        }
        self.last_tick = frame.tick;
    }
}

#[test]
fn run_observed_sees_every_frame_and_changes_nothing() {
    for (path, vector) in common::vectors() {
        let label = path.display();
        let valid =
            ValidManifest::validate(codec::decode_manifest(&vector.manifest).unwrap()).unwrap();
        let assignment = valid
            .assign(codec::decode_candidate(&vector.assignment).unwrap())
            .unwrap();
        let program = ProgramHash::of(&codec::encode_assignment(&assignment));
        let allowance = WorkAllowance {
            max_total: valid.fuel_total(),
        };
        let mut counting = Counting {
            frames: 0,
            tick_zero: 0,
            last_tick: 0,
        };
        let observed = platform::run_observed(
            &valid,
            &assignment,
            RunCapability::mint(valid.hash(), program, allowance, RunRole::Replay),
            &mut counting,
        )
        .unwrap();
        let plain = platform::run(
            &valid,
            &assignment,
            RunCapability::mint(valid.hash(), program, allowance, RunRole::Replay),
        )
        .unwrap();
        assert_eq!(observed.cases(), plain.cases(), "{label}");
        assert_eq!(observed.output_hash(), plain.output_hash(), "{label}");
        assert_eq!(
            counting.tick_zero,
            valid.cases().len() as u32,
            "{label}: one loading frame per case"
        );
        let expected: u32 = observed
            .cases()
            .iter()
            .map(|case| case.ticks_completed + 1)
            .sum();
        assert_eq!(
            counting.frames, expected,
            "{label}: one frame per completed tick plus loading"
        );
        assert_eq!(
            counting.last_tick,
            observed.cases().last().unwrap().ticks_completed,
            "{label}"
        );
    }
}
