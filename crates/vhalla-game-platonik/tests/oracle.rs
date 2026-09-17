//! Parity of the restated converter with the witness corpus, and the six
//! `Replay`-kind game manifest vectors.

use std::fs;
use std::path::Path;

use vhalla_game_platonik::ids::InnerKind;
use vhalla_game_platonik::manifest::SessionKind;
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::oracle::corpus::{replay_manifest, worst_case};
use vhalla_game_platonik::wire::{decode_game_manifest, encode_game_manifest};
use vhalla_witness::codec;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::vectors::{hex, parse, unhex};

const PUBLISHER: [u8; 32] = [11; 32];

fn witness_vectors() -> Vec<(String, vhalla_witness::vectors::Vector)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vhalla-witness/tests/vectors");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| {
            let vector = parse(&fs::read_to_string(&path).unwrap()).unwrap();
            (vector.id.clone(), vector)
        })
        .collect()
}

fn experiment_for(id: &str) -> platonik_core::model::Experiment {
    if let Some(name) = id.strip_prefix("fixture-") {
        return platonik_core::fixtures::experiment(name).unwrap();
    }
    if let Some(case_id) = id.strip_prefix("bridge-v1-") {
        let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
        return report
            .cases
            .iter()
            .find(|case| case.id == case_id)
            .unwrap()
            .receipt
            .experiment
            .clone();
    }
    assert_eq!(id, "worst-case");
    worst_case()
}

#[test]
fn the_converter_reproduces_every_witness_vector_byte_for_byte() {
    let vectors = witness_vectors();
    assert_eq!(vectors.len(), 28);
    for (id, vector) in vectors {
        let converted = convert(&experiment_for(&id)).unwrap();
        // The witness corpus fixes the contract from the run; the converter
        // declares the open contract, so compare everything but the contract.
        let mut expected = codec::decode_manifest(&vector.manifest).unwrap();
        let actual = converted.task.clone();
        assert_eq!(actual.world, expected.world, "{id}: world");
        assert_eq!(actual.slots, expected.slots, "{id}: slots");
        assert_eq!(
            actual.cases, expected.cases,
            "{id}: cases incl. loading_work"
        );
        expected.contract = actual.contract;
        assert_eq!(
            codec::encode_manifest(&actual),
            codec::encode_manifest(&expected),
            "{id}"
        );
        assert_eq!(
            codec::encode_candidate(&converted.programs),
            vector.assignment,
            "{id}: programs"
        );
        let valid = ValidManifest::validate(converted.template.clone()).unwrap();
        assert!(
            valid.open_slots().next().is_none(),
            "{id}: the replay template fixes every slot"
        );
        assert_eq!(converted.experiment.kind, InnerKind::PlatonikExperimentV1);
    }
}

#[test]
fn six_replay_manifest_vectors_are_committed_and_reproduce() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut seen = 0;
    for name in platonik_core::fixtures::names() {
        let experiment = platonik_core::fixtures::experiment(name).unwrap();
        let converted = convert(&experiment).unwrap();
        let manifest = replay_manifest(&converted, PUBLISHER);
        manifest.validate().unwrap();
        assert_eq!(manifest.limits.kind, SessionKind::Replay);
        let expected_id = platonik_core::check::artifact_hash(&experiment).unwrap();
        assert_eq!(
            converted.experiment.render(),
            expected_id,
            "{name}: experiment id equals Platonik's"
        );
        let raw = encode_game_manifest(&manifest);
        assert_eq!(decode_game_manifest(&raw).unwrap(), manifest);
        let path = dir.join(format!("game-v1-{name}.txt"));
        let text = fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "{}: run `cargo run --example game_vectors --features oracle`",
                path.display()
            )
        });
        let field = |key: &str| -> String {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{key}: ")))
                .unwrap_or_else(|| panic!("{name}: {key}"))
                .to_string()
        };
        assert_eq!(field("id"), name);
        assert_eq!(
            unhex(&field("manifest")).unwrap(),
            raw,
            "{name}: manifest bytes"
        );
        assert_eq!(field("manifest_hash"), hex(&manifest.hash().0), "{name}");
        assert_eq!(field("world_digest"), hex(&manifest.world.0), "{name}");
        assert_eq!(field("experiment"), converted.experiment.render(), "{name}");
        assert_eq!(
            field("loading_work"),
            converted.loading_work.to_string(),
            "{name}"
        );
        seen += 1;
    }
    assert_eq!(seen, 6);
}
