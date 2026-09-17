//! Spike 6: can a receiver without `oracle` audit an inner artifact?
//!
//! For the six habitat fixtures and the 21 `bridge-v1` suite cases, each
//! artifact is serialized with compact `serde_json::to_vec` and its plain
//! SHA-256 is compared to the id of its own kind: the `Experiment` to a
//! `PlatonikExperimentV1` id (equal to the receipt's `experiment_hash`), the
//! `RunResult` to a `PlatonikResultV1` id (equal to the receipt's
//! `result_hash`), and the whole `Receipt` to a `PlatonikReceiptV1` id the
//! publisher computes as `artifact_hash(&receipt)`. No cross-kind comparison
//! is attempted: the kind decides the parse, and bytes of the wrong object
//! fail before any hash is taken. Pretty-printed bytes and a trailing newline
//! are refused as publisher errors.
//!
//! The audit itself lives behind `oracle` and is publisher-side and test-side
//! only. What this spike sizes for the default path is the one operation that
//! path performs: a plain SHA-256 over the 8 MiB artifact ceiling, timed here
//! natively against the 200 ms criterion.

use std::time::Instant;

use platonik_core::check::{self, Receipt};
use vhalla_game_platonik::ids::InnerKind;
use vhalla_game_platonik::oracle::audit::{
    audit, audit_bytes, canonical_bytes, experiment_id, plain_sha256, receipt_id, result_id,
    AuditError,
};

/// Every audited source: the six habitat fixtures and the 21 `bridge-v1`
/// suite cases, each carrying the receipt whose three artifacts are audited.
fn sources() -> Vec<(String, Receipt)> {
    let mut out: Vec<(String, Receipt)> = platonik_core::fixtures::names()
        .into_iter()
        .map(|name| {
            let experiment = platonik_core::fixtures::experiment(name).unwrap();
            (
                format!("fixture-{name}"),
                check::make_receipt(&experiment).unwrap(),
            )
        })
        .collect();
    let report = platonik_core::suite::run_suite("bridge-v1").unwrap();
    for case in report.cases {
        out.push((format!("bridge-v1-{}", case.id), case.receipt));
    }
    out
}

#[test]
fn every_artifact_hashes_to_the_id_of_its_own_kind() {
    let sources = sources();
    assert_eq!(sources.len(), 27, "six fixtures and 21 bridge-v1 cases");
    let mut fixtures = 0_usize;
    let mut suite_cases = 0_usize;
    let mut audited = 0_usize;
    let mut cross_kind_refusals = 0_usize;
    let mut pretty_refusals = 0_usize;
    let mut bytes_total = 0_usize;
    let mut largest = 0_usize;
    let mut verified = 0_usize;
    for (id, receipt) in &sources {
        if id.starts_with("fixture-") {
            fixtures += 1;
        } else {
            suite_cases += 1;
        }

        // The experiment: compact bytes, audited as kind 1, equal to the
        // receipt's own `experiment_hash` field.
        let experiment_bytes = canonical_bytes(&receipt.experiment).unwrap();
        let experiment = audit_bytes(InnerKind::PlatonikExperimentV1, &experiment_bytes).unwrap();
        assert_eq!(experiment.kind, InnerKind::PlatonikExperimentV1, "{id}");
        assert_eq!(experiment.render(), receipt.experiment_hash, "{id}");
        assert_eq!(
            experiment,
            experiment_id(&receipt.experiment).unwrap(),
            "{id}"
        );
        assert_eq!(experiment.sha256, plain_sha256(&experiment_bytes), "{id}");

        // The run result: compact bytes, audited as kind 2, equal to the
        // receipt's own `result_hash` field.
        let result_bytes = canonical_bytes(&receipt.result).unwrap();
        let result = audit_bytes(InnerKind::PlatonikResultV1, &result_bytes).unwrap();
        assert_eq!(result.kind, InnerKind::PlatonikResultV1, "{id}");
        assert_eq!(result.render(), receipt.result_hash, "{id}");
        assert_eq!(result, result_id(&receipt.result).unwrap(), "{id}");

        // The whole receipt: a third value, the one a moved receipt needs.
        let receipt_bytes = canonical_bytes(receipt).unwrap();
        let audited_receipt = audit(InnerKind::PlatonikReceiptV1, &receipt_bytes).unwrap();
        assert_eq!(
            audited_receipt.id.kind,
            InnerKind::PlatonikReceiptV1,
            "{id}"
        );
        assert_eq!(
            audited_receipt.id.render(),
            check::artifact_hash(receipt).unwrap(),
            "{id}"
        );
        assert_eq!(audited_receipt.id, receipt_id(receipt).unwrap(), "{id}");
        assert_ne!(audited_receipt.id.sha256, experiment.sha256, "{id}");
        assert_ne!(audited_receipt.id.sha256, result.sha256, "{id}");
        let report = audited_receipt.report.expect("a receipt carries a verdict");
        assert!(report.verified, "{id}");
        assert_eq!(report.passed, receipt.passed(), "{id}");
        assert_eq!(report.experiment_hash, experiment.render(), "{id}");
        assert_eq!(report.result_hash, result.render(), "{id}");
        verified += 1;

        audited += 3;
        bytes_total += experiment_bytes.len() + result_bytes.len() + receipt_bytes.len();
        largest = largest.max(receipt_bytes.len());
        assert!(
            receipt_bytes.len() <= 8 * 1024 * 1024,
            "{id}: {} bytes exceeds the 8 MiB artifact ceiling",
            receipt_bytes.len()
        );

        // No cross-kind comparison is attempted: the kind decides the parse.
        for (kind, bytes) in [
            (InnerKind::PlatonikResultV1, &experiment_bytes),
            (InnerKind::PlatonikReceiptV1, &experiment_bytes),
            (InnerKind::PlatonikExperimentV1, &result_bytes),
            (InnerKind::PlatonikReceiptV1, &result_bytes),
            (InnerKind::PlatonikExperimentV1, &receipt_bytes),
            (InnerKind::PlatonikResultV1, &receipt_bytes),
        ] {
            let error = audit_bytes(kind, bytes).unwrap_err();
            assert!(
                matches!(error, AuditError::Parse(_)),
                "{id}: {kind:?} accepted the bytes of another kind: {error:?}"
            );
            cross_kind_refusals += 1;
        }

        // Pretty printing and a trailing newline are publisher errors.
        for bytes in [serde_json::to_vec_pretty(&receipt.experiment).unwrap(), {
            let mut with_newline = experiment_bytes.clone();
            with_newline.push(b'\n');
            with_newline
        }] {
            assert_eq!(
                audit_bytes(InnerKind::PlatonikExperimentV1, &bytes),
                Err(AuditError::NotCompact),
                "{id}"
            );
            pretty_refusals += 1;
        }
    }

    // The two kinds with no JSON object here are refused, never guessed at.
    for kind in [InnerKind::PlatonikCheckpointV1, InnerKind::FrameTraceV1] {
        assert_eq!(
            audit_bytes(kind, b"{}"),
            Err(AuditError::UnsupportedKind(kind))
        );
    }

    assert_eq!(fixtures, 6);
    assert_eq!(suite_cases, 21);
    assert_eq!(audited, 81);
    assert_eq!(cross_kind_refusals, 27 * 6);
    assert_eq!(pretty_refusals, 27 * 2);
    assert_eq!(verified, 27);
    println!(
        "spike 6: {fixtures} fixtures + {suite_cases} bridge-v1 cases = {} sources",
        sources.len()
    );
    println!(
        "spike 6: {audited} artifacts audited, {verified} receipts verified by verify_receipt"
    );
    println!("spike 6: {cross_kind_refusals} cross-kind audits refused, {pretty_refusals} non-compact audits refused");
    println!(
        "spike 6: {bytes_total} canonical bytes audited, largest receipt {largest} bytes ({:.2} MiB)",
        largest as f64 / (1024.0 * 1024.0)
    );
}

/// The 8 MiB artifact ceiling, hashed the way the default path hashes an
/// assembled artifact.
///
/// The spike criterion is 200 ms native and it is a statement about shipped
/// code, so it is asserted on an optimized build and reported on both. An
/// unoptimized `sha2` runs about twenty times slower than the same code
/// compiled with optimizations, which says nothing about the receiver; the
/// debug bound below only catches an algorithmic regression. Run
/// `cargo test -p vhalla-game-platonik --release --test audit` for the number
/// the criterion is judged on.
#[test]
fn eight_mebibytes_hash_well_inside_the_two_hundred_millisecond_criterion() {
    // The one operation the default path performs on a fetched artifact: a
    // plain SHA-256 over the whole assembled buffer at the 8 MiB ceiling.
    const SIZE: usize = 8 * 1024 * 1024;
    let buffer: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
    // One warm pass, then the measured one, so the page faults of the first
    // touch are not charged to the hash.
    let warm = plain_sha256(&buffer);
    let start = Instant::now();
    let hash = plain_sha256(&buffer);
    let elapsed = start.elapsed();
    assert_eq!(hash, warm);
    let millis = elapsed.as_secs_f64() * 1000.0;
    let optimized = !cfg!(debug_assertions);
    let profile = if optimized { "optimized" } else { "debug" };
    println!(
        "spike 6: 8 MiB plain SHA-256 native in {millis:.1} ms ({profile} build; criterion 200 ms on an optimized build)"
    );
    let bound = if optimized { 200 } else { 2_000 };
    assert!(
        elapsed.as_millis() <= bound,
        "8 MiB SHA-256 took {millis:.1} ms on a {profile} build, above the {bound} ms bound"
    );
}
