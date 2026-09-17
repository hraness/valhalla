//! Spike 2's four measurements. Run with `-- --nocapture` to read the
//! numbers the plan records.

use game_artifact_sizes::{
    assemble, blocks_for, platonik_artifacts, widest_frame_fits, worst_case_traces, Measured,
    GRID_CEILING, MAX_TRANSPORT_BYTES, REQUIRED_FRAME_MARGIN,
};
use vhalla_crypto::MAX_SIGNED_BODY_BYTES;
use vhalla_game_platonik::ids::InnerKind;
use vhalla_game_platonik::manifest::MAX_ARTIFACT_BYTES;
use vhalla_game_platonik::wire::{BLOCK_LEN, MAX_BLOCKS};

fn largest(measured: &[Measured]) -> &Measured {
    measured.iter().max_by_key(|m| m.len).expect("non-empty")
}

/// (a) Every Platonik artifact of the six fixtures and the `bridge-v1` suite
/// fits one bounded artifact.
#[test]
fn every_platonik_artifact_fits_eight_mebibytes() {
    let measured = platonik_artifacts();
    assert_eq!(
        measured.len() % 3,
        0,
        "three artifacts per corpus experiment"
    );
    let experiments = measured.len() / 3;
    for kind in [
        InnerKind::PlatonikExperimentV1,
        InnerKind::PlatonikResultV1,
        InnerKind::PlatonikReceiptV1,
    ] {
        let of_kind: Vec<&Measured> = measured.iter().filter(|m| m.kind == kind).collect();
        let biggest = of_kind.iter().max_by_key(|m| m.len).expect("non-empty");
        let smallest = of_kind.iter().min_by_key(|m| m.len).expect("non-empty");
        println!(
            "spike2(a) {kind:?}: {} artifacts, smallest {} bytes, largest {} bytes \
             ({}, {} block{})",
            of_kind.len(),
            smallest.len,
            biggest.len,
            biggest.id,
            biggest.blocks(),
            if biggest.blocks() == 1 { "" } else { "s" }
        );
    }
    for m in &measured {
        assert!(
            m.len as u64 <= MAX_ARTIFACT_BYTES,
            "{} {:?} is {} bytes, above the 8 MiB ceiling",
            m.id,
            m.kind,
            m.len
        );
        assert!(m.blocks() <= MAX_BLOCKS);
    }
    let biggest = largest(&measured);
    println!(
        "spike2(a) {experiments} corpus experiments, {} artifacts; largest overall {} bytes \
         ({}, {:?}, {} of {MAX_BLOCKS} blocks, {:.2}% of the 8 MiB ceiling)",
        measured.len(),
        biggest.len,
        biggest.id,
        biggest.kind,
        biggest.blocks(),
        biggest.len as f64 * 100.0 / MAX_ARTIFACT_BYTES as f64
    );
    // The plan's largest known Platonik receipt is a habitat session receipt
    // outside this corpus. The same grid carries it.
    const LARGEST_KNOWN_RECEIPT: usize = 7_141_362;
    println!(
        "spike2(a) the plan's largest known Platonik receipt, {LARGEST_KNOWN_RECEIPT} bytes, \
         needs {} of {MAX_BLOCKS} blocks ({:.2}% of the 8 MiB ceiling)",
        blocks_for(LARGEST_KNOWN_RECEIPT),
        LARGEST_KNOWN_RECEIPT as f64 * 100.0 / MAX_ARTIFACT_BYTES as f64
    );
    assert!(blocks_for(LARGEST_KNOWN_RECEIPT) <= MAX_BLOCKS);
    assert!(LARGEST_KNOWN_RECEIPT as u64 <= MAX_ARTIFACT_BYTES);
}

/// (b) One `(segment, case)` frame trace of the witness corpus worst case
/// fits one artifact.
#[test]
fn one_frame_trace_fits_one_artifact() {
    let (traces, frames, state_bytes) = worst_case_traces();
    let total: usize = traces.iter().map(Vec::len).sum();
    let widest = traces.iter().map(Vec::len).max().expect("a case ran");
    for (case, trace) in traces.iter().enumerate() {
        println!(
            "spike2(b) worst-case segment, case {case}: {} bytes, {} block{}",
            trace.len(),
            blocks_for(trace.len()),
            if blocks_for(trace.len()) == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    println!(
        "spike2(b) {} case{}, {frames} frames, {state_bytes} encoded state bytes, \
         {total} trace bytes in total; widest single trace {widest} bytes \
         ({} of {MAX_BLOCKS} blocks, {:.2}% of the 8 MiB ceiling)",
        traces.len(),
        if traces.len() == 1 { "" } else { "s" },
        blocks_for(widest),
        widest as f64 * 100.0 / MAX_ARTIFACT_BYTES as f64
    );
    assert!(
        widest as u64 <= MAX_ARTIFACT_BYTES,
        "one trace must fit one artifact"
    );
    assert!(blocks_for(widest) <= MAX_BLOCKS);
}

/// (c) The largest measured artifact assembles natively and through the
/// browser record mapping, inside the 1.25 x retained ceiling.
///
/// The ceiling is charged against the assembly, which is what
/// `max_artifact_bytes` bounds. The transport's own in-flight buffers are a
/// constant of one block and its records, never a ratio, so they are bounded
/// separately and reported beside it.
#[test]
fn the_largest_artifact_assembles_inside_the_retained_ceiling() {
    let measured = platonik_artifacts();
    let biggest = largest(&measured).clone();
    let bytes = largest_bytes(&biggest);
    assert_eq!(bytes.len(), biggest.len);

    for (path, browser) in [("native", false), ("browser", true)] {
        let run = assemble(&bytes, biggest.kind, browser);
        println!(
            "spike2(c) largest corpus artifact, {path}: {} bytes in {} blocks, peak retained {} \
             = {:.4} x artifact, plus {} transport = {} bytes ({:.4} x), {} SHA-256 invocations",
            run.len,
            run.blocks,
            run.peak_retained,
            run.ratio(),
            run.transport_peak,
            run.combined(),
            run.combined_ratio(),
            run.hashes
        );
        assert!(run.ratio() <= 1.25, "assembly peak above 1.25 x");
        assert!(run.transport_peak <= MAX_TRANSPORT_BYTES);
        assert_eq!(run.hashes, run.blocks as u64 + 1);
    }

    // The plan's per-(segment, case) trace figure, driven through the browser
    // path, which is spike 2's named pass criterion.
    let trace_sized: Vec<u8> = (0..1_250_000).map(|i| (i % 251) as u8).collect();
    let run = assemble(&trace_sized, InnerKind::FrameTraceV1, true);
    println!(
        "spike2(c) 1.25 MB trace, browser: {} blocks, peak retained {} = {:.4} x, \
         plus {} transport = {:.4} x",
        run.blocks,
        run.peak_retained,
        run.ratio(),
        run.transport_peak,
        run.combined_ratio()
    );
    assert!(run.combined_ratio() <= 1.25);

    // The 8 MiB, 128-block worst case the grid is sized for.
    let ceiling: Vec<u8> = (0..GRID_CEILING as usize)
        .map(|i| (i % 251) as u8)
        .collect();
    assert_eq!(ceiling.len() as u64, MAX_ARTIFACT_BYTES);
    for (path, browser) in [("native", false), ("browser", true)] {
        let run = assemble(&ceiling, InnerKind::FrameTraceV1, browser);
        println!(
            "spike2(c) 8 MiB ceiling, {path}: {} blocks of {BLOCK_LEN}, peak retained {} \
             = {:.4} x, plus {} transport = {} bytes ({:.4} x), {} SHA-256 invocations",
            run.blocks,
            run.peak_retained,
            run.ratio(),
            run.transport_peak,
            run.combined(),
            run.combined_ratio(),
            run.hashes
        );
        assert_eq!(run.blocks, MAX_BLOCKS);
        assert!(run.ratio() <= 1.25);
        assert!(run.combined_ratio() <= 1.25);
    }

    // A full eight-segment, eight-case session fetches 64 traces. They are
    // sequential assemblies inside one 8 MiB budget, never a cumulative total.
    let trace = worst_case_traces().0.into_iter().max_by_key(Vec::len);
    if let Some(trace) = trace {
        let mut peak = 0_u64;
        for _ in 0..64 {
            let run = assemble(&trace, InnerKind::FrameTraceV1, false);
            peak = peak.max(run.combined());
        }
        println!(
            "spike2(c) 64 sequential trace fetches of {} bytes: peak retained {peak} bytes, \
             {:.2}% of the 8 MiB session budget (a cumulative reading would be {} bytes)",
            trace.len(),
            peak as f64 * 100.0 / MAX_ARTIFACT_BYTES as f64,
            trace.len() * 64
        );
        assert!(peak <= MAX_ARTIFACT_BYTES);
    }
}

/// Re-derives the exact bytes of the largest measured artifact.
fn largest_bytes(measured: &Measured) -> Vec<u8> {
    let experiment = if let Some(name) = measured.id.strip_prefix("fixture-") {
        platonik_core::fixtures::experiment(name).expect("fixture")
    } else {
        let case_id = measured
            .id
            .strip_prefix("bridge-v1-")
            .expect("a corpus id is a fixture or a suite case");
        platonik_core::suite::run_suite("bridge-v1")
            .expect("suite")
            .cases
            .into_iter()
            .find(|case| case.id == case_id)
            .expect("case")
            .receipt
            .experiment
    };
    match measured.kind {
        InnerKind::PlatonikExperimentV1 => serde_json::to_vec(&experiment).expect("json"),
        InnerKind::PlatonikResultV1 => {
            serde_json::to_vec(&platonik_core::run(&experiment).expect("run")).expect("json")
        }
        InnerKind::PlatonikReceiptV1 => {
            serde_json::to_vec(&platonik_core::check::make_receipt(&experiment).expect("receipt"))
                .expect("json")
        }
        other => panic!("{other:?} is not a Platonik JSON artifact"),
    }
}

/// (d) The widest `GameManifest` and `SessionOpen` fit one signed frame with
/// at least 8 KiB of margin.
#[test]
fn the_widest_manifest_and_opening_fit_one_signed_frame() {
    let (manifest, open) = widest_frame_fits();
    println!(
        "spike2(d) widest GameManifest {} bytes, margin {} bytes under \
         MAX_SIGNED_BODY_BYTES ({MAX_SIGNED_BODY_BYTES})",
        manifest.len, manifest.margin
    );
    println!(
        "spike2(d) widest SessionOpen {} bytes, margin {} bytes under \
         MAX_SIGNED_BODY_BYTES ({MAX_SIGNED_BODY_BYTES})",
        open.len, open.margin
    );
    assert!(
        manifest.margin >= REQUIRED_FRAME_MARGIN,
        "the manifest margin is {} bytes, below the 8 KiB the plan requires",
        manifest.margin
    );
    assert!(
        open.margin >= REQUIRED_FRAME_MARGIN,
        "the opening margin is {} bytes, below the 8 KiB the plan requires",
        open.margin
    );
}
