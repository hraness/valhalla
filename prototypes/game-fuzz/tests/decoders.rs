//! One harness per decoder in `vhalla_game_platonik`, plus the signed
//! carrier's own decoder. Each loads its committed corpus, replays every seed,
//! and then mutates at a fixed seed for a fixed number of iterations.
//!
//! The two assertions live in `game_fuzz::harness`: no input may panic, and an
//! accepted input must re-encode to itself. A failure here is a finding
//! against `vhalla-game-platonik`, never something to patch in this crate; the
//! panic hook prints the exact hex so the finding is reproducible.

use game_fuzz::{harness, Report, ITERATIONS};
use vhalla_game_platonik::record::GameRecord;
use vhalla_game_platonik::wire;

/// Every seed is replayed, every iteration runs, and the mutation loop has to
/// actually reach both answers: a harness that only ever refuses is proving
/// nothing about the canonical law.
fn check(decoder: &str, report: Report) {
    assert_eq!(report.iterations, ITERATIONS, "{decoder} iteration cap");
    assert!(report.seeds > 0, "{decoder} has seeds");
    assert!(report.accepted > 0, "{decoder} accepted no mutant");
    assert!(report.rejected > 0, "{decoder} refused no mutant");
    println!(
        "{decoder}: {} seeds, {} iterations, {} accepted, {} refused",
        report.seeds, report.iterations, report.accepted, report.rejected
    );
}

#[test]
fn game_manifest_decoder() {
    let report = harness(
        "game-manifest",
        0x6761_6d65_0001,
        wire::decode_game_manifest,
        wire::encode_game_manifest,
    );
    check("game-manifest", report);
}

#[test]
fn session_open_decoder() {
    let report = harness(
        "session-open",
        0x6761_6d65_0002,
        wire::decode_session_open,
        wire::encode_session_open,
    );
    check("session-open", report);
}

#[test]
fn game_event_decoder() {
    let report = harness(
        "game-event",
        0x6761_6d65_0003,
        wire::decode_game_event,
        wire::encode_game_event,
    );
    check("game-event", report);
}

#[test]
fn checkpoint_decoder() {
    let report = harness(
        "checkpoint",
        0x6761_6d65_0004,
        wire::decode_checkpoint,
        wire::encode_checkpoint,
    );
    check("checkpoint", report);
}

#[test]
fn settlement_decoder() {
    let report = harness(
        "settlement",
        0x6761_6d65_0005,
        wire::decode_settlement,
        wire::encode_settlement,
    );
    check("settlement", report);
}

#[test]
fn artifact_request_decoder() {
    let report = harness(
        "artifact-request",
        0x6761_6d65_0006,
        wire::decode_artifact_request,
        wire::encode_artifact_request,
    );
    check("artifact-request", report);
}

#[test]
fn artifact_manifest_decoder() {
    let report = harness(
        "artifact-manifest",
        0x6761_6d65_0007,
        wire::decode_artifact_manifest,
        wire::encode_artifact_manifest,
    );
    check("artifact-manifest", report);
}

#[test]
fn block_decoder() {
    let report = harness(
        "block",
        0x6761_6d65_0008,
        wire::decode_block,
        wire::encode_block,
    );
    check("block", report);
}

#[test]
fn game_record_decoder() {
    let report = harness(
        "game-record",
        0x6761_6d65_0009,
        GameRecord::decode,
        GameRecord::encode,
    );
    check("game-record", report);
}
