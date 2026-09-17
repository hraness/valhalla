//! The vector file format: one text file per corpus case with the canonical
//! manifest and assignment bytes and every digest and quantity a run of them
//! must reproduce. Written by `examples/vectors.rs`, read by the tests and by
//! the wasm parity spike.

use alloc::string::String;
use alloc::vec::Vec;

/// A parsed vector file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vector {
    /// Corpus case id.
    pub id: String,
    /// Canonical manifest bytes.
    pub manifest: Vec<u8>,
    /// Canonical candidate assignment bytes for the open slots.
    pub assignment: Vec<u8>,
    /// Expected `ManifestHash`.
    pub manifest_hash: [u8; 32],
    /// Expected `ProgramHash`.
    pub program_hash: [u8; 32],
    /// Expected `OutputHash`.
    pub output_hash: [u8; 32],
    /// Expected per-case `StateHash` values.
    pub state_hashes: Vec<[u8; 32]>,
    /// Expected `useful`.
    pub useful: u64,
    /// Expected `total`.
    pub total: u64,
    /// Expected `passed`.
    pub passed: bool,
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

/// Parses lowercase or uppercase hex; `None` on an odd length or a bad digit.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

fn hash32(text: &str) -> Option<[u8; 32]> {
    let bytes = unhex(text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Renders a vector file.
#[must_use]
pub fn render(vector: &Vector) -> String {
    let mut out = String::new();
    out.push_str("id: ");
    out.push_str(&vector.id);
    out.push_str("\nmanifest: ");
    out.push_str(&hex(&vector.manifest));
    out.push_str("\nassignment: ");
    out.push_str(&hex(&vector.assignment));
    out.push_str("\nmanifest_hash: ");
    out.push_str(&hex(&vector.manifest_hash));
    out.push_str("\nprogram_hash: ");
    out.push_str(&hex(&vector.program_hash));
    out.push_str("\noutput_hash: ");
    out.push_str(&hex(&vector.output_hash));
    for state in &vector.state_hashes {
        out.push_str("\nstate_hash: ");
        out.push_str(&hex(state));
    }
    out.push_str("\nuseful: ");
    out.push_str(&alloc::format!("{}", vector.useful));
    out.push_str("\ntotal: ");
    out.push_str(&alloc::format!("{}", vector.total));
    out.push_str("\npassed: ");
    out.push_str(if vector.passed { "true" } else { "false" });
    out.push('\n');
    out
}

/// Parses a vector file; `None` on any malformed line.
#[must_use]
pub fn parse(text: &str) -> Option<Vector> {
    let mut id = None;
    let mut manifest = None;
    let mut assignment = None;
    let mut manifest_hash = None;
    let mut program_hash = None;
    let mut output_hash = None;
    let mut state_hashes = Vec::new();
    let mut useful = None;
    let mut total = None;
    let mut passed = None;
    for line in text.lines() {
        let (key, value) = line.split_once(": ")?;
        match key {
            "id" => id = Some(String::from(value.trim())),
            "manifest" => manifest = Some(unhex(value)?),
            "assignment" => assignment = Some(unhex(value)?),
            "manifest_hash" => manifest_hash = Some(hash32(value)?),
            "program_hash" => program_hash = Some(hash32(value)?),
            "output_hash" => output_hash = Some(hash32(value)?),
            "state_hash" => state_hashes.push(hash32(value)?),
            "useful" => useful = Some(value.trim().parse().ok()?),
            "total" => total = Some(value.trim().parse().ok()?),
            "passed" => {
                passed = Some(match value.trim() {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                })
            }
            _ => return None,
        }
    }
    Some(Vector {
        id: id?,
        manifest: manifest?,
        assignment: assignment?,
        manifest_hash: manifest_hash?,
        program_hash: program_hash?,
        output_hash: output_hash?,
        state_hashes,
        useful: useful?,
        total: total?,
        passed: passed?,
    })
}

/// Replays one vector: decodes, validates, assigns, runs, and returns the
/// observed values in the same shape, so callers compare with `==`.
pub fn replay(vector: &Vector) -> Result<Vector, ReplayError> {
    use crate::codec;
    use crate::hash::ProgramHash;
    use crate::manifest::ValidManifest;
    use crate::platform::{self, RunCapability, RunRole, WorkAllowance};
    let manifest = codec::decode_manifest(&vector.manifest).map_err(ReplayError::Codec)?;
    let valid = ValidManifest::validate(manifest).map_err(ReplayError::Manifest)?;
    let candidate = codec::decode_candidate(&vector.assignment).map_err(ReplayError::Codec)?;
    let assignment = valid.assign(candidate).map_err(ReplayError::Manifest)?;
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    let capability = RunCapability::mint(
        valid.hash(),
        program,
        WorkAllowance {
            max_total: valid.fuel_total(),
        },
        RunRole::Replay,
    );
    let run = platform::run(&valid, &assignment, capability).map_err(ReplayError::Run)?;
    Ok(Vector {
        id: vector.id.clone(),
        manifest: vector.manifest.clone(),
        assignment: vector.assignment.clone(),
        manifest_hash: valid.hash().0,
        program_hash: program.0,
        output_hash: run.output_hash().0,
        state_hashes: run.cases().iter().map(|case| case.final_state.0).collect(),
        useful: run.useful(),
        total: run.total(),
        passed: run.passed(),
    })
}

/// Why a vector could not be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// Bytes did not decode.
    Codec(crate::codec::CodecError),
    /// The manifest or candidate was refused.
    Manifest(crate::manifest::ManifestError),
    /// The run was refused.
    Run(crate::platform::RunRefused),
}
