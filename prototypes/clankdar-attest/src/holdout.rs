//! `clankdar-holdout-v1` — private derived pools for held-out challenge
//! cells.
//!
//! A holdout pool re-parameterizes published generator cells with secret
//! labels so the issued instance stream is unpublished. The held-out
//! instance for a cell is `generate(tier, mixSeed(label, seed))`: the label
//! decorrelates the cell's stream from the published one while the public
//! `seed` stays the caller seed recorded in the receipt. Challenges minted
//! from a pool carry `heldout: {poolKey}`; only a checker holding the pool
//! can replay the instance — everyone else verifies the signature,
//! commitment, timing, and subject proof while the score stays
//! issuer-claimed (`replayable: false`).
//!
//! Publishing the pool later upgrades every historical held-out receipt to
//! fully replayable (deferred disclosure). A held-out cell is the same
//! puzzle family under an unpublished parameterization: it prevents
//! instance lookup and precomputation against the stream, but a general
//! solver for the family still solves it — held-out is not a new puzzle
//! type.
//!
//! This module mirrors `bench/holdout.ts` in the clankdar repository. One
//! deliberate divergence, matching [`crate::GatePolicy::parse`]: the
//! TypeScript `parsePool` checks every cell's family and tier against the
//! suite's base pool, while [`HoldoutPool::parse`] validates the cell
//! *shape* and the `poolKey` commitment only — base-pool membership is
//! enforced by regeneration through the generator oracle instead.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{canonical_json, sha256_hex, suite_version, AttestError, Challenge, GeneratedInstance};

/// Wire protocol identifier.
pub const HOLDOUT_PROTOCOL: &str = "clankdar-holdout-v1";

/// Maximum `cells` entries in a pool (mirrors `MAX_CELLS`).
pub const MAX_POOL_CELLS: usize = 256;

/// `^[A-Za-z0-9_-]{22,128}$` — the secret label shape (>=128 bits).
fn is_label(value: &str) -> bool {
    (22..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `Number.isInteger(value)` for a non-negative JSON number: an integral
/// `4.0` counts as the integer `4`, matching JavaScript.
fn js_integer_u64(value: &Value) -> Option<u64> {
    if let Some(u) = value.as_u64() {
        return Some(u);
    }
    let f = value.as_f64()?;
    if f.fract() == 0.0 && f >= 0.0 && f <= u64::MAX as f64 {
        Some(f as u64)
    } else {
        None
    }
}

/// One held-out cell: a published generator cell plus a secret stream
/// label.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoldoutCell {
    /// Puzzle family name in the base suite.
    pub family: String,
    /// Difficulty tier inside the family.
    pub tier: u64,
    /// Secret seed-mix label (>=128 bits); revealing it replays the stream.
    pub label: String,
}

/// An issuer-private pool: secret labels committed by `poolKey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HoldoutPool {
    /// Protocol identifier.
    pub protocol: String,
    /// Published suite whose generators the labels re-parameterize.
    pub suite: String,
    /// sha256 over `canonical({protocol, suite, cells})` — binds labels
    /// and cells.
    pub pool_key: String,
    /// The labeled cells.
    pub cells: Vec<HoldoutCell>,
}

/// `poolKeyOf`: sha256 over the canonical committed members.
pub fn pool_key_of(suite: &str, cells: &[HoldoutCell]) -> String {
    sha256_hex(
        canonical_json(&serde_json::json!({
            "protocol": HOLDOUT_PROTOCOL,
            "suite": suite,
            "cells": cells,
        }))
        .as_bytes(),
    )
}

/// `cellId`: the `"family:tN"` spelling of a cell.
fn cell_id(family: &str, tier: u64) -> String {
    format!("{family}:t{tier}")
}

impl HoldoutPool {
    /// Strictly parse a pool file and re-check its `poolKey` commitment,
    /// mirroring `parsePool` in `bench/holdout.ts` — except base-pool
    /// membership: the TypeScript side looks every cell up in the suite
    /// pool; this side validates the cell shape and defers "cell exists"
    /// to instance regeneration, which fails for a nonexistent cell
    /// anyway.
    pub fn parse(value: &Value) -> Result<Self, AttestError> {
        let fail =
            |message: &str| AttestError::InvalidInput(format!("invalid holdout pool: {message}"));
        let object = value
            .as_object()
            .ok_or_else(|| fail("expected an object"))?;
        if object.get("protocol").and_then(Value::as_str) != Some(HOLDOUT_PROTOCOL) {
            return Err(fail(&format!("protocol must be {HOLDOUT_PROTOCOL}")));
        }
        let suite = match object.get("suite").and_then(Value::as_str) {
            Some(suite @ ("v2" | "frontier" | "agent")) => suite.to_string(),
            _ => return Err(fail("suite must be v2, frontier, or agent")),
        };
        let raw_cells = match object.get("cells").and_then(Value::as_array) {
            Some(cells) if !cells.is_empty() && cells.len() <= MAX_POOL_CELLS => cells,
            _ => return Err(fail(&format!("cells must be 1..{MAX_POOL_CELLS} objects"))),
        };
        let mut cells = Vec::with_capacity(raw_cells.len());
        for raw in raw_cells {
            let family = raw.get("family").and_then(Value::as_str);
            let tier = raw.get("tier").and_then(js_integer_u64);
            let (Some(family), Some(tier)) = (family, tier) else {
                return Err(fail(&format!(
                    "unknown base cell: {}",
                    serde_json::to_string(raw).unwrap_or_default()
                )));
            };
            let label = match raw.get("label").and_then(Value::as_str) {
                Some(label) if is_label(label) => label.to_string(),
                _ => return Err(fail("cell label must be 22..128 base64url chars")),
            };
            cells.push(HoldoutCell {
                family: family.to_string(),
                tier,
                label,
            });
        }
        if cells
            .iter()
            .map(|cell| cell_id(&cell.family, cell.tier))
            .collect::<std::collections::HashSet<_>>()
            .len()
            != cells.len()
        {
            return Err(fail("cells must be distinct"));
        }
        let pool_key = object.get("poolKey").and_then(Value::as_str);
        if pool_key != Some(pool_key_of(&suite, &cells).as_str()) {
            return Err(fail("poolKey does not commit the cell list"));
        }
        Ok(Self {
            protocol: HOLDOUT_PROTOCOL.to_string(),
            suite,
            pool_key: pool_key.unwrap_or_default().to_string(),
            cells,
        })
    }
}

/// `holdoutCell`: look up a labeled cell by family and tier.
pub fn holdout_cell<'a>(pool: &'a HoldoutPool, family: &str, tier: u64) -> Option<&'a HoldoutCell> {
    pool.cells
        .iter()
        .find(|c| c.family == family && c.tier == tier)
}

/// `mixSeed`: FNV-1a mix of a label into a seed, decorrelating streams
/// across cells that share a seed. JavaScript iterates the label's UTF-16
/// code units (`charCodeAt(i)`), which `encode_utf16` reproduces exactly —
/// pool labels are base64url (ASCII) anyway, where the two agree trivially.
pub fn mix_seed(label: &str, seed: u64) -> u64 {
    let mut h: u32 = 0x811c9dc5;
    for unit in label.encode_utf16() {
        h ^= unit as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    ((seed as u32) ^ h) as u64
}

/// `holdoutInstance`: regenerate a held-out instance through the
/// generator oracle; the recorded `seed` stays the public caller seed
/// while the instance itself draws from `mixSeed(label, seed)`.
pub fn holdout_instance(
    pool: &HoldoutPool,
    cell: &HoldoutCell,
    seed: u64,
    oracle: impl FnOnce(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<GeneratedInstance, String> {
    let tier = u32::try_from(cell.tier).map_err(|_| {
        format!(
            "unknown base cell for {}: {}",
            pool.suite,
            cell_id(&cell.family, cell.tier)
        )
    })?;
    let mut instance = oracle(
        suite_version(&pool.suite),
        &cell.family,
        tier,
        mix_seed(&cell.label, seed),
    )?;
    instance.seed = seed;
    Ok(instance)
}

/// `instanceFor`: regenerate a ticket's instance from the published
/// stream or the committed holdout pool. A `heldout`-marked challenge
/// needs a supplied pool whose `poolKey` equals the marker's, then the
/// named cell inside it.
pub fn instance_for(
    challenge: &Challenge,
    seed: u64,
    pool: Option<&HoldoutPool>,
    oracle: impl Fn(&str, &str, u32, u64) -> Result<GeneratedInstance, String>,
) -> Result<GeneratedInstance, AttestError> {
    if let Some(heldout) = &challenge.heldout {
        // `pool.poolKey !== challenge.heldout.poolKey` in TypeScript: a
        // marker whose `poolKey` member is missing or not a string never
        // equals a pool key, so the ticket is refused either way. (A
        // `heldout: null` member parses as absent here — the TypeScript
        // reference throws on `null.poolKey`; refusing via the published
        // path's prompt check is the graceful equivalent.)
        let marker_key = heldout.get("poolKey").and_then(Value::as_str);
        let pool = pool
            .filter(|p| Some(p.pool_key.as_str()) == marker_key)
            .ok_or_else(|| {
                AttestError::InvalidInput("ticket needs the matching holdout pool".to_string())
            })?;
        let cell =
            holdout_cell(pool, &challenge.family, challenge.tier as u64).ok_or_else(|| {
                AttestError::InvalidInput("ticket cell is not in the holdout pool".to_string())
            })?;
        return holdout_instance(pool, cell, seed, oracle).map_err(AttestError::Malformed);
    }
    oracle(
        &challenge.suite_version,
        &challenge.family,
        challenge.tier,
        seed,
    )
    .map_err(AttestError::Malformed)
}
