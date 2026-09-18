//! Stage 4 wasm32 parity of the frozen game session vectors.
//!
//! Each committed vector carries a game manifest, a session opening, and every
//! signed record as hex. [`run_corpus`] rebuilds the session from that hex
//! alone, replays every record through a fresh `Receiver<PlatonikV1>`, and
//! renders what the receiver reproduced: each record's event digest, each
//! seal's verified checkpoint fields and checkpoint hash, and the final
//! receipt. [`expected_corpus`] renders the same shape from the committed
//! values themselves. A native run and a wasm32 run must produce the same
//! text, and both must equal the committed rendering.
//!
//! The graph here is `vhalla-game-platonik` with default features: the
//! receiver path a receiver without `oracle` runs, with no `platonik-core`, no
//! serde, and no JSON anywhere.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::ids::{CheckpointHash, GameManifestHash};
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::GameRecord;
use vhalla_game_platonik::session::{SealPlan, Session};
use vhalla_game_platonik::wire::{
    decode_checkpoint, decode_game_event, decode_game_manifest, decode_session_open, EventBody,
};
use vhalla_witness::hash::{digest, RECEIPT_DOMAIN};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vectors::{hex, unhex};

/// The committed session vector files, embedded at compile time.
pub const VECTORS: &[(&str, &str)] = &include!(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors.in"));

/// The `key: value` lines of one vector file.
fn fields(text: &str) -> BTreeMap<&str, &str> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            out.insert(key, value);
        }
    }
    out
}

/// A missing or malformed field is a rendering difference, never a panic.
fn field<'a>(fields: &BTreeMap<&str, &'a str>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| format!("missing field {key}"))
}

fn raw(fields: &BTreeMap<&str, &str>, key: &str) -> Result<Vec<u8>, String> {
    unhex(field(fields, key)?).ok_or_else(|| format!("bad hex in {key}"))
}

fn hash32(fields: &BTreeMap<&str, &str>, key: &str) -> Result<[u8; 32], String> {
    let bytes = raw(fields, key)?;
    let mut out = [0_u8; 32];
    if bytes.len() != 32 {
        return Err(format!("{key} is not 32 bytes"));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn count(fields: &BTreeMap<&str, &str>, key: &str) -> Result<usize, String> {
    field(fields, key)?
        .parse()
        .map_err(|_| format!("{key} is not a count"))
}

/// The receiver's own budget: this prototype measures parity, not exhaustion.
fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// The receipt the final seal's replay produces, derived the way the receiver
/// derives it from the session state before the seal is committed.
fn final_receipt(session: &Session, plan: &SealPlan) -> Result<Vec<u8>, String> {
    let manifest =
        ValidManifest::validate(plan.manifest.clone()).map_err(|e| format!("manifest {e:?}"))?;
    let allowance = WorkAllowance {
        max_total: manifest
            .fuel_total()
            .min(session.manifest().limits.replay.max_total),
    };
    let binding = ReceiptBinding {
        challenge_id: session.key().0,
        subject_key: session.host(),
    };
    let evidence = PlatonikV1
        .replay(
            session.world(),
            &manifest,
            plan.candidate.clone(),
            allowance,
            plan.through_tick,
            binding,
        )
        .map_err(|e| format!("replay {e:?}"))?;
    Ok(evidence.receipt.encode())
}

/// Replays one vector and renders what the receiver reproduced.
fn replay(text: &str) -> Result<String, String> {
    let fields = fields(text);
    let manifest_raw = raw(&fields, "game_manifest")?;
    let manifest = decode_game_manifest(&manifest_raw)
        .map_err(|e| format!("the game manifest does not decode: {e:?}"))?;
    if manifest.hash() != GameManifestHash::of(&manifest_raw) {
        return Err("the game manifest does not hash to its own bytes".into());
    }
    let open_raw = raw(&fields, "session_open")?;
    let open = decode_session_open(&open_raw)
        .map_err(|e| format!("the session opening does not decode: {e:?}"))?;
    let realm = open.realm;
    let mut session = Session::open(manifest, open, realm).map_err(|e| format!("open {e:?}"))?;
    let mut receiver = Receiver::new(PlatonikV1, policy());

    let mut out = String::new();
    writeln!(out, "session_key: {}", hex(&session.key().0)).unwrap();
    let records = count(&fields, "record_count")?;
    writeln!(out, "records: {records}").unwrap();
    let mut receipt: Option<Vec<u8>> = None;
    let mut seals = 0_usize;
    for index in 0..records {
        let record_raw = raw(&fields, &format!("record[{index}].record"))?;
        let record = GameRecord::decode(&record_raw)
            .map_err(|e| format!("record {index} does not decode: {e:?}"))?;
        record
            .verify()
            .map_err(|e| format!("record {index} signature {e:?}"))?;
        let event = decode_game_event(&record.body)
            .map_err(|e| format!("record {index} body does not decode: {e:?}"))?;
        writeln!(out, "record[{index}].digest: {}", hex(&event.digest().0)).unwrap();
        // The final seal's receipt is derived before the seal is committed,
        // from the plan the receiver itself builds.
        if matches!(event.body, EventBody::Seal { .. }) {
            let plan = session
                .plan_seal(&event)
                .map_err(|e| format!("record {index} seal plan {e:?}"))?;
            if plan.is_final {
                receipt = Some(final_receipt(&session, &plan)?);
            }
        }
        let step = index as u64 + 1;
        let verified = receiver
            .admit(&mut session, &record, step)
            .map_err(|e| format!("record {index} refused {e:?}"))?;
        let Some(verified) = verified else {
            continue;
        };
        let work = verified.work();
        writeln!(out, "seal[{seals}].session: {}", hex(&verified.session().0)).unwrap();
        writeln!(out, "seal[{seals}].segment: {}", verified.segment()).unwrap();
        writeln!(
            out,
            "seal[{seals}].through_tick: {}",
            verified.through_tick()
        )
        .unwrap();
        writeln!(out, "seal[{seals}].useful: {}", work.useful).unwrap();
        writeln!(out, "seal[{seals}].total: {}", work.total).unwrap();
        writeln!(
            out,
            "seal[{seals}].final: {}",
            u8::from(verified.is_final())
        )
        .unwrap();
        writeln!(
            out,
            "seal[{seals}].checkpoint_hash: {}",
            hex(&verified.hash().0)
        )
        .unwrap();
        seals += 1;
    }
    if seals == 0 {
        return Err("no seal was verified".into());
    }
    let receipt = receipt.ok_or("no final seal")?;
    writeln!(out, "receipt: {}", hex(&receipt)).unwrap();
    writeln!(
        out,
        "receipt_hash: {}",
        hex(&digest(RECEIPT_DOMAIN, &receipt))
    )
    .unwrap();
    Ok(out)
}

/// Renders the same shape from the committed values: the session key and the
/// receipt as the file states them, and every seal's fields read out of the
/// committed checkpoint bytes that hash to the committed checkpoint hash.
fn committed(text: &str) -> Result<String, String> {
    let fields = fields(text);
    let mut out = String::new();
    writeln!(out, "session_key: {}", field(&fields, "session_key")?).unwrap();
    let records = count(&fields, "record_count")?;
    writeln!(out, "records: {records}").unwrap();
    let mut seals = 0_usize;
    for index in 0..records {
        writeln!(
            out,
            "record[{index}].digest: {}",
            field(&fields, &format!("record[{index}].event_digest"))?
        )
        .unwrap();
        let key = format!("record[{index}].checkpoint");
        if !fields.contains_key(key.as_str()) {
            continue;
        }
        let checkpoint_raw = raw(&fields, &key)?;
        let checkpoint = decode_checkpoint(&checkpoint_raw)
            .map_err(|e| format!("checkpoint {index} does not decode: {e:?}"))?;
        let claimed = CheckpointHash(hash32(
            &fields,
            &format!("record[{index}].checkpoint_hash"),
        )?);
        if checkpoint.hash() != claimed {
            return Err(format!("checkpoint {index} does not hash to its own bytes"));
        }
        writeln!(out, "seal[{seals}].session: {}", hex(&checkpoint.session.0)).unwrap();
        writeln!(out, "seal[{seals}].segment: {}", checkpoint.segment).unwrap();
        writeln!(
            out,
            "seal[{seals}].through_tick: {}",
            checkpoint.through_tick
        )
        .unwrap();
        writeln!(out, "seal[{seals}].useful: {}", checkpoint.work.useful).unwrap();
        writeln!(out, "seal[{seals}].total: {}", checkpoint.work.total).unwrap();
        writeln!(
            out,
            "seal[{seals}].final: {}",
            field(&fields, &format!("record[{index}].final"))?
        )
        .unwrap();
        writeln!(out, "seal[{seals}].checkpoint_hash: {}", hex(&claimed.0)).unwrap();
        seals += 1;
    }
    writeln!(out, "receipt: {}", field(&fields, "receipt")?).unwrap();
    writeln!(out, "receipt_hash: {}", field(&fields, "receipt_hash")?).unwrap();
    Ok(out)
}

fn render(what: fn(&str) -> Result<String, String>) -> String {
    let mut out = String::new();
    for (name, text) in VECTORS {
        out.push_str("vector: ");
        out.push_str(name);
        out.push('\n');
        match what(text) {
            Ok(body) => out.push_str(&body),
            Err(error) => {
                out.push_str("error: ");
                out.push_str(&error);
                out.push('\n');
            }
        }
        out.push('\n');
    }
    out
}

/// The replayed rendering of every committed vector, in file order.
#[must_use]
pub fn run_corpus() -> String {
    render(replay)
}

/// The committed expectations in the same shape as [`run_corpus`].
#[must_use]
pub fn expected_corpus() -> String {
    render(committed)
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::wasm_bindgen;

    /// The replayed rendering, for the Node driver.
    #[wasm_bindgen]
    pub fn run_corpus() -> String {
        super::run_corpus()
    }

    /// The committed expectations, for the Node driver.
    #[wasm_bindgen]
    pub fn expected_corpus() -> String {
        super::expected_corpus()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_native_replay_reproduces_every_committed_session_vector() {
        assert_eq!(super::VECTORS.len(), 2);
        let observed = super::run_corpus();
        assert!(!observed.contains("error: "), "{observed}");
        assert_eq!(observed, super::expected_corpus());
    }
}
