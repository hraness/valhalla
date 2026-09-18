//! `vhalla game replay BUNDLE`: verify a Platonik session from a second,
//! independent point of view.
//!
//! The bundle is a session vector file in the frozen `key: value` format:
//! the game manifest, the session opening, and every signed record as hex. The
//! command holds no key, trusts no digest the bundle states, and asks the host
//! for nothing. It rebuilds the session from the bundle's bytes, opens a fresh
//! `Receiver<PlatonikV1>`, and replays every record. Each seal is re-derived by
//! running the segment itself, so the checkpoint hash printed here is the one
//! this process computed, compared afterwards with the one the bundle claims.
//! A single refusal ends the run with a non-zero exit status.

use std::ffi::OsString;

use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::ids::CheckpointHash;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::GameRecord;
use vhalla_game_platonik::session::{SealPlan, Session};
use vhalla_game_platonik::wire::{
    decode_game_event, decode_game_manifest, decode_session_open, EventBody, SessionOpen,
};
use vhalla_witness::hash::{digest, RECEIPT_DOMAIN};
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::vectors::{hex, unhex};

pub const HELP: &str = "Experimental Platonik session replay (build: --features experimental-game):
vhalla game replay BUNDLE
  BUNDLE is a session vector file in the frozen `key: value` format, carrying
  the game manifest, the session opening and every signed record as hex.
  The session is rebuilt from those bytes and replayed through a fresh
  receiver that trusts nothing the bundle claims: every signature is checked,
  every segment is re-run, and every checkpoint hash is recomputed. One line
  is printed per accepted record and per seal, then the final receipt hash and
  `verified`. The exit status is zero only when every record verified.";

/// The receiver's own budget. A bundle is a file the operator chose to read,
/// so the caps here are the session's own limits rather than a smaller local
/// policy; the receiver still takes the minimum of the two.
fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// One `key: value` bundle.
struct Bundle {
    fields: Vec<(String, String)>,
}

impl Bundle {
    fn parse(text: &str) -> Self {
        let mut fields = Vec::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once(": ") {
                fields.push((key.to_string(), value.to_string()));
            }
        }
        Self { fields }
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
    fn field(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .ok_or_else(|| format!("the bundle has no {key} field"))
    }
    fn raw(&self, key: &str) -> Result<Vec<u8>, String> {
        unhex(self.field(key)?).ok_or_else(|| format!("the bundle's {key} is not hex"))
    }
}

/// The name this command prints for an event body.
fn kind_of(body: &EventBody) -> &'static str {
    match body {
        EventBody::BindCommit { .. } => "bind-commit",
        EventBody::BindReveal { .. } => "bind-reveal",
        EventBody::BindClose { .. } => "bind-close",
        EventBody::Reveal { .. } => "reveal",
        EventBody::Input { .. } => "input",
        EventBody::Seal { .. } => "seal",
        EventBody::Replace { .. } => "replace",
        EventBody::Fill { .. } => "fill",
    }
}

/// The realm, room and epoch the opening names, in `vhalla-core`'s own types.
fn context(open: &SessionOpen) -> String {
    let realm: RealmId = open.realm;
    let room: RoomId = open.room;
    let epoch: Epoch = open.epoch;
    format!(
        "realm {:032x} room {:032x} epoch {}",
        realm.0, room.0, epoch.0
    )
}

/// The receipt the final seal's replay produces, derived here rather than read
/// from the bundle.
fn final_receipt(session: &Session, plan: &SealPlan) -> Result<Vec<u8>, String> {
    let manifest = ValidManifest::validate(plan.manifest.clone())
        .map_err(|error| format!("the segment manifest is invalid: {error:?}"))?;
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
        .map_err(|error| format!("the final segment did not replay: {error:?}"))?;
    Ok(evidence.receipt.encode())
}

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let usage = "usage: vhalla game replay BUNDLE";
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() != 3 || args[1] != "replay" {
        return Err(usage.into());
    }
    let path = &args[2];
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("the bundle could not be read: {error}"))?;
    replay(&Bundle::parse(&text))
}

fn replay(bundle: &Bundle) -> Result<(), String> {
    let manifest_raw = bundle.raw("game_manifest")?;
    let manifest = decode_game_manifest(&manifest_raw)
        .map_err(|error| format!("the game manifest does not decode: {error:?}"))?;
    let open_raw = bundle.raw("session_open")?;
    let open = decode_session_open(&open_raw)
        .map_err(|error| format!("the session opening does not decode: {error:?}"))?;
    let realm = open.realm;
    println!("manifest {}", hex(&manifest.hash().0));
    println!("{}", context(&open));
    let mut session = Session::open(manifest, open, realm)
        .map_err(|error| format!("the session does not open: {error:?}"))?;
    println!("session {}", hex(&session.key().0));
    println!("host {}", hex(&session.host()));
    let mut receiver = Receiver::new(PlatonikV1, policy());

    let records: usize = bundle
        .field("record_count")?
        .parse()
        .map_err(|_| "the bundle's record_count is not a number".to_string())?;
    let mut receipt = None;
    let mut seals = 0_usize;
    for index in 0..records {
        let record_raw = bundle.raw(&format!("record[{index}].record"))?;
        let record = GameRecord::decode(&record_raw)
            .map_err(|error| format!("record {index} does not decode: {error:?}"))?;
        record
            .verify()
            .map_err(|error| format!("record {index} is not correctly signed: {error:?}"))?;
        let event = decode_game_event(&record.body)
            .map_err(|error| format!("record {index} does not decode: {error:?}"))?;
        let kind = kind_of(&event.body);
        if matches!(event.body, EventBody::Seal { .. }) {
            let plan = session
                .plan_seal(&event)
                .map_err(|error| format!("record {index} is not a sealable order: {error:?}"))?;
            if plan.is_final {
                receipt = Some(final_receipt(&session, &plan)?);
            }
        }
        let step = index as u64 + 1;
        let verified = receiver
            .admit(&mut session, &record, step)
            .map_err(|error| format!("record {index} ({kind}) was refused: {error:?}"))?;
        println!("record {index} {kind} {}", hex(&event.digest().0));
        let Some(verified) = verified else {
            continue;
        };
        // The receiver only returns a verified checkpoint when its own replay
        // reproduced the hash the seal claims, so this hash is derived here.
        // The bundle's own copy, when it carries one, is a second check on the
        // file rather than on the session.
        let reproduced = verified.hash();
        let claimed = bundle
            .get(&format!("record[{index}].checkpoint_hash"))
            .map(|value| {
                unhex(value)
                    .filter(|raw| raw.len() == 32)
                    .ok_or_else(|| format!("record {index} checkpoint_hash is not 32 hex bytes"))
            })
            .transpose()?
            .map(|raw| {
                let mut out = [0_u8; 32];
                out.copy_from_slice(&raw);
                CheckpointHash(out)
            });
        let matched = match claimed {
            None => "unclaimed",
            Some(claimed) if claimed == reproduced => "matched",
            Some(_) => "mismatched",
        };
        println!(
            "seal {seals} segment {} through-tick {} work {}/{} checkpoint {} {matched}",
            verified.segment(),
            verified.through_tick(),
            verified.work().useful,
            verified.work().total,
            hex(&reproduced.0),
        );
        if matched == "mismatched" {
            return Err(format!(
                "seal {seals} reproduced a checkpoint the bundle does not claim"
            ));
        }
        seals += 1;
    }
    if seals == 0 {
        return Err("the bundle seals nothing, so it verifies nothing".into());
    }
    let receipt = receipt.ok_or("the bundle carries no final seal")?;
    let receipt_hash = digest(RECEIPT_DOMAIN, &receipt);
    println!("receipt {}", hex(&receipt_hash));
    if let Some(claimed) = bundle.get("receipt_hash") {
        if claimed != hex(&receipt_hash) {
            return Err("the replayed receipt is not the one the bundle claims".into());
        }
    }
    println!("verified {records} records {seals} seals");
    Ok(())
}
