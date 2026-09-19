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

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_game_platonik::ids::CheckpointHash;
use vhalla_game_platonik::manifest::{MAX_REPLAYS, MAX_SESSION_EVENTS};
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, MAX_RECORD_BYTES};
use vhalla_game_platonik::session::Session;
use vhalla_game_platonik::wire::{
    decode_game_event, decode_game_manifest, decode_session_open, EventBody, SessionOpen,
    MAX_GAME_MANIFEST_BYTES, MAX_SESSION_OPEN_BYTES,
};
use vhalla_witness::vectors::{hex, unhex};

pub const HELP: &str = "Experimental Platonik session replay (build: --features experimental-game):
vhalla game replay BUNDLE [--max-work N] [--max-replays N]
  Reads a regular, non-symlink bundle of at most 64 MiB in the frozen
  `key: value` format. At most 1024 signed records are admitted, with no
  duplicate fields. Every signature and checkpoint is independently checked.
  The operator's defaults are 10000000 total replay work and 64 replays;
  explicit positive limits can replace them, up to 64 replays. The stricter
  of these limits and the session's declared limits always applies.
  The receipt hash comes from the receiver's already-budgeted final replay.
  Exit status is zero only when the complete bundle verifies.";

const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELDS: usize = 32 + MAX_SESSION_EVENTS as usize * 16;
const MAX_LINE_BYTES: usize = MAX_RECORD_BYTES * 2 + 256;
const DEFAULT_MAX_WORK: u64 = 10_000_000;

fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: MAX_REPLAYS,
        max_work: DEFAULT_MAX_WORK,
        max_steps: u64::from(MAX_SESSION_EVENTS),
    }
}

/// Bounded fields borrow their input; annotations never duplicate large strings.
struct Bundle<'a> {
    fields: BTreeMap<&'a str, &'a str>,
}

impl<'a> Bundle<'a> {
    fn parse(text: &'a str) -> Result<Self, String> {
        if text.len() > MAX_BUNDLE_BYTES {
            return Err("bundle exceeds 64 MiB".into());
        }
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            if line.len() > MAX_LINE_BYTES {
                return Err("bundle field exceeds the record byte limit".into());
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once(": ")
                .ok_or("bundle lines must be key: value fields")?;
            if key.is_empty() || key.len() > 128 || fields.len() >= MAX_FIELDS {
                return Err("bundle has an invalid field name or too many fields".into());
            }
            if fields.insert(key, value).is_some() {
                return Err(format!("duplicate bundle field: {key}"));
            }
        }
        Ok(Self { fields })
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).copied()
    }
    fn field(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .ok_or_else(|| format!("the bundle has no {key} field"))
    }
    fn raw(&self, key: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
        let value = self.field(key)?;
        if value.len() > max_bytes * 2 {
            return Err(format!("the bundle's {key} exceeds its byte limit"));
        }
        unhex(value).ok_or_else(|| format!("the bundle's {key} is not hex"))
    }
    fn record_count(&self) -> Result<usize, String> {
        let count: usize = self
            .field("record_count")?
            .parse()
            .map_err(|_| "the bundle's record_count is not a number")?;
        if count == 0 || count > MAX_SESSION_EVENTS as usize {
            return Err("record_count must be between 1 and 1024".into());
        }
        for key in self.fields.keys() {
            if let Some(rest) = key.strip_prefix("record[") {
                let (index, _) = rest.split_once("].").ok_or("invalid record field name")?;
                let parsed: usize = index.parse().map_err(|_| "invalid record field index")?;
                if parsed >= count || parsed.to_string() != index {
                    return Err("record field index is outside record_count".into());
                }
            }
        }
        Ok(count)
    }
}

fn read_bundle(path: &OsString) -> Result<String, String> {
    // Nonblocking descriptor validation avoids hanging on a FIFO or a path swap.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| format!("the bundle could not be opened: {error}"))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_BUNDLE_BYTES as u64 {
        return Err("bundle must be a regular file of at most 64 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BUNDLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the bundle could not be read: {error}"))?;
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err("bundle exceeds 64 MiB".into());
    }
    String::from_utf8(bytes).map_err(|_| "bundle is not UTF-8".into())
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

pub fn run(args: Vec<OsString>) -> Result<(), String> {
    let usage = "usage: vhalla game replay BUNDLE [--max-work N] [--max-replays N]";
    if args.len() == 2 && (args[1] == "--help" || args[1] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() < 3 || args[1] != "replay" || !(args.len() - 3).is_multiple_of(2) {
        return Err(usage.into());
    }
    let mut policy = policy();
    let mut seen = std::collections::BTreeSet::new();
    for pair in args[3..].as_chunks::<2>().0 {
        let flag = pair[0].to_str().ok_or(usage)?;
        let value: u64 = pair[1]
            .to_str()
            .and_then(|s| s.parse().ok())
            .filter(|n| *n > 0)
            .ok_or("replay limits must be positive integers")?;
        if !seen.insert(flag) {
            return Err(format!("duplicate option: {flag}"));
        }
        match flag {
            "--max-work" => policy.max_work = value,
            "--max-replays" if value <= u64::from(MAX_REPLAYS) => policy.max_replays = value as u32,
            _ => return Err(usage.into()),
        }
    }
    let text = read_bundle(&args[2])?;
    replay(&Bundle::parse(&text)?, policy)
}

fn replay(bundle: &Bundle<'_>, policy: ReceiverPolicy) -> Result<(), String> {
    let manifest_raw = bundle.raw("game_manifest", MAX_GAME_MANIFEST_BYTES)?;
    let manifest = decode_game_manifest(&manifest_raw)
        .map_err(|error| format!("the game manifest does not decode: {error:?}"))?;
    let open_raw = bundle.raw("session_open", MAX_SESSION_OPEN_BYTES)?;
    let open = decode_session_open(&open_raw)
        .map_err(|error| format!("the session opening does not decode: {error:?}"))?;
    let realm = open.realm;
    println!("manifest {}", hex(&manifest.hash().0));
    println!("{}", context(&open));
    let mut session = Session::open(manifest, open, realm)
        .map_err(|error| format!("the session does not open: {error:?}"))?;
    println!("session {}", hex(&session.key().0));
    println!("host {}", hex(&session.host()));
    let mut receiver = Receiver::new(PlatonikV1, policy);

    let records = bundle.record_count()?;
    let mut receipt_hash = None;
    let mut seals = 0_usize;
    for index in 0..records {
        let record_raw = bundle.raw(&format!("record[{index}].record"), MAX_RECORD_BYTES)?;
        let record = GameRecord::decode(&record_raw)
            .map_err(|error| format!("record {index} does not decode: {error:?}"))?;
        record
            .verify()
            .map_err(|error| format!("record {index} is not correctly signed: {error:?}"))?;
        let event = decode_game_event(&record.body)
            .map_err(|error| format!("record {index} does not decode: {error:?}"))?;
        let kind = kind_of(&event.body);
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
        if let Some(hash) = verified.final_receipt_hash() {
            receipt_hash = Some(hash.0);
        }
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
    let receipt_hash = receipt_hash.ok_or("the bundle carries no final seal")?;
    println!("receipt {}", hex(&receipt_hash));
    if let Some(claimed) = bundle.get("receipt_hash") {
        if claimed != hex(&receipt_hash) {
            return Err("the replayed receipt is not the one the bundle claims".into());
        }
    }
    println!("verified {records} records {seals} seals");
    Ok(())
}
