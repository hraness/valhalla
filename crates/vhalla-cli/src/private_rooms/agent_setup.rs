//! Trusted local grant preparation. Never reachable through the agent's RPC.
use super::{hex, now, Args, RoomSession};
use serde_json::{json, Value};
use std::{io::ErrorKind, path::Path};
use vhalla_private_native::client::agent_rpc::LaunchGrant;

pub(super) fn execute(args: &Args, room: &RoomSession) -> Result<(), String> {
    let status = room
        .status()
        .map_err(|_| "agent grant requires current room custody")?;
    let queue = match args.text("mode")? {
        "read-only" => false,
        "read-write" => true,
        _ => return Err("agent mode must be read-only or read-write".into()),
    };
    let follow = match args.flags.get("follow-inbox") {
        None => false,
        Some(value) if value == "true" => true,
        Some(value) if value == "false" => false,
        _ => return Err("follow-inbox must be explicitly true or false".into()),
    };
    let number = |name, default| -> Result<u64, String> {
        if args.flags.contains_key(name) {
            args.number(name)
        } else {
            Ok(default)
        }
    };
    let lifetime = number("lifetime", 900)?;
    if lifetime == 0 || lifetime > 86_400 {
        return Err("agent grant lifetime must be 1..86400 seconds".into());
    }
    let start = now()?;
    let expires = start.checked_add(lifetime).ok_or("grant expiry overflow")?;
    let read_records = number("max-read-records", 256)?;
    let through = number(
        "inbox-through",
        if follow {
            status
                .inbox_head
                .checked_add(read_records.min(4096))
                .ok_or("inbox ceiling overflow")?
        } else {
            status.inbox_head
        },
    )?;
    let after = number("inbox-after", 0)?;
    if after > through
        || (!follow && through > status.inbox_head)
        || through > status.inbox_head.saturating_add(4096)
    {
        return Err("inbox selection exceeds this explicit snapshot or finite follow bound".into());
    }
    // Provider fields are declarations by the trusted host, never an assurance
    // about an independently privileged CLI agent or its remote provider.
    let disclosure: Value = serde_json::from_slice(&args.input("disclosure", 8192, false)?)
        .map_err(|_| "disclosure must be a bounded private JSON file")?;
    let receipt = vhalla_custody::absolute(Path::new(args.value("receipt")?))
        .map_err(|_| "invalid agent claim path")?;
    let parent = receipt
        .parent()
        .ok_or("agent claim parent required")?
        .canonicalize()
        .map_err(|_| "agent claim parent unavailable")?;
    let receipt = parent.join(receipt.file_name().ok_or("agent claim name required")?);
    let output = vhalla_custody::absolute(Path::new(args.value("out")?))
        .map_err(|_| "invalid grant output path")?;
    let output_parent = output
        .parent()
        .ok_or("grant output parent required")?
        .canonicalize()
        .map_err(|_| "grant output parent unavailable")?;
    if receipt == output_parent.join(output.file_name().ok_or("grant output name required")?) {
        return Err("the launch grant and its one-use claim require different new paths".into());
    }
    vhalla_custody::open_private_directory(&parent)
        .map_err(|_| "agent claim parent must be owner-private 0700")?;
    match receipt.symlink_metadata() {
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        _ => return Err("agent claim must be a never-used path; preserve existing claims".into()),
    }
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|_| "secure grant ID generation unavailable")?;
    if id == [0; 16] {
        return Err("secure grant ID generation refused".into());
    }
    let context = status.context;
    let grant = json!({
        "version": 1, "grant_id": hex(&id),
        "context": {"room":hex(context.scope.room.as_bytes()), "anchor":hex(context.scope.anchor.as_bytes()),
            "account":hex(context.account.as_bytes()), "device":hex(context.device.as_bytes())},
        "epoch":status.epoch, "roster":hex(&status.roster), "not_before":start, "expires_at":expires,
        "permissions":{"inbox":true, "queue":queue, "outbox_status":true},
        "budget":{"preparations":if queue {number("max-preparations",64)?} else {0},
            "messages":if queue {number("max-messages",32)?} else {0},
            "body_bytes":if queue {number("max-body-bytes",128*1024)?} else {0},
            "read_records":read_records, "read_bytes":number("max-read-bytes",32*1024*1024)?},
        "inbox":{"after":after,"through":through,"follow":follow},
        "receipt":receipt.to_str().ok_or("agent claim path must be UTF-8")?, "disclosure":disclosure,
    });
    let bytes = serde_json::to_vec_pretty(&grant).map_err(|_| "grant encoding failed")?;
    LaunchGrant::decode(&bytes).map_err(|_| "grant or disclosure refused; check finite budgets and explicit cooperating-host acknowledgment")?;
    // This only prepares reviewed configuration. The one-use claim is created
    // atomically by agent-serve immediately before any agent access is granted.
    args.output(&bytes)
}
