//! Trusted local grant preparation. Never reachable through the agent's RPC.
//!
//! `agent-grant` mints one grant from command-line options; `agent-launch`
//! mints one grant per spawn from an operator-reviewed policy file and then
//! serves it, so an MCP registration can point at one stable command line.
use super::{agent, files, hex, now, Args, RoomSession};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    ffi::OsString,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use vhalla_custody as custody;
use vhalla_identity::Identity;
use vhalla_private_kernel::Status;
use vhalla_private_native::client::agent_rpc::LaunchGrant;

const LAUNCH_HELP: &str = "vhalla private agent-launch ID STORE --policy PRIVATE_JSON --session-dir PRIVATE_DIR [--delivery PRIVATE_JSON] (mints one fresh grant and claim per spawn from a reviewed policy, then serves it over pipes)";
const MAX_LAUNCHES: u64 = 9999;

/// Everything `agent-grant` needs, from either command options or a policy file.
pub(super) struct GrantSpec {
    queue: bool,
    follow: bool,
    lifetime: u64,
    read_records: u64,
    inbox_after: u64,
    inbox_through: Option<u64>,
    max_preparations: u64,
    max_messages: u64,
    max_body_bytes: u64,
    max_read_bytes: u64,
    disclosure: Value,
}

/// Reviewed launch policy: the same fields as `agent-grant`, kept in one 0600
/// file. `max_launches` bounds how many grants one session directory may hold.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    mode: String,
    #[serde(default)]
    follow_inbox: bool,
    lifetime: Option<u64>,
    inbox_after: Option<u64>,
    inbox_through: Option<u64>,
    max_preparations: Option<u64>,
    max_messages: Option<u64>,
    max_body_bytes: Option<u64>,
    max_read_records: Option<u64>,
    max_read_bytes: Option<u64>,
    max_launches: Option<u64>,
    disclosure: Value,
}

fn mode(text: &str) -> Result<bool, String> {
    match text {
        "read-only" => Ok(false),
        "read-write" => Ok(true),
        _ => Err("agent mode must be read-only or read-write".into()),
    }
}

impl GrantSpec {
    fn from_args(args: &Args) -> Result<Self, String> {
        let queue = mode(args.text("mode")?)?;
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
        // Provider fields are declarations by the trusted host, never an assurance
        // about an independently privileged CLI agent or its remote provider.
        let disclosure: Value = serde_json::from_slice(&args.input("disclosure", 8192, false)?)
            .map_err(|_| "disclosure must be a bounded private JSON file")?;
        Ok(Self {
            queue,
            follow,
            lifetime: number("lifetime", 900)?,
            read_records: number("max-read-records", 256)?,
            inbox_after: number("inbox-after", 0)?,
            inbox_through: args
                .flags
                .contains_key("inbox-through")
                .then(|| args.number("inbox-through"))
                .transpose()?,
            max_preparations: number("max-preparations", 64)?,
            max_messages: number("max-messages", 32)?,
            max_body_bytes: number("max-body-bytes", 128 * 1024)?,
            max_read_bytes: number("max-read-bytes", 32 * 1024 * 1024)?,
            disclosure,
        })
    }

    fn from_policy(bytes: &[u8]) -> Result<(Self, Option<u64>), String> {
        let policy: Policy = serde_json::from_slice(bytes).map_err(|_| {
            "launch policy must be a bounded private JSON file with only the documented fields"
        })?;
        if policy.version != 1 {
            return Err("launch policy version must be 1".into());
        }
        let queue = mode(&policy.mode)?;
        if !policy.disclosure.is_object() {
            return Err("launch policy disclosure must be an object".into());
        }
        Ok((
            Self {
                queue,
                follow: policy.follow_inbox,
                lifetime: policy.lifetime.unwrap_or(900),
                read_records: policy.max_read_records.unwrap_or(256),
                inbox_after: policy.inbox_after.unwrap_or(0),
                inbox_through: policy.inbox_through,
                max_preparations: policy.max_preparations.unwrap_or(64),
                max_messages: policy.max_messages.unwrap_or(32),
                max_body_bytes: policy.max_body_bytes.unwrap_or(128 * 1024),
                max_read_bytes: policy.max_read_bytes.unwrap_or(32 * 1024 * 1024),
                disclosure: policy.disclosure,
            },
            policy.max_launches,
        ))
    }

    /// Mint one grant for this exact status and never-used claim path. Refuses
    /// unsafe lifetimes, inbox ranges, budgets and disclosures identically for
    /// both entry points; the result is the exact bytes `agent-serve` decodes.
    fn mint(&self, status: Status, receipt: &Path) -> Result<Vec<u8>, String> {
        if self.lifetime == 0 || self.lifetime > 86_400 {
            return Err("agent grant lifetime must be 1..86400 seconds".into());
        }
        let start = now()?;
        let expires = start
            .checked_add(self.lifetime)
            .ok_or("grant expiry overflow")?;
        let through = match self.inbox_through {
            Some(through) => through,
            None if self.follow => status
                .inbox_head
                .checked_add(self.read_records.min(4096))
                .ok_or("inbox ceiling overflow")?,
            None => status.inbox_head,
        };
        if self.inbox_after > through
            || (!self.follow && through > status.inbox_head)
            || through > status.inbox_head.saturating_add(4096)
        {
            return Err(
                "inbox selection exceeds this explicit snapshot or finite follow bound".into(),
            );
        }
        let parent = receipt.parent().ok_or("agent claim parent required")?;
        custody::open_private_directory(parent)
            .map_err(|_| "agent claim parent must be owner-private 0700")?;
        match receipt.symlink_metadata() {
            Err(error) if error.kind() == ErrorKind::NotFound => (),
            _ => {
                return Err(
                    "agent claim must be a never-used path; preserve existing claims".into(),
                )
            }
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| "secure grant ID generation unavailable")?;
        if id == [0; 16] {
            return Err("secure grant ID generation refused".into());
        }
        let context = status.context;
        let queue = self.queue;
        let grant = json!({
            "version": 1, "grant_id": hex(&id),
            "context": {"room":hex(context.scope.room.as_bytes()), "anchor":hex(context.scope.anchor.as_bytes()),
                "account":hex(context.account.as_bytes()), "device":hex(context.device.as_bytes())},
            "epoch":status.epoch, "roster":hex(&status.roster), "not_before":start, "expires_at":expires,
            "permissions":{"inbox":true, "queue":queue, "outbox_status":true},
            "budget":{"preparations":if queue {self.max_preparations} else {0},
                "messages":if queue {self.max_messages} else {0},
                "body_bytes":if queue {self.max_body_bytes} else {0},
                "read_records":self.read_records, "read_bytes":self.max_read_bytes},
            "inbox":{"after":self.inbox_after,"through":through,"follow":self.follow},
            "receipt":receipt.to_str().ok_or("agent claim path must be UTF-8")?, "disclosure":self.disclosure,
        });
        let bytes = serde_json::to_vec_pretty(&grant).map_err(|_| "grant encoding failed")?;
        LaunchGrant::decode(&bytes).map_err(|_| "grant or disclosure refused; check finite budgets and explicit cooperating-host acknowledgment")?;
        Ok(bytes)
    }
}

fn canonical_new_path(path: &Path, what: &str) -> Result<PathBuf, String> {
    let absolute = custody::absolute(path).map_err(|_| format!("invalid {what} path"))?;
    let parent = absolute
        .parent()
        .ok_or(format!("{what} parent required"))?
        .canonicalize()
        .map_err(|_| format!("{what} parent unavailable"))?;
    Ok(parent.join(
        absolute
            .file_name()
            .ok_or(format!("{what} name required"))?,
    ))
}

pub(super) fn execute(args: &Args, room: &RoomSession) -> Result<(), String> {
    let status = room
        .status()
        .map_err(|_| "agent grant requires current room custody")?;
    let spec = GrantSpec::from_args(args)?;
    let receipt = canonical_new_path(Path::new(args.value("receipt")?), "agent claim")?;
    let output = canonical_new_path(Path::new(args.value("out")?), "grant output")?;
    if receipt == output {
        return Err("the launch grant and its one-use claim require different new paths".into());
    }
    let bytes = spec.mint(status, &receipt)?;
    // This only prepares reviewed configuration. The one-use claim is created
    // atomically by agent-serve immediately before the first tool call.
    args.output(&bytes)
}

/// `agent-launch`: mint the next numbered grant/claim pair under the session
/// directory from the reviewed policy, then serve it. Every spawn is a fresh
/// finite grant; a consumed or expired one is never reused or renewed.
pub(super) fn launch(raw: &[OsString]) -> Result<(), String> {
    if !matches!(raw.len(), 8 | 10)
        || raw[0] != "private"
        || raw[1] != "agent-launch"
        || raw[4] != "--policy"
        || raw[6] != "--session-dir"
        || raw[2].is_empty()
        || raw[3].is_empty()
        || raw[5].is_empty()
        || raw[7].is_empty()
        || (raw.len() == 10 && (raw[8] != "--delivery" || raw[9].is_empty()))
    {
        return Err(LAUNCH_HELP.into());
    }
    agent::stdio_is_piped()?;
    let (spec, max_launches) =
        GrantSpec::from_policy(&files::read(Path::new(&raw[5]), 16384, false)?)?;
    let session = custody::absolute(Path::new(&raw[7])).map_err(|_| "invalid session directory")?;
    custody::ensure_private_directory(&session)
        .map_err(|_| "session directory must be a new or owner-private 0700 directory")?;
    let session = session
        .canonicalize()
        .map_err(|_| "session directory unavailable")?;
    let mut used = 0;
    for entry in std::fs::read_dir(&session).map_err(|_| "session directory unreadable")? {
        let name = entry
            .map_err(|_| "session directory unreadable")?
            .file_name();
        let name = name.to_string_lossy();
        if let Some(n) = name
            .strip_suffix("-grant.json")
            .or_else(|| name.strip_suffix("-claim.json"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            used = used.max(n);
        }
    }
    let next = used + 1;
    if next > max_launches.unwrap_or(MAX_LAUNCHES).min(MAX_LAUNCHES) {
        return Err(
            "launch policy exhausted: prepare a new reviewed policy or session directory".into(),
        );
    }
    let grant_path = session.join(format!("{next:04}-grant.json"));
    let claim_path = session.join(format!("{next:04}-claim.json"));
    let identity_path = Path::new(&raw[2]);
    let store_path = Path::new(&raw[3]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| "private runtime unavailable")?;
    {
        let identity =
            Identity::open(identity_path).map_err(|_| "existing identity custody unavailable")?;
        let hint =
            vhalla_private_native::private_rooms::NativePrivateStore::locate_context(store_path)
                .map_err(|_| "private store unavailable")?;
        let context = super::context(hint.as_bytes())?;
        let room = runtime
            .block_on(RoomSession::open(identity, store_path, context))
            .map_err(|_| "private room custody unavailable")?;
        let status = room
            .status()
            .map_err(|_| "agent grant requires current room custody")?;
        let bytes = spec.mint(status, &claim_path)?;
        files::write(&grant_path, &bytes)?;
        // Release room custody before agent-serve reopens it exclusively.
        drop(room);
    }
    drop(runtime);
    agent::serve_paths(
        identity_path,
        store_path,
        &grant_path,
        (raw.len() == 10).then(|| Path::new(&raw[9])),
    )
}
