//! Explicit local experimental room-directory commands; no network admission.
//!
//! Every mutating command signs a real room wire record, applies it to a
//! candidate `Registry` through the authority adapter and commits the whole
//! snapshot through `vhalla-rooms-store`'s pin compare-and-swap. A process
//! never edits the pinned state in place: a torn publication leaves an intent
//! for `rooms recover`, and a rewound or divergent candidate conflicts.

use crate::json;
use std::{
    ffi::OsString,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_rooms::{
    registry::{Applied, DirectoryPolicy, Registry, RegistryError},
    CreateAction, CreationIntent, Description, DirectoryId, PolicyId, RoomControl, RoomRecordId,
    RoomUpdate, Slug, UpdateAction,
};
use vhalla_rooms_store::Store as RoomStore;
use vhalla_social::{control::ControlView, AgentId, OwnerId, RecordId};
use vhalla_social_store::Store as SocialStore;

pub const HELP: &str = "Experimental local room directory (build: --features experimental-rooms):
vhalla rooms COMMAND SOCIAL_STORE ROOMS_STORE REALM32HEX [arguments] [--now SECONDS]
  init DIRECTORY64 BASE_COST WINDOW_SEC MAX_IN_WINDOW EPOCH_SEC MAX_LIFETIME [ELIGIBLE_OWNER_CSV]
  grant OWNER_KEYDIR OWNER64 AGENT64 AGENT_KEY64 EXPIRY MAX_CHARGE
  collect
  quote OWNER64
  create OWNER_KEYDIR AGENT_KEYDIR OWNER64 AGENT64 GRANT64 SLUG EXPIRY DESCRIPTION
  describe OWNER_KEYDIR SLUG EXPIRY TEXT
  archive OWNER_KEYDIR SLUG EXPIRY
  list | search QUERY | show SLUG | account OWNER64 | proof RECORD64 | evidence RECORD64 | recover
  node NODE_HOME --config FILE  (build: --features experimental-rooms-node)
  tui REPLICA_HOME NODE_HOME --config FILE  (build: --features experimental-rooms-tui)
SOCIAL_STORE is an existing `vhalla social` store; ROOMS_STORE is created by `init`.
IDs are full hex. Slot and charge are computed from the current policy quote.
Read paging: --limit N (1..64). Output is ASCII JSON. The directory clock is
--now or the local clock; admission still requires the current social basis.
`node` hosts a room-consensus validator: NODE_HOME holds its journal, WAL and
application store; --config names a JSON file with node_key (hex seed), port,
peers, validators, directory, policy, eligible owners and archive limits.
Producers submit canonical batches by dropping *.batch files into
NODE_HOME/intake/; committed state is queryable through the store commands.";

pub(crate) struct Args {
    command: String,
    pub(crate) social_store: String,
    /// The rooms store path — for `node`, the validator's home directory.
    pub(crate) rooms_store: String,
    pub(crate) realm: RealmId,
    values: Vec<String>,
    now: u64,
    limit: usize,
    pub(crate) config: Option<String>,
}
impl Args {
    fn parse(raw: Vec<OsString>) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut now = None;
        let mut limit = 32usize;
        let mut config = None;
        let mut literal = false;
        let mut args = raw.into_iter().skip(1);
        while let Some(raw) = args.next() {
            if raw.len() > vhalla_social::MAX_RECORD_BYTES {
                return Err("argument exceeds 8192 bytes".into());
            }
            let value = raw
                .into_string()
                .map_err(|_| "rooms arguments must be UTF-8")?;
            if !literal && value == "--" {
                literal = true;
                continue;
            }
            if !literal && value.starts_with("--") {
                let option = args
                    .next()
                    .ok_or("option needs a value")?
                    .into_string()
                    .map_err(|_| "option must be UTF-8")?;
                match value.as_str() {
                    "--now" => now = Some(option.parse::<u64>().map_err(|_| "invalid --now")?),
                    "--limit" => {
                        limit = option.parse::<usize>().map_err(|_| "invalid --limit")?;
                        if limit == 0 || limit > 64 {
                            return Err("limit must be 1..64".into());
                        }
                    }
                    "--config" => config = Some(option),
                    _ => return Err("unknown rooms option".into()),
                }
            } else {
                values.push(value);
            }
        }
        if values.len() < 4 {
            return Err(HELP.into());
        }
        let command = values.remove(0);
        let social_store = values.remove(0);
        let rooms_store = values.remove(0);
        let realm = RealmId(hex128(&values.remove(0))?);
        Ok(Self {
            command,
            social_store,
            rooms_store,
            realm,
            values,
            now: match now {
                Some(now) => now,
                None => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "clock before Unix epoch")?
                    .as_secs(),
            },
            limit,
            config,
        })
    }
    fn count(&self, n: usize) -> Result<(), String> {
        if self.values.len() == n {
            Ok(())
        } else {
            Err(format!(
                "wrong argument count for {}; see vhalla rooms --help",
                self.command
            ))
        }
    }
    fn get(&self, n: usize) -> Result<&str, String> {
        self.values
            .get(n)
            .map(String::as_str)
            .ok_or_else(|| "missing argument".into())
    }
    /// The agreed clock (`--now` or local); used by sibling service
    /// modules that need the same admission clock.
    #[cfg(feature = "experimental-rooms-tui")]
    pub(crate) fn now(&self) -> u64 {
        self.now
    }
    /// Positional arguments after the fixed four.
    #[cfg(feature = "experimental-rooms-tui")]
    pub(crate) fn value(&self, n: usize) -> Option<&str> {
        self.values.get(n).map(String::as_str)
    }
}

fn hex128(text: &str) -> Result<u128, String> {
    let raw = hex_decode(text)?;
    if raw.len() != 16 {
        return Err("expected 32 hex characters".into());
    }
    Ok(u128::from_be_bytes(raw.try_into().unwrap()))
}

pub(crate) fn hex32(text: &str) -> Result<[u8; 32], String> {
    let raw = hex_decode(text)?;
    raw.try_into()
        .map_err(|_| "expected 64 hex characters".to_string())
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected hex".into());
    }
    Ok((0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect())
}

fn identity(path: &str) -> Result<Identity, String> {
    Identity::open(path).map_err(|e| format!("identity: {e:?}"))
}

fn rooms_error(error: RegistryError) -> String {
    format!("registry: {error:?}")
}

fn open_social(args: &Args) -> Result<SocialStore, String> {
    SocialStore::open(
        &args.social_store,
        args.realm,
        vhalla_social::archive::Limits::default(),
        None,
    )
    .map_err(|e| e.to_string())
}

fn open_rooms(args: &Args) -> Result<RoomStore, String> {
    RoomStore::open(&args.rooms_store, None).map_err(|e| e.to_string())
}

/// The owner's accepted social head under the agreed clock, or a denied path.
fn owner_head(
    archive: &vhalla_social::archive::Archive,
    now: u64,
    owner: OwnerId,
    key: &Identity,
) -> Result<RecordId, String> {
    let view = ControlView::new(archive, now);
    let status = view.owner(owner).ok_or("owner missing from social store")?;
    if status.frozen() || status.incomplete() || status.capacity_blocked() {
        return Err("owner authority is frozen, incomplete or capacity-blocked".into());
    }
    if status.key() != Some(key.public_key()) {
        return Err("key directory does not control that owner".into());
    }
    status
        .head()
        .ok_or_else(|| "owner has no accepted head".into())
}

type Fields = Vec<(&'static str, String)>;

fn commit(store: &mut RoomStore, candidate: Registry) -> Result<Fields, String> {
    let published = store
        .commit(candidate, store.pin())
        .map_err(|e| e.to_string())?;
    Ok(vec![
        ("durable", "true".into()),
        ("generation", published.pin().generation().to_string()),
        ("root", json::id(&published.pin().logical())),
        ("reconciled", published.reconciled().to_string()),
    ])
}

fn apply_and_commit(
    store: &mut RoomStore,
    archive: &vhalla_social::archive::Archive,
    record: &vhalla_rooms::SignedRecord,
    now: u64,
) -> Result<(Applied, Fields), String> {
    let verified = record
        .clone()
        .verify()
        .map_err(|e| format!("wire: {e:?}"))?;
    let mut candidate = store.registry().clone();
    let view = ControlView::new(archive, now);
    let applied = candidate
        .apply(&verified, &view, now)
        .map_err(rooms_error)?;
    drop(view);
    let fields = commit(store, candidate)?;
    Ok((applied, fields))
}

pub fn run(raw: Vec<OsString>) -> Result<(), String> {
    if raw.len() == 2 && (raw[1] == "--help" || raw[1] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let args = Args::parse(raw)?;
    if args.command == "node" {
        #[cfg(feature = "experimental-rooms-node")]
        {
            return crate::rooms_node::run(&args);
        }
        #[cfg(not(feature = "experimental-rooms-node"))]
        {
            return Err(format!(
                "rooms node needs --features experimental-rooms-node{}",
                if args.config.is_some() {
                    " (config ignored)"
                } else {
                    ""
                }
            ));
        }
    }
    if args.command == "tui" {
        #[cfg(feature = "experimental-rooms-tui")]
        {
            return crate::rooms_tui::run(&args);
        }
        #[cfg(not(feature = "experimental-rooms-tui"))]
        {
            return Err(format!(
                "rooms tui needs --features experimental-rooms-tui{}",
                if args.config.is_some() {
                    " (config ignored)"
                } else {
                    ""
                }
            ));
        }
    }
    if args.command == "init" {
        if args.values.len() != 6 && args.values.len() != 7 {
            return Err(
                "init takes DIRECTORY64 BASE WINDOW MAXWIN EPOCH LIFETIME [ELIGIBLE]".into(),
            );
        }
        let policy = DirectoryPolicy {
            base_cost: args.get(1)?.parse().map_err(|_| "invalid base cost")?,
            window_seconds: args.get(2)?.parse().map_err(|_| "invalid window")?,
            max_in_window: args.get(3)?.parse().map_err(|_| "invalid max-in-window")?,
            support_epoch_seconds: args.get(4)?.parse().map_err(|_| "invalid epoch")?,
            max_lifetime_rooms: args.get(5)?.parse().map_err(|_| "invalid lifetime")?,
        };
        let eligible: Vec<OwnerId> = match args.values.get(6).map_or("-", String::as_str) {
            "-" => Vec::new(),
            csv => csv
                .split(',')
                .take(256)
                .map(|id| hex32(id).map(OwnerId::from_bytes))
                .collect::<Result<_, _>>()?,
        };
        if std::fs::symlink_metadata(&args.rooms_store).is_ok() {
            return Err("init requires a nonexistent rooms store path".into());
        }
        let store = RoomStore::create(
            &args.rooms_store,
            DirectoryId::from_bytes(hex32(args.get(0)?)?),
            args.realm,
            policy,
            &eligible,
        )
        .map_err(|e| e.to_string())?;
        return emit(json::object(vec![
            ("durable", "true".into()),
            ("generation", store.pin().generation().to_string()),
            ("policy", json::id(policy.id().as_bytes())),
            ("directory", json::string(args.get(0)?)),
        ]));
    }
    let social = open_social(&args)?;
    if social.recovery_required().map_err(|e| e.to_string())? {
        return Err("social store requires explicit social recover first".into());
    }
    let mut rooms = open_rooms(&args)?;
    if args.command != "recover" && rooms.recovery_required().map_err(|e| e.to_string())? {
        return Err("retained publication requires explicit rooms recover first".into());
    }
    let archive = social.archive();
    let output = match args.command.as_str() {
        "grant" => {
            args.count(6)?;
            let owner_key = identity(args.get(0)?)?;
            let owner = OwnerId::from_bytes(hex32(args.get(1)?)?);
            let registry = rooms.registry();
            let control = RoomControl {
                directory: registry.directory(),
                realm: args.realm,
                owner,
                social_control: owner_head(archive, args.now, owner, &owner_key)?,
                controller_key: owner_key.public_key(),
                previous: registry.authority().head(owner),
                sequence: registry.authority().sequence(owner),
                action: CreateAction::GrantCreate {
                    agent: AgentId::from_bytes(hex32(args.get(2)?)?),
                    agent_key: hex32(args.get(3)?)?,
                    expires_at: args.get(4)?.parse().map_err(|_| "invalid expiry")?,
                    maximum_charge: args.get(5)?.parse().map_err(|_| "invalid maximum charge")?,
                    nonce: nonce()?,
                },
            };
            let record = owner_key
                .sign_room_control(control)
                .map_err(|e| format!("sign: {e:?}"))?;
            let (applied, mut fields) = apply_and_commit(&mut rooms, archive, &record, args.now)?;
            debug_assert_eq!(applied, Applied::Control);
            fields.push(("record", json::id(record.id().as_bytes())));
            json::object(fields)
        }
        "collect" => {
            args.count(0)?;
            let mut candidate = rooms.registry().clone();
            let view = ControlView::new(archive, args.now);
            let (mut awarded, mut duplicate) = (0u64, 0u64);
            for record in archive.records() {
                match candidate.award(record, &view, args.now) {
                    Ok(Applied::Awarded) => awarded += 1,
                    Ok(Applied::DuplicateAward) => duplicate += 1,
                    _ => {}
                }
            }
            drop(view);
            let mut fields = vec![
                ("awarded", awarded.to_string()),
                ("duplicate", duplicate.to_string()),
            ];
            if candidate.revision() != rooms.registry().revision() {
                fields.extend(commit(&mut rooms, candidate)?);
            } else {
                fields.push(("durable", "true".into()));
            }
            json::object(fields)
        }
        "quote" => {
            args.count(1)?;
            let owner = OwnerId::from_bytes(hex32(args.get(0)?)?);
            let (slot, cost) = rooms.registry().quote(owner).map_err(rooms_error)?;
            let account = rooms.registry().account(owner);
            json::object(vec![
                ("slot", slot.to_string()),
                ("cost", cost.to_string()),
                ("earned", account.earned.to_string()),
                ("spent", account.spent.to_string()),
                ("lifetimeSlots", account.lifetime_slots.to_string()),
            ])
        }
        "create" => {
            args.count(8)?;
            let owner_key = identity(args.get(0)?)?;
            let agent_key = identity(args.get(1)?)?;
            let owner = OwnerId::from_bytes(hex32(args.get(2)?)?);
            let registry = rooms.registry();
            let (slot, charge) = registry.quote(owner).map_err(rooms_error)?;
            let intent = CreationIntent {
                directory: registry.directory(),
                realm: args.realm,
                policy: registry.policy().id(),
                initial_settings: default_settings(),
                owner,
                agent: AgentId::from_bytes(hex32(args.get(3)?)?),
                owner_key: owner_key.public_key(),
                agent_key: agent_key.public_key(),
                social_control: owner_head(archive, args.now, owner, &owner_key)?,
                room_control: registry
                    .authority()
                    .head(owner)
                    .ok_or("owner has no room-control chain; grant first")?,
                grant: RoomRecordId::from_bytes(hex32(args.get(4)?)?),
                slug: Slug::new(args.get(5)?).map_err(|e| format!("slug: {e:?}"))?,
                description: Description::new(args.get(7)?)
                    .map_err(|e| format!("description: {e:?}"))?,
                slot,
                charge,
                expires_at: args.get(6)?.parse().map_err(|_| "invalid expiry")?,
                nonce: nonce()?,
            };
            let permit = owner_key
                .sign_room_permit(intent)
                .map_err(|e| format!("sign: {e:?}"))?;
            let record = agent_key
                .sign_room_proposal(permit)
                .map_err(|e| format!("sign: {e:?}"))?;
            let (applied, mut fields) = apply_and_commit(&mut rooms, archive, &record, args.now)?;
            let genesis = match applied {
                Applied::Created(id) | Applied::Existing(id) => id,
                _ => return Err("unexpected apply result".into()),
            };
            fields.push(("genesis", json::id(genesis.as_bytes())));
            fields.push(("record", json::id(record.id().as_bytes())));
            fields.push(("slot", slot.to_string()));
            fields.push(("charge", charge.to_string()));
            json::object(fields)
        }
        "describe" | "archive" => {
            let owner_key = identity(args.get(0)?)?;
            let slug = Slug::new(args.get(1)?).map_err(|e| format!("slug: {e:?}"))?;
            let expires_at: u64 = args.get(2)?.parse().map_err(|_| "invalid expiry")?;
            let room = rooms
                .registry()
                .room(&slug)
                .ok_or("room missing from this directory")?;
            let update = RoomUpdate {
                directory: rooms.registry().directory(),
                realm: args.realm,
                genesis: room.genesis(),
                previous: room.head(),
                owner: room.owner(),
                social_control: owner_head(archive, args.now, room.owner(), &owner_key)?,
                controller_key: owner_key.public_key(),
                expires_at,
                nonce: nonce()?,
                action: if args.command == "describe" {
                    args.count(4)?;
                    UpdateAction::Describe(
                        Description::new(args.get(3)?)
                            .map_err(|e| format!("description: {e:?}"))?,
                    )
                } else {
                    args.count(3)?;
                    UpdateAction::Archive
                },
            };
            let record = owner_key
                .sign_room_update(update)
                .map_err(|e| format!("sign: {e:?}"))?;
            let (applied, mut fields) = apply_and_commit(&mut rooms, archive, &record, args.now)?;
            debug_assert!(matches!(applied, Applied::Updated(_)));
            fields.push(("record", json::id(record.id().as_bytes())));
            json::object(fields)
        }
        "list" | "search" => {
            let query = if args.command == "list" {
                args.count(0)?;
                ""
            } else {
                args.count(1)?;
                args.get(0)?
            };
            let page = rooms
                .registry()
                .search(query, args.limit, vhalla_rooms::registry::MAX_ROOMS)
                .map_err(rooms_error)?;
            let rooms_json: Vec<String> = page
                .rooms
                .iter()
                .map(|room| {
                    json::object(vec![
                        ("slug", json::string(room.slug().as_str())),
                        ("genesis", json::id(room.genesis().as_bytes())),
                        ("owner", json::id(room.owner().as_bytes())),
                        ("description", json::string(room.description().as_str())),
                        ("createdAt", room.created_at().to_string()),
                    ])
                })
                .collect();
            json::object(vec![
                ("rooms", json::array(rooms_json)),
                ("partial", page.partial.to_string()),
                ("retained", page.retained.to_string()),
                ("revision", page.revision.to_string()),
            ])
        }
        "show" => {
            args.count(1)?;
            let slug = Slug::new(args.get(0)?).map_err(|e| format!("slug: {e:?}"))?;
            let room = rooms
                .registry()
                .room(&slug)
                .ok_or("room missing from this directory")?;
            json::object(vec![
                ("slug", json::string(room.slug().as_str())),
                ("genesis", json::id(room.genesis().as_bytes())),
                ("owner", json::id(room.owner().as_bytes())),
                ("agent", json::id(room.intent().agent.as_bytes())),
                ("description", json::string(room.description().as_str())),
                ("slot", room.intent().slot.to_string()),
                ("charge", room.intent().charge.to_string()),
                ("head", json::id(room.head().as_bytes())),
                ("revisions", room.revisions().len().to_string()),
                ("createdAt", room.created_at().to_string()),
                ("archived", room.archived().to_string()),
            ])
        }
        "account" => {
            args.count(1)?;
            let owner = OwnerId::from_bytes(hex32(args.get(0)?)?);
            let account = rooms.registry().account(owner);
            json::object(vec![
                ("earned", account.earned.to_string()),
                ("spent", account.spent.to_string()),
                ("lifetimeSlots", account.lifetime_slots.to_string()),
            ])
        }
        "proof" => {
            args.count(1)?;
            let id = RoomRecordId::from_bytes(hex32(args.get(0)?)?);
            let bytes = rooms
                .registry()
                .source_proof(id)
                .ok_or("no retained record carries that id")?;
            json::object(vec![
                ("record", json::id(id.as_bytes())),
                ("bytes", json::id(&bytes)),
            ])
        }
        "evidence" => {
            args.count(1)?;
            let id = RecordId::from_bytes(hex32(args.get(0)?)?);
            let bytes = rooms
                .registry()
                .evidence_proof(id)
                .ok_or("no retained award evidence carries that id")?;
            json::object(vec![
                ("record", json::id(id.as_bytes())),
                ("bytes", json::id(&bytes)),
            ])
        }
        "recover" => {
            args.count(0)?;
            let publication = rooms.recover().map_err(|e| e.to_string())?;
            json::object(vec![
                ("durable", "true".into()),
                ("generation", publication.pin().generation().to_string()),
                ("root", json::id(&publication.pin().logical())),
                ("reconciled", publication.reconciled().to_string()),
            ])
        }
        _ => return Err(HELP.into()),
    };
    emit(output)
}

fn emit(output: String) -> Result<(), String> {
    // The escaped presentation has its own ceiling, separate from signed
    // payloads and query budgets. Never emit a partial JSON object on overflow.
    if output.len() > 2 * 1024 * 1024 {
        return Err("presentation exceeds 2 MiB; reduce --limit and inspect durable state".into());
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{output}")
        .and_then(|()| stdout.flush())
        .map_err(|e| format!("output failed after operation; inspect durable store: {e}"))
}

/// The empty room-settings commitment: a fixed well-known `PolicyId` for
/// callers that declare no initial room policy overrides.
fn default_settings() -> PolicyId {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"vhalla/rooms/default-settings/v1\0");
    PolicyId::from_bytes(hash.finalize().into())
}

fn nonce() -> Result<[u8; 32], String> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| "entropy source failed")?;
    Ok(nonce)
}
