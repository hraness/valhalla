//! The `rooms submit` command: the scriptable sibling of `rooms tui`.
//!
//! `vhalla rooms submit SOCIAL_STORE REPLICA_HOME REALM NODE_HOME KIND
//! ARGS... --config FILE` opens the replica service, asks it for the
//! committed intent context, signs in-process from the named identity
//! directories, and drops a canonical `*.body` into the node's intake.
//! The command never touches the local rooms store — the node's
//! committed registry is the only authority — and reports the pending
//! marker, not a success claim.

use std::path::Path;

use vhalla_rooms_app::{Service, ServiceConfig};
use vhalla_rooms_tui::{form, sign, CREATE_LABELS, DESCRIBE_LABELS};

use crate::rooms::Args;

/// The pure half of the replica prelude: --config and NODE_HOME must be
/// present, the file must parse, and its realm must match — no I/O yet,
/// so callers can finish argument validation before opening anything.
/// `command` names the caller for error text.
fn service_target<'a>(args: &'a Args, command: &str) -> Result<(&'a str, ServiceConfig), String> {
    let config_path = args
        .config
        .as_deref()
        .ok_or_else(|| format!("{command} needs --config FILE"))?;
    let node_home = args
        .value(0)
        .ok_or_else(|| format!("{command} takes NODE_HOME; see vhalla rooms --help"))?;
    let raw = std::fs::read(config_path).map_err(|e| format!("config: {e}"))?;
    let config = ServiceConfig::parse(&raw).map_err(|e| e.to_string())?;
    if config.realm_id().map_err(|e| e.to_string())? != args.realm {
        return Err("config realm does not match the REALM argument".into());
    }
    Ok((node_home, config))
}

/// Open the caller-owned replica for a validated target and sync it to
/// the node's latest committed journal height.
fn connect(args: &Args, node_home: &str, config: &ServiceConfig) -> Result<Service, String> {
    let mut service = Service::open(
        Path::new(&args.social_store),
        Path::new(node_home),
        Path::new(&args.rooms_store),
        config,
    )
    .map_err(|e| e.to_string())?;
    // The context must reflect the node's latest committed state, not the
    // replica's last sync.
    service.sync().map_err(|e| e.to_string())?;
    Ok(service)
}

/// The replica prelude every NODE_HOME-backed command shares: validate
/// the target, open the replica, sync to the node's committed height.
fn open_service(args: &Args, command: &str) -> Result<Service, String> {
    let (node_home, config) = service_target(args, command)?;
    connect(args, node_home, &config)
}

/// Opens the replica, signs the requested operation, drops the body.
pub fn run(args: &Args) -> Result<(), String> {
    // Argument precedence is user-visible: --config, then NODE_HOME, then
    // the kind — and nothing is opened until all three validate.
    let (node_home, config) = service_target(args, "submit")?;
    let kind = args
        .value(1)
        .ok_or("submit takes a kind: create | describe | archive")?;
    let mut service = connect(args, node_home, &config)?;
    let now = args.now();

    let (evidence, records) = match kind {
        "create" => {
            // OWNER_KEYDIR AGENT_KEYDIR OWNER64 AGENT64 SLUG EXPIRY
            // DESCRIPTION [EVIDENCE_CSV]
            let v: Vec<&str> = (2..10).filter_map(|i| args.value(i)).collect();
            if v.len() < 7 || args.value(10).is_some() {
                return Err(
                    "submit create takes OWNER_KEYDIR AGENT_KEYDIR OWNER64 AGENT64 SLUG EXPIRY DESCRIPTION [EVIDENCE_CSV]"
                        .into(),
                );
            }
            let mut f = form("create a room", &CREATE_LABELS);
            // CREATE_LABELS order: slug, description, expires, owner,
            // agent, owner_key, agent_key, evidence.
            f.fields[0].value = v[4].into();
            f.fields[1].value = v[6].into();
            f.fields[2].value = v[5].into();
            f.fields[3].value = v[2].into();
            f.fields[4].value = v[3].into();
            f.fields[5].value = v[0].into();
            f.fields[6].value = v[1].into();
            f.fields[7].value = v.get(7).copied().unwrap_or("-").into();
            sign::create_body(&f, now, &mut service)?
        }
        "describe" => {
            // OWNER_KEYDIR SLUG EXPIRY DESCRIPTION
            let key_dir = args.value(2).ok_or("describe takes OWNER_KEYDIR")?;
            let slug = args.value(3).ok_or("describe takes SLUG")?;
            let expiry = args.value(4).ok_or("describe takes EXPIRY")?;
            let text = args.value(5).ok_or("describe takes DESCRIPTION")?;
            if args.value(6).is_some() {
                return Err("describe takes exactly OWNER_KEYDIR SLUG EXPIRY DESCRIPTION".into());
            }
            let mut f = form("describe room", &DESCRIBE_LABELS);
            f.fields[0].value = text.into();
            f.fields[1].value = expiry.into();
            f.fields[2].value = key_dir.into();
            (
                Vec::new(),
                vec![sign::describe_body(slug, &f, now, &mut service)?],
            )
        }
        "archive" => {
            // OWNER_KEYDIR SLUG
            let key_dir = args.value(2).ok_or("archive takes OWNER_KEYDIR")?;
            let slug = args.value(3).ok_or("archive takes SLUG")?;
            if args.value(4).is_some() {
                return Err("archive takes exactly OWNER_KEYDIR SLUG".into());
            }
            (
                Vec::new(),
                vec![sign::archive_body(slug, key_dir, now, &mut service)?],
            )
        }
        _ => return Err("submit kind must be create, describe or archive".into()),
    };

    let marker = service
        .submit_body(now, evidence, records)
        .map_err(|e| e.to_string())?;
    crate::rooms::emit(crate::json::object(vec![
        ("queued", "true".into()),
        ("marker", crate::json::string(&marker)),
    ]))
}

/// One pending marker's JSON row — shared by `pending` and `status`.
fn pending_row(p: &vhalla_rooms_app::Pending) -> String {
    crate::json::object(vec![
        ("marker", crate::json::string(&p.name)),
        (
            "slug",
            crate::json::optional(p.slug.as_deref(), crate::json::string),
        ),
        (
            "state",
            crate::json::string(match p.state {
                vhalla_rooms_app::PendingState::Queued => "queued",
                vhalla_rooms_app::PendingState::Submitted => "submitted",
                vhalla_rooms_app::PendingState::Committed => "committed",
                vhalla_rooms_app::PendingState::Collision => "collision",
                vhalla_rooms_app::PendingState::Rejected => "rejected",
            }),
        ),
        (
            "reason",
            crate::json::optional(p.reason.as_deref(), crate::json::string),
        ),
    ])
}

/// JSON object for the validator set active at the committed height.
fn quorum_row(q: &vhalla_rooms_app::Quorum) -> String {
    let validators: Vec<String> = q
        .validators
        .iter()
        .map(|(key, power)| {
            crate::json::object(vec![
                ("publicKey", crate::json::string(key)),
                ("power", power.to_string()),
            ])
        })
        .collect();
    crate::json::object(vec![
        ("height", q.height.to_string()),
        ("totalPower", q.total_power.to_string()),
        ("threshold", q.threshold.to_string()),
        ("validators", crate::json::array(validators)),
    ])
}

/// `rooms pending` — syncs the replica and reports every local marker's
/// resolution: the operator-visible counterpart of the TUI pending strip.
pub fn pending(args: &Args) -> Result<(), String> {
    let service = open_service(args, "pending")?;
    let height = service.height();
    let pending = service.pending().map_err(|e| e.to_string())?;
    let rows: Vec<String> = pending.iter().map(pending_row).collect();
    crate::rooms::emit(crate::json::object(vec![
        ("height", height.to_string()),
        ("pending", crate::json::array(rows)),
    ]))
}

/// `rooms status` — one-shot live-mesh observation: syncs the replica
/// and reports committed height, the directory's room listing and every
/// local marker's resolution in a single object. This is the read path a
/// running node allows — `rooms list` cannot touch `NODE_HOME/app/rooms`
/// while the node holds its writer lock, so operators keep a REPLICA_HOME
/// and point `status` at it.
pub fn status(args: &Args) -> Result<(), String> {
    let service = open_service(args, "status")?;
    let height = service.height();
    let pending = service.pending().map_err(|e| e.to_string())?;
    let page = service
        .registry()
        .search("", args.limit, vhalla_rooms::registry::MAX_ROOMS)
        .map_err(crate::rooms::rooms_error)?;
    let rooms: Vec<String> = page
        .rooms
        .iter()
        .map(|room| {
            crate::json::object(vec![
                ("slug", crate::json::string(room.slug().as_str())),
                ("genesis", crate::json::id(room.genesis().as_bytes())),
                ("owner", crate::json::id(room.owner().as_bytes())),
                (
                    "description",
                    crate::json::string(room.description().as_str()),
                ),
                ("createdAt", room.created_at().to_string()),
            ])
        })
        .collect();
    let quorum = crate::json::optional(service.quorum().as_ref(), quorum_row);
    crate::rooms::emit(crate::json::object(vec![
        ("height", height.to_string()),
        ("revision", page.revision.to_string()),
        ("partial", page.partial.to_string()),
        ("quorum", quorum),
        ("rooms", crate::json::array(rooms)),
        (
            "pending",
            crate::json::array(pending.iter().map(pending_row)),
        ),
    ]))
}
