//! Independently configured trusted host delivery; never an agent tool.
use super::{files, hex, now, unhex};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use vhalla_custody as custody;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, Error as KernelError, MemberAcceptance, OperationId, OutboxKind,
};
use vhalla_private_native::{
    agent::Error as AgentError,
    client::{agent_rpc::RpcSession, Error as ClientError},
    relay::{
        delivery::{DeliveryStore, JobState, Limits, RetryPolicy, TickBudget},
        net::{NetError, RelayToken, ScanDirectory, ScanFailure},
        tls::TlsRelay,
        RelayItem, RelayKind, RelayNamespace, MAX_RELAY_ITEMS, MAX_RELAY_PAGE,
    },
};

const REFUSED: &str = "host delivery refused; preserve the exact room, queue, scan and applied evidence; reconcile before another explicitly granted launch";
/// Fresh staged work per tick for scan and apply alike; a page that still has
/// results repolls immediately instead of waiting out the idle interval.
const PAGE: usize = MAX_RELAY_PAGE;
/// The kernel's own record bound is smaller than a relay page: outbox drains
/// loop until an empty page, so catch-up still converges in one tick budget.
const OUTBOX_PAGE: usize = vhalla_private_kernel::MAX_PAGE_RECORDS;
const TICK: Duration = Duration::from_secs(2);
/// Relay job attempts per tick, within the store's byte and deadline budget.
const TICK_JOBS: usize = 8;
const TICK_BYTES: usize = 4 * 1024 * 1024;
/// A staged position whose kernel outcome stays transient this long is not
/// healing; the launch ends for reconciliation instead of stalling the
/// contiguous applied watermark silently.
const PENDING_MAX: Duration = Duration::from_secs(300);
/// How long one held page request may stay open on the host's relay. The
/// server clamps to its own maximum; a quiet client therefore emits at most
/// one relay exchange per minute while nothing arrives.
const WATCH_WAIT: Duration = Duration::from_secs(60);
/// One wait round trip's outer bound: the hold plus connect, handshake and
/// response time for a single exchange.
const WATCH_EXCHANGE: Duration = Duration::from_secs(30);
/// Watch worker states observed by `poll`: still holding requests, closed on
/// a transient failure (re-armed by the next proven scan), or refused the
/// waited request shape — a host that predates it stays on plain polling.
const WATCH_LIVE: u8 = 0;
const WATCH_TRANSIENT: u8 = 1;
const WATCH_UNSUPPORTED: u8 = 2;

/// One held-page mailbox watch on its own relay connection, so a tick never
/// blocks on a minute-scale wait. The worker only publishes the largest head
/// it observed; the driver re-validates through `scan_page_until`, so the
/// hint accelerates a scan but can never fabricate staged evidence.
struct Watch {
    /// Largest mailbox head the worker has observed from the relay.
    head: Arc<AtomicU64>,
    /// Driver's staged head; the worker never waits below it.
    cursor: Arc<AtomicU64>,
    /// WATCH_LIVE / WATCH_TRANSIENT / WATCH_UNSUPPORTED.
    state: Arc<AtomicU8>,
    /// Set when the driver drops or replaces this watch; the worker exits
    /// after its current exchange rather than starting another wait.
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<()>,
}
impl Watch {
    fn spawn(relay: TlsRelay, staged_head: u64) -> Self {
        let head = Arc::new(AtomicU64::new(staged_head));
        let cursor = Arc::new(AtomicU64::new(staged_head));
        let state = Arc::new(AtomicU8::new(WATCH_LIVE));
        let stop = Arc::new(AtomicBool::new(false));
        let join = thread::spawn({
            let (head, cursor, state, stop) =
                (head.clone(), cursor.clone(), state.clone(), stop.clone());
            move || {
                let mut after = staged_head;
                while !stop.load(Ordering::Acquire) {
                    after = after.max(cursor.load(Ordering::Acquire));
                    match relay.page_wait_until(
                        after,
                        1,
                        WATCH_WAIT,
                        Instant::now() + WATCH_WAIT + WATCH_EXCHANGE,
                    ) {
                        Ok(page) => {
                            head.fetch_max(page.head, Ordering::Release);
                            // Advance past observed arrivals so the next held
                            // request blocks again instead of echoing them.
                            after = after.max(page.head);
                        }
                        Err(error) => {
                            state.store(
                                match error {
                                    // Bounds means a host that predates the
                                    // bounded wait; a refused or foreign
                                    // credential cannot hold a page either.
                                    NetError::Bounds
                                    | NetError::Malformed
                                    | NetError::Denied
                                    | NetError::Scope => WATCH_UNSUPPORTED,
                                    _ => WATCH_TRANSIENT,
                                },
                                Ordering::Release,
                            );
                            return;
                        }
                    }
                }
            }
        });
        Self {
            head,
            cursor,
            state,
            stop,
            join,
        }
    }
    /// Whether the worker still holds its request loop open. A worker that
    /// ended without recording its terminal state (panic) is not live.
    fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) == WATCH_LIVE && !self.join.is_finished()
    }
    /// Whether a dead watch may be re-armed once a scan proves the path.
    /// Anything but an explicit refusal re-arms through the transient path.
    fn rearmable(&self) -> bool {
        self.state.load(Ordering::Acquire) != WATCH_UNSUPPORTED
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

mod applied;
pub(super) mod generation;
mod polling;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    context: ContextConfig,
    namespace: String,
    addr: SocketAddr,
    tls_name: String,
    ca: PathBuf,
    token: PathBuf,
    state: PathBuf,
    max_jobs: usize,
    max_bytes: usize,
    max_attempts: u32,
    initial_backoff_secs: u64,
    max_backoff_secs: u64,
    emit_acceptance: bool,
    #[serde(default)]
    initial_cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lineage: Option<generation::Lineage>,
    /// Mailbox cadence is distinct from outbound job retry authority. The
    /// faster policy must be selected before initializing a new profile.
    #[serde(default)]
    mailbox_polling: polling::Policy,
    /// Exact selected bytes for conditional atomic version publication.
    #[serde(skip)]
    encoded: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContextConfig {
    room: String,
    anchor: String,
    account: String,
    device: String,
}
impl Config {
    fn load(path: &Path, context: Context) -> Result<(Self, RelayNamespace, TlsRelay), String> {
        let bytes = files::read(path, 16384, false)?;
        let mut c: Self = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        if ![1, 2, 3].contains(&c.version) || (c.version == 3) != c.lineage.is_some() {
            return Err(REFUSED.into());
        }
        c.encoded = bytes.to_vec();
        generation::check_selection(path, &c)?;
        let key = |s: &str| Key::from_bytes(unhex(s)?).map_err(|_| REFUSED.to_string());
        let selected = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(unhex(&c.context.room)?).map_err(|_| REFUSED)?,
                anchor: AnchorId::from_bytes(unhex(&c.context.anchor)?).map_err(|_| REFUSED)?,
            },
            account: key(&c.context.account)?,
            device: key(&c.context.device)?,
        };
        if selected != context
            || !c.state.is_absolute()
            || !c.ca.is_absolute()
            || !c.token.is_absolute()
        {
            return Err(REFUSED.into());
        }
        let parent = c
            .state
            .parent()
            .ok_or(REFUSED)?
            .canonicalize()
            .map_err(|_| REFUSED)?;
        custody::open_private_directory(&parent).map_err(|_| REFUSED)?;
        c.state = parent.join(c.state.file_name().ok_or(REFUSED)?);
        let namespace = RelayNamespace::from_bytes(unhex(&c.namespace)?).map_err(|_| REFUSED)?;
        let token = files::read(&c.token, 65, false)?;
        let token = std::str::from_utf8(&token).map_err(|_| REFUSED)?;
        let token = RelayToken::from_bytes(unhex(token.strip_suffix('\n').unwrap_or(token))?)
            .map_err(|_| REFUSED)?;
        let relay = TlsRelay::new(
            c.addr,
            &c.tls_name,
            files::read(&c.ca, 65536, false)?.to_vec(),
            token,
            namespace,
        )
        .map_err(|_| REFUSED)?;
        Ok((c, namespace, relay))
    }
    fn limits(&self) -> Limits {
        Limits {
            max_jobs: self.max_jobs,
            max_bytes: self.max_bytes,
        }
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.max_attempts,
            initial_backoff_secs: self.initial_backoff_secs,
            max_backoff_secs: self.max_backoff_secs,
        }
    }
}

fn binding(context: Context, ns: RelayNamespace, relay: &TlsRelay, config: &Config) -> Vec<u8> {
    // Version 1 omitted limits and retry authority. Refuse it without altering
    // the old state; reinterpreting its queue would silently widen a new config.
    // Versions 2 and 3 retain their exact adaptive-policy bytes. Version 4
    // explicitly binds the interactive policy and its starting cursor, even 0.
    let mut bytes = if config.mailbox_polling == polling::Policy::Interactive {
        b"VHDELHOST\x04".to_vec()
    } else if config.initial_cursor == 0 {
        b"VHDELHOST\x02".to_vec()
    } else {
        b"VHDELHOST\x03".to_vec()
    };
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
        ns.as_bytes(),
        relay.endpoint_id().as_bytes(),
    ] {
        bytes.extend_from_slice(field);
    }
    bytes.push(u8::from(config.emit_acceptance));
    for value in [
        config.max_jobs as u64,
        config.max_bytes as u64,
        u64::from(config.max_attempts),
        config.initial_backoff_secs,
        config.max_backoff_secs,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    if config.initial_cursor != 0 || config.mailbox_polling == polling::Policy::Interactive {
        bytes.extend_from_slice(&config.initial_cursor.to_be_bytes());
    }
    if config.mailbox_polling == polling::Policy::Interactive {
        bytes.push(1);
    }
    bytes
}

fn retained_scan(
    path: &Path,
    namespace: RelayNamespace,
    initial_cursor: u64,
) -> Result<ScanDirectory, String> {
    // ScanDirectory also supports explicit first-time initialization. This host
    // already has initialized custody: absent children must not reset its cursor.
    let (_, owner) = custody::open_private_directory(path).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("namespace"), owner, 1024).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("lock"), owner, 0).map_err(|_| REFUSED)?;
    custody::open_private_directory(&path.join("items")).map_err(|_| REFUSED)?;
    ScanDirectory::open_from(path, namespace, initial_cursor).map_err(|_| REFUSED.into())
}

fn net_error(e: NetError) -> &'static str {
    match e {
        NetError::Connect => "connect",
        NetError::Timeout => "timeout",
        NetError::Denied => "denied",
        NetError::Conflict => "conflict",
        NetError::Capacity => "capacity",
        NetError::Bounds => "bounds",
        NetError::Scope => "scope",
        NetError::Malformed => "malformed",
        NetError::Unavailable => "unavailable",
    }
}

/// Read-only durable delivery metadata for one configured profile. The queue
/// is opened under its own custody lock: the report is the retained journal —
/// relay job states, charged attempts, durable driver watermarks — never
/// keys, plaintext or ciphertext, and it makes no network contact. Relay
/// retention is not member acceptance; member claims live in kernel custody
/// and surface through the session's outbox status.
pub(super) fn status(args: &super::Args, context: Context) -> Result<(), String> {
    let (stream, queue) = open_queue(args, context)?;
    let after = if args.flags.contains_key("after") {
        args.number("after")?
    } else {
        0
    };
    let limit = if args.flags.contains_key("limit") {
        args.number("limit")?
    } else {
        MAX_RELAY_PAGE as u64
    };
    if limit == 0 || limit > MAX_RELAY_PAGE as u64 {
        return Err(REFUSED.into());
    }
    let (outgoing, applied) = queue.driver_checkpoint().map_err(|_| REFUSED)?;
    let jobs = queue.statuses(after, limit as usize).map_err(|_| REFUSED)?;
    let jobs: Vec<serde_json::Value> = jobs
        .iter()
        .map(|status| {
            json!({
                "digest": hex(&status.id),
                "sequence": status.sequence.to_string(),
                "operation": hex(status.operation.as_bytes()),
                "state": match status.state {
                    JobState::Pending => "pending",
                    JobState::Uncertain => "uncertain",
                    JobState::Retained => "retained",
                    JobState::Stopped => "stopped",
                },
                "attempts": status.attempts,
                "uncertain": status.uncertain,
                "next_due": status.next_due.to_string(),
                "position": status.position.map(|p| p.to_string()),
                "last_error": status.last_error.map(net_error),
            })
        })
        .collect();
    args.json(json!({
        "stream": stream,
        "coverage": "durable local delivery journal; relay retention is not member acceptance or human reading",
        "driver": {"outgoing": outgoing.to_string(), "applied": applied.to_string()},
        "jobs": jobs,
        "evidence": "queue custody only; member acceptance claims are device-signed and surface through the agent session",
    }))
}

/// Select one existing bound queue without contacting the relay. Control
/// inspection/re-arm requires the explicit additive upgrade marker, just like
/// a driver launch; naming a child directory cannot expand delivery authority.
pub(super) fn open_queue(
    args: &super::Args,
    context: Context,
) -> Result<(&'static str, DeliveryStore), String> {
    let stream = match args.flags.get("stream").map(|s| s.to_str()) {
        None | Some(Some("outbox")) => "outbox",
        Some(Some("control")) => "control",
        _ => return Err(REFUSED.into()),
    };
    let (config, namespace, relay) = Config::load(Path::new(args.value("config")?), context)?;
    if stream == "control" && ![2, 3].contains(&config.version) {
        return Err(
            "control delivery requires an explicit delivery-upgrade of this legacy profile".into(),
        );
    }
    if *files::read(&config.state.join("binding"), 1024, false)?
        != binding(context, namespace, &relay, &config)
    {
        return Err(REFUSED.into());
    }
    if stream == "control"
        && *files::read(&config.state.join("controls.enabled"), 1024, false)?
            != control_binding(&config, context, namespace, &relay)
    {
        return Err(REFUSED.into());
    }
    let queue = DeliveryStore::open(
        config.state.join(if stream == "control" {
            "controls"
        } else {
            "jobs"
        }),
        context,
        namespace,
        relay.endpoint_id(),
    )
    .map_err(|_| REFUSED)?;
    if queue.policy() != (config.limits(), config.retry()) {
        return Err(REFUSED.into());
    }
    Ok((stream, queue))
}
pub(super) fn initialize(path: &Path, context: Context) -> Result<(), String> {
    let (c, ns, relay) = Config::load(path, context)?;
    // Validate policy before creating any names. Actual queue creation performs
    // the authoritative validation; partial initialization is never auto-reset.
    if c.initial_cursor > MAX_RELAY_ITEMS as u64
        || c.max_jobs == 0
        || c.max_jobs > MAX_RELAY_ITEMS
        || c.max_bytes == 0
        || c.max_bytes > 1024 * 1024 * 1024
        || !(1..=100).contains(&c.max_attempts)
        || !(1..=3600).contains(&c.initial_backoff_secs)
        || c.max_backoff_secs < c.initial_backoff_secs
        || c.max_backoff_secs > 86400
    {
        return Err(REFUSED.into());
    }
    let (directory, _) = custody::create_private_directory(&c.state).map_err(|_| REFUSED)?;
    let lock = custody::create_private_file(&c.state.join("lock")).map_err(|_| REFUSED)?;
    custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
    let _queue = DeliveryStore::create_new(
        c.state.join("jobs"),
        context,
        ns,
        relay.endpoint_id(),
        c.limits(),
        c.retry(),
    )
    .map_err(|_| REFUSED)?;
    let _scan = ScanDirectory::open_from(&c.state.join("scan"), ns, c.initial_cursor)
        .map_err(|_| REFUSED)?;
    custody::create_private_directory(&c.state.join("applied")).map_err(|_| REFUSED)?;
    files::write(&c.state.join("binding"), &binding(context, ns, &relay, &c))?;
    enable_controls(&c, context, ns, &relay, true)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    publish_control_version(path, &c.encoded)?;
    Ok(())
}

/// Explicitly add a separate finite control stream to an existing exact driver.
/// Existing jobs, scans, retries and ratchets are preserved. The new stream has
/// its own configured queue allowance; this command is the authorization to add it.
pub(super) fn upgrade(path: &Path, context: Context) -> Result<(), String> {
    let (c, ns, relay) = Config::load(path, context)?;
    let (_, owner) = custody::open_private_directory(&c.state).map_err(|_| REFUSED)?;
    let lock = custody::open_private_file(&c.state.join("lock"), owner, 0).map_err(|_| REFUSED)?;
    custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
    if *files::read(&c.state.join("binding"), 1024, false)? != binding(context, ns, &relay, &c) {
        return Err(REFUSED.into());
    }
    drop(
        DeliveryStore::open(c.state.join("jobs"), context, ns, relay.endpoint_id())
            .map_err(|_| REFUSED)?,
    );
    // A selected v2 profile already committed to this control custody. Missing
    // names are lost evidence, never an interrupted additive initialization.
    enable_controls(&c, context, ns, &relay, c.version == 1)?;
    publish_control_version(path, &c.encoded)
}

/// The selected config is the final activation record. Version 1 remains an
/// inert legacy selection until all additive stores are complete; version 2
/// makes older binaries refuse before they can send application jobs. One
/// atomic rename chooses a complete old or new selection after interruption.
fn publish_control_version(path: &Path, expected: &[u8]) -> Result<(), String> {
    publish_control_version_with(path, expected, |_| Ok(()))
}
fn publish_control_version_with(
    path: &Path,
    expected: &[u8],
    mut after_boundary: impl FnMut(u8) -> Result<(), String>,
) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let absolute = custody::absolute(path).map_err(|_| REFUSED)?;
    let parent = absolute
        .parent()
        .ok_or(REFUSED)?
        .canonicalize()
        .map_err(|_| REFUSED)?;
    let name = absolute.file_name().ok_or(REFUSED)?;
    let target = parent.join(name);
    let (directory, owner) = custody::open_private_directory(&parent).map_err(|_| REFUSED)?;
    if files::read(&target, 16384, false)?.as_slice() != expected {
        return Err(REFUSED.into());
    }
    let mut value: serde_json::Value = serde_json::from_slice(expected).map_err(|_| REFUSED)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(REFUSED)?;
    if ![1, 2].contains(&version) {
        return Err(REFUSED.into());
    }
    value["version"] = json!(2);
    let next = serde_json::to_vec(&value).map_err(|_| REFUSED)?;
    if next.len() > 16384 {
        return Err(REFUSED.into());
    }
    let mut scratch = name.to_os_string();
    scratch.push(".controls-upgrade-tmp");
    let scratch = parent.join(scratch);
    let present = custody::private_file_present(&scratch, owner, 16384).map_err(|_| REFUSED)?;
    if version == 2 {
        // A previous rename may have returned uncertainty before its barrier.
        directory.sync_all().map_err(|_| REFUSED)?;
        if present {
            let prefix = custody::read_private_file(&scratch, owner, 16384).map_err(|_| REFUSED)?;
            if !next.starts_with(&prefix) {
                return Err(REFUSED.into());
            }
            directory.sync_all().map_err(|_| REFUSED)?;
            std::fs::remove_file(&scratch).map_err(|_| REFUSED)?;
            directory.sync_all().map_err(|_| REFUSED)?;
        }
        return Ok(());
    }
    let mut file = if present {
        custody::open_private_file(&scratch, owner, 16384).map_err(|_| REFUSED)?
    } else {
        custody::create_private_file(&scratch).map_err(|_| REFUSED)?
    };
    let prefix = custody::read_private_file(&scratch, owner, 16384).map_err(|_| REFUSED)?;
    if !next.starts_with(&prefix) {
        return Err(REFUSED.into());
    }
    file.seek(SeekFrom::End(0)).map_err(|_| REFUSED)?;
    file.write_all(&next[prefix.len()..])
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|_| REFUSED)?;
    if files::read(&scratch, 16384, false)?.as_slice() != next
        || files::read(&target, 16384, false)?.as_slice() != expected
    {
        return Err(REFUSED.into());
    }
    after_boundary(0)?;
    std::fs::rename(&scratch, &target).map_err(|_| REFUSED)?;
    after_boundary(1)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    after_boundary(2)?;
    if files::read(&target, 16384, false)?.as_slice() != next {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn control_binding(c: &Config, context: Context, ns: RelayNamespace, relay: &TlsRelay) -> Vec<u8> {
    let mut bytes = b"VHDELCTRL\x01".to_vec();
    bytes.extend(binding(context, ns, relay, c));
    bytes
}

fn enable_controls(
    c: &Config,
    context: Context,
    ns: RelayNamespace,
    relay: &TlsRelay,
    allow_creation: bool,
) -> Result<(), String> {
    let path = c.state.join("controls");
    let marker = c.state.join("controls.enabled");
    let expected = control_binding(c, context, ns, relay);
    let marker_present = match marker.symlink_metadata() {
        Ok(_) => {
            if *files::read(&marker, 1024, false)? != expected {
                return Err(REFUSED.into());
            }
            true
        }
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(_) => return Err(REFUSED.into()),
    };
    if !marker_present && !allow_creation {
        return Err(REFUSED.into());
    }
    let queue = match path.symlink_metadata() {
        Ok(_) => DeliveryStore::open(&path, context, ns, relay.endpoint_id()),
        Err(e) if e.kind() == ErrorKind::NotFound && !marker_present => DeliveryStore::create_new(
            &path,
            context,
            ns,
            relay.endpoint_id(),
            c.limits(),
            c.retry(),
        ),
        _ => return Err(REFUSED.into()),
    }
    .map_err(|_| REFUSED)?;
    if queue.policy() != (c.limits(), c.retry()) {
        return Err(REFUSED.into());
    }
    if !marker_present {
        files::write(&marker, &expected)?;
    }
    Ok(())
}

/// Lifetime queue custody is separate from a finite, one-use agent grant.
pub(super) struct Driver {
    config: Config,
    context: Context,
    namespace: RelayNamespace,
    relay: TlsRelay,
    queue: DeliveryStore,
    controls: DeliveryStore,
    control_outgoing: u64,
    control_boundary_checked: bool,
    /// Next candidate beyond the contiguous watermark. A deferred prefix must
    /// not repeatedly consume the whole per-tick budget and hide its parent.
    apply_next: u64,
    scan: ScanDirectory,
    _directory: File,
    _lock: File,
    /// Local outbox watermark: records up to `outgoing` were considered for
    /// enqueue. Durable via the queue's driver checkpoint.
    outgoing: u64,
    /// Contiguous applied watermark validated in this custody lifetime. Reopen
    /// starts at the selected initial cursor and verifies durable markers again.
    applied: u64,
    /// Staged positions above the watermark that already carry a marker.
    ahead: BTreeSet<u64>,
    /// Staged positions whose kernel outcome stayed transient, and when the
    /// first deferral happened. Unhealing positions refuse, they do not wedge.
    pending: BTreeMap<u64, Instant>,
    /// Queue-sequence watermark for job rows already fed into the RPC view.
    fed: u64,
    /// Staged relay cursor, refreshed only after a successful scan.
    staged_head: u64,
    /// `(outgoing, applied)` as last persisted.
    checkpoint: (u64, u64),
    /// One-time boundary check that the durable outgoing watermark agrees with
    /// kernel custody and the queue.
    boundary_checked: bool,
    polling: polling::Schedule,
    scan_full: bool,
    /// Held-page mailbox watch on its own connection. `None` only before the
    /// first poll; a dead entry stays as the re-arm decision record.
    watch: Option<Watch>,
    /// A dead watch's termination already charged the cadence once.
    watch_dead: bool,
}
impl Driver {
    pub(super) fn open(path: &Path, context: Context) -> Result<Self, String> {
        let (config, namespace, relay) = Config::load(path, context)?;
        generation::check_active(&config)?;
        if ![2, 3].contains(&config.version) {
            return Err("legacy delivery profile requires delivery-upgrade before another agent-serve launch".into());
        }
        let (directory, owner) =
            custody::open_private_directory(&config.state).map_err(|_| REFUSED)?;
        let lock = custody::open_private_file(&config.state.join("lock"), owner, 0)
            .map_err(|_| REFUSED)?;
        custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
        if *files::read(&config.state.join("binding"), 1024, false)?
            != binding(context, namespace, &relay, &config)
        {
            return Err(REFUSED.into());
        }
        let applied_dir = config.state.join("applied");
        custody::open_private_directory(&applied_dir).map_err(|_| REFUSED)?;
        // Missing child state is a refusal, never an implicit new cursor/queue.
        // The scan directory stays open for the launch: its staged positions
        // and cursor are authoritative between relay polls.
        let scan = retained_scan(&config.state.join("scan"), namespace, config.initial_cursor)?;
        let queue = DeliveryStore::open(
            config.state.join("jobs"),
            context,
            namespace,
            relay.endpoint_id(),
        )
        .map_err(|_| REFUSED)?;
        if *files::read(&config.state.join("controls.enabled"), 1024, false)?
            != control_binding(&config, context, namespace, &relay)
        {
            return Err(REFUSED.into());
        }
        let controls = DeliveryStore::open(
            config.state.join("controls"),
            context,
            namespace,
            relay.endpoint_id(),
        )
        .map_err(|_| REFUSED)?;
        if controls.policy() != (config.limits(), config.retry()) {
            return Err(REFUSED.into());
        }
        generation::verify_baselines(&config, context, &queue, &controls)?;
        let (control_outgoing, _) = controls.driver_checkpoint().map_err(|_| REFUSED)?;
        let staged_head = scan.cursor();
        let (cp_outgoing, cp_applied) = queue.driver_checkpoint().map_err(|_| REFUSED)?;
        let (applied, ahead) =
            applied_restore(&applied_dir, config.initial_cursor, staged_head, cp_applied)?;
        let polling = polling::Schedule::new(config.mailbox_polling, Instant::now());
        Ok(Self {
            config,
            context,
            namespace,
            relay,
            queue,
            controls,
            control_outgoing,
            control_boundary_checked: false,
            apply_next: applied.saturating_add(1),
            scan,
            _directory: directory,
            _lock: lock,
            outgoing: cp_outgoing,
            applied,
            ahead,
            pending: BTreeMap::new(),
            fed: 0,
            staged_head,
            checkpoint: (cp_outgoing, cp_applied),
            boundary_checked: cp_outgoing == 0,
            polling,
            scan_full: false,
            watch: None,
            watch_dead: false,
        })
    }
    /// One bounded host tick between RPCs. Kernel uncertainty ends the grant;
    /// no latch-clearing reopen, ratchet regeneration or budget renewal occurs.
    /// Each stage resumes from durable or staged positions, so a partial pass
    /// loses no work; relaunch reauthenticates completed stages read-only.
    pub(super) async fn tick(&mut self, rpc: &mut RpcSession) -> Result<(), String> {
        // A configured driver performs grant-scoped work from the first tick,
        // so the one-use claim is reserved before the first effect rather than
        // waiting for a client tool call.
        rpc.ensure_claimed().map_err(|_| REFUSED)?;
        rpc.check_release().map_err(|_| REFUSED)?;
        self.scan.reset_deadline();
        let deadline = (Instant::now() + TICK).min(rpc.deadline());
        // Feed durable job rows first: catch-up marks `fed` as it delivers new
        // jobs, and rows enqueued before the durable watermark only reach the
        // session view through this pass.
        self.feed(rpc, deadline).await?;
        self.catch_up_controls(rpc, deadline).await?;
        self.catch_up(rpc, deadline).await?;
        self.deliver_ordered(rpc, deadline).await?;
        self.poll(deadline)?;
        self.apply(rpc, deadline).await?;
        self.save()?;
        rpc.check_release().map_err(|_| REFUSED.to_string())
    }

    /// Retain exact encrypted owner controls in their own sequence domain.
    /// A joined member may forward its authenticated suffix; canonical relay
    /// deduplication makes every forwarder publish identical bytes only once.
    async fn catch_up_controls(
        &mut self,
        rpc: &mut RpcSession,
        deadline: Instant,
    ) -> Result<(), String> {
        loop {
            if Instant::now() >= deadline {
                return Ok(());
            }
            let page = rpc
                .host()
                .encrypted_controls(
                    (self.control_outgoing != 0).then_some(self.control_outgoing),
                    OUTBOX_PAGE,
                )
                .await
                .map_err(|_| REFUSED)?;
            if !self.control_boundary_checked {
                // A retained watermark above the joining boundary must name
                // an exact existing queue item. Never interpret a checkpoint
                // alone as evidence that a control was enqueued or delivered.
                if self.control_outgoing > page.base.sequence()
                    && !self
                        .controls
                        .predecessor_baseline()
                        .map_err(|_| REFUSED)?
                        .is_some_and(|(head, _)| self.control_outgoing == head)
                {
                    let boundary = rpc
                        .host()
                        .encrypted_controls(Some(self.control_outgoing - 1), 1)
                        .await
                        .map_err(|_| REFUSED)?;
                    let control = boundary.records.first().ok_or(REFUSED)?;
                    if control.floor().sequence() != self.control_outgoing
                        || self
                            .controls
                            .job(
                                RelayItem::from_control(self.namespace, control)
                                    .map_err(|_| REFUSED)?
                                    .digest(),
                            )
                            .map_err(|_| REFUSED)?
                            .is_none()
                    {
                        return Err(REFUSED.into());
                    }
                }
                self.control_boundary_checked = true;
            }
            if self.control_outgoing == 0 && page.base.sequence() != 0 {
                self.control_outgoing = page.base.sequence();
                self.controls
                    .save_driver_checkpoint(self.control_outgoing, 0, now()?)
                    .map_err(|_| REFUSED)?;
            }
            for control in &page.records {
                let item = RelayItem::from_control(self.namespace, control).map_err(|_| REFUSED)?;
                match self.controls.enqueue(&item, now()?) {
                    Ok(_) => (),
                    Err(vhalla_private_native::relay::delivery::Error::Capacity) => return Ok(()),
                    Err(_) => return Err(REFUSED.into()),
                }
                self.control_outgoing = control.floor().sequence();
                self.polling.activity(Instant::now());
                self.controls
                    .save_driver_checkpoint(self.control_outgoing, 0, now()?)
                    .map_err(|_| REFUSED)?;
            }
            if page.records.is_empty() {
                return Ok(());
            }
        }
    }

    /// Drain the kernel outbox into the durable queue. Inbound staging never
    /// waits on this watermark: own echoes are still recognized by the durable
    /// job table and the kernel sent-index below.
    async fn catch_up(&mut self, rpc: &mut RpcSession, deadline: Instant) -> Result<(), String> {
        if !self.boundary_checked {
            self.boundary(rpc).await?;
            self.boundary_checked = true;
        }
        loop {
            if Instant::now() >= deadline {
                return Ok(());
            }
            let page = rpc
                .host()
                .outbox(self.outgoing, OUTBOX_PAGE)
                .await
                .map_err(|_| REFUSED)?;
            // Committed outbox is append-only; a smaller head means the kernel
            // custody no longer matches the durable checkpoint.
            if page.head < self.outgoing {
                return Err(REFUSED.into());
            }
            for entry in &page.records {
                if let Some(artifact) = entry.artifact().filter(|a| super::relay_kind(a.kind())) {
                    let item =
                        RelayItem::from_artifact(self.namespace, artifact).map_err(|_| REFUSED)?;
                    let status = match self.queue.enqueue(&item, now()?) {
                        Ok(status) => status,
                        // A full queue is honest backpressure, not corruption:
                        // the watermark stays at the last enqueued record and
                        // catch-up resumes once the relay drains jobs.
                        Err(vhalla_private_native::relay::delivery::Error::Capacity) => {
                            return Ok(());
                        }
                        Err(_) => return Err(REFUSED.into()),
                    };
                    rpc.update_delivery(self.namespace, &status)
                        .await
                        .map_err(|_| REFUSED)?;
                    self.polling.activity(Instant::now());
                    // `fed` is not marked here: `feed` delivers every durable
                    // row in sequence order, and a deadline-stopped feed must
                    // still reach rows enqueued before this job.
                }
                self.outgoing = entry.sequence();
            }
            if page.records.is_empty() {
                self.outgoing = page.head;
                return Ok(());
            }
        }
    }

    /// One-time boundary check: a relay-kind record at the durable `outgoing`
    /// watermark must already have a durable job. The queue publishes jobs
    /// before the checkpoint advances, so a gap means torn or foreign state.
    async fn boundary(&mut self, rpc: &mut RpcSession) -> Result<(), String> {
        if self.outgoing == 0
            || self
                .queue
                .predecessor_baseline()
                .map_err(|_| REFUSED)?
                .is_some_and(|(head, _)| self.outgoing == head)
        {
            return Ok(());
        }
        let page = rpc
            .host()
            .outbox(self.outgoing - 1, 1)
            .await
            .map_err(|_| REFUSED)?;
        if let Some(artifact) = page
            .records
            .first()
            .and_then(|entry| entry.artifact())
            .filter(|a| super::relay_kind(a.kind()))
        {
            let item = RelayItem::from_artifact(self.namespace, artifact).map_err(|_| REFUSED)?;
            if self
                .queue
                .job(item.digest())
                .map_err(|_| REFUSED)?
                .is_none()
            {
                return Err(REFUSED.into());
            }
        }
        Ok(())
    }

    /// Feed durable job rows the RPC view has not seen yet, so a relaunched
    /// session reports the same delivery evidence without re-attempting work.
    async fn feed(&mut self, rpc: &mut RpcSession, deadline: Instant) -> Result<(), String> {
        loop {
            if Instant::now() >= deadline {
                return Ok(());
            }
            let jobs = self.queue.statuses(self.fed, PAGE).map_err(|_| REFUSED)?;
            if jobs.is_empty() {
                return Ok(());
            }
            for status in &jobs {
                rpc.update_delivery(self.namespace, status)
                    .await
                    .map_err(|_| REFUSED)?;
                self.fed = self.fed.max(status.sequence);
            }
        }
    }

    /// Merge both retained streams by authenticated epoch dependencies. Local
    /// old-epoch applications precede the next control; new-epoch applications
    /// follow it. A stopped or uncertain predecessor never gets leapfrogged.
    async fn deliver_ordered(
        &mut self,
        rpc: &mut RpcSession,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut bytes = 0usize;
        for _ in 0..TICK_JOBS {
            if Instant::now() >= deadline || bytes >= TICK_BYTES {
                break;
            }
            // Retention frees finite live-job capacity. Refill before choosing
            // the next cross-stream dependency, including max_jobs=1 queues.
            self.catch_up_controls(rpc, deadline).await?;
            self.catch_up(rpc, deadline).await?;
            if Instant::now() >= deadline {
                break;
            }
            let normal = self.queue.first_unretained().map_err(|_| REFUSED)?;
            // Older controllers could enqueue an acceptance at the tail while
            // an earlier artifact was still unstaged. Preserve that evidence,
            // but do not send it across an unproven local ordering boundary.
            // A normal enqueue-before-checkpoint crash reconciles in catch_up
            // above, which recognizes the exact item even at queue capacity.
            if normal
                .as_ref()
                .is_some_and(|job| job.sequence > self.outgoing)
            {
                return Err(REFUSED.into());
            }
            let control = self.controls.first_unretained().map_err(|_| REFUSED)?;
            let accepted = rpc.host().agent().status().map_err(|_| REFUSED)?.accepted;
            let use_control = match (&normal, &control) {
                (None, None) => break,
                (None, Some(_)) => {
                    // Catch-up may have stopped at capacity/deadline. The next
                    // unseen local artifact might still precede this control.
                    if self.outgoing != accepted.outbox_head {
                        break;
                    }
                    true
                }
                (Some(_), None) => {
                    if self.control_outgoing != accepted.control_floor.sequence() {
                        break;
                    }
                    false
                }
                (Some(job), Some(next)) => {
                    let page = rpc
                        .host()
                        .outbox(job.sequence - 1, 1)
                        .await
                        .map_err(|_| REFUSED)?;
                    let artifact = page
                        .records
                        .first()
                        .and_then(|r| r.artifact())
                        .ok_or(REFUSED)?;
                    if RelayItem::from_artifact(self.namespace, artifact)
                        .map_err(|_| REFUSED)?
                        .digest()
                        != job.id
                    {
                        return Err(REFUSED.into());
                    }
                    let page = rpc
                        .host()
                        .encrypted_controls(Some(next.sequence - 1), 1)
                        .await
                        .map_err(|_| REFUSED)?;
                    let retained = page.records.first().ok_or(REFUSED)?;
                    if RelayItem::from_control(self.namespace, retained)
                        .map_err(|_| REFUSED)?
                        .digest()
                        != next.id
                    {
                        return Err(REFUSED.into());
                    }
                    match artifact.application_epoch().map_err(|_| REFUSED)? {
                        Some(epoch) => epoch > retained.prior_epoch().map_err(|_| REFUSED)?,
                        // These are duplicate legacy control artifacts. Publish
                        // the ordered control suffix before its legacy copy.
                        None => matches!(
                            artifact.kind(),
                            OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession
                        ),
                    }
                }
            };
            let job = if use_control {
                control.as_ref()
            } else {
                normal.as_ref()
            }
            .ok_or(REFUSED)?;
            if job.state == JobState::Stopped {
                break;
            }
            let queue = if use_control {
                &mut self.controls
            } else {
                &mut self.queue
            };
            let report = queue
                .tick_only(
                    &mut self.relay,
                    now()?,
                    TickBudget {
                        max_jobs: 1,
                        max_bytes: TICK_BYTES - bytes,
                        deadline,
                    },
                    job.id,
                )
                .map_err(|_| REFUSED)?;
            bytes += report.bytes;
            if report.jobs.is_empty() {
                break;
            }
            for status in &report.jobs {
                if !use_control {
                    rpc.update_delivery(self.namespace, status)
                        .await
                        .map_err(|_| REFUSED)?;
                }
                if status.last_error == Some(NetError::Denied) {
                    return Err(REFUSED.into());
                }
                if status.state != JobState::Retained {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Poll the relay mailbox under the selected cadence. A live held-page
    /// watch replaces scheduled polls entirely: arrivals surface within one
    /// tick of the observed head advancing. When no watch holds — dead or
    /// refused by an older host — the ordinary cadence applies unchanged, and
    /// a transiently dead watch re-arms on the next proven scan.
    fn poll(&mut self, deadline: Instant) -> Result<(), String> {
        if self.scan_full {
            return Ok(());
        }
        if self.watch.is_none() {
            self.watch = Some(Watch::spawn(self.relay.clone(), self.staged_head));
        }
        let watch = self.watch.as_ref().expect("spawned");
        watch.cursor.store(self.staged_head, Ordering::Release);
        if watch.live() {
            if watch.head.load(Ordering::Acquire) > self.staged_head {
                return self.scan_page(deadline);
            }
            return Ok(());
        }
        if !self.watch_dead {
            // The held exchange ended like a failed scan: charge the cadence
            // once so polling resumes without a fresh burst.
            self.polling.network_error(Instant::now());
            self.watch_dead = true;
        }
        if self.polling.due(Instant::now()) {
            self.scan_page(deadline)?;
        }
        Ok(())
    }

    /// One bounded page scan; a nonempty page or a cursor still behind the
    /// observed head repolls on the next tick. On success a transiently dead
    /// watch re-arms against the now-proven path.
    fn scan_page(&mut self, deadline: Instant) -> Result<(), String> {
        match self.scan.scan_page_until(&self.relay, PAGE, deadline) {
            Ok(report) => {
                self.staged_head = self.scan.cursor();
                self.polling.success(
                    Instant::now(),
                    report.scanned > 0 || self.staged_head < report.head,
                );
                if self
                    .watch
                    .as_ref()
                    .is_some_and(|watch| !watch.live() && watch.rearmable())
                {
                    self.watch = Some(Watch::spawn(self.relay.clone(), self.staged_head));
                    self.watch_dead = false;
                }
            }
            Err(ScanFailure::Net(
                NetError::Connect | NetError::Timeout | NetError::Capacity | NetError::Unavailable,
            )) => {
                self.polling.network_error(Instant::now());
            }
            Err(ScanFailure::Timeout) => {
                self.polling.budget_exhausted(Instant::now());
            }
            Err(ScanFailure::Capacity) => {
                // The retained window exceeds relay bounds; staged items still
                // apply, but no further positions can be staged safely.
                self.scan_full = true;
            }
            Err(_) => return Err(REFUSED.into()),
        }
        Ok(())
    }

    /// Mark a staged position complete and advance the contiguous watermark
    /// through any completed positions it unblocks.
    fn complete(&mut self, position: u64) {
        self.pending.remove(&position);
        if position > self.applied {
            self.ahead.insert(position);
        }
        while self.ahead.remove(&(self.applied + 1)) {
            self.applied += 1;
        }
    }

    /// Defer a position whose kernel outcome is still transient; end the
    /// launch when it does not heal within the bounded pending window.
    fn defer(&mut self, position: u64) -> Result<(), String> {
        let first = *self.pending.entry(position).or_insert_with(Instant::now);
        if first.elapsed() > PENDING_MAX {
            return Err(REFUSED.into());
        }
        Ok(())
    }

    /// Whether these exact retained bytes are a committed send from this
    /// custody. The durable job table answers first; application items also
    /// consult the kernel sent-index, so an echo is recognized even before the
    /// outbox catch-up reaches it.
    async fn own_echo(&mut self, rpc: &mut RpcSession, item: &RelayItem) -> Result<bool, String> {
        if item.kind() == RelayKind::Control
            && self
                .controls
                .job(item.digest())
                .map_err(|_| REFUSED)?
                .is_some()
        {
            return Ok(true);
        }
        if self
            .queue
            .job(item.digest())
            .map_err(|_| REFUSED)?
            .is_some()
        {
            return Ok(true);
        }
        if item.kind() == OutboxKind::Application
            && rpc
                .host()
                .original(&MemberAcceptance::ciphertext_commitment(item.payload()))
                .await
                .map_err(|_| REFUSED)?
                .is_some()
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Apply staged items to the kernel and publish per-position markers.
    /// Staged positions are always the contiguous range up to `staged_head`,
    /// so no directory listing is needed per tick. Positions already holding
    /// a valid marker complete without re-running the kernel; markers that
    /// carry kernel authority are recomputed and must match byte-for-byte.
    async fn apply(&mut self, rpc: &mut RpcSession, deadline: Instant) -> Result<(), String> {
        let dir = self.config.state.join("applied");
        let mut done = 0usize;
        let candidates = round_robin(self.applied, self.staged_head, self.apply_next, PAGE);
        for position in candidates {
            if done >= PAGE || Instant::now() >= deadline {
                break;
            }
            self.apply_next = position.saturating_add(1);
            if self.ahead.contains(&position) {
                continue;
            }
            done += 1;
            let item = self.scan.read(position).map_err(|_| REFUSED)?;
            let path = dir.join(format!("{position:016x}.json"));
            let existing = match path.symlink_metadata() {
                Ok(_) => Some(files::read(&path, 2048, false)?),
                Err(e) if e.kind() == ErrorKind::NotFound => None,
                Err(_) => return Err(REFUSED.into()),
            };
            let own_echo = self.own_echo(rpc, &item).await?;
            if let Some(bytes) = &existing {
                let status = rpc.host().agent().status().map_err(|_| REFUSED)?.accepted;
                let reauth = applied::validate(
                    bytes,
                    &item,
                    position,
                    status,
                    own_echo,
                    self.config.emit_acceptance,
                )?;
                if !reauth {
                    self.complete(position);
                    continue;
                }
                // Read-only evidence lookups cannot mint a receipt, receive a
                // forged marked item or apply a new control during recovery.
                self.restore_marker(rpc, &item, bytes).await?;
                self.complete(position);
                continue;
            }
            match self.process(rpc, &item, position, own_echo).await? {
                Some(marker) => {
                    applied::publish(&path, &marker)?;
                    self.complete(position);
                    rpc.check_release().map_err(|_| REFUSED)?;
                }
                None => self.defer(position)?,
            }
        }
        Ok(())
    }

    async fn restore_marker(
        &mut self,
        rpc: &mut RpcSession,
        item: &RelayItem,
        bytes: &[u8],
    ) -> Result<(), String> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
        let state = value["state"].as_str().ok_or(REFUSED)?;
        if state == "locally-applied-control" {
            if !rpc
                .host()
                .retained_control(item.payload())
                .await
                .map_err(|_| REFUSED)?
            {
                return Err(REFUSED.into());
            }
            return Ok(());
        }
        let received = rpc
            .host()
            .retained_received(item.payload())
            .await
            .map_err(|_| REFUSED)?
            .ok_or(REFUSED)?;
        if value["inbox_sequence"].as_str() != Some(received.sequence().to_string().as_str()) {
            return Err(REFUSED.into());
        }
        let mut verified = None;
        if let Some(hash) = MemberAcceptance::claimed_ciphertext(received.body()) {
            if let Some(original) = rpc.host().original(&hash).await.map_err(|_| REFUSED)? {
                if let Ok(Some(claim)) =
                    MemberAcceptance::verify(self.context, &original, &received)
                {
                    verified = Some((original.sequence(), claim));
                }
            }
        }
        match state {
            "locally-received" if !MemberAcceptance::is_receipt(received.body()) => {
                if self.config.emit_acceptance {
                    let sequence = value["receipt_outbox_sequence"]
                        .as_str()
                        .ok_or(REFUSED)?
                        .parse::<u64>()
                        .map_err(|_| REFUSED)?;
                    let page = rpc
                        .host()
                        .outbox(sequence - 1, 1)
                        .await
                        .map_err(|_| REFUSED)?;
                    let receipt = page
                        .records
                        .first()
                        .and_then(|record| record.artifact())
                        .ok_or(REFUSED)?;
                    if receipt.sequence() != sequence
                        || receipt.kind() != OutboxKind::Application
                        || receipt.operation()
                            != acceptance_operation(self.context, item.payload())?
                    {
                        return Err(REFUSED.into());
                    }
                }
            }
            "unmatched-receipt-content"
                if MemberAcceptance::is_receipt(received.body()) && verified.is_none() => {}
            "recipient-device-claim" => {
                let (sequence, claim) = verified.ok_or(REFUSED)?;
                if value["outbox_sequence"].as_str() != Some(sequence.to_string().as_str())
                    || value["recipient"] != hex(claim.recipient().as_bytes())
                    || value["recipient_inbox_sequence"].as_str()
                        != Some(claim.received_sequence().to_string().as_str())
                {
                    return Err(REFUSED.into());
                }
                rpc.record_member_acceptance(sequence, claim)
                    .await
                    .map_err(|_| REFUSED)?;
            }
            _ => return Err(REFUSED.into()),
        }
        Ok(())
    }

    /// Run one staged item through the kernel and return its durable marker,
    /// or `None` when a typed transient gap defers it to a later pass.
    async fn process(
        &mut self,
        rpc: &mut RpcSession,
        item: &RelayItem,
        position: u64,
        own_echo: bool,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut result = json!({"digest":hex(&item.digest()),"position":position.to_string()});
        if own_echo {
            result["state"] = json!("exact-local-outbox-echo");
            return Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?));
        }
        match item.kind() {
            RelayKind::Outbox(OutboxKind::Application) => match rpc
                .host()
                .receive(item.payload())
                .await
            {
                Ok(received) => {
                    result["state"] = json!("locally-received");
                    result["inbox_sequence"] = json!(received.sequence().to_string());
                    if MemberAcceptance::is_receipt(received.body()) {
                        result["state"] = json!("unmatched-receipt-content");
                        if let Some(hash) = MemberAcceptance::claimed_ciphertext(received.body()) {
                            if let Some(original) =
                                rpc.host().original(&hash).await.map_err(|_| REFUSED)?
                            {
                                // An invalid inner claim remains inert received
                                // content; it cannot promote delivery or
                                // acknowledge another ACK.
                                if let Ok(Some(claim)) =
                                    MemberAcceptance::verify(self.context, &original, &received)
                                {
                                    let sequence = original.sequence();
                                    result["state"] = json!("recipient-device-claim");
                                    result["outbox_sequence"] = json!(sequence.to_string());
                                    result["recipient"] = json!(hex(claim.recipient().as_bytes()));
                                    result["recipient_inbox_sequence"] =
                                        json!(claim.received_sequence().to_string());
                                    rpc.record_member_acceptance(sequence, claim)
                                        .await
                                        .map_err(|_| REFUSED)?;
                                }
                            }
                        }
                    } else if self.config.emit_acceptance {
                        let operation = acceptance_operation(self.context, item.payload())?;
                        let receipt =
                            match rpc.host().issue_acceptance(operation, item.payload()).await {
                                Ok(receipt) => receipt,
                                // Only wall-clock conditions defer; every other
                                // failure surfaces rather than publishing a marker
                                // that claims a receipt the kernel never issued.
                                Err(ClientError::Agent(AgentError::Kernel(
                                    KernelError::ClockRegressed | KernelError::Time,
                                )))
                                | Err(ClientError::Agent(AgentError::Clock)) => return Ok(None),
                                Err(_) => return Err(REFUSED.into()),
                            };
                        // The exact receipt is already durable in the kernel.
                        // Only monotone outbox catch-up may enqueue it: a tail
                        // fast path could fill a finite queue while older local
                        // applications remain unstaged and make them leapfrog.
                        result["receipt_outbox_sequence"] = json!(receipt.sequence().to_string());
                    }
                    Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
                }
                Err(e) => match host_outcome(e, application_outcome) {
                    Outcome::Skip(reason) => {
                        result["state"] = json!("undecryptable-foreign-or-stale");
                        result["error"] = json!(reason);
                        Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
                    }
                    Outcome::Retry => Ok(None),
                    Outcome::Fatal => Err(REFUSED.into()),
                },
            },
            RelayKind::Control
            | RelayKind::Outbox(
                OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession,
            ) => match rpc.host().apply_control(item.payload()).await {
                Ok(_) => {
                    result["state"] = json!("locally-applied-control");
                    Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
                }
                Err(e) => match host_outcome(e, control_outcome) {
                    Outcome::Skip(reason) => {
                        result["state"] = json!("unverifiable-control");
                        result["error"] = json!(reason);
                        Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
                    }
                    Outcome::Retry => Ok(None),
                    Outcome::Fatal => Err(REFUSED.into()),
                },
            },
            RelayKind::Outbox(OutboxKind::ContactInvitation | OutboxKind::ContactRequest) => {
                result["state"] = json!("dedicated-bootstrap-command-required");
                Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
            }
            _ => Err(REFUSED.into()),
        }
    }

    /// Persist the `(outgoing, applied)` checkpoint when it advanced.
    fn save(&mut self) -> Result<(), String> {
        // Reopen revalidates from the initial cursor in bounded passes. Keep
        // the prior durable checkpoint intact until that replay catches up.
        let current = (self.outgoing, self.applied.max(self.checkpoint.1));
        if current != self.checkpoint {
            self.queue
                .save_driver_checkpoint(current.0, current.1, now()?)
                .map_err(|_| REFUSED)?;
            self.checkpoint = current;
        }
        Ok(())
    }
}

/// Per-item outcome the driver records: a durable terminal skip marker, a
/// bounded transient deferral, or a launch-ending condition that needs
/// operator reconciliation.
enum Outcome {
    Skip(&'static str),
    Retry,
    Fatal,
}

fn acceptance_operation(context: Context, ciphertext: &[u8]) -> Result<OperationId, String> {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/host/receipt-operation/v1\0");
    hash.update(context.device.as_bytes());
    hash.update(MemberAcceptance::ciphertext_commitment(ciphertext));
    let digest: [u8; 32] = hash.finalize().into();
    OperationId::from_bytes(digest[..16].try_into().map_err(|_| REFUSED)?)
        .map_err(|_| REFUSED.into())
}

/// One finite circular window; reset after reopen only repeats retained work.
/// Every staged position is visited even when the earliest PAGE items defer.
fn round_robin(applied: u64, head: u64, next: u64, limit: usize) -> Vec<u64> {
    if applied >= head || limit == 0 {
        return Vec::new();
    }
    let first = applied + 1;
    let start = if (first..=head).contains(&next) {
        next
    } else {
        first
    };
    (start..=head).chain(first..start).take(limit).collect()
}

/// Map a host-session failure through the typed kernel classification.
/// `ClientError::Agent(AgentError::Kernel)` carries the kernel refusal;
/// agent-local clock failure defers; every other session or storage
/// condition needs reconciliation rather than a marker.
fn host_outcome(e: ClientError, classify: fn(KernelError) -> Outcome) -> Outcome {
    match e {
        ClientError::Agent(AgentError::Kernel(ke)) => classify(ke),
        ClientError::Agent(AgentError::Clock) => Outcome::Retry,
        _ => Outcome::Fatal,
    }
}

/// Typed kernel refusals for inbound application items. Terminal classes name
/// conditions under which these exact bytes can never apply to this room;
/// transient gap classes defer; everything else needs reconciliation.
fn application_outcome(e: KernelError) -> Outcome {
    match e {
        KernelError::StaleEpoch => Outcome::Skip("stale_epoch"),
        KernelError::RatchetGap { past: true } => Outcome::Skip("ratchet_gap_past"),
        KernelError::Scope => Outcome::Skip("foreign_scope"),
        KernelError::Authentication => Outcome::Skip("authentication"),
        KernelError::Encoding => Outcome::Skip("malformed_encoding"),
        KernelError::Mls => Outcome::Skip("unprocessable_mls"),
        KernelError::Bounds => Outcome::Skip("bounds"),
        KernelError::Policy => Outcome::Skip("policy"),
        KernelError::FutureEpoch
        | KernelError::RatchetGap { past: false }
        | KernelError::ClockRegressed
        | KernelError::Time
        | KernelError::ControlGap => Outcome::Retry,
        _ => Outcome::Fatal,
    }
}

/// Inbound control additionally treats a missing prior floor as terminal: the
/// retained item predates everything this custody can verify.
fn control_outcome(e: KernelError) -> Outcome {
    if e == KernelError::Policy {
        return Outcome::Fatal;
    }
    if e == KernelError::Missing {
        return Outcome::Skip("predates_control_floor");
    }
    application_outcome(e)
}

/// Restore the contiguous applied watermark and the completed positions beyond
/// it from the durable markers. A marker the staged scan cannot reach, a
/// marker at or below the initial cursor, or a checkpoint claiming more than
/// the marker evidence is foreign state and refuses the launch.
fn applied_restore(
    dir: &Path,
    initial_cursor: u64,
    staged_head: u64,
    checkpoint_applied: u64,
) -> Result<(u64, BTreeSet<u64>), String> {
    let mut marked = BTreeSet::new();
    for entry in std::fs::read_dir(dir).map_err(|_| REFUSED)? {
        let entry = entry.map_err(|_| REFUSED)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(REFUSED)?;
        if name.ends_with(".pending") {
            continue;
        }
        let Some(hex_part) = name.strip_suffix(".json") else {
            return Err(REFUSED.into());
        };
        if hex_part.len() != 16 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(REFUSED.into());
        }
        let position = u64::from_str_radix(hex_part, 16).map_err(|_| REFUSED)?;
        if format!("{position:016x}") != hex_part
            || position <= initial_cursor
            || position > staged_head
        {
            return Err(REFUSED.into());
        }
        marked.insert(position);
    }
    let mut applied = initial_cursor;
    while marked.contains(&(applied + 1)) {
        applied += 1;
    }
    if checkpoint_applied > applied {
        return Err(REFUSED.into());
    }
    // Filenames establish consistency only. Every restored marker must bind
    // its staged bytes and reauthenticate its semantic claims before progress.
    Ok((initial_cursor, BTreeSet::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_authority_policy_halts_while_forged_ciphertext_stays_terminal() {
        assert!(matches!(
            control_outcome(KernelError::Policy),
            Outcome::Fatal
        ));
        assert!(matches!(
            control_outcome(KernelError::Quarantined),
            Outcome::Fatal
        ));
        assert!(matches!(
            control_outcome(KernelError::Authentication),
            Outcome::Skip("authentication")
        ));
        assert!(matches!(
            control_outcome(KernelError::ControlGap),
            Outcome::Retry
        ));
    }

    #[test]
    fn control_version_publication_recovers_every_atomic_selection_boundary() {
        use std::os::unix::fs::DirBuilderExt;
        for boundary in 0..3 {
            let root = std::env::temp_dir().join(format!(
                "vhalla-control-config-upgrade-{}-{boundary}",
                std::process::id()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let path = root.join("delivery.json");
            let original = b"{\"version\":1,\"retained\":\"unchanged selection\"}";
            files::write(&path, original).unwrap();
            assert!(publish_control_version_with(&path, original, |at| {
                if at == boundary {
                    Err("injected config publication interruption".into())
                } else {
                    Ok(())
                }
            })
            .is_err());
            let observed = files::read(&path, 16384, false).unwrap();
            let version = serde_json::from_slice::<serde_json::Value>(&observed).unwrap()
                ["version"]
                .as_u64()
                .unwrap();
            assert_eq!(version, if boundary == 0 { 1 } else { 2 });
            publish_control_version(&path, &observed).unwrap();
            let new = files::read(&path, 16384, false).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&new).unwrap();
            assert_eq!(value["version"], 2);
            assert_eq!(value["retained"], "unchanged selection");
            publish_control_version(&path, &new).unwrap();
            assert_eq!(
                files::read(&path, 16384, false).unwrap().as_slice(),
                new.as_slice()
            );
            assert!(!root.join("delivery.json.controls-upgrade-tmp").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn control_version_publication_preserves_foreign_scratch_and_concurrent_selection() {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!(
            "vhalla-control-config-refusal-{}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let path = root.join("delivery.json");
        let original = b"{\"version\":1}";
        files::write(&path, original).unwrap();
        let scratch = root.join("delivery.json.controls-upgrade-tmp");
        files::write(&scratch, b"foreign evidence").unwrap();
        assert!(publish_control_version(&path, original).is_err());
        assert_eq!(
            files::read(&path, 16384, false).unwrap().as_slice(),
            original
        );
        assert_eq!(
            files::read(&scratch, 16384, false).unwrap().as_slice(),
            b"foreign evidence"
        );
        std::fs::remove_file(&scratch).unwrap();
        assert!(publish_control_version(&path, b"{\"version\":1,\"different\":true}").is_err());
        assert_eq!(
            files::read(&path, 16384, false).unwrap().as_slice(),
            original
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deferred_prefix_cannot_hide_later_control_across_bounded_passes() {
        // The first page is temporarily undecryptable; the enabling control
        // arrives just past it. Reopen replays work but never classifies it lost.
        let head = PAGE as u64 + 1;
        let first = round_robin(0, head, 1, PAGE);
        assert_eq!(first, (1..head).collect::<Vec<_>>());
        let second = round_robin(0, head, first.last().unwrap() + 1, PAGE);
        assert_eq!(second[0], head);
        let reopened = round_robin(0, head, 1, PAGE);
        let after_reopen = round_robin(0, head, reopened.last().unwrap() + 1, PAGE);
        assert_eq!(after_reopen[0], head);
        // Review/regrant after the control retries every unresolved position.
        let retried = round_robin(0, head, head + 1, PAGE);
        assert_eq!(retried, first);
        assert!(round_robin(head, head, 1, PAGE).is_empty());
    }

    #[test]
    fn retained_scan_never_initializes_missing_namespace_lock_or_items() {
        let root =
            std::env::temp_dir().join(format!("vhalla-retained-scan-{}", std::process::id()));
        custody::create_private_directory(&root).unwrap();
        let namespace = RelayNamespace::from_bytes([6; 32]).unwrap();
        for (index, missing) in ["namespace", "lock", "items"].iter().enumerate() {
            let path = root.join(index.to_string());
            drop(ScanDirectory::open(&path, namespace).unwrap());
            std::fs::rename(path.join(missing), root.join(format!("saved-{index}"))).unwrap();
            assert!(retained_scan(&path, namespace, 0).is_err());
            assert!(!path.join(missing).exists());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
