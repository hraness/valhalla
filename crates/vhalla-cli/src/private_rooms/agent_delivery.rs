//! Independently configured trusted host delivery; never an agent tool.
use super::{files, hex, now, unhex};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
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
        RelayItem, RelayNamespace, MAX_RELAY_ITEMS, MAX_RELAY_PAGE,
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
/// Idle mailbox poll backoff: a quiet room backs off 5s -> 30s; any staged or
/// applied work resets it. Relay delivery attempts keep their own due times.
const IDLE_BASE: Duration = Duration::from_secs(5);
const IDLE_MAX: Duration = Duration::from_secs(30);
/// Network-error backoff for relay scans, independent of the idle cadence.
const ERR_BASE: Duration = Duration::from_secs(1);
const ERR_MAX: Duration = Duration::from_secs(30);
/// Relay job attempts per tick, within the store's byte and deadline budget.
const TICK_JOBS: usize = 8;
const TICK_BYTES: usize = 4 * 1024 * 1024;
/// A staged position whose kernel outcome stays transient this long is not
/// healing; the launch ends for reconciliation instead of stalling the
/// contiguous applied watermark silently.
const PENDING_MAX: Duration = Duration::from_secs(300);

mod applied;

#[derive(Deserialize)]
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
}

#[derive(Deserialize)]
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
        if c.version != 1 {
            return Err(REFUSED.into());
        }
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
    let mut bytes = if config.initial_cursor == 0 {
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
    if config.initial_cursor != 0 {
        bytes.extend_from_slice(&config.initial_cursor.to_be_bytes());
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
    let (_, uid) = custody::open_private_directory(path).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("namespace"), uid, 1024).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("lock"), uid, 0).map_err(|_| REFUSED)?;
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
    let (config, namespace, relay) = Config::load(Path::new(args.value("config")?), context)?;
    let queue = DeliveryStore::open(
        config.state.join("jobs"),
        context,
        namespace,
        relay.endpoint_id(),
    )
    .map_err(|_| REFUSED)?;
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
        "coverage": "durable local delivery journal; relay retention is not member acceptance or human reading",
        "driver": {"outgoing": outgoing.to_string(), "applied": applied.to_string()},
        "jobs": jobs,
        "evidence": "queue custody only; member acceptance claims are device-signed and surface through the agent session",
    }))
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
    directory.sync_all().map_err(|_| REFUSED)?;
    Ok(())
}

/// Lifetime queue custody is separate from a finite, one-use agent grant.
pub(super) struct Driver {
    config: Config,
    context: Context,
    namespace: RelayNamespace,
    relay: TlsRelay,
    queue: DeliveryStore,
    scan: ScanDirectory,
    _directory: File,
    _lock: File,
    /// Local outbox watermark: records up to `outgoing` were considered for
    /// enqueue. Durable via the queue's driver checkpoint.
    outgoing: u64,
    /// Contiguous applied watermark: every staged mailbox position at or below
    /// it has a validated marker. Restored from the markers on open.
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
    next_poll: Instant,
    idle: Duration,
    err: Duration,
    scan_full: bool,
}
impl Driver {
    pub(super) fn open(path: &Path, context: Context) -> Result<Self, String> {
        let (config, namespace, relay) = Config::load(path, context)?;
        let (directory, uid) =
            custody::open_private_directory(&config.state).map_err(|_| REFUSED)?;
        let lock =
            custody::open_private_file(&config.state.join("lock"), uid, 0).map_err(|_| REFUSED)?;
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
        let staged_head = scan.cursor();
        let (cp_outgoing, cp_applied) = queue.driver_checkpoint().map_err(|_| REFUSED)?;
        let (applied, ahead) =
            applied_restore(&applied_dir, config.initial_cursor, staged_head, cp_applied)?;
        Ok(Self {
            config,
            context,
            namespace,
            relay,
            queue,
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
            next_poll: Instant::now(),
            idle: IDLE_BASE,
            err: ERR_BASE,
            scan_full: false,
        })
    }
    /// One bounded host tick between RPCs. Kernel uncertainty ends the grant;
    /// no latch-clearing reopen, ratchet regeneration or budget renewal occurs.
    /// Each stage resumes from durable or staged positions, so a partial pass
    /// loses no work and a relaunch does not replay completed stages.
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
        self.catch_up(rpc, deadline).await?;
        self.deliver(rpc, deadline).await?;
        self.poll(deadline)?;
        self.apply(rpc, deadline).await?;
        self.save()?;
        rpc.check_release().map_err(|_| REFUSED.to_string())
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
        if self.outgoing == 0 {
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

    /// Attempt due relay jobs within the tick budget and deliver each updated
    /// status to the RPC view.
    async fn deliver(&mut self, rpc: &mut RpcSession, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline {
            return Ok(());
        }
        let tick = self
            .queue
            .tick(
                &mut self.relay,
                now()?,
                TickBudget {
                    max_jobs: TICK_JOBS,
                    max_bytes: TICK_BYTES,
                    deadline,
                },
            )
            .map_err(|_| REFUSED)?;
        for status in &tick.jobs {
            rpc.update_delivery(self.namespace, status)
                .await
                .map_err(|_| REFUSED)?;
            if status.last_error == Some(NetError::Denied) {
                // The exact job and charged backoff survive for a new explicit
                // grant with corrected credentials. End this grant before any
                // further scan or agent output; do not renew its authority.
                return Err(REFUSED.into());
            }
        }
        Ok(())
    }

    /// Poll the relay mailbox under the adaptive cadence. A nonempty page or a
    /// cursor still behind the observed head repolls on the next tick; a quiet
    /// room backs off; network errors back off independently without touching
    /// staged evidence. No lifetime attempt cap: only the current pass counts.
    fn poll(&mut self, deadline: Instant) -> Result<(), String> {
        if self.scan_full || Instant::now() < self.next_poll {
            return Ok(());
        }
        match self.scan.scan_page_until(&self.relay, PAGE, deadline) {
            Ok(report) => {
                self.staged_head = self.scan.cursor();
                if report.scanned > 0 || self.staged_head < report.head {
                    self.next_poll = Instant::now();
                    self.idle = IDLE_BASE;
                } else {
                    self.idle = (self.idle * 2).min(IDLE_MAX);
                    self.next_poll = Instant::now() + self.idle;
                }
                self.err = ERR_BASE;
            }
            Err(ScanFailure::Net(
                NetError::Connect | NetError::Timeout | NetError::Capacity | NetError::Unavailable,
            )) => {
                self.next_poll = Instant::now() + self.err;
                self.err = (self.err * 2).min(ERR_MAX);
            }
            Err(ScanFailure::Timeout) => {
                self.next_poll = Instant::now();
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
        while self.ahead.contains(&(self.applied + 1)) {
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
        let start = self.applied;
        for position in (start + 1)..=self.staged_head {
            if done >= PAGE || Instant::now() >= deadline {
                break;
            }
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
                // Restore claims after restart only by re-reading authenticated
                // kernel receive evidence and checking the signature below.
                match self.process(rpc, &item, position, own_echo).await? {
                    Some(expected) if expected == **bytes => {
                        self.complete(position);
                        continue;
                    }
                    Some(_) => return Err(REFUSED.into()),
                    None => {
                        self.defer(position)?;
                        continue;
                    }
                }
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
            OutboxKind::Application => match rpc.host().receive(item.payload()).await {
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
                        let mut hash = Sha256::new();
                        hash.update(b"vhalla/host/receipt-operation/v1\0");
                        hash.update(self.context.device.as_bytes());
                        hash.update(MemberAcceptance::ciphertext_commitment(item.payload()));
                        let digest: [u8; 32] = hash.finalize().into();
                        let operation =
                            OperationId::from_bytes(digest[..16].try_into().map_err(|_| REFUSED)?)
                                .map_err(|_| REFUSED)?;
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
                        let relay = RelayItem::from_artifact(self.namespace, &receipt)
                            .map_err(|_| REFUSED)?;
                        let status = self.queue.enqueue(&relay, now()?).map_err(|_| REFUSED)?;
                        rpc.update_delivery(self.namespace, &status)
                            .await
                            .map_err(|_| REFUSED)?;
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
            OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession => {
                match rpc.host().apply_control(item.payload()).await {
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
                }
            }
            OutboxKind::ContactInvitation | OutboxKind::ContactRequest => {
                result["state"] = json!("dedicated-bootstrap-command-required");
                Ok(Some(serde_json::to_vec(&result).map_err(|_| REFUSED)?))
            }
            _ => Err(REFUSED.into()),
        }
    }

    /// Persist the `(outgoing, applied)` checkpoint when it advanced.
    fn save(&mut self) -> Result<(), String> {
        let current = (self.outgoing, self.applied);
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
    let ahead: BTreeSet<u64> = marked.into_iter().filter(|p| *p > applied).collect();
    Ok((applied, ahead))
}

#[cfg(test)]
mod tests {
    use super::*;

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
