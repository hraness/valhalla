//! Trusted-host durable exact-ciphertext delivery jobs. No keys, encryption,
//! room operations, background loops, sleeps or member-acceptance claims.
//!
//! A tick writes and synchronizes attempt intent before calling the transport.
//! Reopen preserves uncertain attempts, exact bytes and monotonically observed
//! caller time. This is local custody, not defense against coherent host rollback.
//!
//! Transport-unreachable outcomes (`Connect`, `Timeout`, `Unavailable`) are an
//! outage, not a refusal: they never spend the finite attempt budget. They are
//! bounded by the exponential backoff ceiling instead and counted as outage
//! evidence. Only definitive refusals (`Denied`, `Capacity`) spend attempts,
//! and permanent refusals stop a job at once. A stopped job can be re-armed
//! explicitly with [`DeliveryStore::resume`], which keeps every prior attempt
//! as evidence and never creates a new queue.
use super::{net::NetError, RelayItem, RelayNamespace, RelayReceipt, MAX_RELAY_ITEMS};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    net::SocketAddr,
    path::Path,
    time::{Duration, Instant},
};
use vhalla_custody as custody;
use vhalla_private_kernel::{Context, OperationId};
#[cfg(test)]
mod tests;
const MAX_ITEM_BYTES: usize = super::codec::MAX_PUT_BODY - 32;
const MAX_TICK_BYTES: usize = 4 * 1024 * 1024;
const MAX_DATABASE_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Largest tolerated wall-clock regression. Within it the committed clock is
/// held (retries wait a little longer); beyond it the caller time is refused
/// because the retained clock or the host clock needs operator review.
pub const MAX_CLOCK_REGRESSION_SECS: u64 = 3600;
type MetadataRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, i64, i64, i64);
type JobRow = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, Option<i64>, i64);
const EVIDENCE_TABLE: &str = "CREATE TABLE IF NOT EXISTS job_evidence(id BLOB PRIMARY KEY REFERENCES jobs(id),outages INTEGER NOT NULL CHECK(outages>=0),resumes INTEGER NOT NULL CHECK(resumes>=0),spent_attempts INTEGER NOT NULL CHECK(spent_attempts>=0),resumed_at INTEGER NOT NULL CHECK(resumed_at>=0))";

/// Opaque commitment to the explicitly selected transport trust configuration.
/// It excludes rotating tokens; credential replacement cannot redirect jobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointId([u8; 32]);
impl EndpointId {
    /// Import an independently pinned transport-profile commitment.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(Error::Bounds)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Full profile commitment for trusted local metadata, never a routing address.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Canonical TLS trust profile. Address, name, CA bytes and namespace all bind.
    /// Tokens are deliberately absent so explicit rotation preserves queued work.
    pub fn tls(
        address: SocketAddr,
        name: &str,
        ca_der: &[u8],
        namespace: RelayNamespace,
    ) -> Result<Self> {
        if name.is_empty() || name.len() > 253 || ca_der.is_empty() || ca_der.len() > 65536 {
            return Err(Error::Bounds);
        }
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/delivery-endpoint/tls/v1");
        for bytes in [
            address.to_string().as_bytes(),
            name.as_bytes(),
            ca_der,
            namespace.as_bytes(),
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Self::from_bytes(hash.finalize().into())
    }
}
/// The host selects a transport under the store's exact profile before a tick.
pub trait Transport {
    /// Independent endpoint trust selection; never derive it from a peer reply.
    fn endpoint_id(&self) -> EndpointId;
    /// Explicit opaque rendezvous namespace.
    fn namespace(&self) -> RelayNamespace;
    /// Submit exactly these committed bytes inside one absolute deadline.
    fn submit_until(
        &mut self,
        item: &RelayItem,
        deadline: Instant,
    ) -> std::result::Result<RelayReceipt, NetError>;
}
/// Immutable queue retention limits. Reaching them never deletes existing jobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum live jobs (pending, uncertain or stopped). Retained jobs keep
    /// their evidence but no longer count, so a busy queue never bricks itself;
    /// `enqueue` at this bound returns the retryable [`Error::Capacity`].
    pub max_jobs: usize,
    /// Total canonical ciphertext bytes across every job, at most 1 GiB.
    pub max_bytes: usize,
}
/// Immutable finite retry policy in seconds. There is no automatic budget reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum budget-charged attempts for a job, 1..100. Outages never charge.
    pub max_attempts: u32,
    /// Initial backoff, 1..3600 seconds.
    pub initial_backoff_secs: u64,
    /// Backoff ceiling, at most one day.
    pub max_backoff_secs: u64,
}
/// Work admitted by one externally scheduled tick; this method never sleeps.
#[derive(Clone, Copy, Debug)]
pub struct TickBudget {
    /// Maximum eligible jobs, 1..64.
    pub max_jobs: usize,
    /// Total attempted canonical bytes, 1..4 MiB.
    pub max_bytes: usize,
    /// Absolute operation deadline, at most 90 seconds away.
    pub deadline: Instant,
}
/// Local queue state, deliberately separate from member acceptance or reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobState {
    /// Retained locally; last known refusal had no effects.
    Pending,
    /// An attempt may have retained bytes remotely; retry exact bytes.
    Uncertain,
    /// Exact digest/position retention receipt was checked and retained.
    Retained,
    /// Finite retry budget ended or a permanent refusal needs operator review.
    Stopped,
}
/// Metadata only; no ciphertext or private context is returned to agent views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStatus {
    /// Stable exact-ciphertext job identity.
    pub id: [u8; 32],
    /// Original sender-local outbox position.
    pub sequence: u64,
    /// Original kernel operation identity.
    pub operation: OperationId,
    /// Current local delivery state.
    pub state: JobState,
    /// Budget-charged attempts: intents whose outcome was a refusal or is still
    /// unknown. Outage outcomes are reverted here and counted in [`JobEvidence`].
    pub attempts: u32,
    /// Earliest caller UNIX second eligible for retry.
    pub next_due: u64,
    /// True means a prior transport outcome remains uncertain, including Stopped.
    pub uncertain: bool,
    /// Checked mailbox position for Retained only.
    pub position: Option<u64>,
    /// Closed last transport failure, without private data.
    pub last_error: Option<NetError>,
}
/// Retained per-job evidence that is never spent or pruned by retries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobEvidence {
    /// Transport-unreachable outcomes observed for this job.
    pub outages: u32,
    /// Explicit operator re-arms of a stopped job.
    pub resumes: u32,
    /// Attempts consumed before each re-arm, summed.
    pub spent_attempts: u32,
    /// Caller UNIX second of the last re-arm, zero when never resumed.
    pub resumed_at: u64,
}
/// One finite tick's updated jobs. A budget stop preserves all remaining work.
#[derive(Clone, Debug)]
pub struct TickReport {
    /// Attempt results in stable due-time/outbox order.
    pub jobs: Vec<JobStatus>,
    /// Attempted exact canonical bytes.
    pub bytes: usize,
    /// An item/time/work boundary ended this tick.
    pub budget_exhausted: bool,
}
/// Closed failures; uncertain local writes require exact-store reopen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Malformed or excessive input.
    Bounds,
    /// Foreign room, namespace or endpoint binding.
    Scope,
    /// Conflicting immutable operation or sequence.
    Conflict,
    /// Queue storage is full; evidence remains retained.
    Capacity,
    /// Another owner holds the persistent queue lock.
    Busy,
    /// A storage operation may be incomplete; preserve and reopen.
    Storage,
    /// Retained records contradict their commitments or bounds.
    Corrupt,
    /// Caller time moved more than [`MAX_CLOCK_REGRESSION_SECS`] behind the
    /// retained clock or exceeds the supported range.
    Clock,
    /// This handle had an uncertain write and must be reopened.
    NeedsReopen,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// One exact room/namespace/endpoint queue with lifetime exclusive custody.
/// Full context stays in this owner-private local store, never the relay protocol.
pub struct DeliveryStore {
    conn: Connection,
    directory: File,
    _db_guard: File,
    _lock: File,
    namespace: RelayNamespace,
    endpoint: EndpointId,
    limits: Limits,
    policy: RetryPolicy,
    needs_reopen: bool,
}
fn context_bytes(context: Context) -> [u8; 128] {
    let mut raw = [0; 128];
    for (slot, field) in raw.as_chunks_mut::<32>().0.iter_mut().zip([
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
    ]) {
        slot.copy_from_slice(field);
    }
    raw
}
fn check_limits(limits: Limits, policy: RetryPolicy) -> Result<()> {
    if !(1..=MAX_RELAY_ITEMS).contains(&limits.max_jobs)
        || limits.max_bytes == 0
        || limits.max_bytes > 1024 * 1024 * 1024
        || !(1..=100).contains(&policy.max_attempts)
        || !(1..=3600).contains(&policy.initial_backoff_secs)
        || policy.max_backoff_secs < policy.initial_backoff_secs
        || policy.max_backoff_secs > 86400
    {
        return Err(Error::Bounds);
    }
    Ok(())
}
fn configure(conn: &Connection) -> Result<()> {
    conn.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        (MAX_ITEM_BYTES + 4096) as i32,
    )
    .map_err(|_| Error::Storage)?;
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
    )
    .map_err(|_| Error::Storage)
}
impl DeliveryStore {
    /// Create a never-used private directory and bind all immutable policy before use.
    pub fn create_new(
        path: impl AsRef<Path>,
        context: Context,
        namespace: RelayNamespace,
        endpoint: EndpointId,
        limits: Limits,
        policy: RetryPolicy,
    ) -> Result<Self> {
        check_limits(limits, policy)?;
        let path = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        let (directory, _) =
            custody::create_private_directory(&path).map_err(|_| Error::Storage)?;
        let lock = custody::create_private_file(&path.join("lock")).map_err(|_| Error::Storage)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Busy)?;
        let db_guard =
            custody::create_private_file(&path.join("delivery.db")).map_err(|_| Error::Storage)?;
        let conn = Connection::open_with_flags(
            path.join("delivery.db"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|_| Error::Storage)?;
        configure(&conn)?;
        conn.execute_batch("CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=1),context BLOB NOT NULL CHECK(length(context)=128),namespace BLOB NOT NULL CHECK(length(namespace)=32),endpoint BLOB NOT NULL CHECK(length(endpoint)=32),max_jobs INTEGER NOT NULL,max_bytes INTEGER NOT NULL,max_attempts INTEGER NOT NULL,initial_backoff INTEGER NOT NULL,max_backoff INTEGER NOT NULL,clock INTEGER NOT NULL CHECK(clock>=0));
            CREATE TABLE jobs(id BLOB PRIMARY KEY CHECK(length(id)=32),sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8),operation BLOB NOT NULL UNIQUE CHECK(length(operation)=16),item BLOB NOT NULL,state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),attempts INTEGER NOT NULL CHECK(attempts>=0),next_due INTEGER NOT NULL CHECK(next_due>=0),uncertain INTEGER NOT NULL CHECK(uncertain IN (0,1)),position INTEGER,last_error INTEGER NOT NULL CHECK(last_error BETWEEN 0 AND 9));
            CREATE TABLE driver(id INTEGER PRIMARY KEY CHECK(id=1),outgoing INTEGER NOT NULL CHECK(outgoing>=0),applied INTEGER NOT NULL CHECK(applied>=0));
            INSERT INTO driver VALUES(1,0,0);").map_err(|_|Error::Storage)?;
        conn.execute_batch(EVIDENCE_TABLE)
            .map_err(|_| Error::Storage)?;
        conn.execute(
            "INSERT INTO meta VALUES(1,1,?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![
                context_bytes(context).as_slice(),
                namespace.as_bytes().as_slice(),
                endpoint.as_bytes().as_slice(),
                limits.max_jobs as i64,
                limits.max_bytes as i64,
                policy.max_attempts,
                policy.initial_backoff_secs as i64,
                policy.max_backoff_secs as i64
            ],
        )
        .map_err(|_| Error::Storage)?;
        let out = Self {
            conn,
            directory,
            _db_guard: db_guard,
            _lock: lock,
            namespace,
            endpoint,
            limits,
            policy,
            needs_reopen: false,
        };
        out.sync()?;
        File::open(path.parent().ok_or(Error::Storage)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
        Ok(out)
    }
    /// Reopen exact retained custody. Missing lock/database/binding files refuse;
    /// no used queue is ever initialized, reset, pruned or implicitly rebound.
    pub fn open(
        path: impl AsRef<Path>,
        context: Context,
        namespace: RelayNamespace,
        endpoint: EndpointId,
    ) -> Result<Self> {
        let path = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        let (directory, uid) =
            custody::open_private_directory(&path).map_err(|_| Error::Storage)?;
        let lock =
            custody::open_private_file(&path.join("lock"), uid, 0).map_err(|_| Error::Corrupt)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Busy)?;
        let db_guard =
            custody::open_private_file(&path.join("delivery.db"), uid, MAX_DATABASE_BYTES)
                .map_err(|_| Error::Corrupt)?;
        if custody::private_file_present(&path.join("delivery.db-journal"), uid, MAX_DATABASE_BYTES)
            .map_err(|_| Error::Corrupt)?
        { /* SQLite recovers exact owned rollback evidence. */
        }
        let conn = Connection::open_with_flags(
            path.join("delivery.db"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(|_| Error::Storage)?;
        configure(&conn)?;
        let (format,stored_context,stored_ns,stored_endpoint,max_jobs,max_bytes,max_attempts,initial,max_backoff,clock):MetadataRow=conn.query_row("SELECT format,context,namespace,endpoint,max_jobs,max_bytes,max_attempts,initial_backoff,max_backoff,clock FROM meta WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).map_err(|_|Error::Corrupt)?;
        if format != 1
            || stored_context != context_bytes(context)
            || stored_ns != namespace.as_bytes()
            || stored_endpoint != endpoint.as_bytes()
        {
            return Err(Error::Scope);
        }
        let limits = Limits {
            max_jobs: usize::try_from(max_jobs).map_err(|_| Error::Corrupt)?,
            max_bytes: usize::try_from(max_bytes).map_err(|_| Error::Corrupt)?,
        };
        let policy = RetryPolicy {
            max_attempts: u32::try_from(max_attempts).map_err(|_| Error::Corrupt)?,
            initial_backoff_secs: u64::try_from(initial).map_err(|_| Error::Corrupt)?,
            max_backoff_secs: u64::try_from(max_backoff).map_err(|_| Error::Corrupt)?,
        };
        check_limits(limits, policy).map_err(|_| Error::Corrupt)?;
        if clock < 0 {
            return Err(Error::Corrupt);
        }
        let present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='job_evidence'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Corrupt)?;
        let mut out = Self {
            conn,
            directory,
            _db_guard: db_guard,
            _lock: lock,
            namespace,
            endpoint,
            limits,
            policy,
            needs_reopen: false,
        };
        if present == 0 {
            // Additive evidence table for queues created before outage
            // accounting existed. Jobs, bytes, clock and binding are untouched.
            out.conn
                .execute_batch(EVIDENCE_TABLE)
                .map_err(|_| Error::Storage)?;
            out.sync()?;
        }
        out.validate()?;
        // Format-1 queues predate the driver watermark table. Add the table
        // and its zero row under the same commit barrier; job/meta bytes and
        // every retained attempt are untouched. A later save may only advance
        // the monotone watermarks, never reinterpret them.
        out.begin()?;
        out.conn
            .execute_batch("CREATE TABLE IF NOT EXISTS driver(id INTEGER PRIMARY KEY CHECK(id=1),outgoing INTEGER NOT NULL CHECK(outgoing>=0),applied INTEGER NOT NULL CHECK(applied>=0));
                INSERT OR IGNORE INTO driver VALUES(1,0,0);")
            .map_err(|_| Error::Storage)?;
        out.commit(clock)?;
        Ok(out)
    }
    /// One durability barrier per commit. SQLite already fsyncs the journal and
    /// database under `synchronous=FULL`; the directory barrier is a whole-device
    /// flush on Apple hosts and also makes the journal unlink durable.
    fn sync(&self) -> Result<()> {
        self.directory.sync_all().map_err(|_| Error::Storage)
    }
    fn live(&self) -> Result<()> {
        if self.needs_reopen {
            Err(Error::NeedsReopen)
        } else {
            Ok(())
        }
    }
    fn clock(&self, now: u64) -> Result<i64> {
        self.live()?;
        if now > i64::MAX as u64 - self.policy.max_backoff_secs {
            return Err(Error::Clock);
        }
        let previous: i64 = self
            .conn
            .query_row("SELECT clock FROM meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| Error::Corrupt)?;
        if previous < 0 {
            return Err(Error::Corrupt);
        }
        let previous = previous as u64;
        if now < previous {
            // Hold the committed clock through a bounded wall-clock step back;
            // retries wait slightly longer instead of ending every launch.
            return if previous - now <= MAX_CLOCK_REGRESSION_SECS {
                Ok(previous as i64)
            } else {
                Err(Error::Clock)
            };
        }
        Ok(now as i64)
    }
    fn begin(&mut self) -> Result<()> {
        self.live()?;
        self.needs_reopen = true;
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| Error::Storage)
    }
    fn commit(&mut self, now: i64) -> Result<()> {
        self.conn
            .execute("UPDATE meta SET clock=?1 WHERE id=1", params![now])
            .map_err(|_| Error::Storage)?;
        self.conn
            .execute_batch("COMMIT")
            .map_err(|_| Error::Storage)?;
        self.sync()?;
        let actual: i64 = self
            .conn
            .query_row("SELECT clock FROM meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| Error::Corrupt)?;
        if actual != now {
            return Err(Error::Corrupt);
        }
        self.needs_reopen = false;
        Ok(())
    }
    /// Persist canonical committed ciphertext before scheduling. Exact retries
    /// return original job status; sequence or operation reuse with new bytes refuses.
    pub fn enqueue(&mut self, item: &RelayItem, now: u64) -> Result<JobStatus> {
        let clock = self.clock(now)?;
        if item.namespace() != self.namespace {
            return Err(Error::Scope);
        }
        if let Some(prior) = self.find(item.digest())? {
            if self.item(item.digest())? != *item {
                return Err(Error::Conflict);
            }
            // An exact retry is a pure read: it must not append a begin/commit
            // barrier, or every relaunch replay would rewrite the journal once
            // per already-enqueued job. The retained clock is unchanged because
            // no durable fact was published.
            return Ok(prior);
        }
        let conflict: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM jobs WHERE sequence=?1 OR operation=?2)",
                params![
                    item.sequence().to_be_bytes().as_slice(),
                    item.operation().as_bytes().as_slice()
                ],
                |r| r.get(0),
            )
            .map_err(|_| Error::Corrupt)?;
        if conflict {
            return Err(Error::Conflict);
        }
        let bytes = item.encode().map_err(|_| Error::Bounds)?;
        let (count, total) = self.usage()?;
        if count >= self.limits.max_jobs
            || total
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.limits.max_bytes)
        {
            return Err(Error::Capacity);
        }
        self.begin()?;
        self.conn
            .execute(
                "INSERT INTO jobs VALUES(?1,?2,?3,?4,0,0,?5,0,NULL,0)",
                params![
                    item.digest().as_slice(),
                    item.sequence().to_be_bytes().as_slice(),
                    item.operation().as_bytes().as_slice(),
                    bytes,
                    clock
                ],
            )
            .map_err(|_| Error::Storage)?;
        self.commit(clock)?;
        self.find(item.digest())?.ok_or(Error::Corrupt)
    }
    /// Bounded immutable metadata view in original sender outbox order.
    pub fn statuses(&self, after: u64, limit: usize) -> Result<Vec<JobStatus>> {
        self.live()?;
        if !(1..=64).contains(&limit) {
            return Err(Error::Bounds);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM jobs WHERE sequence>?1 ORDER BY sequence LIMIT ?2")
            .map_err(|_| Error::Corrupt)?;
        let ids = stmt
            .query_map(params![after.to_be_bytes().as_slice(), limit as i64], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(|_| Error::Corrupt)?;
        let mut out = Vec::new();
        for id in ids {
            let id: [u8; 32] = id
                .map_err(|_| Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            out.push(self.find(id)?.ok_or(Error::Corrupt)?);
        }
        Ok(out)
    }
    /// Read the retained status of one exact-ciphertext job, if present. The
    /// digest is a durable local-echo commitment: a staged mailbox item whose
    /// digest matches a job was already committed to this queue by this owner.
    pub fn job(&self, id: [u8; 32]) -> Result<Option<JobStatus>> {
        self.live()?;
        self.find(id)
    }
    /// Durable monotone driver watermarks: the local-outbox sequence already
    /// scanned into this queue and the contiguous applied mailbox position.
    /// Both start at zero for queues that predate the driver table.
    pub fn driver_checkpoint(&self) -> Result<(u64, u64)> {
        self.live()?;
        let row: Option<(i64, i64)> = self
            .conn
            .query_row("SELECT outgoing,applied FROM driver WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(|_| Error::Corrupt)?;
        let Some((outgoing, applied)) = row else {
            return Ok((0, 0));
        };
        Ok((
            u64::try_from(outgoing).map_err(|_| Error::Corrupt)?,
            u64::try_from(applied).map_err(|_| Error::Corrupt)?,
        ))
    }
    /// Advance the durable driver watermarks. They may only move forward; a
    /// lower value than retained is a caller bug, never a state repair.
    pub fn save_driver_checkpoint(&mut self, outgoing: u64, applied: u64, now: u64) -> Result<()> {
        let clock = self.clock(now)?;
        let (last_outgoing, last_applied) = self.driver_checkpoint()?;
        if outgoing < last_outgoing || applied < last_applied {
            return Err(Error::Bounds);
        }
        if outgoing == last_outgoing && applied == last_applied {
            return Ok(());
        }
        self.begin()?;
        self.conn
            .execute(
                "UPDATE driver SET outgoing=?1,applied=?2 WHERE id=1",
                params![outgoing as i64, applied as i64],
            )
            .map_err(|_| Error::Storage)?;
        self.commit(clock)?;
        if self.driver_checkpoint()? != (outgoing, applied) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    /// Live job count (pending, uncertain, stopped) and total retained bytes.
    fn usage(&self) -> Result<(usize, usize)> {
        let (count, total): (i64, i64) = self
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM jobs WHERE state IN (0,1,3)),COALESCE((SELECT SUM(length(item)) FROM jobs),0)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Corrupt)?;
        if count < 0 || total < 0 {
            return Err(Error::Corrupt);
        }
        Ok((count as usize, total as usize))
    }
    /// Live jobs, the live bound, retained bytes and the byte bound, in that
    /// order, so a host can report a full queue instead of ending its grant.
    pub fn capacity(&self) -> Result<(usize, usize, usize, usize)> {
        self.live()?;
        let (count, total) = self.usage()?;
        Ok((count, self.limits.max_jobs, total, self.limits.max_bytes))
    }
    /// Retained outage/re-arm evidence for one job; absent rows are zero.
    pub fn evidence(&self, id: [u8; 32]) -> Result<JobEvidence> {
        self.live()?;
        if self.find(id)?.is_none() {
            return Err(Error::Bounds);
        }
        self.evidence_row(id)
    }
    fn evidence_row(&self, id: [u8; 32]) -> Result<JobEvidence> {
        let row: Option<(i64, i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT outages,resumes,spent_attempts,resumed_at FROM job_evidence WHERE id=?1",
                params![id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| Error::Corrupt)?;
        let Some((outages, resumes, spent, at)) = row else {
            return Ok(JobEvidence::default());
        };
        Ok(JobEvidence {
            outages: u32::try_from(outages).map_err(|_| Error::Corrupt)?,
            resumes: u32::try_from(resumes).map_err(|_| Error::Corrupt)?,
            spent_attempts: u32::try_from(spent).map_err(|_| Error::Corrupt)?,
            resumed_at: u64::try_from(at).map_err(|_| Error::Corrupt)?,
        })
    }
    fn record_outage(&self, id: [u8; 32]) -> Result<()> {
        self.conn.execute("INSERT INTO job_evidence VALUES(?1,1,0,0,0) ON CONFLICT(id) DO UPDATE SET outages=MIN(outages+1,1000000)",params![id.as_slice()]).map_err(|_|Error::Storage)?;
        Ok(())
    }
    /// Explicitly re-arm stopped jobs (all, or one exact job id). Attempts spent
    /// so far move into retained evidence, prior uncertainty is preserved and
    /// the exact bytes are retried from a fresh budget. Nothing is pruned; the
    /// queue must be closed by any driver first because custody is exclusive.
    pub fn resume(&mut self, only: Option<[u8; 32]>, now: u64) -> Result<Vec<JobStatus>> {
        let clock = self.clock(now)?;
        let ids = {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM jobs WHERE state=3 ORDER BY sequence")
                .map_err(|_| Error::Corrupt)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))
                .map_err(|_| Error::Corrupt)?;
            let mut ids = Vec::new();
            for id in rows {
                let id = <[u8; 32]>::try_from(id.map_err(|_| Error::Corrupt)?)
                    .map_err(|_| Error::Corrupt)?;
                if only.is_none_or(|wanted| wanted == id) {
                    ids.push(id);
                }
            }
            ids
        };
        if let Some(wanted) = only {
            if self.find(wanted)?.is_none() {
                return Err(Error::Bounds);
            }
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.begin()?;
        for id in &ids {
            let prior = self.find(*id)?.ok_or(Error::Corrupt)?;
            self.conn.execute("INSERT INTO job_evidence VALUES(?1,0,1,?2,?3) ON CONFLICT(id) DO UPDATE SET resumes=resumes+1,spent_attempts=spent_attempts+?2,resumed_at=?3",params![id.as_slice(),prior.attempts,clock]).map_err(|_|Error::Storage)?;
            self.conn
                .execute(
                    "UPDATE jobs SET state=?1,attempts=0,next_due=?2 WHERE id=?3",
                    params![i64::from(prior.uncertain), clock, id.as_slice()],
                )
                .map_err(|_| Error::Storage)?;
        }
        self.commit(clock)?;
        ids.into_iter()
            .map(|id| self.find(id)?.ok_or(Error::Corrupt))
            .collect()
    }
    /// Run finite due work without sleeping or re-encrypting. The host schedules
    /// another tick after next_due; an expired deadline never starts a new attempt.
    /// Credential denial ends this tick with its charged attempt and backoff
    /// retained. The host must end the current grant before explicitly replacing
    /// credentials; a replacement never renews the original retry budget.
    /// A tick with nothing due performs no durable write.
    pub fn tick(
        &mut self,
        transport: &mut impl Transport,
        now: u64,
        budget: TickBudget,
    ) -> Result<TickReport> {
        let clock = self.clock(now)?;
        if transport.endpoint_id() != self.endpoint || transport.namespace() != self.namespace {
            return Err(Error::Scope);
        }
        if !(1..=64).contains(&budget.max_jobs)
            || budget.max_bytes == 0
            || budget.max_bytes > MAX_TICK_BYTES
            || budget
                .deadline
                .checked_duration_since(Instant::now())
                .is_some_and(|d| d > Duration::from_secs(90))
        {
            return Err(Error::Bounds);
        }
        if Instant::now() >= budget.deadline {
            return Ok(TickReport {
                jobs: Vec::new(),
                bytes: 0,
                budget_exhausted: true,
            });
        }
        let ids = {
            let mut stmt=self.conn.prepare("SELECT id FROM jobs WHERE state IN (0,1) AND next_due<=?1 ORDER BY next_due,sequence LIMIT ?2").map_err(|_|Error::Corrupt)?;
            let rows = stmt
                .query_map(params![clock, budget.max_jobs as i64], |r| {
                    r.get::<_, Vec<u8>>(0)
                })
                .map_err(|_| Error::Corrupt)?;
            let mut ids = Vec::new();
            for id in rows {
                ids.push(
                    <[u8; 32]>::try_from(id.map_err(|_| Error::Corrupt)?)
                        .map_err(|_| Error::Corrupt)?,
                );
            }
            ids
        };
        let mut report = TickReport {
            jobs: Vec::new(),
            bytes: 0,
            budget_exhausted: ids.len() == budget.max_jobs,
        };
        for id in ids {
            if Instant::now() >= budget.deadline {
                report.budget_exhausted = true;
                break;
            }
            let prior = self.find(id)?.ok_or(Error::Corrupt)?;
            let item = self.item(id)?;
            let size = item.encode().map_err(|_| Error::Corrupt)?.len();
            if report
                .bytes
                .checked_add(size)
                .is_none_or(|n| n > budget.max_bytes)
            {
                report.budget_exhausted = true;
                break;
            }
            if prior.attempts >= self.policy.max_attempts {
                self.begin()?;
                self.conn
                    .execute(
                        "UPDATE jobs SET state=3 WHERE id=?1",
                        params![id.as_slice()],
                    )
                    .map_err(|_| Error::Storage)?;
                self.commit(clock)?;
                report.jobs.push(self.find(id)?.ok_or(Error::Corrupt)?);
                continue;
            }
            let attempt = prior.attempts + 1;
            // Outages keep growing the backoff without spending the budget.
            let exponent = prior
                .attempts
                .saturating_add(self.evidence_row(id)?.outages);
            let delay = self
                .policy
                .initial_backoff_secs
                .saturating_mul(1u64.checked_shl(exponent).unwrap_or(u64::MAX))
                .min(self.policy.max_backoff_secs);
            let due = (clock as u64).checked_add(delay).ok_or(Error::Clock)?;
            self.begin()?;
            self.conn.execute("UPDATE jobs SET state=1,attempts=?1,next_due=?2,uncertain=1,last_error=0 WHERE id=?3",params![attempt,due as i64,id.as_slice()]).map_err(|_|Error::Storage)?;
            self.commit(clock)?;
            // A crash or expired deadline after this barrier leaves recoverable
            // uncertainty; never erase intent just because no reply was observed.
            if Instant::now() >= budget.deadline {
                report.budget_exhausted = true;
                report.jobs.push(self.find(id)?.ok_or(Error::Corrupt)?);
                break;
            }
            let outcome = transport.submit_until(&item, budget.deadline);
            report.bytes += size;
            let (state, uncertain, position, error, outage) = match outcome {
                Ok(receipt)
                    if receipt.position > 0
                        && receipt.position <= i64::MAX as u64
                        && receipt.digest == id =>
                {
                    (2, false, Some(receipt.position as i64), 0, false)
                }
                Ok(_) => (3, true, None, error_code(NetError::Malformed), false),
                Err(error) => {
                    let outage = matches!(
                        error,
                        NetError::Connect | NetError::Timeout | NetError::Unavailable
                    );
                    // An unreachable relay may still have retained the bytes.
                    let uncertain = prior.uncertain || outage;
                    let permanent = matches!(
                        error,
                        NetError::Conflict
                            | NetError::Bounds
                            | NetError::Scope
                            | NetError::Malformed
                    );
                    (
                        if permanent || (!outage && attempt >= self.policy.max_attempts) {
                            3
                        } else if uncertain {
                            1
                        } else {
                            0
                        },
                        uncertain,
                        None,
                        error_code(error),
                        outage,
                    )
                }
            };
            self.begin()?;
            if outage {
                // The intent was durable, but an outage is not a spent attempt:
                // revert the charge and retain it as outage evidence instead.
                self.record_outage(id)?;
                self.conn
                    .execute(
                        "UPDATE jobs SET attempts=?1 WHERE id=?2",
                        params![prior.attempts, id.as_slice()],
                    )
                    .map_err(|_| Error::Storage)?;
            }
            self.conn
                .execute(
                    "UPDATE jobs SET state=?1,uncertain=?2,position=?3,last_error=?4 WHERE id=?5",
                    params![state, i64::from(uncertain), position, error, id.as_slice()],
                )
                .map_err(|_| Error::Storage)?;
            self.commit(clock)?;
            report.jobs.push(self.find(id)?.ok_or(Error::Corrupt)?);
            if error == error_code(NetError::Denied) {
                // Do not spend other jobs' attempts on the same denied
                // credential. Trusted orchestration must end this launch.
                break;
            }
        }
        Ok(report)
    }
    fn item(&self, id: [u8; 32]) -> Result<RelayItem> {
        let raw: Vec<u8> = self
            .conn
            .query_row(
                "SELECT item FROM jobs WHERE id=?1",
                params![id.as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| Error::Corrupt)?;
        if raw.len() > MAX_ITEM_BYTES {
            return Err(Error::Corrupt);
        }
        let item = RelayItem::decode(&raw).map_err(|_| Error::Corrupt)?;
        if item.digest() != id || item.namespace() != self.namespace {
            return Err(Error::Corrupt);
        }
        Ok(item)
    }
    fn find(&self, id: [u8; 32]) -> Result<Option<JobStatus>> {
        let row:Option<JobRow>=self.conn.query_row("SELECT sequence,operation,state,attempts,next_due,uncertain,position,last_error FROM jobs WHERE id=?1",params![id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(|_|Error::Corrupt)?;
        let Some((sequence, operation, state, attempts, due, uncertain, position, error)) = row
        else {
            return Ok(None);
        };
        let sequence = u64::from_be_bytes(sequence.try_into().map_err(|_| Error::Corrupt)?);
        let operation = OperationId::from_bytes(operation.try_into().map_err(|_| Error::Corrupt)?)
            .map_err(|_| Error::Corrupt)?;
        let state = match state {
            0 => JobState::Pending,
            1 => JobState::Uncertain,
            2 => JobState::Retained,
            3 => JobState::Stopped,
            _ => return Err(Error::Corrupt),
        };
        let attempts = u32::try_from(attempts).map_err(|_| Error::Corrupt)?;
        let next_due = u64::try_from(due).map_err(|_| Error::Corrupt)?;
        let uncertain = match uncertain {
            0 => false,
            1 => true,
            _ => return Err(Error::Corrupt),
        };
        let position = position
            .map(|n| u64::try_from(n).map_err(|_| Error::Corrupt))
            .transpose()?;
        if sequence == 0
            || attempts > self.policy.max_attempts
            || position == Some(0)
            || (state == JobState::Retained) != (position.is_some())
            || (state == JobState::Retained && uncertain)
            || (state == JobState::Uncertain && !uncertain)
            || (state == JobState::Pending && uncertain)
            || (attempts == 0
                && state != JobState::Pending
                && self.evidence_row(id)? == JobEvidence::default())
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(JobStatus {
            id,
            sequence,
            operation,
            state,
            attempts,
            next_due,
            uncertain,
            position,
            last_error: decode_error(error)?,
        }))
    }
    fn validate(&self) -> Result<()> {
        let (count, total) = self.usage()?;
        if count > self.limits.max_jobs || total > self.limits.max_bytes {
            return Err(Error::Corrupt);
        }
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM jobs ORDER BY sequence")
            .map_err(|_| Error::Corrupt)?;
        let ids = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Corrupt)?;
        for id in ids {
            let id: [u8; 32] = id
                .map_err(|_| Error::Corrupt)?
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            let status = self.find(id)?.ok_or(Error::Corrupt)?;
            let item = self.item(id)?;
            if item.sequence() != status.sequence || item.operation() != status.operation {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
}
fn error_code(error: NetError) -> i64 {
    match error {
        NetError::Connect => 1,
        NetError::Timeout => 2,
        NetError::Denied => 3,
        NetError::Conflict => 4,
        NetError::Capacity => 5,
        NetError::Bounds => 6,
        NetError::Scope => 7,
        NetError::Malformed => 8,
        NetError::Unavailable => 9,
    }
}
fn decode_error(code: i64) -> Result<Option<NetError>> {
    Ok(match code {
        0 => None,
        1 => Some(NetError::Connect),
        2 => Some(NetError::Timeout),
        3 => Some(NetError::Denied),
        4 => Some(NetError::Conflict),
        5 => Some(NetError::Capacity),
        6 => Some(NetError::Bounds),
        7 => Some(NetError::Scope),
        8 => Some(NetError::Malformed),
        9 => Some(NetError::Unavailable),
        _ => return Err(Error::Corrupt),
    })
}
