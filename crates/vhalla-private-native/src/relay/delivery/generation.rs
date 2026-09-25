use super::*;

const MAX_GENERATIONS: u64 = 16;
const LEDGER_BYTES: usize = 88;
#[cfg(test)]
thread_local! { static CREATION_FAULT: std::cell::Cell<Option<u8>> = const { std::cell::Cell::new(None) }; }
fn creation_point(point: u8) -> Result<()> {
    #[cfg(test)]
    if CREATION_FAULT.with(|fault| fault.get() == Some(point)) {
        return Err(Error::Storage);
    }
    let _ = point;
    Ok(())
}
#[cfg(test)]
mod tests;

/// Exact inherited authority for an explicitly selected successor queue.
#[derive(Clone, Copy)]
pub struct SuccessorSeed {
    /// Successor ordinal, from one through fifteen.
    pub generation: u64,
    /// Drained predecessor evidence, including all older spend.
    pub prior: LedgerSnapshot,
    /// Full private controller pause receipt commitment.
    pub receipt: [u8; 32],
    /// Caller time for a newly initialized monotone queue clock.
    pub now: u64,
}

fn encode(value: LedgerSnapshot) -> Vec<u8> {
    let mut raw = Vec::with_capacity(LEDGER_BYTES);
    for n in [
        value.outgoing,
        value.applied,
        value.retained_jobs,
        value.canonical_bytes,
        value.charged_attempts,
        value.outages,
        value.resumes,
    ] {
        raw.extend(n.to_be_bytes());
    }
    raw.extend(value.commitment);
    raw
}
fn decode(raw: &[u8]) -> Result<LedgerSnapshot> {
    if raw.len() != LEDGER_BYTES {
        return Err(Error::Corrupt);
    }
    let number = |index: usize| {
        u64::from_be_bytes(
            raw[index * 8..index * 8 + 8]
                .try_into()
                .expect("fixed range"),
        )
    };
    let value = LedgerSnapshot {
        outgoing: number(0),
        applied: number(1),
        retained_jobs: number(2),
        canonical_bytes: number(3),
        charged_attempts: number(4),
        outages: number(5),
        resumes: number(6),
        commitment: raw[56..].try_into().map_err(|_| Error::Corrupt)?,
    };
    if value.commitment == [0; 32]
        || value.canonical_bytes > 1024 * 1024 * 1024
        || value.retained_jobs > MAX_GENERATIONS * MAX_RELAY_ITEMS as u64
    {
        return Err(Error::Corrupt);
    }
    Ok(value)
}

impl DeliveryStore {
    /// Create or exactly finish an intent-bound successor. Every schema object
    /// and its immutable binding appears in one SQLite transaction. An empty
    /// database after interruption can finish only under the retained exact
    /// creation intent; an existing queue is opened and never reset.
    pub fn create_successor(
        path: impl AsRef<Path>,
        context: Context,
        namespace: RelayNamespace,
        endpoint: EndpointId,
        limits: Limits,
        policy: RetryPolicy,
        seed: SuccessorSeed,
    ) -> Result<Self> {
        use std::io::{Seek, SeekFrom, Write};
        check_limits(limits, policy)?;
        decode(&encode(seed.prior))?;
        if !(1..MAX_GENERATIONS).contains(&seed.generation)
            || seed.receipt == [0; 32]
            || seed.prior.canonical_bytes > limits.max_bytes as u64
            || seed.prior.outgoing > i64::MAX as u64
            || seed.now > i64::MAX as u64 - policy.max_backoff_secs
        {
            return Err(Error::Bounds);
        }
        let requested = custody::absolute(path.as_ref()).map_err(|_| Error::Storage)?;
        // SQLite NOFOLLOW rejects aliases in any path component, including
        // macOS /var. Resolve the selected existing parent only; the store
        // leaf and database retain their private no-follow checks.
        let path = requested
            .parent()
            .ok_or(Error::Storage)?
            .canonicalize()
            .map_err(|_| Error::Storage)?
            .join(requested.file_name().ok_or(Error::Storage)?);
        let existed = path.symlink_metadata().is_ok();
        let (directory, uid) = if existed {
            custody::open_private_directory(&path)
        } else {
            custody::create_private_directory(&path)
        }
        .map_err(|_| Error::Storage)?;
        creation_point(0)?;
        let mut intent = b"VHDELSEED\x01".to_vec();
        intent.extend(context_bytes(context));
        intent.extend(namespace.as_bytes());
        intent.extend(endpoint.as_bytes());
        for n in [
            limits.max_jobs as u64,
            limits.max_bytes as u64,
            u64::from(policy.max_attempts),
            policy.initial_backoff_secs,
            policy.max_backoff_secs,
            seed.generation,
        ] {
            intent.extend(n.to_be_bytes());
        }
        intent.extend(encode(seed.prior));
        intent.extend(seed.receipt);
        let intent_path = path.join("creation");
        let has_intent =
            custody::private_file_present(&intent_path, uid, 1024).map_err(|_| Error::Corrupt)?;
        let mut count = 0;
        for entry in std::fs::read_dir(&path).map_err(|_| Error::Corrupt)? {
            count += 1;
            let entry = entry.map_err(|_| Error::Corrupt)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Corrupt)?;
            if count > 4
                || !["creation", "lock", "delivery.db", "delivery.db-journal"].contains(&name)
                || (!has_intent && name != "lock")
            {
                return Err(Error::Corrupt);
            }
        }
        let lock_path = path.join("lock");
        let lock =
            if custody::private_file_present(&lock_path, uid, 0).map_err(|_| Error::Corrupt)? {
                custody::open_private_file(&lock_path, uid, 0)
            } else {
                custody::create_private_file(&lock_path)
            }
            .map_err(|_| Error::Storage)?;
        custody::acquire_exclusive(&lock).map_err(|_| Error::Busy)?;
        let prior = if has_intent {
            custody::read_private_file(&intent_path, uid, 1024).map_err(|_| Error::Corrupt)?
        } else {
            Vec::new()
        };
        if !intent.starts_with(&prior)
            || (prior.len() != intent.len() && path.join("delivery.db").symlink_metadata().is_ok())
        {
            return Err(Error::Conflict);
        }
        let mut intent_file = if has_intent {
            custody::open_private_file(&intent_path, uid, 1024)
        } else {
            custody::create_private_file(&intent_path)
        }
        .map_err(|_| Error::Storage)?;
        creation_point(1)?;
        intent_file
            .seek(SeekFrom::End(0))
            .and_then(|_| intent_file.write_all(&intent[prior.len()..]))
            .and_then(|_| intent_file.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| Error::Storage)?;
        if custody::read_private_file(&intent_path, uid, 1024).map_err(|_| Error::Corrupt)?
            != intent
        {
            return Err(Error::Corrupt);
        }
        creation_point(2)?;
        let db_path = path.join("delivery.db");
        let db = if custody::private_file_present(&db_path, uid, MAX_DATABASE_BYTES)
            .map_err(|_| Error::Corrupt)?
        {
            custody::open_private_file(&db_path, uid, MAX_DATABASE_BYTES)
        } else {
            custody::create_private_file(&db_path)
        }
        .map_err(|_| Error::Storage)?;
        creation_point(3)?;
        custody::private_file_present(&path.join("delivery.db-journal"), uid, MAX_DATABASE_BYTES)
            .map_err(|_| Error::Corrupt)?;
        let conn = Connection::open_with_flags(
            &db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::Storage)?;
        configure(&conn)?;
        let tables: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| Error::Corrupt)?;
        if tables == 0 {
            let pages: i64 = conn
                .pragma_query_value(None, "page_count", |r| r.get(0))
                .map_err(|_| Error::Corrupt)?;
            let free: i64 = conn
                .pragma_query_value(None, "freelist_count", |r| r.get(0))
                .map_err(|_| Error::Corrupt)?;
            let application: i64 = conn
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .map_err(|_| Error::Corrupt)?;
            let version: i64 = conn
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .map_err(|_| Error::Corrupt)?;
            if pages > 1
                || free != 0
                || application != 0
                || version != 0
                || db.metadata().map_err(|_| Error::Storage)?.len() > 4096
            {
                return Err(Error::Corrupt);
            }
            conn.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=2),context BLOB NOT NULL CHECK(length(context)=128),namespace BLOB NOT NULL CHECK(length(namespace)=32),endpoint BLOB NOT NULL CHECK(length(endpoint)=32),max_jobs INTEGER NOT NULL,max_bytes INTEGER NOT NULL,max_attempts INTEGER NOT NULL,initial_backoff INTEGER NOT NULL,max_backoff INTEGER NOT NULL,clock INTEGER NOT NULL CHECK(clock>=0));
                CREATE TABLE jobs(id BLOB PRIMARY KEY CHECK(length(id)=32),sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8),operation BLOB NOT NULL UNIQUE CHECK(length(operation)=16),item BLOB NOT NULL,state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),attempts INTEGER NOT NULL CHECK(attempts>=0),next_due INTEGER NOT NULL CHECK(next_due>=0),uncertain INTEGER NOT NULL CHECK(uncertain IN (0,1)),position INTEGER,last_error INTEGER NOT NULL CHECK(last_error BETWEEN 0 AND 9));
                CREATE TABLE driver(id INTEGER PRIMARY KEY CHECK(id=1),outgoing INTEGER NOT NULL CHECK(outgoing>=0),applied INTEGER NOT NULL CHECK(applied>=0));
                CREATE TABLE lineage(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 15),prior BLOB NOT NULL CHECK(length(prior)=88),receipt BLOB NOT NULL CHECK(length(receipt)=32));").map_err(|_| Error::Storage)?;
            conn.execute_batch(EVIDENCE_TABLE)
                .map_err(|_| Error::Storage)?;
            conn.execute(
                "INSERT INTO meta VALUES(1,2,?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    context_bytes(context).as_slice(),
                    namespace.as_bytes().as_slice(),
                    endpoint.as_bytes().as_slice(),
                    limits.max_jobs as i64,
                    limits.max_bytes as i64,
                    policy.max_attempts,
                    policy.initial_backoff_secs as i64,
                    policy.max_backoff_secs as i64,
                    seed.now as i64
                ],
            )
            .map_err(|_| Error::Storage)?;
            conn.execute(
                "INSERT INTO driver VALUES(1,?1,0)",
                params![seed.prior.outgoing as i64],
            )
            .map_err(|_| Error::Storage)?;
            conn.execute(
                "INSERT INTO lineage VALUES(1,?1,?2,?3)",
                params![
                    seed.generation as i64,
                    encode(seed.prior),
                    seed.receipt.as_slice()
                ],
            )
            .map_err(|_| Error::Storage)?;
            creation_point(4)?;
            conn.execute_batch("COMMIT").map_err(|_| Error::Storage)?;
            creation_point(5)?;
            directory.sync_all().map_err(|_| Error::Storage)?;
        }
        let (format, stored_context, stored_namespace, stored_endpoint, max_jobs, max_bytes, max_attempts, initial, max_backoff, clock): MetadataRow = conn.query_row("SELECT format,context,namespace,endpoint,max_jobs,max_bytes,max_attempts,initial_backoff,max_backoff,clock FROM meta WHERE id=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?))).map_err(|_| Error::Corrupt)?;
        if format != 2
            || stored_context != context_bytes(context)
            || stored_namespace != namespace.as_bytes()
            || stored_endpoint != endpoint.as_bytes()
            || max_jobs != limits.max_jobs as i64
            || max_bytes != limits.max_bytes as i64
            || max_attempts != i64::from(policy.max_attempts)
            || initial != policy.initial_backoff_secs as i64
            || max_backoff != policy.max_backoff_secs as i64
            || clock < 0
        {
            return Err(Error::Conflict);
        }
        let out = Self {
            conn,
            directory,
            _db_guard: db,
            _lock: lock,
            namespace,
            endpoint,
            limits,
            policy,
            needs_reopen: false,
        };
        if out.lineage()? != Some((seed.generation, seed.prior, seed.receipt)) {
            return Err(Error::Conflict);
        }
        out.validate()?;
        out.sync()?;
        creation_point(6)?;
        File::open(path.parent().ok_or(Error::Storage)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Storage)?;
        Ok(out)
    }

    pub(super) fn lineage(&self) -> Result<Option<(u64, LedgerSnapshot, [u8; 32])>> {
        let format: i64 = self
            .conn
            .query_row("SELECT format FROM meta WHERE id=1", [], |r| r.get(0))
            .map_err(|_| Error::Corrupt)?;
        if format == 1 {
            return Ok(None);
        }
        if format != 2 {
            return Err(Error::Corrupt);
        }
        let (generation, prior, receipt): (i64, Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT generation,prior,receipt FROM lineage WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| Error::Corrupt)?;
        let generation = u64::try_from(generation).map_err(|_| Error::Corrupt)?;
        let receipt: [u8; 32] = receipt.try_into().map_err(|_| Error::Corrupt)?;
        if !(1..MAX_GENERATIONS).contains(&generation) || receipt == [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(Some((generation, decode(&prior)?, receipt)))
    }

    /// Complete ordered evidence for a drained queue. This never marks a job
    /// retained or infers a transport result; uncertain and stopped jobs refuse.
    pub fn drained_snapshot(&self) -> Result<LedgerSnapshot> {
        self.live()?;
        if !self.is_drained()? {
            return Err(Error::Conflict);
        }
        let lineage = self.lineage()?;
        let prior = lineage.map(|(_, prior, _)| prior).unwrap_or_default();
        let (outgoing, applied) = self.driver_checkpoint()?;
        let mut snapshot = LedgerSnapshot {
            outgoing,
            applied,
            ..prior
        };
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private/delivery-ledger/v1\0");
        hash.update(self.namespace.as_bytes());
        hash.update(self.endpoint.as_bytes());
        hash.update(outgoing.to_be_bytes());
        hash.update(applied.to_be_bytes());
        if let Some((generation, prior, receipt)) = lineage {
            hash.update([1]);
            hash.update(generation.to_be_bytes());
            hash.update(encode(prior));
            hash.update(receipt);
        } else {
            hash.update([0]);
        }
        let mut after = 0;
        loop {
            let jobs = self.statuses(after, super::super::MAX_RELAY_PAGE)?;
            if jobs.is_empty() {
                break;
            }
            for job in jobs {
                if job.state != JobState::Retained || job.uncertain || job.sequence > outgoing {
                    return Err(Error::Conflict);
                }
                let item = self.item(job.id)?;
                let evidence = self.evidence_row(job.id)?;
                snapshot.retained_jobs =
                    snapshot.retained_jobs.checked_add(1).ok_or(Error::Bounds)?;
                snapshot.canonical_bytes = snapshot
                    .canonical_bytes
                    .checked_add(item.encode().map_err(|_| Error::Corrupt)?.len() as u64)
                    .ok_or(Error::Bounds)?;
                snapshot.charged_attempts = snapshot
                    .charged_attempts
                    .checked_add(u64::from(job.attempts) + u64::from(evidence.spent_attempts))
                    .ok_or(Error::Bounds)?;
                snapshot.outages = snapshot
                    .outages
                    .checked_add(u64::from(evidence.outages))
                    .ok_or(Error::Bounds)?;
                snapshot.resumes = snapshot
                    .resumes
                    .checked_add(u64::from(evidence.resumes))
                    .ok_or(Error::Bounds)?;
                hash.update(job.id);
                hash.update(job.sequence.to_be_bytes());
                hash.update(job.operation.as_bytes());
                hash.update(job.position.ok_or(Error::Corrupt)?.to_be_bytes());
                for n in [
                    u64::from(job.attempts),
                    job.next_due,
                    u64::from(evidence.outages),
                    u64::from(evidence.resumes),
                    u64::from(evidence.spent_attempts),
                    evidence.resumed_at,
                ] {
                    hash.update(n.to_be_bytes());
                }
                after = job.sequence;
            }
        }
        snapshot.commitment = hash.finalize().into();
        Ok(snapshot)
    }

    /// Seed only an empty successor, preserving predecessor spend and boundary.
    /// The explicit queue byte limit is cumulative, including inherited bytes.
    /// Version two rejects older writers. Exact retries reconcile without reset.
    pub fn initialize_successor(
        &mut self,
        generation: u64,
        prior: LedgerSnapshot,
        receipt: [u8; 32],
        now: u64,
    ) -> Result<()> {
        self.live()?;
        decode(&encode(prior))?;
        if !(1..MAX_GENERATIONS).contains(&generation)
            || receipt == [0; 32]
            || prior.canonical_bytes > self.limits.max_bytes as u64
            || prior.outgoing > i64::MAX as u64
        {
            return Err(Error::Bounds);
        }
        if let Some(existing) = self.lineage()? {
            return if existing == (generation, prior, receipt) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if self.driver_checkpoint()? != (0, 0) || !self.statuses(0, 1)?.is_empty() {
            return Err(Error::Conflict);
        }
        let clock = self.clock(now)?;
        self.begin()?;
        self.conn.execute_batch("ALTER TABLE meta RENAME TO meta_v1;
            CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),format INTEGER NOT NULL CHECK(format=2),context BLOB NOT NULL CHECK(length(context)=128),namespace BLOB NOT NULL CHECK(length(namespace)=32),endpoint BLOB NOT NULL CHECK(length(endpoint)=32),max_jobs INTEGER NOT NULL,max_bytes INTEGER NOT NULL,max_attempts INTEGER NOT NULL,initial_backoff INTEGER NOT NULL,max_backoff INTEGER NOT NULL,clock INTEGER NOT NULL CHECK(clock>=0));
            INSERT INTO meta SELECT id,2,context,namespace,endpoint,max_jobs,max_bytes,max_attempts,initial_backoff,max_backoff,clock FROM meta_v1;
            DROP TABLE meta_v1;
            CREATE TABLE lineage(id INTEGER PRIMARY KEY CHECK(id=1),generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 15),prior BLOB NOT NULL CHECK(length(prior)=88),receipt BLOB NOT NULL CHECK(length(receipt)=32));")
            .map_err(|_| Error::Storage)?;
        self.conn
            .execute(
                "INSERT INTO lineage VALUES(1,?1,?2,?3)",
                params![generation as i64, encode(prior), receipt.as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        self.conn
            .execute(
                "UPDATE driver SET outgoing=?1,applied=0 WHERE id=1",
                params![prior.outgoing as i64],
            )
            .map_err(|_| Error::Storage)?;
        self.commit(clock)?;
        if self.lineage()? != Some((generation, prior, receipt))
            || self.driver_checkpoint()? != (prior.outgoing, 0)
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    /// Authenticated predecessor boundary; driver checks it against the exact
    /// retained pause receipt before skipping historical predecessor jobs.
    pub fn predecessor_baseline(&self) -> Result<Option<(u64, [u8; 32])>> {
        self.live()?;
        Ok(self
            .lineage()?
            .map(|(_, prior, receipt)| (prior.outgoing, receipt)))
    }
}
