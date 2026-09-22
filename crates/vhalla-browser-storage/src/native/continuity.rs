//! Explicitly created receipt-only sessions. The existing NativeOutbox remains
//! the sole author writer and is borrowed for every read/publication/recovery.
//! No migration, identity creation, author reset, signer or network operation.
use super::NativeOutbox;
use crate::outbox::continuity::{
    codec, ContinuityEvidenceRecord, Limits, Publication, SessionScope, Snapshot, SourceCheck,
    MAX_INTENT_BYTES, MAX_RECORD_BYTES, MAX_STATE_BYTES,
};
use crate::{Error, PublishError};
use std::{fs::File, path::Path};
mod disk;
#[cfg(test)]
mod tests;
use disk::Disk;

/// One selected peer's immutable evidence with one lifetime writer lock. Local
/// cooperating-owner custody is assumed; coherent malicious rollback of all local
/// files is not detected. Uncertain writes poison this handle until exact reopen.
pub struct NativeContinuity {
    disk: Disk,
    _lock: File,
    state: Snapshot,
    poisoned: bool,
}
fn name(index: u64) -> String {
    format!("receipt-{index:016x}")
}
fn source_scope(source: &NativeOutbox, scope: &SessionScope) -> Result<(), Error> {
    if source.head()?.scope() != scope.author() || source.history_head()?.scope() != scope.history()
    {
        return Err(Error::WrongScope);
    }
    Ok(())
}
fn sources(
    source: &NativeOutbox,
    scope: &SessionScope,
    checks: &[SourceCheck],
) -> Result<(), Error> {
    source_scope(source, scope)?;
    let head = source.head()?;
    for check in checks {
        check.check(
            scope,
            head,
            &source.event(check.position.sequence())?.encode(),
        )?;
    }
    Ok(())
}
impl NativeContinuity {
    /// Explicit new namespace only. Requires an existing intact author store;
    /// missing receipt state never authorizes calling this for a prior session.
    /// Initial creation failures preserve partial files and do not reuse them.
    pub fn create_new(
        path: &Path,
        scope: SessionScope,
        limits: Limits,
        source: &NativeOutbox,
    ) -> Result<Self, Error> {
        source_scope(source, &scope)?;
        let state = Snapshot::fresh(scope, limits)?;
        let (mut disk, lock) = Disk::create(path)?;
        disk.create_file("FORMAT", &state.format())?;
        disk.create_file("STATE", &state.encode())?;
        disk.sync()?;
        disk.sync_parent()?;
        Ok(Self {
            disk,
            _lock: lock,
            state,
            poisoned: false,
        })
    }
    /// Open only the exact selected existing namespace/limits. Full format and
    /// source scope precede any recovery write. A missing prior session refuses.
    /// Recovery finishes only its retained exact decision, never new permission.
    pub fn open(
        path: &Path,
        scope: SessionScope,
        limits: Limits,
        source: &NativeOutbox,
    ) -> Result<Self, Error> {
        limits.check()?;
        source_scope(source, &scope)?;
        let (disk, lock) = Disk::open(path)?;
        codec::check_format(&disk.read("FORMAT", codec::MAX_FORMAT)?, &scope, limits)?;
        let state = Snapshot::decode(&disk.read("STATE", MAX_STATE_BYTES)?)?;
        if state.scope() != &scope || state.limits() != limits {
            return Err(Error::WrongScope);
        }
        let mut out = Self {
            disk,
            _lock: lock,
            state,
            poisoned: true,
        };
        out.validate(source)?;
        let final_intent = out.disk.optional("INTENT", MAX_INTENT_BYTES)?;
        let scratch = out.disk.optional("INTENT.tmp", MAX_INTENT_BYTES)?;
        if final_intent.is_some() && scratch.is_some() {
            return Err(Error::Corrupt);
        }
        if let Some(raw) = scratch {
            if out.disk.present("STATE.tmp", MAX_STATE_BYTES)?
                || out.disk.present("RECORD.tmp", MAX_RECORD_BYTES)?
                || out.disk.present(
                    &name(
                        out.state
                            .record_count()
                            .checked_add(1)
                            .ok_or(Error::Bounds)?,
                    ),
                    MAX_RECORD_BYTES,
                )?
            {
                return Err(Error::Corrupt);
            }
            match Publication::decode(&raw) {
                Ok(change) => {
                    if change.before != out.state {
                        return Err(Error::Corrupt);
                    }
                    change
                        .check_sources(source.head()?, |n| source.event(n).map(|e| e.encode()))?;
                    out.disk.promote_staged_intent(&raw)?;
                    out.apply(&change)?;
                    out.state = change.after;
                }
                Err(_) if codec::incomplete_prefix(&raw, &out.state) => {
                    out.disk.resync("STATE", MAX_STATE_BYTES)?;
                    out.disk.discard_staged_intent()?;
                }
                Err(_) => return Err(Error::Corrupt),
            }
        } else if let Some(raw) = final_intent {
            let change = Publication::decode(&raw)?;
            if change.before.scope() != &scope
                || change.before.limits() != limits
                || (out.state != change.before && out.state != change.after)
            {
                return Err(Error::Corrupt);
            }
            // The exact before state may reference old proofs, all still retained.
            let checks = change.before.validate_records(|i| out.record(i))?;
            sources(source, &scope, &checks)?;
            change.check_sources(source.head()?, |n| source.event(n).map(|e| e.encode()))?;
            out.disk.resync("INTENT", MAX_INTENT_BYTES)?;
            out.apply(&change)?;
            out.state = change.after;
        } else if out.disk.present("STATE.tmp", MAX_STATE_BYTES)?
            || out.disk.present("RECORD.tmp", MAX_RECORD_BYTES)?
        {
            return Err(Error::RecoveryRequired);
        }
        if out.disk.present(
            &name(
                out.state
                    .record_count()
                    .checked_add(1)
                    .ok_or(Error::Bounds)?,
            ),
            MAX_RECORD_BYTES,
        )? {
            return Err(Error::Corrupt);
        }
        out.validate(source)?;
        out.disk.resync("STATE", MAX_STATE_BYTES)?;
        out.disk.sync_parent()?;
        out.poisoned = false;
        Ok(out)
    }
    /// Whether this handle requires exact reopen after uncertainty/corruption.
    pub const fn needs_reopen(&self) -> bool {
        self.poisoned
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::NeedsReopen)
        } else {
            Ok(())
        }
    }
    fn record(&self, index: u64) -> Result<ContinuityEvidenceRecord, Error> {
        let record =
            ContinuityEvidenceRecord::decode(&self.disk.read(&name(index), MAX_RECORD_BYTES)?)?;
        if record.reference().index() != index || record.scope() != self.state.scope() {
            return Err(Error::Corrupt);
        }
        Ok(record)
    }
    fn validate(&self, source: &NativeOutbox) -> Result<(), Error> {
        let checks = self.state.validate_records(|i| self.record(i))?;
        sources(source, self.state.scope(), &checks)
    }
    /// Read/reauthenticate fixed referenced evidence and local source, never repair.
    /// At most three bounded records plus one attempt; no history-wide scan.
    pub fn snapshot(&mut self, source: &NativeOutbox) -> Result<Snapshot, Error> {
        self.ready()?;
        self.poisoned = true;
        if self.disk.read("STATE", MAX_STATE_BYTES)? != self.state.encode() {
            return Err(Error::Corrupt);
        }
        self.validate(source)?;
        self.poisoned = false;
        Ok(self.state.clone())
    }
    /// Consume a move-only prepared change, exactly compare STATE and recheck
    /// every actual local signed record before publishing. Success follows fsync
    /// of intent, optional immutable proof, STATE, and intent removal directory.
    pub fn publish(
        &mut self,
        source: &NativeOutbox,
        change: Publication,
    ) -> Result<Snapshot, PublishError> {
        self.ready().map_err(PublishError::Rejected)?;
        if self.state != change.before {
            return Err(PublishError::Rejected(Error::Stale));
        }
        source_scope(source, self.state.scope()).map_err(PublishError::Rejected)?;
        change
            .check_sources(source.head().map_err(PublishError::Rejected)?, |n| {
                source.event(n).map(|e| e.encode())
            })
            .map_err(PublishError::Rejected)?;
        let raw = change.encode();
        if raw.len() > MAX_INTENT_BYTES {
            return Err(PublishError::Rejected(Error::Bounds));
        }
        self.poisoned = true;
        let result = (|| {
            if self.disk.read("STATE", MAX_STATE_BYTES)? != self.state.encode() {
                return Err(Error::Stale);
            }
            self.validate(source)?;
            self.disk.stage_intent(&raw)?;
            self.apply(&change)?;
            Ok(())
        })();
        result.map_err(PublishError::ReopenRequired)?;
        self.state = change.after;
        self.poisoned = false;
        Ok(self.state.clone())
    }
    fn apply(&mut self, change: &Publication) -> Result<(), Error> {
        if let Some(record) = change.record() {
            self.disk
                .immutable(&name(record.reference().index()), &record.encode())?;
        }
        self.disk
            .replace_state(&change.before.encode(), &change.after.encode())?;
        self.disk.remove_intent()
    }
    /// Read one exact published record by ordinal; missing acknowledged bytes are
    /// corruption, never an absent receipt. Old records are not silently relabeled.
    pub fn read_record(
        &mut self,
        source: &NativeOutbox,
        index: u64,
    ) -> Result<Option<ContinuityEvidenceRecord>, Error> {
        self.ready()?;
        if index == 0 {
            return Err(Error::Bounds);
        }
        source_scope(source, self.state.scope())?;
        if index > self.state.record_count() {
            return Ok(None);
        }
        self.poisoned = true;
        let record = self.record(index)?;
        sources(source, self.state.scope(), &record.sources()?)?;
        self.poisoned = false;
        Ok(Some(record))
    }
}

impl Drop for NativeContinuity {
    fn drop(&mut self) {
        // A fork/dup copy must not prolong custody after this sole owner ends.
        // This does not release a live borrowed session or relax exclusion.
        let _ = self._lock.unlock();
    }
}
