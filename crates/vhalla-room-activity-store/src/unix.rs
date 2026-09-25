use crate::codec::{
    self, Index, Intent, Record, FORMAT_BYTES, INDEX_BYTES, MAX_INTENT_BYTES, MAX_RECORD_BYTES,
    RECORD_OVERHEAD,
};
use crate::{Limits, Pin, PIN_BYTES};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use vhalla_custody::{self as custody, Owner};
use vhalla_room_activity::{
    AdmissionContext, AuthorChain, ChainPosition, RoomScope, VerifiedEvent,
};

const LOCK: &str = "lock";
const FORMAT: &str = "format";
const HEAD: &str = "HEAD";
const INTENT: &str = "intent";
const INTENT_TEMP: &str = "intent.tmp";
const HEAD_TEMP: &str = "HEAD.tmp";
const AUTHOR_TEMP: &str = "author.tmp";
const RECORDS: &str = "records";
const AUTHORS: &str = "authors";
/// Maximum records per direct disk page; memory never grows with lifetime history.
pub const MAX_PAGE: usize = 64;

/// Failures never authorize deletion, resetting state, or reusing an author sequence.
#[derive(Debug)]
pub enum Error {
    /// Unsafe file type, permissions, owner, link, or directory entry.
    UnsafePath,
    /// Another cooperating writer holds the store's exclusive lifetime lock.
    Busy,
    /// Canonical metadata, a receipt, or an index is torn, missing or inconsistent.
    Corrupt,
    /// The requested context, expected author head, or external pin conflicts.
    Conflict,
    /// An independently retained exact pin differs from the published disk pin.
    Freshness,
    /// A retained transaction or unexpected temporary requires reconciliation.
    RecoveryRequired,
    /// A fixed local storage or bounded request limit was exceeded.
    Capacity,
    /// Activity signature, chain or current policy validation refused admission.
    Activity(vhalla_room_activity::Error),
    /// Filesystem operation failed; creation can leave a partial directory.
    Io(io::Error),
    /// Admission may be durable: preserve state, reopen and recover the exact intent.
    Indeterminate(io::Error),
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<vhalla_room_activity::Error> for Error {
    fn from(e: vhalla_room_activity::Error) -> Self {
        Self::Activity(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "room activity store: {self:?}")
    }
}
impl std::error::Error for Error {}
fn map_custody(e: custody::Error) -> Error {
    match e {
        custody::Error::UnsafePath => Error::UnsafePath,
        custody::Error::Busy => Error::Busy,
        custody::Error::Io(e) => Error::Io(e),
        custody::Error::Capacity | custody::Error::Corrupt => Error::Corrupt,
    }
}
fn indeterminate(e: Error) -> Error {
    match e {
        Error::Io(e) => Error::Indeterminate(e),
        other => other,
    }
}

/// Exact locally stored evidence, not consensus, global admission, current
/// permission, freshness, network delivery or a host capability.
#[derive(Debug)]
pub struct StoredEvent {
    record: Record,
    reconciled: bool,
}
impl StoredEvent {
    /// Authenticated full event bytes retained by this local store.
    pub fn event(&self) -> &VerifiedEvent {
        &self.record.event
    }
    /// Local disk-order cursor. Author sequence and consensus height are separate.
    pub const fn cursor(&self) -> u64 {
        self.record.ordinal
    }
    /// Exact registry evaluation basis frozen at the original local admission.
    /// This digest is metadata, not a signed registry receipt or certificate.
    pub const fn registry_digest(&self) -> &[u8; 32] {
        &self.record.registry
    }
    /// Whether this is an exact already-stored retry or recovered transaction.
    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }
}
/// One bounded local history page; it makes no claim of global completeness.
#[derive(Debug)]
pub struct Page {
    records: Vec<StoredEvent>,
    next: u64,
    tip: Pin,
}
impl Page {
    /// Locally published records in disk order.
    pub fn records(&self) -> &[StoredEvent] {
        &self.records
    }
    /// Last returned cursor, or the unchanged input cursor for an empty page.
    pub const fn next_cursor(&self) -> u64 {
        self.next
    }
    /// Exact local tip observed under this store's lock.
    pub const fn tip(&self) -> Pin {
        self.tip
    }
}

/// One owner-private store pinned to one exact room scope. Its lifetime lock
/// serializes cooperating store writers, NOT the caller's certified registry.
/// Requires owner-controlled ancestors on a filesystem supporting atomic rename
/// and file/directory sync. These checks are not a sandbox against owner/root
/// path replacement or rollback of coherent local state.
pub struct Store {
    path: PathBuf,
    directory: File,
    records: File,
    authors: File,
    _lock: File,
    owner: Owner,
    scope: RoomScope,
    limits: Limits,
    pin: Pin,
    #[cfg(test)]
    fault: Option<Step>,
}
impl Store {
    /// Initialize a previously nonexistent directory. Partial creation is retained;
    /// an existing directory is never reset or silently adopted.
    pub fn create(path: impl AsRef<Path>, scope: RoomScope, limits: Limits) -> Result<Self, Error> {
        limits.check()?;
        if scope.network == [0; 32] {
            return Err(Error::Conflict);
        }
        let path = custody::absolute(path.as_ref()).map_err(map_custody)?;
        let (directory, owner) = custody::create_private_directory(&path).map_err(map_custody)?;
        let lock = create(&path.join(LOCK))?;
        custody::acquire_exclusive(&lock).map_err(map_custody)?;
        lock.sync_all()?;
        let (records, rowner) =
            custody::create_private_directory(&path.join(RECORDS)).map_err(map_custody)?;
        let (authors, aowner) =
            custody::create_private_directory(&path.join(AUTHORS)).map_err(map_custody)?;
        if rowner != owner || aowner != owner {
            return Err(Error::UnsafePath);
        }
        write_new(&path.join(FORMAT), &codec::format(scope, limits))?;
        write_new(&path.join(HEAD), &Pin::EMPTY.encode())?;
        records.sync_all()?;
        authors.sync_all()?;
        directory.sync_all()?;
        File::open(path.parent().ok_or(Error::UnsafePath)?)?.sync_all()?;
        Ok(Self {
            path,
            directory,
            records,
            authors,
            _lock: lock,
            owner,
            scope,
            limits,
            pin: Pin::EMPTY,
            #[cfg(test)]
            fault: None,
        })
    }
    /// Open existing local evidence without creating or repairing anything.
    /// Valid intent is retained for explicit recovery; torn metadata fails closed.
    /// Startup reads only constant-size metadata, tip and at most one intent.
    pub fn open(
        path: impl AsRef<Path>,
        scope: RoomScope,
        limits: Limits,
        expected: Option<Pin>,
    ) -> Result<Self, Error> {
        limits.check()?;
        let path = custody::absolute(path.as_ref()).map_err(map_custody)?;
        let (directory, owner) = custody::open_private_directory(&path).map_err(map_custody)?;
        let lock = open(&path.join(LOCK), owner, 0)?;
        if lock.metadata()?.len() != 0 {
            return Err(Error::Corrupt);
        }
        custody::acquire_exclusive(&lock).map_err(map_custody)?;
        let (actual_scope, actual_limits) =
            codec::decode_format(&read(&path.join(FORMAT), owner, FORMAT_BYTES)?)?;
        if actual_scope != scope || actual_limits != limits {
            return Err(Error::Conflict);
        }
        let records = open_dir(&path.join(RECORDS), owner)?;
        let authors = open_dir(&path.join(AUTHORS), owner)?;
        let pin = Pin::decode(&read(&path.join(HEAD), owner, PIN_BYTES)?)?;
        if expected.is_some_and(|e| e != pin) {
            return Err(Error::Freshness);
        }
        if pin.count > limits.max_events || pin.bytes > limits.max_history_bytes {
            return Err(Error::Corrupt);
        }
        let store = Self {
            path,
            directory,
            records,
            authors,
            _lock: lock,
            owner,
            scope,
            limits,
            pin,
            #[cfg(test)]
            fault: None,
        };
        store.root_inventory()?;
        store.validate_pin(pin)?;
        if store.present(INTENT_TEMP, MAX_INTENT_BYTES)? {
            store.validate_staged_intent()?;
        } else if store.present(INTENT, MAX_INTENT_BYTES)? {
            store.validate_intent()?;
        } else {
            store.ready()?;
            store.validate_published_tip()?;
        }
        Ok(store)
    }
    /// Exact current local publication anchor. Retain independently for rollback detection.
    pub const fn pin(&self) -> Pin {
        self.pin
    }
    /// Exact full room scope retained in immutable store format metadata.
    pub const fn scope(&self) -> RoomScope {
        self.scope
    }
    /// True when an exact retained local admission needs explicit completion.
    pub fn recovery_required(&self) -> Result<bool, Error> {
        Ok(self.present(INTENT, MAX_INTENT_BYTES)?
            || self.present(INTENT_TEMP, MAX_INTENT_BYTES)?)
    }
    /// Current full-key author floor, obtained from verified local log/index bytes.
    /// Missing, torn or inconsistent referenced evidence refuses the read.
    pub fn author_head(&self, author: [u8; 32]) -> Result<Option<ChainPosition>, Error> {
        self.ready()?;
        self.check_pin()?;
        let head = self.load_author(author, self.pin.count)?;
        head.map(|(_, record)| {
            self.chain_for_record(author, record)
                .map(|c| c.position().expect("restored head"))
        })
        .transpose()
    }
    /// Append under exact author and certified-registry bases. The caller MUST
    /// hold its registry integration lock until this method returns and pass that
    /// lock's current pinned digest, not a remote claim or cached gateway value.
    /// The context is a locally verified frontier, never proof of global latest state.
    ///
    /// Exact byte retries return old stored evidence even after policy revocation;
    /// they do not refresh authorization or re-enqueue network work. New events
    /// require current policy and exact expected author head. A durable intent
    /// freezes the checked local admission; failures thereafter are uncertain.
    /// No successful receipt is returned before every publication sync succeeds.
    pub fn append(
        &mut self,
        event: VerifiedEvent,
        expected: Option<ChainPosition>,
        context: &AdmissionContext<'_>,
        current_registry_digest: [u8; 32],
    ) -> Result<StoredEvent, Error> {
        self.append_inner(event, expected, context, current_registry_digest)
            .map_err(indeterminate)
    }
    fn append_inner(
        &mut self,
        event: VerifiedEvent,
        expected: Option<ChainPosition>,
        context: &AdmissionContext<'_>,
        current_registry_digest: [u8; 32],
    ) -> Result<StoredEvent, Error> {
        self.check_pin()?;
        if event.claims().scope != self.scope {
            return Err(Error::Conflict);
        }
        if self.present(INTENT_TEMP, MAX_INTENT_BYTES)? {
            if self
                .validate_staged_intent()?
                .is_some_and(|intent| intent.record.event.encode() != event.encode())
            {
                return Err(Error::RecoveryRequired);
            }
            if let Some(stored) = self.recover_inner()? {
                return Ok(stored);
            }
        }
        if self.present(INTENT, MAX_INTENT_BYTES)? {
            let intent = self.validate_intent()?;
            if intent.record.event.encode() != event.encode() {
                return Err(Error::RecoveryRequired);
            }
            return self.finish_intent(intent, None, true);
        }
        self.ready()?;
        self.validate_pin(self.pin)?;
        let author = event.claims().author;
        let old = self.load_author(author, self.pin.count)?;
        if let Some(record) =
            self.lookup_sequence(author, event.claims().sequence, self.pin.count)?
        {
            if old.as_ref().is_none_or(|(head, _)| {
                head.sequence < record.event.claims().sequence || head.ordinal < record.ordinal
            }) {
                return Err(Error::Corrupt);
            }
            if record.event.encode() != event.encode() {
                return Err(Error::Conflict);
            }
            return Ok(StoredEvent {
                record,
                reconciled: true,
            });
        }
        if old
            .as_ref()
            .is_some_and(|(head, _)| event.claims().sequence <= head.sequence)
        {
            return Err(Error::Corrupt);
        }
        let chain = match &old {
            Some((_, record)) => self.chain_for_record(author, record.clone())?,
            None => AuthorChain::new(self.scope, author)?,
        };
        if chain.position() != expected {
            return Err(Error::Conflict);
        }
        if *context.registry_digest() != current_registry_digest {
            return Err(Error::Conflict);
        }
        let candidate = chain.prepare_next(event.clone(), context)?;
        let ordinal = self.pin.count.checked_add(1).ok_or(Error::Capacity)?;
        let increment = (RECORD_OVERHEAD + event.encode().len() + INDEX_BYTES) as u64;
        let bytes = self
            .pin
            .bytes
            .checked_add(increment)
            .ok_or(Error::Capacity)?;
        if ordinal > self.limits.max_events || bytes > self.limits.max_history_bytes {
            return Err(Error::Capacity);
        }
        let record = Record {
            ordinal,
            bytes,
            previous: self.pin.tail,
            registry: current_registry_digest,
            event,
        };
        let intent = Intent {
            expected: self.pin,
            next: record.pin(),
            old: old.map(|(index, _)| index),
            record,
        };
        let mut file = create(&self.path.join(INTENT_TEMP))?;
        self.step(Step::IntentCreated)?;
        let raw = intent.encode();
        let split = raw.len() / 2;
        file.write_all(&raw[..split])?;
        self.step(Step::IntentPartial)?;
        file.write_all(&raw[split..])?;
        self.step(Step::IntentWritten)?;
        file.sync_all()?;
        self.step(Step::IntentSynced)?;
        fs::rename(self.path.join(INTENT_TEMP), self.path.join(INTENT))?;
        self.step(Step::IntentRenamed)?;
        self.directory.sync_all()?;
        self.step(Step::IntentDurable)?;
        // The exact INTENT inode was synced before its rename and its root
        // directory entry was just synced above, still under the lifetime
        // lock. Mint the proof that lets `finish_intent` skip re-syncing them;
        // nothing between here and there may mutate either, and no other call
        // site can produce the token.
        let result = self.finish_intent(intent, Some(IntentDurable { _sealed: () }), false)?;
        let mut chain = chain;
        chain.commit_after_persist(candidate, context)?;
        Ok(result)
    }
    /// Complete only the exact previously checked local admission in retained
    /// intent. No current-policy permission is inferred or newly granted. This
    /// can recover an old admission after the room closed. A torn intent is never
    /// guessed, deleted, replaced, or used to synthesize signed bytes.
    pub fn recover(&mut self) -> Result<Option<StoredEvent>, Error> {
        self.recover_inner().map_err(indeterminate)
    }
    fn recover_inner(&mut self) -> Result<Option<StoredEvent>, Error> {
        self.check_pin()?;
        if self.present(INTENT_TEMP, MAX_INTENT_BYTES)? {
            if self.validate_staged_intent()?.is_some() {
                open(&self.path.join(INTENT_TEMP), self.owner, MAX_INTENT_BYTES)?.sync_all()?;
                self.step(Step::IntentSynced)?;
                fs::rename(self.path.join(INTENT_TEMP), self.path.join(INTENT))?;
                self.step(Step::IntentRenamed)?;
                self.directory.sync_all()?;
                self.step(Step::IntentDurable)?;
            } else {
                fs::remove_file(self.path.join(INTENT_TEMP))?;
                self.directory.sync_all()?;
            }
        }
        if !self.present(INTENT, MAX_INTENT_BYTES)? {
            self.ready()?;
            return Ok(None);
        }
        let intent = self.validate_intent()?;
        self.finish_intent(intent, None, true).map(Some)
    }
    /// Read at most MAX_PAGE verified records directly by local ordinal. This
    /// neither enumerates the history directory nor collects lifetime history.
    /// Cursor zero starts at the beginning; a cursor beyond the local tip refuses.
    pub fn read_page(&self, after: u64, limit: usize) -> Result<Page, Error> {
        if limit == 0 || limit > MAX_PAGE {
            return Err(Error::Capacity);
        }
        self.ready()?;
        self.check_pin()?;
        if after > self.pin.count {
            return Err(Error::Conflict);
        }
        let mut records = Vec::with_capacity(limit);
        let mut cursor = after;
        let (mut previous, mut accounted) = if after == 0 {
            ([0; 32], 0)
        } else {
            let prior = self.load_record(after, self.pin.count)?;
            (prior.digest(), prior.bytes)
        };
        while records.len() < limit && cursor < self.pin.count {
            cursor = cursor.checked_add(1).ok_or(Error::Capacity)?;
            let record = self.load_record(cursor, self.pin.count)?;
            if record.previous != previous
                || accounted.checked_add((record.encode().len() + INDEX_BYTES) as u64)
                    != Some(record.bytes)
            {
                return Err(Error::Corrupt);
            }
            let claims = record.event.claims();
            // The sequence index must point back at this exact record. Compare
            // the stored index itself: loading the record again would decode
            // and re-verify the same signature a second time per page row.
            let indexed = self
                .read_sequence_index(claims.author, claims.sequence)?
                .ok_or(Error::Corrupt)?;
            if indexed != record.index() {
                return Err(Error::Corrupt);
            }
            previous = record.digest();
            accounted = record.bytes;
            records.push(StoredEvent {
                record,
                reconciled: true,
            });
        }
        if cursor == self.pin.count && previous != self.pin.tail {
            return Err(Error::Corrupt);
        }
        Ok(Page {
            records,
            next: cursor,
            tip: self.pin,
        })
    }
    fn finish_intent(
        &mut self,
        intent: Intent,
        durable: Option<IntentDurable>,
        reconciled: bool,
    ) -> Result<StoredEvent, Error> {
        self.check_pin()?;
        self.validate_intent_structure(&intent)?;
        // Recovery may find a complete intent whose original writer stopped
        // before fsync. Re-establish its durability before dependent writes —
        // unless this append just synced the same inode and root directory
        // entry in this critical section and carries the token proving it.
        if durable.is_none() {
            open(&self.path.join(INTENT), self.owner, MAX_INTENT_BYTES)?.sync_all()?;
            self.directory.sync_all()?;
            self.step(Step::RecoveryIntentSynced)?;
        }
        // O_NOFOLLOW on the final record file does not protect its parent.
        open_dir(&self.path.join(RECORDS), self.owner)?;
        let committed = self.pin == intent.next;
        let author = intent.record.event.claims().author;
        let author_dir = self.ensure_author_dir(author)?;
        let raw = intent.record.encode();
        self.write_known(&self.record_path(intent.next.count), &raw, !committed)?;
        self.records.sync_all()?;
        self.step(Step::RecordPublished)?;
        let index = intent.record.index();
        let index_raw = index.encode();
        self.write_known(
            &self.sequence_path(author, index.sequence),
            &index_raw,
            !committed,
        )?;
        author_dir.sync_all()?;
        self.step(Step::SequenceIndexed)?;
        let author_head = self.author_path(author).join(HEAD);
        if exists(&author_head, self.owner, INDEX_BYTES)? {
            let current = Index::decode(&read(&author_head, self.owner, INDEX_BYTES)?)?;
            if Some(current) != intent.old && current != index {
                return Err(Error::Corrupt);
            }
        } else if intent.old.is_some() {
            return Err(Error::Corrupt);
        }
        self.write_known(&self.path.join(AUTHOR_TEMP), &index_raw, true)?;
        self.step(Step::AuthorTempDurable)?;
        fs::rename(self.path.join(AUTHOR_TEMP), &author_head)?;
        author_dir.sync_all()?;
        self.directory.sync_all()?;
        self.step(Step::AuthorHeadPublished)?;
        self.write_known(&self.path.join(HEAD_TEMP), &intent.next.encode(), true)?;
        self.step(Step::HeadTempDurable)?;
        fs::rename(self.path.join(HEAD_TEMP), self.path.join(HEAD))?;
        self.step(Step::HeadPublished)?;
        self.directory.sync_all()?;
        self.pin = intent.next;
        self.step(Step::DirectorySynced)?;
        // Intent is the only removed evidence, after its exact durable result exists.
        let persisted = Intent::decode(
            &read(&self.path.join(INTENT), self.owner, MAX_INTENT_BYTES)?,
            self.scope,
            self.limits,
        )?;
        if persisted.encode() != intent.encode() {
            return Err(Error::Corrupt);
        }
        fs::remove_file(self.path.join(INTENT))?;
        self.step(Step::IntentRemoved)?;
        self.directory.sync_all()?;
        Ok(StoredEvent {
            record: intent.record,
            reconciled,
        })
    }
    fn validate_staged_intent(&self) -> Result<Option<Intent>, Error> {
        self.root_inventory()?;
        self.check_pin()?;
        self.validate_pin(self.pin)?;
        self.validate_published_tip()?;
        // No successor effect is lawful until final intent publication.
        if self.present(INTENT, MAX_INTENT_BYTES)?
            || self.present(HEAD_TEMP, PIN_BYTES)?
            || self.present(AUTHOR_TEMP, INDEX_BYTES)?
        {
            return Err(Error::Corrupt);
        }
        if let Some(next) = self.pin.count.checked_add(1) {
            if exists(&self.record_path(next), self.owner, MAX_RECORD_BYTES)? {
                return Err(Error::Corrupt);
            }
        }
        let raw = read(&self.path.join(INTENT_TEMP), self.owner, MAX_INTENT_BYTES)?;
        let intent = Intent::decode_staged(&raw, self.pin, self.scope, self.limits)?;
        if let Some(intent) = &intent {
            self.validate_intent_structure(intent)?;
            let author = intent.record.event.claims().author;
            if self.read_author_index(author)? != intent.old
                || self
                    .read_sequence_index(author, intent.record.event.claims().sequence)?
                    .is_some()
            {
                return Err(Error::Corrupt);
            }
        }
        Ok(intent)
    }
    fn validate_intent(&self) -> Result<Intent, Error> {
        let intent = Intent::decode(
            &read(&self.path.join(INTENT), self.owner, MAX_INTENT_BYTES)?,
            self.scope,
            self.limits,
        )?;
        self.validate_intent_structure(&intent)?;
        Ok(intent)
    }
    fn validate_intent_structure(&self, intent: &Intent) -> Result<(), Error> {
        if self.pin != intent.expected && self.pin != intent.next {
            return Err(Error::Conflict);
        }
        self.validate_pin(intent.expected)?;
        let author = intent.record.event.claims().author;
        if let Some(old) = intent.old {
            self.load_index_record(old, author, intent.expected.count)?;
            // The sequence file must retain exactly the prior head index; its
            // pointed-to record was just proven by load_index_record.
            if self.read_sequence_index(author, old.sequence)? != Some(old) {
                return Err(Error::Corrupt);
            }
        }
        let current = self.read_author_index(author)?;
        if current != intent.old && current != Some(intent.record.index()) {
            return Err(Error::Corrupt);
        }
        if self.pin == intent.next {
            let actual = self.load_record(intent.next.count, intent.next.count)?;
            if actual.encode() != intent.record.encode() || current != Some(intent.record.index()) {
                return Err(Error::Corrupt);
            }
            // Index equality is record equality here: index.receipt is the
            // SHA-256 identity of the record encoding, and the pointed record
            // itself was just proven byte-identical by `actual` above.
            let indexed = self
                .read_sequence_index(author, intent.record.event.claims().sequence)?
                .ok_or(Error::Corrupt)?;
            if indexed != intent.record.index() {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), Error> {
        if self.present(INTENT, MAX_INTENT_BYTES)?
            || self.present(INTENT_TEMP, MAX_INTENT_BYTES)?
            || self.present(HEAD_TEMP, PIN_BYTES)?
            || self.present(AUTHOR_TEMP, INDEX_BYTES)?
        {
            return Err(Error::RecoveryRequired);
        }
        if let Some(next) = self.pin.count.checked_add(1) {
            if exists(&self.record_path(next), self.owner, MAX_RECORD_BYTES)? {
                return Err(Error::RecoveryRequired);
            }
        }
        Ok(())
    }
    fn check_pin(&self) -> Result<(), Error> {
        if Pin::decode(&read(&self.path.join(HEAD), self.owner, PIN_BYTES)?)? != self.pin {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn validate_pin(&self, pin: Pin) -> Result<(), Error> {
        if pin == Pin::EMPTY {
            return Ok(());
        }
        if self.load_record(pin.count, pin.count)?.pin() != pin {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn validate_published_tip(&self) -> Result<(), Error> {
        if self.pin.count == 0 {
            return Ok(());
        }
        let tip = self.load_record(self.pin.count, self.pin.count)?;
        let (index, _) = self
            .load_author(tip.event.claims().author, self.pin.count)?
            .ok_or(Error::Corrupt)?;
        if index != tip.index() {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn chain_for_record(&self, author: [u8; 32], record: Record) -> Result<AuthorChain, Error> {
        Ok(AuthorChain::restore_local_admitted_head(
            self.scope,
            author,
            record.event,
        )?)
    }
    fn load_record(&self, ordinal: u64, ceiling: u64) -> Result<Record, Error> {
        if ordinal == 0 || ordinal > ceiling {
            return Err(Error::Corrupt);
        }
        open_dir(&self.path.join(RECORDS), self.owner)?;
        let record = Record::decode(
            &required_read(&self.record_path(ordinal), self.owner, MAX_RECORD_BYTES)?,
            self.scope,
        )?;
        if record.ordinal != ordinal || record.bytes > self.limits.max_history_bytes {
            return Err(Error::Corrupt);
        }
        Ok(record)
    }
    fn load_index_record(
        &self,
        index: Index,
        author: [u8; 32],
        ceiling: u64,
    ) -> Result<Record, Error> {
        let record = self.load_record(index.ordinal, ceiling)?;
        if record.index() != index || record.event.claims().author != author {
            return Err(Error::Corrupt);
        }
        Ok(record)
    }
    fn load_author(
        &self,
        author: [u8; 32],
        ceiling: u64,
    ) -> Result<Option<(Index, Record)>, Error> {
        let Some(index) = self.read_author_index(author)? else {
            return Ok(None);
        };
        let record = self.load_index_record(index, author, ceiling)?;
        // Confirm the per-sequence index agrees with the head index without
        // decoding and re-verifying the same head record a second time.
        if self.read_sequence_index(author, index.sequence)? != Some(index) {
            return Err(Error::Corrupt);
        }
        Ok(Some((index, record)))
    }
    /// Read only the stored sequence index. Callers that already hold the
    /// record it must name compare `Index` values directly and never decode or
    /// re-verify the pointed record a second time.
    fn read_sequence_index(&self, author: [u8; 32], sequence: u64) -> Result<Option<Index>, Error> {
        if !self.has_author_dir(author)? {
            return Ok(None);
        }
        let path = self.sequence_path(author, sequence);
        if !exists(&path, self.owner, INDEX_BYTES)? {
            return Ok(None);
        }
        let index = Index::decode(&read(&path, self.owner, INDEX_BYTES)?)?;
        if index.sequence != sequence {
            return Err(Error::Corrupt);
        }
        Ok(Some(index))
    }
    fn lookup_sequence(
        &self,
        author: [u8; 32],
        sequence: u64,
        ceiling: u64,
    ) -> Result<Option<Record>, Error> {
        let Some(index) = self.read_sequence_index(author, sequence)? else {
            return Ok(None);
        };
        self.load_index_record(index, author, ceiling).map(Some)
    }
    fn read_author_index(&self, author: [u8; 32]) -> Result<Option<Index>, Error> {
        if !self.has_author_dir(author)? {
            return Ok(None);
        }
        let path = self.author_path(author).join(HEAD);
        if !exists(&path, self.owner, INDEX_BYTES)? {
            // Author directories are created only after durable intent. Without
            // that intent, an existing directory with no head is torn state.
            if !self.present(INTENT, MAX_INTENT_BYTES)? {
                return Err(Error::Corrupt);
            }
            return Ok(None);
        }
        Index::decode(&read(&path, self.owner, INDEX_BYTES)?).map(Some)
    }
    fn has_author_dir(&self, author: [u8; 32]) -> Result<bool, Error> {
        open_dir(&self.path.join(AUTHORS), self.owner)?;
        match fs::symlink_metadata(self.author_path(author)) {
            Ok(_) => {
                open_dir(&self.author_path(author), self.owner)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn ensure_author_dir(&self, author: [u8; 32]) -> Result<File, Error> {
        if self.has_author_dir(author)? {
            return open_dir(&self.author_path(author), self.owner);
        }
        let (directory, owner) =
            custody::create_private_directory(&self.author_path(author)).map_err(map_custody)?;
        if owner != self.owner {
            return Err(Error::UnsafePath);
        }
        directory.sync_all()?;
        self.authors.sync_all()?;
        Ok(directory)
    }
    fn record_path(&self, ordinal: u64) -> PathBuf {
        self.path.join(RECORDS).join(format!("{ordinal:020}"))
    }
    fn author_path(&self, author: [u8; 32]) -> PathBuf {
        self.path.join(AUTHORS).join(hex(&author))
    }
    fn sequence_path(&self, author: [u8; 32], sequence: u64) -> PathBuf {
        self.author_path(author).join(format!("{sequence:020}"))
    }
    fn present(&self, name: &str, max: usize) -> Result<bool, Error> {
        exists(&self.path.join(name), self.owner, max)
    }
    fn write_known(&self, path: &Path, bytes: &[u8], allow_prefix: bool) -> Result<(), Error> {
        if exists(path, self.owner, bytes.len())? {
            let retained = read(path, self.owner, bytes.len())?;
            if retained == bytes {
                open(path, self.owner, bytes.len())?.sync_all()?;
                return Ok(());
            }
            if !allow_prefix || !bytes.starts_with(&retained) {
                return Err(Error::Corrupt);
            }
            let mut file = open(path, self.owner, bytes.len())?;
            file.write_all(bytes)?;
            file.set_len(bytes.len() as u64)?;
            file.sync_all()?;
        } else {
            write_new(path, bytes)?;
        }
        Ok(())
    }
    fn root_inventory(&self) -> Result<(), Error> {
        let mut count = 0;
        for entry in fs::read_dir(&self.path)? {
            count += 1;
            if count > 8 {
                return Err(Error::UnsafePath);
            }
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::UnsafePath)?;
            match name.as_str() {
                AUTHORS | RECORDS => {
                    open_dir(&entry.path(), self.owner)?;
                }
                LOCK => {
                    open(&entry.path(), self.owner, 0)?;
                }
                FORMAT => {
                    open(&entry.path(), self.owner, FORMAT_BYTES)?;
                }
                HEAD | HEAD_TEMP => {
                    open(&entry.path(), self.owner, PIN_BYTES)?;
                }
                INTENT | INTENT_TEMP => {
                    open(&entry.path(), self.owner, MAX_INTENT_BYTES)?;
                }
                AUTHOR_TEMP => {
                    open(&entry.path(), self.owner, INDEX_BYTES)?;
                }
                _ => return Err(Error::UnsafePath),
            }
        }
        Ok(())
    }
    fn step(&mut self, step: Step) -> Result<(), Error> {
        #[cfg(test)]
        if self.fault == Some(step) {
            self.fault = None;
            return Err(Error::Indeterminate(io::Error::other(
                "injected activity publication interruption",
            )));
        }
        let _ = step;
        Ok(())
    }
}
/// Proof that the exact retained `intent` inode and its root directory entry
/// were synchronized inside this append's critical section. It is minted only
/// in `append_inner` after `Step::IntentDurable` completes and is consumed by
/// `finish_intent`; retained-intent and explicit-recovery paths never hold
/// one, so a crash between those two points still re-syncs before dependent
/// writes. Private fields keep it unforgeable outside this module.
struct IntentDurable {
    _sealed: (),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    IntentCreated,
    IntentPartial,
    IntentWritten,
    IntentSynced,
    IntentRenamed,
    IntentDurable,
    RecoveryIntentSynced,
    RecordPublished,
    SequenceIndexed,
    AuthorTempDurable,
    AuthorHeadPublished,
    HeadTempDurable,
    HeadPublished,
    DirectorySynced,
    IntentRemoved,
}
fn create(path: &Path) -> Result<File, Error> {
    custody::create_private_file(path).map_err(map_custody)
}
fn open(path: &Path, owner: Owner, max: usize) -> Result<File, Error> {
    custody::open_private_file(path, owner, max).map_err(map_custody)
}
fn read(path: &Path, owner: Owner, max: usize) -> Result<Vec<u8>, Error> {
    custody::read_private_file(path, owner, max).map_err(map_custody)
}
fn required_read(path: &Path, owner: Owner, max: usize) -> Result<Vec<u8>, Error> {
    read(path, owner, max).map_err(|e| match e {
        Error::Io(e) if e.kind() == io::ErrorKind::NotFound => Error::Corrupt,
        other => other,
    })
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn open_dir(path: &Path, owner: Owner) -> Result<File, Error> {
    let (directory, actual) = custody::open_private_directory(path).map_err(map_custody)?;
    if actual != owner {
        return Err(Error::UnsafePath);
    }
    Ok(directory)
}
fn exists(path: &Path, owner: Owner, max: usize) -> Result<bool, Error> {
    custody::private_file_present(path, owner, max).map_err(map_custody)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut s, "{byte:02x}").expect("string formatting");
    }
    s
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
