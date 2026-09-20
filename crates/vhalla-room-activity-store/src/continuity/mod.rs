//! Separate, explicitly initialized continuity-capable store. Version-one stores
//! are never adopted or migrated. Current registry provenance/serialization is
//! supplied by the caller; retained intents freeze prior local decisions.
mod catalogue;
mod disk;
mod frames;
mod intent;
mod model;
mod pin;

use crate::Error;
use catalogue::{Catalogue, Stage, StageState, MAX_CATALOGUE_BYTES};
use disk::{Disk, MAX_TRANSACTION_BYTES};
use frames::{
    digest, Evidence, Position, StagePage, Terminal, MAX_EVIDENCE_BYTES, MAX_STAGE_PAGE_BYTES,
    MAX_TERMINAL_BYTES, SEGMENT_EVENTS,
};
use intent::{Intent, Operation};
pub use model::{ContinuityLimits, ContinuityReceipt, Maintenance, PublishedEvidence, StageTicket};
pub use pin::{ContinuityPin, CONTINUITY_PIN_BYTES};
use std::{collections::BTreeMap, path::Path};
use vhalla_room_activity::{
    continuity::{ContinuityPosition, EvidenceRole},
    AdmissionContext, AuthorChain, EventId, RoomScope, VerifiedEvent,
};

/// One private, exclusively owned store. Temporary staging is finite and leased;
/// published signed evidence and author floors are never expired or deleted.
/// Calls require the caller's certified-registry lock through their completion.
pub struct ContinuityStore {
    disk: Disk,
    scope: RoomScope,
    limits: ContinuityLimits,
    pin: ContinuityPin,
    catalogue: Catalogue,
    poisoned: bool,
}
impl ContinuityStore {
    /// Explicitly initialize a nonexistent directory; any partial result is
    /// preserved and must never be interpreted as permission to reset identity.
    pub fn create(
        path: impl AsRef<Path>,
        scope: RoomScope,
        limits: ContinuityLimits,
    ) -> Result<Self, Error> {
        let format = pin::format(scope, limits)?;
        let scope_id = digest(&format);
        let disk = Disk::create(path.as_ref())?;
        let pin = ContinuityPin::empty(scope_id);
        let catalogue = Catalogue {
            scope: scope_id,
            generation: 1,
            clock: 0,
            stages: BTreeMap::new(),
        };
        disk.initial("format", &format)?;
        disk.initial("HEAD", &pin.encode())?;
        disk.initial("STAGES", &catalogue.encode())?;
        Ok(Self {
            disk,
            scope,
            limits,
            pin,
            catalogue,
            poisoned: false,
        })
    }
    /// Open and finish any exact protected transaction before returning. Recovery
    /// is a previous local decision, not fresh current-policy authorization.
    /// An external pin must equal the current publication, or exactly one side
    /// of a retained intent. An unrelated pin refuses before any recovery write.
    pub fn open(
        path: impl AsRef<Path>,
        scope: RoomScope,
        expected: Option<ContinuityPin>,
    ) -> Result<Self, Error> {
        let disk = Disk::open(path.as_ref())?;
        let (actual, limits, scope_id) =
            pin::decode_format(&disk.read("format", pin::FORMAT_BYTES)?)?;
        if scope != actual {
            return Err(Error::Conflict);
        }
        let pin = ContinuityPin::decode(&disk.read("HEAD", CONTINUITY_PIN_BYTES)?)?;
        if pin.scope != scope_id
            || pin.events > limits.history.max_events
            || pin.bytes > limits.history.max_history_bytes
        {
            return Err(Error::Corrupt);
        }
        let catalogue = Catalogue::decode(
            &disk.read("STAGES", MAX_CATALOGUE_BYTES)?,
            scope_id,
            scope,
            limits,
        )?;
        let mut store = Self {
            disk,
            scope,
            limits,
            pin,
            catalogue,
            poisoned: false,
        };
        if let Some(raw) = store.disk.optional("INTENT", MAX_TRANSACTION_BYTES)? {
            let intent = Intent::decode(&raw, scope, limits, scope_id)?;
            if expected.is_some_and(|value| value != intent.pin && value != intent.next_pin) {
                return Err(Error::Freshness);
            }
            store.apply(&intent)?;
            store.finish(&intent, &raw)?;
        } else {
            if expected.is_some_and(|value| value != store.pin) {
                return Err(Error::Freshness);
            }
            // These are unpublished duplicate temporaries; no dependent effect
            // is permitted before the fully synced final INTENT exists.
            store.disk.clear_temp("INTENT.tmp")?;
            store.disk.clear_temp("DATA.tmp")?;
        }
        store.check_tip()?;
        Ok(store)
    }
    /// Last confirmed local publication anchor, not a global completeness claim.
    /// If recovery is required, disk may be ahead; reopen before relying on it.
    pub const fn pin(&self) -> ContinuityPin {
        self.pin
    }
    /// Immutable local budgets.
    pub const fn limits(&self) -> ContinuityLimits {
        self.limits
    }
    /// An uncertain write occurred; drop this owner and explicitly reopen before
    /// reading, retrying, admitting another event, or reclaiming staging pages.
    pub const fn recovery_required(&self) -> bool {
        self.poisoned
    }
    fn healthy(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::RecoveryRequired)
        } else {
            Ok(())
        }
    }
    fn check_tip(&self) -> Result<(), Error> {
        if self.pin.feed == 0 {
            return Ok(());
        }
        let terminal = self.load_terminal(self.pin.feed, self.pin)?;
        if terminal.digest() != self.pin.tail {
            return Err(Error::Corrupt);
        }
        let author = terminal.event.claims().author;
        let head = self.load_author(author, self.pin)?.ok_or(Error::Corrupt)?;
        if head.ordinal < terminal.ordinal {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn load_terminal(&self, ordinal: u64, pin: ContinuityPin) -> Result<Terminal, Error> {
        if ordinal == 0 || ordinal > pin.feed {
            return Err(Error::Corrupt);
        }
        let value = Terminal::decode(
            &self.disk.read(&feed_path(ordinal), MAX_TERMINAL_BYTES)?,
            self.scope,
        )?;
        if value.ordinal != ordinal || (ordinal == pin.feed && value.digest() != pin.tail) {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
    fn load_evidence(
        &self,
        author: [u8; 32],
        sequence: u64,
        pin: ContinuityPin,
    ) -> Result<Option<Evidence>, Error> {
        if sequence == 0 {
            return Err(Error::Conflict);
        }
        let Some(raw) = self
            .disk
            .optional(&evidence_path(author, sequence), MAX_EVIDENCE_BYTES)?
        else {
            return Ok(None);
        };
        let evidence = Evidence::decode(&raw, self.scope, author)?;
        if evidence.event.claims().sequence != sequence || evidence.committed_by > pin.feed {
            return Err(Error::Corrupt);
        }
        let terminal = self.load_terminal(evidence.committed_by, pin)?;
        if terminal.event.claims().author != author
            || terminal.event.claims().sequence < sequence
            || (evidence.role == EvidenceRole::CurrentAdmission
                && (terminal.event.encode() != evidence.event.encode()
                    || terminal.registry != evidence.registry))
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(evidence))
    }
    fn load_author(&self, author: [u8; 32], pin: ContinuityPin) -> Result<Option<Terminal>, Error> {
        let key = hex(&author);
        if !self.disk.has_author(&key)? {
            return Ok(None);
        }
        // Existing author directory with a missing HEAD is always torn state.
        // Only apply_commit's exact protected intent permits its partial birth.
        let raw = self.disk.read(&author_path(author), MAX_TERMINAL_BYTES)?;
        let value = Terminal::decode(&raw, self.scope)?;
        if value.event.claims().author != author
            || self.load_terminal(value.ordinal, pin)?.encode() != raw
        {
            return Err(Error::Corrupt);
        }
        let evidence = self
            .load_evidence(author, value.event.claims().sequence, pin)?
            .ok_or(Error::Corrupt)?;
        if evidence.role != EvidenceRole::CurrentAdmission
            || evidence.event.encode() != value.event.encode()
        {
            return Err(Error::Corrupt);
        }
        Ok(Some(value))
    }
    fn chain(&self, author: [u8; 32]) -> Result<(AuthorChain, Option<Terminal>), Error> {
        let head = self.load_author(author, self.pin)?;
        let chain = match &head {
            Some(head) => {
                AuthorChain::restore_local_admitted_head(self.scope, author, head.event.clone())?
            }
            None => AuthorChain::new(self.scope, author)?,
        };
        Ok((chain, head))
    }
    fn page(&self, stage: &Stage, number: u32) -> Result<StagePage, Error> {
        let page = StagePage::decode(
            &self
                .disk
                .read(&page_path(stage.id, number), MAX_STAGE_PAGE_BYTES)?,
            self.scope,
            stage.author,
        )?;
        let offset = u64::from(number)
            .checked_mul(SEGMENT_EVENTS as u64)
            .ok_or(Error::Corrupt)?;
        if page.id != stage.id
            || page.number != number
            || stage
                .base
                .sequence
                .checked_add(offset)
                .and_then(|n| n.checked_add(1))
                != Some(page.events[0].claims().sequence)
        {
            return Err(Error::Corrupt);
        }
        Ok(page)
    }
    /// Streams at most the finite staging budget, retaining only one 32-event
    /// page. No lifetime-history enumeration or materialization is performed.
    fn visit_stage(
        &self,
        stage: &Stage,
        mut visit: impl FnMut(&StagePage) -> Result<(), Error>,
    ) -> Result<VerifiedEvent, Error> {
        if stage.cleaned != 0 {
            return Err(Error::Corrupt);
        }
        let mut previous = [0; 32];
        let mut position = stage.base;
        let mut bytes = 0u64;
        let mut tail = None;
        for number in 0..stage.pages {
            let page = self.page(stage, number)?;
            if page.previous != previous {
                return Err(Error::Corrupt);
            }
            for event in &page.events {
                if !Position::of(event).extends(position, event) {
                    return Err(Error::Corrupt);
                }
                position = Position::of(event);
            }
            bytes = bytes
                .checked_add(page.event_bytes())
                .ok_or(Error::Corrupt)?;
            previous = page.digest();
            tail = page.events.last().cloned();
            visit(&page)?;
        }
        if previous != stage.root || position != stage.tail || bytes != stage.event_bytes {
            return Err(Error::Corrupt);
        }
        tail.ok_or(Error::Corrupt)
    }
    fn staged_position(
        &self,
        chain: &AuthorChain,
        author: [u8; 32],
    ) -> Result<ContinuityPosition, Error> {
        match self.catalogue.stages.get(&author) {
            None => Ok(ContinuityPosition::begin(chain)),
            Some(stage) if stage.state == StageState::Active => {
                if position(chain) != stage.base {
                    return Err(Error::Conflict);
                }
                // The synced private catalogue records prior complete checked
                // pages. Appending verifies only its exact last page; final
                // publication still streams and verifies the complete prefix.
                let page = self.page(stage, stage.pages.checked_sub(1).ok_or(Error::Corrupt)?)?;
                if page.digest() != stage.root || page.tail() != stage.tail {
                    return Err(Error::Corrupt);
                }
                let tail = page.events.last().ok_or(Error::Corrupt)?;
                Ok(ContinuityPosition::restore_local_staging(chain, tail)?)
            }
            Some(_) => Err(Error::Capacity),
        }
    }
    /// Upload exactly 32 historical ancestors. Smaller final remainders belong
    /// inline in `commit`. Fixed pages bound file-count amplification. A returned
    /// ticket is temporary staging, never a delivery or admission receipt.
    pub fn stage(
        &mut self,
        events: Vec<VerifiedEvent>,
        context: &AdmissionContext<'_>,
        now: u64,
    ) -> Result<StageTicket, Error> {
        self.healthy()?;
        if events.len() != SEGMENT_EVENTS {
            return Err(Error::Capacity);
        }
        self.maintain(now)?;
        let author = events[0].claims().author;
        if let Some(stage) = self.catalogue.stages.get(&author) {
            let sequence = events[0].claims().sequence;
            if stage.state == StageState::Active
                && sequence > stage.base.sequence
                && sequence <= stage.tail.sequence
            {
                let offset = sequence - stage.base.sequence - 1;
                if !offset.is_multiple_of(SEGMENT_EVENTS as u64) {
                    return Err(Error::Conflict);
                }
                let number =
                    u32::try_from(offset / SEGMENT_EVENTS as u64).map_err(|_| Error::Capacity)?;
                let retained = self.page(stage, number)?;
                if retained
                    .events
                    .iter()
                    .map(VerifiedEvent::encode)
                    .collect::<Vec<_>>()
                    != events.iter().map(VerifiedEvent::encode).collect::<Vec<_>>()
                {
                    return Err(Error::Conflict);
                }
                return Ok(ticket(stage));
            }
        }
        let (chain, _) = self.chain(author)?;
        let staged = self.staged_position(&chain, author)?;
        let candidate = staged.prepare_segment(events, context)?;
        let old = self.catalogue.stages.get(&author);
        let generation = self
            .catalogue
            .generation
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let page = StagePage {
            id: old.map_or_else(
                || stage_id(self.pin.scope, author, position(&chain), generation),
                |value| value.id,
            ),
            number: old.map_or(0, |value| value.pages),
            previous: old.map_or([0; 32], |value| value.root),
            registry: *candidate.registry_digest(),
            events: candidate.events().to_vec(),
        };
        let after = stage_transition(&self.catalogue, &page, now, self.limits)?;
        let ticket = ticket(after.stages.get(&author).ok_or(Error::Corrupt)?);
        let intent = Intent {
            before: self.catalogue.clone(),
            after,
            pin: self.pin,
            next_pin: self.pin,
            operation: Operation::Stage(page),
        };
        self.transact(intent)?;
        Ok(ticket)
    }
    /// Admit one current-policy terminal with zero to 32 inline causal ancestors.
    /// Exact prior terminal retries return their original receipt; historical
    /// evidence cannot be promoted by retry. Policy and chain checks precede I/O.
    pub fn commit(
        &mut self,
        inline: Vec<VerifiedEvent>,
        terminal: VerifiedEvent,
        context: &AdmissionContext<'_>,
        now: u64,
    ) -> Result<ContinuityReceipt, Error> {
        self.healthy()?;
        if inline.len() > SEGMENT_EVENTS {
            return Err(Error::Capacity);
        }
        let author = terminal.claims().author;
        if terminal.claims().scope != self.scope {
            return Err(Error::Conflict);
        }
        if let Some(old) = self.load_evidence(author, terminal.claims().sequence, self.pin)? {
            if old.role != EvidenceRole::CurrentAdmission || old.event.encode() != terminal.encode()
            {
                return Err(Error::Conflict);
            }
            let start = terminal
                .claims()
                .sequence
                .checked_sub(inline.len() as u64)
                .ok_or(Error::Conflict)?;
            for (offset, event) in inline.iter().enumerate() {
                let sequence = start.checked_add(offset as u64).ok_or(Error::Conflict)?;
                if sequence == 0
                    || event.claims().scope != self.scope
                    || event.claims().author != author
                    || event.claims().sequence != sequence
                {
                    return Err(Error::Conflict);
                }
                let retained = self
                    .load_evidence(author, sequence, self.pin)?
                    .ok_or(Error::Conflict)?;
                if retained.role != EvidenceRole::HistoricalContinuity
                    || retained.committed_by != old.committed_by
                    || retained.event.encode() != event.encode()
                {
                    return Err(Error::Conflict);
                }
            }
            if inline
                .last()
                .is_some_and(|event| event.id() != terminal.claims().previous)
            {
                return Err(Error::Conflict);
            }
            return Ok(ContinuityReceipt {
                terminal: self.load_terminal(old.committed_by, self.pin)?,
                reconciled: true,
            });
        }
        self.maintain(now)?;
        let (chain, base) = self.chain(author)?;
        let mut staged = self.staged_position(&chain, author)?;
        if !inline.is_empty() {
            staged = staged
                .prepare_segment(inline.clone(), context)?
                .next_position();
        }
        let candidate = chain.prepare_continuity_terminal(staged, terminal, context)?;
        let prefix = prefix_root(
            self.catalogue
                .stages
                .get(&author)
                .map_or([0; 32], |stage| stage.root),
            &inline,
        );
        let terminal = Terminal {
            ordinal: self.pin.feed.checked_add(1).ok_or(Error::Capacity)?,
            previous: self.pin.tail,
            registry: *candidate.registry_digest(),
            prefix,
            event: candidate.event().clone(),
        };
        let mut after = self.catalogue.next(now)?;
        if let Some(stage) = after.stages.get_mut(&author) {
            stage.state = StageState::PublishedCleanup(terminal.ordinal);
        }
        let (events, bytes) =
            self.commit_cost(self.catalogue.stages.get(&author), &inline, &terminal)?;
        let next_pin = self
            .pin
            .next(events, bytes, terminal.digest(), self.limits.history)?;
        let receipt = ContinuityReceipt {
            terminal: terminal.clone(),
            reconciled: false,
        };
        self.transact(Intent {
            before: self.catalogue.clone(),
            after,
            pin: self.pin,
            next_pin,
            operation: Operation::Commit {
                base: base.map(Box::new),
                inline,
                terminal: Box::new(terminal),
            },
        })?;
        Ok(receipt)
    }
    /// Bound automatic abandoned-stage reclamation to at most 32 exact pages.
    /// No published record or author floor is eligible. An uncertain intent must
    /// be reconciled by reopening before any reclamation is permitted.
    pub fn maintain(&mut self, now: u64) -> Result<Maintenance, Error> {
        self.healthy()?;
        if now < self.catalogue.clock {
            return Err(Error::Conflict);
        }
        let after = clock_transition(&self.catalogue, now)?;
        if after.stages != self.catalogue.stages || now != self.catalogue.clock {
            self.transact(Intent {
                before: self.catalogue.clone(),
                after,
                pin: self.pin,
                next_pin: self.pin,
                operation: Operation::Clock,
            })?;
        }
        let mut removed = 0;
        while removed < SEGMENT_EVENTS as u32 {
            let Some(stage) = self
                .catalogue
                .stages
                .values()
                .find(|value| value.state != StageState::Active)
                .cloned()
            else {
                break;
            };
            let page = self.page(&stage, stage.cleaned)?;
            let after = cleanup_transition(&self.catalogue, &page, now)?;
            self.transact(Intent {
                before: self.catalogue.clone(),
                after,
                pin: self.pin,
                next_pin: self.pin,
                operation: Operation::Cleanup(page),
            })?;
            removed += 1;
        }
        Ok(Maintenance {
            pages_removed: removed,
            more: self
                .catalogue
                .stages
                .values()
                .any(|value| value.state != StageState::Active),
        })
    }
    /// Temporary position only; callers must preserve their signed source frames.
    pub fn stage_ticket(&self, author: [u8; 32]) -> Result<Option<StageTicket>, Error> {
        self.healthy()?;
        Ok(self
            .catalogue
            .stages
            .get(&author)
            .filter(|value| value.state == StageState::Active)
            .map(ticket))
    }
    /// Bounded published feed. Only current-admission terminal events appear.
    pub fn feed(&self, after: u64, count: usize) -> Result<Vec<ContinuityReceipt>, Error> {
        self.healthy()?;
        if count == 0 || count > SEGMENT_EVENTS || after > self.pin.feed {
            return Err(Error::Capacity);
        }
        let mut result = Vec::new();
        let mut previous = if after == 0 {
            [0; 32]
        } else {
            self.load_terminal(after, self.pin)?.digest()
        };
        for index in 0..count {
            let Some(ordinal) = after
                .checked_add(index as u64)
                .and_then(|value| value.checked_add(1))
            else {
                break;
            };
            if ordinal > self.pin.feed {
                break;
            }
            let terminal = self.load_terminal(ordinal, self.pin)?;
            if terminal.previous != previous {
                return Err(Error::Corrupt);
            }
            previous = terminal.digest();
            result.push(ContinuityReceipt {
                terminal,
                reconciled: false,
            });
        }
        Ok(result)
    }
    /// Public causal evidence, including explicit history-only roles. History-only
    /// is not confidential: these exact frames support independent chain replay.
    pub fn author_evidence(
        &self,
        author: [u8; 32],
        after: u64,
        count: usize,
    ) -> Result<Vec<PublishedEvidence>, Error> {
        self.healthy()?;
        if count == 0 || count > SEGMENT_EVENTS {
            return Err(Error::Capacity);
        }
        let head = self.load_author(author, self.pin)?;
        let ceiling = head
            .as_ref()
            .map_or(0, |value| value.event.claims().sequence);
        if after > ceiling {
            return Err(Error::Conflict);
        }
        let mut previous = if after == 0 {
            EventId::ZERO
        } else {
            self.load_evidence(author, after, self.pin)?
                .ok_or(Error::Corrupt)?
                .event
                .id()
        };
        let mut records = Vec::new();
        for index in 0..count {
            let Some(sequence) = after
                .checked_add(index as u64)
                .and_then(|n| n.checked_add(1))
            else {
                break;
            };
            if sequence > ceiling {
                break;
            }
            let record = self
                .load_evidence(author, sequence, self.pin)?
                .ok_or(Error::Corrupt)?;
            if record.event.claims().previous != previous {
                return Err(Error::Corrupt);
            }
            previous = record.event.id();
            records.push(PublishedEvidence { record });
        }
        Ok(records)
    }
    fn commit_cost(
        &self,
        stage: Option<&Stage>,
        inline: &[VerifiedEvent],
        terminal: &Terminal,
    ) -> Result<(u64, u64), Error> {
        let mut count = 0u64;
        // Count both immutable feed record and the current author index. Old
        // index replacements are conservatively charged again, never undercounted.
        let mut bytes = u64::try_from(terminal.encode().len())
            .map_err(|_| Error::Capacity)?
            .checked_mul(2)
            .ok_or(Error::Capacity)?;
        let mut add = |events: &[VerifiedEvent], role, registry| -> Result<(), Error> {
            for event in events {
                count = count.checked_add(1).ok_or(Error::Capacity)?;
                let evidence = Evidence {
                    role,
                    committed_by: terminal.ordinal,
                    registry,
                    event: event.clone(),
                };
                bytes = bytes
                    .checked_add(evidence.encode().len() as u64)
                    .ok_or(Error::Capacity)?;
            }
            Ok(())
        };
        if let Some(stage) = stage {
            self.visit_stage(stage, |page| {
                add(
                    &page.events,
                    EvidenceRole::HistoricalContinuity,
                    page.registry,
                )
            })?;
        }
        add(
            inline,
            EvidenceRole::HistoricalContinuity,
            terminal.registry,
        )?;
        add(
            std::slice::from_ref(&terminal.event),
            EvidenceRole::CurrentAdmission,
            terminal.registry,
        )?;
        Ok((count, bytes))
    }
    fn transact(&mut self, intent: Intent) -> Result<(), Error> {
        self.healthy()?;
        if intent.before != self.catalogue || intent.pin != self.pin {
            return Err(Error::Conflict);
        }
        let raw = intent.encode();
        if raw.len() > MAX_TRANSACTION_BYTES {
            return Err(Error::Capacity);
        }
        self.validate_intent(&intent)?;
        // From the first intent write onward, any uncertain result requires
        // reopen; no in-process retry can accidentally consume a new sequence.
        self.poisoned = true;
        let result = (|| {
            self.disk.install_intent(&raw)?;
            self.apply(&intent)?;
            self.finish(&intent, &raw)
        })();
        match result {
            Ok(()) => {
                self.poisoned = false;
                Ok(())
            }
            Err(Error::Io(error)) => Err(Error::Indeterminate(error)),
            Err(error) => Err(error),
        }
    }
    fn finish(&mut self, intent: &Intent, raw: &[u8]) -> Result<(), Error> {
        self.disk.remove_exact("INTENT", raw, false)?;
        self.disk.clear_temp("INTENT.tmp")?;
        self.disk.clear_temp("DATA.tmp")?;
        self.pin = intent.next_pin;
        self.catalogue = intent.after.clone();
        Ok(())
    }
    fn validate_intent(&self, intent: &Intent) -> Result<(), Error> {
        let next_generation = intent
            .before
            .generation
            .checked_add(1)
            .ok_or(Error::Corrupt)?;
        if intent.before.scope != self.pin.scope
            || intent.pin.scope != self.pin.scope
            || intent.next_pin.scope != self.pin.scope
            || intent.after.scope != self.pin.scope
            || intent.after.generation != next_generation
            || intent.after.clock < intent.before.clock
        {
            return Err(Error::Corrupt);
        }
        let after = match &intent.operation {
            Operation::Clock => clock_transition(&intent.before, intent.after.clock)?,
            Operation::Stage(page) => {
                stage_transition(&intent.before, page, intent.after.clock, self.limits)?
            }
            Operation::Cleanup(page) => {
                let author = page.events[0].claims().author;
                let stage = intent.before.stages.get(&author).ok_or(Error::Corrupt)?;
                if let StageState::PublishedCleanup(cursor) = stage.state {
                    let terminal = self.load_terminal(cursor, intent.pin)?;
                    if terminal.event.claims().author != author
                        || terminal.event.claims().sequence <= stage.tail.sequence
                    {
                        return Err(Error::Corrupt);
                    }
                    // Delete only the temporary duplicate after proving its
                    // exact permanent role-labelled evidence is published.
                    for event in &page.events {
                        let permanent = self
                            .load_evidence(author, event.claims().sequence, intent.pin)?
                            .ok_or(Error::Corrupt)?;
                        if permanent.role != EvidenceRole::HistoricalContinuity
                            || permanent.committed_by != cursor
                            || permanent.registry != page.registry
                            || permanent.event.encode() != event.encode()
                        {
                            return Err(Error::Corrupt);
                        }
                    }
                }
                cleanup_transition(&intent.before, page, intent.after.clock)?
            }
            Operation::Commit {
                base,
                inline,
                terminal,
            } => {
                if terminal.ordinal != intent.pin.feed.checked_add(1).ok_or(Error::Corrupt)?
                    || terminal.previous != intent.pin.tail
                    || inline.len() > SEGMENT_EVENTS
                {
                    return Err(Error::Corrupt);
                }
                let author = terminal.event.claims().author;
                let mut position = base
                    .as_ref()
                    .map_or(Position::EMPTY, |value| Position::of(&value.event));
                if let Some(base) = base {
                    if base.event.claims().author != author
                        || base.ordinal > intent.pin.feed
                        || self.load_terminal(base.ordinal, intent.pin)?.encode() != base.encode()
                    {
                        return Err(Error::Corrupt);
                    }
                }
                let stage = intent.before.stages.get(&author);
                if let Some(stage) = stage {
                    if stage.base != position
                        || stage.state != StageState::Active
                        || stage.expires <= intent.after.clock
                    {
                        return Err(Error::Corrupt);
                    }
                    position = Position::of(&self.visit_stage(stage, |_| Ok(()))?);
                }
                for event in inline.iter().chain(std::iter::once(&terminal.event)) {
                    if event.claims().scope != self.scope
                        || event.claims().author != author
                        || !Position::of(event).extends(position, event)
                    {
                        return Err(Error::Corrupt);
                    }
                    position = Position::of(event);
                }
                if terminal.prefix != prefix_root(stage.map_or([0; 32], |value| value.root), inline)
                {
                    return Err(Error::Corrupt);
                }
                let (count, bytes) = self.commit_cost(stage, inline, terminal)?;
                if intent
                    .pin
                    .next(count, bytes, terminal.digest(), self.limits.history)?
                    != intent.next_pin
                {
                    return Err(Error::Corrupt);
                }
                let mut after = intent.before.next(intent.after.clock)?;
                if let Some(stage) = after.stages.get_mut(&author) {
                    stage.state = StageState::PublishedCleanup(terminal.ordinal);
                }
                after
            }
        };
        if after != intent.after
            || (!matches!(intent.operation, Operation::Commit { .. })
                && intent.pin != intent.next_pin)
        {
            return Err(Error::Corrupt);
        }
        intent.after.check_capacity(self.limits)?;
        Ok(())
    }
    fn apply(&self, intent: &Intent) -> Result<(), Error> {
        self.validate_intent(intent)?;
        let disk_pin = ContinuityPin::decode(&self.disk.read("HEAD", CONTINUITY_PIN_BYTES)?)?;
        let disk_cat = self.disk.read("STAGES", MAX_CATALOGUE_BYTES)?;
        if (disk_pin != intent.pin && disk_pin != intent.next_pin)
            || (disk_cat != intent.before.encode() && disk_cat != intent.after.encode())
            || (disk_cat == intent.after.encode() && disk_pin != intent.next_pin)
        {
            return Err(Error::Conflict);
        }
        self.disk.confirm_intent(&intent.encode())?;
        match &intent.operation {
            Operation::Clock => {}
            Operation::Stage(page) => {
                let author = page.events[0].claims().author;
                let actual_base = self
                    .load_author(author, intent.pin)?
                    .map_or(Position::EMPTY, |value| Position::of(&value.event));
                if intent.after.stages.get(&author).ok_or(Error::Corrupt)?.base != actual_base {
                    return Err(Error::Conflict);
                }
                self.disk
                    .immutable(&page_path(page.id, page.number), &page.encode())?;
            }
            Operation::Cleanup(page) => {
                self.disk
                    .remove_exact(&page_path(page.id, page.number), &page.encode(), true)?;
            }
            Operation::Commit {
                base,
                inline,
                terminal,
            } => {
                let author = terminal.event.claims().author;
                let write = |events: &[VerifiedEvent], role, registry| -> Result<(), Error> {
                    for event in events {
                        let record = Evidence {
                            role,
                            committed_by: terminal.ordinal,
                            registry,
                            event: event.clone(),
                        };
                        self.disk.immutable(
                            &evidence_path(author, event.claims().sequence),
                            &record.encode(),
                        )?;
                    }
                    Ok(())
                };
                if let Some(stage) = intent.before.stages.get(&author) {
                    self.visit_stage(stage, |page| {
                        write(
                            &page.events,
                            EvidenceRole::HistoricalContinuity,
                            page.registry,
                        )
                    })?;
                }
                write(
                    inline,
                    EvidenceRole::HistoricalContinuity,
                    terminal.registry,
                )?;
                write(
                    std::slice::from_ref(&terminal.event),
                    EvidenceRole::CurrentAdmission,
                    terminal.registry,
                )?;
                self.disk
                    .immutable(&feed_path(terminal.ordinal), &terminal.encode())?;
                self.disk.ensure_author(&hex(&author))?;
                self.disk.replace_optional(
                    &author_path(author),
                    base.as_ref().map(|value| value.encode()).as_deref(),
                    &terminal.encode(),
                )?;
                self.disk
                    .replace("HEAD", &intent.pin.encode(), &intent.next_pin.encode())?;
            }
        }
        self.disk
            .replace("STAGES", &intent.before.encode(), &intent.after.encode())?;
        Ok(())
    }
}
fn position(chain: &AuthorChain) -> Position {
    chain.position().map_or(Position::EMPTY, |value| Position {
        sequence: value.sequence(),
        id: value.id(),
    })
}
fn ticket(stage: &Stage) -> StageTicket {
    StageTicket {
        id: stage.id,
        author: stage.author,
        sequence: stage.tail.sequence,
        event: stage.tail.id,
        pages: stage.pages,
        expires: stage.expires,
    }
}
fn stage_id(scope: [u8; 32], author: [u8; 32], base: Position, generation: u64) -> [u8; 32] {
    let mut input = b"vhalla/local-continuity-stage/v2\0".to_vec();
    input.extend_from_slice(&scope);
    input.extend_from_slice(&author);
    base.write(&mut input);
    input.extend_from_slice(&generation.to_be_bytes());
    digest(&input)
}
fn prefix_root(mut root: [u8; 32], events: &[VerifiedEvent]) -> [u8; 32] {
    for event in events {
        let mut input = b"vhalla/local-continuity-prefix/v2\0".to_vec();
        input.extend_from_slice(&root);
        input.extend_from_slice(event.id().as_bytes());
        root = digest(&input);
    }
    root
}
fn stage_transition(
    before: &Catalogue,
    page: &StagePage,
    now: u64,
    limits: ContinuityLimits,
) -> Result<Catalogue, Error> {
    if page.events.len() != SEGMENT_EVENTS {
        return Err(Error::Corrupt);
    }
    let author = page.events[0].claims().author;
    let mut after = before.next(now)?;
    let first = &page.events[0];
    let mut stage = if let Some(stage) = before.stages.get(&author) {
        if stage.state != StageState::Active || now >= stage.expires {
            return Err(Error::Conflict);
        }
        stage.clone()
    } else {
        let base = Position {
            sequence: first
                .claims()
                .sequence
                .checked_sub(1)
                .ok_or(Error::Corrupt)?,
            id: first.claims().previous,
        };
        if (base.sequence == 0) != (base.id == EventId::ZERO) {
            return Err(Error::Corrupt);
        }
        Stage {
            id: stage_id(before.scope, author, base, after.generation),
            author,
            base,
            tail: base,
            pages: 0,
            event_bytes: 0,
            remaining_bytes: 0,
            created: now,
            expires: now
                .checked_add(limits.stage_ttl_seconds)
                .ok_or(Error::Capacity)?,
            generation: after.generation,
            root: [0; 32],
            cleaned: 0,
            state: StageState::Active,
        }
    };
    if page.id != stage.id || page.number != stage.pages || page.previous != stage.root {
        return Err(Error::Conflict);
    }
    let mut prior = stage.tail;
    for event in &page.events {
        if event.claims().author != author
            || event.claims().scope != first.claims().scope
            || !Position::of(event).extends(prior, event)
        {
            return Err(Error::Conflict);
        }
        prior = Position::of(event);
    }
    stage.pages = stage.pages.checked_add(1).ok_or(Error::Capacity)?;
    stage.tail = prior;
    stage.root = page.digest();
    stage.event_bytes = stage
        .event_bytes
        .checked_add(page.event_bytes())
        .ok_or(Error::Capacity)?;
    stage.remaining_bytes = stage
        .remaining_bytes
        .checked_add(page.encode().len() as u64)
        .ok_or(Error::Capacity)?;
    after.stages.insert(author, stage);
    after.check_capacity(limits)?;
    Ok(after)
}
fn clock_transition(before: &Catalogue, now: u64) -> Result<Catalogue, Error> {
    let mut after = before.next(now)?;
    for stage in after.stages.values_mut() {
        if stage.state == StageState::Active && now >= stage.expires {
            stage.state = StageState::ExpiredCleanup;
        }
    }
    Ok(after)
}
fn cleanup_transition(before: &Catalogue, page: &StagePage, now: u64) -> Result<Catalogue, Error> {
    let author = page.events[0].claims().author;
    let mut after = before.next(now)?;
    let stage = after.stages.get_mut(&author).ok_or(Error::Corrupt)?;
    if stage.state == StageState::Active
        || page.id != stage.id
        || page.number != stage.cleaned
        || stage.cleaned >= stage.pages
    {
        return Err(Error::Conflict);
    }
    stage.remaining_bytes = stage
        .remaining_bytes
        .checked_sub(page.encode().len() as u64)
        .ok_or(Error::Corrupt)?;
    stage.cleaned = stage.cleaned.checked_add(1).ok_or(Error::Corrupt)?;
    if stage.cleaned == stage.pages {
        if stage.remaining_bytes != 0 {
            return Err(Error::Corrupt);
        }
        after.stages.remove(&author);
    }
    Ok(after)
}
fn hex(bytes: &[u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 15) as usize] as char);
    }
    value
}
fn feed_path(ordinal: u64) -> String {
    format!("feed/{ordinal:020}")
}
fn author_path(author: [u8; 32]) -> String {
    format!("authors/{}/HEAD", hex(&author))
}
fn evidence_path(author: [u8; 32], sequence: u64) -> String {
    format!("evidence/{}_{sequence:020}", hex(&author))
}
fn page_path(id: [u8; 32], number: u32) -> String {
    format!("pages/{}_{number:010}", hex(&id))
}

#[cfg(test)]
mod tests;
