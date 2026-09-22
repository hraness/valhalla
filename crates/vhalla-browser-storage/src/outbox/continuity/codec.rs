use super::*;
const STATE: &[u8; 8] = b"VHCCST01";
const RECORD: &[u8; 8] = b"VHCCRC01";
#[cfg(any(unix, test))]
const INTENT: &[u8; 8] = b"VHCCIN01";
const FORMAT: &[u8; 8] = b"VHCCFM01";
pub(crate) const MAX_FORMAT: usize = 2048;
fn finish(mut raw: Vec<u8>) -> Vec<u8> {
    raw.extend(hash(&raw));
    raw
}
fn start<'a>(raw: &'a [u8], magic: &[u8; 8], max: usize) -> Result<Read<'a>, Error> {
    if raw.len() > max || raw.len() < 40 {
        return Err(Error::Corrupt);
    }
    let (data, digest) = raw.split_at(raw.len() - 32);
    if &data[..8] != magic || hash(data) != digest {
        return Err(Error::Corrupt);
    }
    Ok(Read(&data[8..]))
}
fn u64p(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_be_bytes());
}
fn blob(out: &mut Vec<u8>, raw: &[u8]) {
    out.extend((raw.len() as u32).to_be_bytes());
    out.extend(raw);
}
fn position(out: &mut Vec<u8>, p: wire::Position) {
    u64p(out, p.sequence());
    out.extend(p.event_id().as_bytes());
}
fn scope(out: &mut Vec<u8>, s: &SessionScope) {
    s.author.encode(out);
    out.extend(s.history.bootstrap_pin());
    out.extend(s.peer);
    blob(out, s.endpoint.as_str().as_bytes());
}
fn limits(out: &mut Vec<u8>, l: Limits) {
    u64p(out, l.max_records);
    u64p(out, l.max_bytes);
}
fn job(out: &mut Vec<u8>, j: ContinuityJob) {
    out.extend(j.operation);
    position(out, j.terminal);
    out.extend(j.frame);
}
fn reference(out: &mut Vec<u8>, r: RecordRef) {
    u64p(out, r.index);
    out.extend(r.digest);
}
fn maybe_ref(out: &mut Vec<u8>, r: Option<RecordRef>) {
    out.push(u8::from(r.is_some()));
    if let Some(r) = r {
        reference(out, r);
    }
}
fn attempt(out: &mut Vec<u8>, a: &ContinuityAttempt) {
    blob(out, &a.request.encode());
    blob(out, &a.body);
}
impl Snapshot {
    /// Canonical bounded exact-CAS bytes. Decoding alone authenticates no receipt.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = STATE.to_vec();
        scope(&mut out, &self.scope);
        limits(&mut out, self.limits);
        u64p(&mut out, self.generation);
        out.push(u8::from(self.job.is_some()));
        if let Some(j) = self.job {
            job(&mut out, j);
        }
        out.push(u8::from(self.attempt.is_some()));
        if let Some(a) = &self.attempt {
            attempt(&mut out, a);
        }
        out.extend(self.last_nonce);
        u64p(&mut out, self.records);
        u64p(&mut out, self.bytes);
        maybe_ref(&mut out, self.latest);
        position(&mut out, self.retention.position);
        maybe_ref(&mut out, self.retention.record);
        out.push(match self.retention.role {
            None => 0,
            Some(wire::EvidenceRole::HistoricalContinuity) => 1,
            Some(wire::EvidenceRole::CurrentAdmission) => 2,
        });
        u64p(&mut out, self.retention.committed_by);
        out.extend(self.retention.registry);
        out.push(u8::from(self.terminal.is_some()));
        if let Some(t) = self.terminal {
            position(&mut out, t.position);
            u64p(&mut out, t.cursor);
            out.extend(t.registry);
            reference(&mut out, t.record);
        }
        finish(out)
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = start(raw, STATE, MAX_STATE_BYTES)?;
        let scope = r.scope()?;
        let limits = r.limits()?;
        let generation = r.u64()?;
        let job = if r.flag()? { Some(r.job()?) } else { None };
        let attempt = if r.flag()? { Some(r.attempt()?) } else { None };
        let last_nonce = r.array()?;
        let records = r.u64()?;
        let bytes = r.u64()?;
        let latest = r.maybe_ref()?;
        let retention = RetentionHead {
            position: r.position()?,
            record: r.maybe_ref()?,
            role: match r.byte()? {
                0 => None,
                1 => Some(wire::EvidenceRole::HistoricalContinuity),
                2 => Some(wire::EvidenceRole::CurrentAdmission),
                _ => return Err(Error::Corrupt),
            },
            committed_by: r.u64()?,
            registry: r.array()?,
        };
        let terminal = if r.flag()? {
            Some(TerminalEvidence {
                position: r.position()?,
                cursor: r.u64()?,
                registry: r.array()?,
                record: r.reference()?,
            })
        } else {
            None
        };
        r.end()?;
        let value = Self {
            scope,
            limits,
            generation,
            job,
            attempt,
            last_nonce,
            records,
            bytes,
            latest,
            retention,
            terminal,
        };
        value.shape()?;
        if value.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
    fn shape(&self) -> Result<(), Error> {
        if self.records > self.limits.max_records
            || self.bytes > self.limits.max_bytes
            || (self.records == 0) != (self.bytes == 0)
            || (self.records == 0) != self.latest.is_none()
            || self.latest.is_some_and(|r| r.index != self.records)
            || self
                .retention
                .record
                .is_some_and(|r| r.index > self.records)
            || (self.retention.position == wire::Position::EMPTY)
                != (self.retention == RetentionHead::empty())
        {
            return Err(Error::Corrupt);
        }
        if self.retention.position != wire::Position::EMPTY
            && (self.retention.record.is_none()
                || self.retention.role.is_none()
                || self.retention.committed_by == 0
                || self.retention.registry == [0; 32])
        {
            return Err(Error::Corrupt);
        }
        match self.job {
            None if self.attempt.is_some() || self.records != 0 || self.terminal.is_some() => {
                return Err(Error::Corrupt)
            }
            Some(j) if j.terminal.sequence() < self.retention.position.sequence() => {
                return Err(Error::Corrupt)
            }
            _ => {}
        }
        if let Some(t) = self.terminal {
            if self
                .job
                .is_none_or(|j| t.position.sequence() > j.terminal.sequence())
                || t.cursor == 0
                || t.registry == [0; 32]
                || t.record.index > self.records
            {
                return Err(Error::Corrupt);
            }
        }
        if let Some(a) = &self.attempt {
            if a.request.context().nonce != self.last_nonce {
                return Err(Error::Corrupt);
            }
            request_check(self, a)?;
            body_sources(a, &mut Vec::new())?;
        }
        if self.generation == 0 && (self.job.is_some() || self.last_nonce != [0; 32]) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    pub(crate) fn format(&self) -> Vec<u8> {
        format(&self.scope, self.limits)
    }
    pub(crate) fn references(&self) -> Vec<RecordRef> {
        let mut refs = Vec::new();
        if let Some(r) = self.latest {
            refs.push(r);
        }
        if let Some(r) = self.retention.record {
            refs.push(r);
        }
        if let Some(t) = self.terminal {
            refs.push(t.record);
        }
        refs.sort_by_key(|r| r.index);
        refs.dedup();
        refs
    }
    /// Reauthenticate only fixed referenced evidence, not the entire history.
    /// Actual source is checked separately under backend custody/transaction.
    pub(crate) fn validate_records(
        &self,
        mut read: impl FnMut(u64) -> Result<ContinuityEvidenceRecord, Error>,
    ) -> Result<Vec<SourceCheck>, Error> {
        self.shape()?;
        let refs = self.references();
        let mut sources = Vec::new();
        if let Some(j) = self.job {
            sources.push(SourceCheck {
                position: j.terminal,
                frame: Some(j.frame),
            });
        }
        // At most three bounded proof pages; not a lifetime map/scan.
        for expected in refs {
            let record = read(expected.index)?;
            if record.scope != self.scope || record.reference() != expected {
                return Err(Error::Corrupt);
            }
            reply_sources(record.reply(), &mut sources)?;
            if self.retention.record == Some(expected) {
                let wire::Reply::Evidence(page) = record.reply() else {
                    return Err(Error::Corrupt);
                };
                let last = page.entries.last().ok_or(Error::Corrupt)?;
                if wire::Position::of(&last.event) != self.retention.position
                    || Some(last.role) != self.retention.role
                    || last.committed_by != self.retention.committed_by
                    || last.registry != self.retention.registry
                {
                    return Err(Error::Corrupt);
                }
            }
            if let Some(t) = self.terminal.filter(|t| t.record == expected) {
                let wire::Reply::Committed(receipt) = record.reply() else {
                    return Err(Error::Corrupt);
                };
                if wire::Position::of(&receipt.event) != t.position
                    || receipt.cursor != t.cursor
                    || receipt.registry != t.registry
                    || Some(record.job) != self.job
                {
                    return Err(Error::Corrupt);
                }
            }
        }
        if let Some(a) = &self.attempt {
            body_sources(a, &mut sources)?;
        }
        sources.sort_by_key(|s| s.position.sequence());
        sources.dedup();
        // Up to three 32-frame record pages and one 33-frame attempt, all fixed.
        if sources.len() > 3 * wire::MAX_PAGE + MAX_SOURCE_CHECKS {
            return Err(Error::Bounds);
        }
        Ok(sources)
    }
}
pub(crate) fn format(scope_value: &SessionScope, value: Limits) -> Vec<u8> {
    let mut out = FORMAT.to_vec();
    scope(&mut out, scope_value);
    limits(&mut out, value);
    finish(out)
}
pub(crate) fn check_format(
    raw: &[u8],
    expected: &SessionScope,
    limits_value: Limits,
) -> Result<(), Error> {
    if raw != format(expected, limits_value) {
        return Err(Error::WrongScope);
    }
    Ok(())
}
impl ContinuityEvidenceRecord {
    /// Canonical original proof record. It does not encode a v1 delivery receipt.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = RECORD.to_vec();
        scope(&mut out, &self.scope);
        job(&mut out, self.job);
        u64p(&mut out, self.index);
        out.extend(self.previous);
        blob(&mut out, &self.request.encode());
        blob(&mut out, &self.proof.encode());
        blob(&mut out, &self.body);
        finish(out)
    }
    /// Strictly authenticate original peer proof/frames with embedded full scope.
    /// The backend must additionally compare selected scope, record index/hash,
    /// and actual local source before treating these bytes as retained evidence.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = start(raw, RECORD, MAX_RECORD_BYTES)?;
        let scope = r.scope()?;
        let job = r.job()?;
        let index = r.u64()?;
        let previous = r.array()?;
        let request =
            wire::Request::decode(r.blob(wire::MAX_REQUEST_BYTES)?).map_err(|_| Error::Corrupt)?;
        let proof = wire::ResponseProof::decode(r.blob(wire::MAX_PROOF_BYTES)?)
            .map_err(|_| Error::Corrupt)?;
        let body = r.blob(wire::MAX_REPLY_BYTES)?;
        let value = Self::new(scope, job, index, previous, request, proof, body)?;
        r.end()?;
        if value.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}
#[cfg(any(unix, test))]
impl Publication {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = INTENT.to_vec();
        out.extend([0; 4]);
        blob(&mut out, &self.before.encode());
        match &self.operation {
            Operation::Job(j) => {
                out.push(0);
                job(&mut out, *j);
            }
            Operation::Attempt(a) => {
                out.push(1);
                attempt(&mut out, a);
            }
            Operation::Response(r) => {
                out.push(2);
                blob(&mut out, &r.encode());
            }
        }
        let total = (out.len() + 32) as u32;
        out[8..12].copy_from_slice(&total.to_be_bytes());
        finish(out)
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = start(raw, INTENT, MAX_INTENT_BYTES)?;
        if u32::from_be_bytes(r.array()?) as usize != raw.len() {
            return Err(Error::Corrupt);
        }
        let before = Snapshot::decode(r.blob(MAX_STATE_BYTES)?)?;
        let operation = match r.byte()? {
            0 => Operation::Job(r.job()?),
            1 => Operation::Attempt(Box::new(r.attempt()?)),
            2 => Operation::Response(Box::new(ContinuityEvidenceRecord::decode(
                r.blob(MAX_RECORD_BYTES)?,
            )?)),
            _ => return Err(Error::Corrupt),
        };
        r.end()?;
        let value = prepare(before, operation)?;
        if value.encode() != raw {
            return Err(Error::Corrupt);
        }
        Ok(value)
    }
}
/// Recognize only structurally incomplete unpublished framing, with every
/// available before-state byte exactly matching the validated current state.
/// Full malformed frames and contradicting available fields remain untouched.
#[cfg(any(unix, test))]
pub(crate) fn incomplete_prefix(raw: &[u8], state: &Snapshot) -> bool {
    let before = state.encode();
    let minimum = 12 + 4 + before.len() + 1 + 88 + 32;
    if raw.len() > MAX_INTENT_BYTES {
        return false;
    }
    let magic_n = raw.len().min(8);
    if raw[..magic_n] != INTENT[..magic_n] {
        return false;
    }
    if raw.len() < 12 {
        let mut low = [0; 4];
        let mut high = [255; 4];
        if raw.len() > 8 {
            low[..raw.len() - 8].copy_from_slice(&raw[8..]);
            high[..raw.len() - 8].copy_from_slice(&raw[8..]);
        }
        return (u32::from_be_bytes(low) as usize) <= MAX_INTENT_BYTES
            && (u32::from_be_bytes(high) as usize) >= minimum;
    }
    let total = u32::from_be_bytes(raw[8..12].try_into().expect("four")) as usize;
    if total < minimum || total > MAX_INTENT_BYTES || raw.len() >= total {
        return false;
    }
    let mut prefix = Vec::new();
    blob(&mut prefix, &before);
    let available = (raw.len() - 12).min(prefix.len());
    if raw[12..12 + available] != prefix[..available] {
        return false;
    }
    if available < prefix.len() {
        return true;
    }
    let start = 12 + prefix.len();
    let Some(tag) = raw.get(start) else {
        return true;
    };
    let op = start + 1;
    let body_end = total - 32;
    let plausible = match tag {
        0 => {
            if total != op + 88 + 32 {
                return false;
            }
            if raw.len() >= op + 16 && raw[op..op + 16] == [0; 16] {
                return false;
            }
            if raw.len() >= op + 56 {
                let sequence = u64::from_be_bytes(raw[op + 16..op + 24].try_into().expect("eight"));
                let id = EventId::from_bytes(raw[op + 24..op + 56].try_into().expect("32"));
                if wire::Position::new(sequence, id).is_err() || sequence == 0 {
                    return false;
                }
            }
            true
        }
        1 => {
            // Shortest author-scoped v1 request is Status: magic5, scope112,
            // nonce32, operation16, floor40, selection33, kind1, position40.
            const MIN_REQUEST: usize = 279;
            if state.job.is_none() || total < op + 4 + MIN_REQUEST + 4 + 32 {
                return false;
            }
            let request_max = wire::MAX_REQUEST_BYTES.min(total - op - 4 - 4 - 32);
            let request_len = match partial_length(raw, op, MIN_REQUEST, request_max) {
                Ok(Some(n)) => n,
                Ok(None) => return true,
                Err(()) => return false,
            };
            let request_end = op + 4 + request_len;
            if raw.len() < request_end {
                return true;
            }
            let Ok(request) = wire::Request::decode(&raw[op + 4..request_end]) else {
                return false;
            };
            let probe = ContinuityAttempt {
                request,
                body: Vec::new(),
            };
            if request_check(state, &probe).is_err() || request.context().nonce == state.last_nonce
            {
                return false;
            }
            let body_len = total - request_end - 4 - 32;
            if body_len > wire::MAX_BODY_BYTES {
                return false;
            }
            match request.kind() {
                wire::Kind::Stage { .. } | wire::Kind::Commit { .. } if body_len < 6 => {
                    return false
                }
                wire::Kind::Status { .. } | wire::Kind::Evidence { .. } if body_len != 0 => {
                    return false
                }
                _ => {}
            }
            partial_length(raw, request_end, body_len, body_len).is_ok()
        }
        2 => {
            let Some(job_value) = state.job else {
                return false;
            };
            let Some(attempt_value) = &state.attempt else {
                return false;
            };
            let Some(index) = state.records.checked_add(1) else {
                return false;
            };
            let request_raw = attempt_value.request.encode();
            let mut exact = RECORD.to_vec();
            scope(&mut exact, &state.scope);
            job(&mut exact, job_value);
            u64p(&mut exact, index);
            exact.extend(state.latest.map_or([0; 32], |r| r.digest));
            blob(&mut exact, &request_raw);
            let proof_len = 5 + 32 + 2 + request_raw.len() + 32 + 64;
            let min_reply = match attempt_value.request.kind() {
                wire::Kind::Stage { .. } => 242,
                wire::Kind::Commit { .. } => {
                    let Ok(body) = attempt_value.request.check_body(&attempt_value.body) else {
                        return false;
                    };
                    let Some(terminal) = body.terminal() else {
                        return false;
                    };
                    89 + terminal.encode().len()
                }
                wire::Kind::Status { .. } | wire::Kind::Evidence { .. } => 87,
                wire::Kind::Feed { .. } => return false,
            };
            let minimum_record = exact.len() + 4 + proof_len + 4 + min_reply + 32;
            let Some(n) = total.checked_sub(op + 4 + 32) else {
                return false;
            };
            if n < minimum_record || n > MAX_RECORD_BYTES {
                return false;
            }
            if partial_length(raw, op, n, n).is_err() {
                return false;
            }
            let record_start = op + 4;
            if raw.len() < record_start {
                return true;
            }
            let available = (raw.len() - record_start).min(exact.len());
            if raw[record_start..record_start + available] != exact[..available] {
                return false;
            }
            if available < exact.len() {
                return true;
            }
            let proof_start = record_start + exact.len();
            if partial_length(raw, proof_start, proof_len, proof_len).is_err() {
                return false;
            }
            let mut proof_prefix = b"VHCP\x01".to_vec();
            proof_prefix.extend(state.scope.peer);
            proof_prefix.extend((request_raw.len() as u16).to_be_bytes());
            proof_prefix.extend(&request_raw);
            let proof_bytes = proof_start + 4;
            if raw.len() >= proof_bytes {
                let available = (raw.len() - proof_bytes).min(proof_prefix.len());
                if raw[proof_bytes..proof_bytes + available] != proof_prefix[..available] {
                    return false;
                }
            }
            let body_len = n - exact.len() - 4 - proof_len - 4 - 32;
            if body_len > wire::MAX_REPLY_BYTES {
                return false;
            }
            let body_start = proof_start + 4 + proof_len;
            if partial_length(raw, body_start, body_len, body_len).is_err() {
                return false;
            }
            true
        }
        _ => false,
    };
    if !plausible {
        return false;
    }
    if raw.len() >= body_end {
        let mut full = raw[..body_end].to_vec();
        let digest = hash(&full);
        if raw[body_end..] != digest[..raw.len() - body_end] {
            return false;
        }
        full.extend(digest);
        return Publication::decode(&full).is_ok();
    }
    true
}
#[cfg(any(unix, test))]
fn partial_length(raw: &[u8], offset: usize, min: usize, max: usize) -> Result<Option<usize>, ()> {
    let available = raw.len().saturating_sub(offset).min(4);
    let mut low = [0; 4];
    let mut high = [255; 4];
    if available > 0 {
        low[..available].copy_from_slice(&raw[offset..offset + available]);
        high[..available].copy_from_slice(&raw[offset..offset + available]);
    }
    let value = u32::from_be_bytes(low) as usize;
    if min > max || value > max || (u32::from_be_bytes(high) as usize) < min {
        return Err(());
    }
    Ok(if available == 4 { Some(value) } else { None })
}
pub(crate) struct Read<'a>(&'a [u8]);
impl<'a> Read<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let v = self.0.get(..n).ok_or(Error::Corrupt)?;
        self.0 = &self.0[n..];
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn flag(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Corrupt),
        }
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > max {
            return Err(Error::Bounds);
        }
        self.take(n)
    }
    fn end(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Corrupt)
        }
    }
    fn position(&mut self) -> Result<wire::Position, Error> {
        wire::Position::new(self.u64()?, EventId::from_bytes(self.array()?))
            .map_err(|_| Error::Corrupt)
    }
    fn scope(&mut self) -> Result<SessionScope, Error> {
        let author = AuthorScope {
            network: self.array()?,
            realm: self.array()?,
            directory: self.array()?,
            room: self.array()?,
            author: self.array()?,
        };
        let history = HistoryScope::new(author.network, self.array()?);
        let peer = self.array()?;
        let endpoint =
            Endpoint::parse(std::str::from_utf8(self.blob(1024)?).map_err(|_| Error::Corrupt)?)
                .map_err(|_| Error::Corrupt)?;
        SessionScope::new(author, history, peer, endpoint)
    }
    fn limits(&mut self) -> Result<Limits, Error> {
        let l = Limits {
            max_records: self.u64()?,
            max_bytes: self.u64()?,
        };
        l.check()?;
        Ok(l)
    }
    fn job(&mut self) -> Result<ContinuityJob, Error> {
        let j = ContinuityJob {
            operation: self.array()?,
            terminal: self.position()?,
            frame: self.array()?,
        };
        if j.operation == [0; 16] || j.terminal == wire::Position::EMPTY || j.frame == [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(j)
    }
    fn reference(&mut self) -> Result<RecordRef, Error> {
        let r = RecordRef {
            index: self.u64()?,
            digest: self.array()?,
        };
        if r.index == 0 || r.digest == [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(r)
    }
    fn maybe_ref(&mut self) -> Result<Option<RecordRef>, Error> {
        if self.flag()? {
            Ok(Some(self.reference()?))
        } else {
            Ok(None)
        }
    }
    fn attempt(&mut self) -> Result<ContinuityAttempt, Error> {
        let request = wire::Request::decode(self.blob(wire::MAX_REQUEST_BYTES)?)
            .map_err(|_| Error::Corrupt)?;
        let body = self.blob(wire::MAX_BODY_BYTES)?.to_vec();
        let a = ContinuityAttempt { request, body };
        body_sources(&a, &mut Vec::new())?;
        Ok(a)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn prefix(value: &SessionScope) -> String {
    let mut raw = Vec::new();
    scope(&mut raw, value);
    format!(
        "continuity/v1/{}/",
        vhalla_public_protocol::response::hex(&hash(&raw))
    )
}
