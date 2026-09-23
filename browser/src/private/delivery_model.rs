//! Bounded durable delivery progress; credentials never enter this encoding.
use vhalla_private_relay::{codec, RelayItem};
const MAGIC_V1: &[u8] = b"VHBRDEL\x01";
const MAGIC: &[u8] = b"VHBRDEL\x02";
pub(crate) const ATTEMPTS: u64 = 4096;
pub(crate) const WIRE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const PAGE: usize = 4;
/// Consecutive reserved unsuccessful attempts before delivery pauses.
pub(crate) const MAX_FAILURES: u64 = 10;
/// Tolerated wall-clock regression between reservations. A stored clock
/// further ahead than this is evidence of a bogus clock, not a step back.
pub(crate) const CLOCK_REGRESSION: u64 = 24 * 60 * 60;
/// Retained refused-record ring; the lifetime count is kept separately.
pub(crate) const MAX_REFUSED: usize = 64;
/// Retained relay-delivered bootstrap items awaiting explicit admission.
pub(crate) const MAX_ADMISSIONS: usize = 8;
pub(crate) const MAX_PENDING: usize = codec::MAX_REQUEST;
const REFUSAL_BYTES: usize = 8 + 32 + 1;
const ADMISSION_BYTES: usize = 8 + 1 + 4 + 32;
pub(crate) const MAX_STATE: usize = codec::MAX_PAGE_BODY
    + MAX_PENDING
    + 512
    + MAX_REFUSED * REFUSAL_BYTES
    + MAX_ADMISSIONS * ADMISSION_BYTES;
pub(crate) type Result<T> = core::result::Result<T, ()>;

/// Why delivery is stopped. Only `Backoff` is cleared, by an explicit reopen
/// that re-supplies the capability profile; budgets are never replenished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stop {
    None,
    /// A lifetime attempt or byte budget is spent.
    Exhausted,
    /// A malformed, hostile or contract-violating relay response was retained.
    Refused,
    /// Ten consecutive reserved attempts failed transiently.
    Backoff,
}
impl Stop {
    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Exhausted => 1,
            Self::Refused => 2,
            Self::Backoff => 3,
        }
    }
    fn decode(code: u8) -> Result<Self> {
        Ok(match code {
            0 => Self::None,
            1 => Self::Exhausted,
            2 => Self::Refused,
            3 => Self::Backoff,
            _ => return Err(()),
        })
    }
}
/// Durable detail for a `Refused` stop.
pub(crate) mod halt {
    /// Noncanonical frame, status or content type.
    pub const FRAME: u8 = 1;
    /// A receipt whose commitment differs from the exact item sent.
    pub const RECEIPT: u8 = 2;
    /// A page violating the immutable mailbox contract or namespace.
    pub const PAGE: u8 = 3;
    /// A staged control conflicts with the accepted local control history.
    /// Continuing to trust this mailbox cannot be distinguished from continuing
    /// after local custody moved, so delivery stops rather than skipping.
    pub const CONFLICT: u8 = 4;
    /// A staged owner-sealed control carries a claim the current roster does
    /// not authorize. The cursor cannot honestly pass it, so delivery stops.
    pub const AUTHORITY: u8 = 5;
    /// A stopped version-1 image whose reason was not recorded.
    pub const LEGACY: u8 = 6;
}
/// Why one staged mailbox record was durably refused and skipped. Each names
/// a record that can never apply to this device; nothing local changed.
pub(crate) mod refusal {
    /// Foreign room or context binding; the kernel proves it cannot apply here.
    pub const SCOPE: u8 = 1;
    /// Undecryptable under the current ratchet or unauthenticated MLS content.
    pub const RATCHET: u8 = 2;
    /// Malformed canonical encoding.
    pub const MALFORMED: u8 = 3;
    /// Empty or oversized content.
    pub const BOUNDS: u8 = 4;
    /// This device has no membership that could apply the record.
    pub const PHASE: u8 = 5;
    /// A control at or below this device's retained history base.
    pub const BELOW_BASE: u8 = 6;
    /// A sender or content the current roster does not authorize.
    pub const POLICY: u8 = 7;
    /// A control envelope that does not authenticate under this room's key.
    /// Junk forgeries cannot advance or block the accepted control floor, so
    /// they are skipped with evidence like any other unusable record.
    pub const UNAUTHENTICATED: u8 = 8;
    /// The item's MLS epoch is older than the retained epoch; its keys are
    /// gone, so these exact bytes can never apply to this device.
    pub const STALE_EPOCH: u8 = 9;
    /// The item's MLS epoch is newer than the retained epoch. The control that
    /// would admit it arrives at a later mailbox position and these exact
    /// bytes can never be refetched once the cursor passes them.
    pub const FUTURE_EPOCH: u8 = 10;
}
/// Why the cursor is held before one staged record without ending custody.
/// Cleared when that record applies; the record is never skipped.
pub(crate) mod blocked {
    /// A typed owner-control floor gap: the missing predecessor control must
    /// be applied first, from a later mailbox position or an explicit file.
    pub const CONTROL: u8 = 1;
    /// The kernel clock or an enrollment validity refuses the record now.
    pub const TIME: u8 = 2;
    /// Every retained-admission slot is used; discard or use one first.
    pub const ADMISSIONS_FULL: u8 = 3;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Refusal {
    pub position: u64,
    pub digest: [u8; 32],
    pub reason: u8,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Admission {
    pub position: u64,
    pub kind: u8,
    pub len: u32,
    pub digest: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct State {
    pub binding: [u8; 32],
    pub owner: [u8; 16],
    pub initial: u64,
    pub sent: u64,
    pub cursor: u64,
    pub attempts: u64,
    pub wire_bytes: u64,
    pub wall: u64,
    pub retry_at: u64,
    pub failures: u64,
    pub retained: u64,
    pub received: u64,
    pub refused_total: u64,
    pub stop: Stop,
    pub detail: u8,
    pub blocked: u8,
    pub refused: Vec<Refusal>,
    pub admissions: Vec<Admission>,
    pub pending: Vec<u8>,
    pub staged: Vec<u8>,
    pub staged_after: u64,
    pub applied: u64,
}
impl State {
    pub fn new(binding: [u8; 32], owner: [u8; 16], initial: u64, wall: u64) -> Self {
        Self {
            binding,
            owner,
            initial,
            sent: 0,
            cursor: initial,
            attempts: 0,
            wire_bytes: 0,
            wall,
            retry_at: 0,
            failures: 0,
            retained: 0,
            received: 0,
            refused_total: 0,
            stop: Stop::None,
            detail: 0,
            blocked: 0,
            refused: Vec::new(),
            admissions: Vec::new(),
            pending: Vec::new(),
            staged: Vec::new(),
            staged_after: initial,
            applied: 0,
        }
    }
    pub fn stopped(&self) -> bool {
        self.stop != Stop::None
    }
    pub fn check(&self) -> Result<()> {
        if self.binding == [0; 32]
            || self.owner == [0; 16]
            || self.initial > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || self.cursor > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || self.cursor < self.initial
            || self.attempts > ATTEMPTS
            || self.wire_bytes > WIRE_BYTES
            || self.failures > MAX_FAILURES
            || (self.stop == Stop::Refused) != (self.detail != 0)
            || self.refused.len() > MAX_REFUSED
            || self.refused_total < self.refused.len() as u64
            || self.admissions.len() > MAX_ADMISSIONS
            || self.pending.len() > MAX_PENDING
            || self.staged.len() > codec::MAX_PAGE_BODY
        {
            return Err(());
        }
        for pair in self.refused.windows(2) {
            if pair[0].position >= pair[1].position {
                return Err(());
            }
        }
        for pair in self.admissions.windows(2) {
            if pair[0].position >= pair[1].position {
                return Err(());
            }
        }
        if self
            .refused
            .iter()
            .any(|r| r.reason == 0 || r.position > self.cursor)
            || self
                .admissions
                .iter()
                .any(|a| a.len == 0 || a.position > self.cursor || a.position == 0)
        {
            return Err(());
        }
        if !self.pending.is_empty()
            && RelayItem::decode(&self.pending).map_err(|_| ())?.sequence()
                != self.sent.checked_add(1).ok_or(())?
        {
            return Err(());
        }
        if self.staged.is_empty() {
            if self.applied != 0 || self.staged_after != self.cursor {
                return Err(());
            }
        } else {
            let page = codec::decode_page(&self.staged, self.staged_after, PAGE).map_err(|_| ())?;
            if page.head < self.staged_after
                || self.applied >= page.records.len() as u64
                || self.cursor != self.staged_after.checked_add(self.applied).ok_or(())?
            {
                return Err(());
            }
        }
        Ok(())
    }
    /// Observe the caller clock. A bounded step back is tolerated by keeping
    /// the retained clock; a larger regression is refused as a bogus clock.
    pub fn observe(&mut self, wall: u64) -> Result<u64> {
        if wall
            .checked_add(CLOCK_REGRESSION)
            .is_none_or(|limit| limit < self.wall)
        {
            return Err(());
        }
        self.wall = self.wall.max(wall);
        Ok(self.wall)
    }
    /// Reserve one attempt and its pessimistic byte charge before any network
    /// effect. Returns false when delivery is stopped or deferred.
    pub fn reserve(&mut self, wall: u64, max_bytes: usize) -> Result<bool> {
        self.check()?;
        let wall = self.observe(wall)?;
        if self.stopped() || wall < self.retry_at {
            return Ok(false);
        }
        if self.failures >= MAX_FAILURES {
            self.stop = Stop::Backoff;
            return Ok(false);
        }
        if self.attempts >= ATTEMPTS
            || self
                .wire_bytes
                .checked_add(max_bytes as u64)
                .is_none_or(|v| v > WIRE_BYTES)
        {
            self.stop = Stop::Exhausted;
            return Ok(false);
        }
        self.attempts += 1;
        self.wire_bytes += max_bytes as u64;
        // Reserve the attempt and its backoff before the first network effect.
        // A process loss keeps this charged and never replenishes the budget.
        self.failures += 1;
        self.retry_at = wall
            .checked_add((1u64 << self.failures.min(8)).min(300))
            .ok_or(())?;
        Ok(true)
    }
    /// Charge the exact bytes of a completed exchange instead of its
    /// pessimistic reservation. An interrupted attempt keeps the reservation.
    pub fn settle(&mut self, reserved: usize, actual: usize) {
        if actual < reserved {
            self.wire_bytes = self.wire_bytes.saturating_sub((reserved - actual) as u64);
        }
    }
    pub fn success(&mut self) {
        self.failures = 0;
        self.retry_at = 0;
    }
    /// Explicit reopen with a freshly supplied capability clears only a
    /// transient-failure pause. Spent budgets and refusals remain.
    pub fn resume(&mut self) -> bool {
        if self.stop != Stop::Backoff {
            return false;
        }
        self.stop = Stop::None;
        self.failures = 0;
        self.retry_at = 0;
        true
    }
    pub fn halt(&mut self, detail: u8) {
        self.stop = Stop::Refused;
        self.detail = detail.max(1);
    }
    /// Record one durably refused staged record. Re-recording the same
    /// position is an exact replay of an interrupted page and adds nothing.
    pub fn refuse(&mut self, position: u64, digest: [u8; 32], reason: u8) -> Result<()> {
        if reason == 0 || self.admissions.iter().any(|a| a.position == position) {
            return Err(());
        }
        if let Some(old) = self.refused.iter().find(|r| r.position == position) {
            return if old.digest == digest && old.reason == reason {
                Ok(())
            } else {
                Err(())
            };
        }
        if self.refused.len() == MAX_REFUSED {
            self.refused.remove(0);
        }
        self.refused.push(Refusal {
            position,
            digest,
            reason,
        });
        self.refused_total = self.refused_total.checked_add(1).ok_or(())?;
        Ok(())
    }
    /// Index one retained bootstrap item. Re-retaining the same position with
    /// the same commitment is an exact replay of an interrupted page.
    pub fn admit(&mut self, admission: Admission) -> Result<()> {
        if admission.position == 0 || admission.len == 0 {
            return Err(());
        }
        if let Some(old) = self
            .admissions
            .iter()
            .find(|a| a.position == admission.position)
        {
            return if *old == admission { Ok(()) } else { Err(()) };
        }
        if self.admissions.len() >= MAX_ADMISSIONS
            || self
                .refused
                .iter()
                .any(|r| r.position == admission.position)
        {
            return Err(());
        }
        self.admissions.push(admission);
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.binding);
        out.extend_from_slice(&self.owner);
        for n in [
            self.initial,
            self.sent,
            self.cursor,
            self.attempts,
            self.wire_bytes,
            self.wall,
            self.retry_at,
            self.failures,
            self.retained,
            self.received,
            self.staged_after,
            self.applied,
            self.refused_total,
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.push(self.stop.code());
        out.push(self.detail);
        out.push(self.blocked);
        out.push(self.refused.len() as u8);
        for r in &self.refused {
            out.extend_from_slice(&r.position.to_be_bytes());
            out.extend_from_slice(&r.digest);
            out.push(r.reason);
        }
        out.push(self.admissions.len() as u8);
        for a in &self.admissions {
            out.extend_from_slice(&a.position.to_be_bytes());
            out.push(a.kind);
            out.extend_from_slice(&a.len.to_be_bytes());
            out.extend_from_slice(&a.digest);
        }
        for b in [&self.pending, &self.staged] {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_STATE {
            return Err(());
        }
        if raw.starts_with(MAGIC_V1) {
            return Self::decode_v1(raw);
        }
        if !raw.starts_with(MAGIC) {
            return Err(());
        }
        let mut r = Reader {
            raw,
            at: MAGIC.len(),
        };
        let binding = r.array()?;
        let owner = r.array()?;
        let mut n = [0u64; 13];
        for v in &mut n {
            *v = u64::from_be_bytes(r.array()?);
        }
        let stop = Stop::decode(r.array::<1>()?[0])?;
        let detail = r.array::<1>()?[0];
        let blocked = r.array::<1>()?[0];
        let count = r.array::<1>()?[0] as usize;
        if count > MAX_REFUSED {
            return Err(());
        }
        let mut refused = Vec::with_capacity(count);
        for _ in 0..count {
            refused.push(Refusal {
                position: u64::from_be_bytes(r.array()?),
                digest: r.array()?,
                reason: r.array::<1>()?[0],
            });
        }
        let count = r.array::<1>()?[0] as usize;
        if count > MAX_ADMISSIONS {
            return Err(());
        }
        let mut admissions = Vec::with_capacity(count);
        for _ in 0..count {
            admissions.push(Admission {
                position: u64::from_be_bytes(r.array()?),
                kind: r.array::<1>()?[0],
                len: u32::from_be_bytes(r.array()?),
                digest: r.array()?,
            });
        }
        let pending = r.blob(MAX_PENDING)?;
        let staged = r.blob(codec::MAX_PAGE_BODY)?;
        if r.at != raw.len() {
            return Err(());
        }
        let out = Self {
            binding,
            owner,
            initial: n[0],
            sent: n[1],
            cursor: n[2],
            attempts: n[3],
            wire_bytes: n[4],
            wall: n[5],
            retry_at: n[6],
            failures: n[7],
            retained: n[8],
            received: n[9],
            staged_after: n[10],
            applied: n[11],
            refused_total: n[12],
            stop,
            detail,
            blocked,
            refused,
            admissions,
            pending,
            staged,
        };
        out.check()?;
        Ok(out)
    }
    /// A version-1 image recorded only a stop flag. Its reason cannot be
    /// recovered, so a stopped image stays stopped as a retained refusal.
    fn decode_v1(raw: &[u8]) -> Result<Self> {
        let mut r = Reader {
            raw,
            at: MAGIC_V1.len(),
        };
        let binding = r.array()?;
        let owner = r.array()?;
        let mut n = [0u64; 12];
        for v in &mut n {
            *v = u64::from_be_bytes(r.array()?);
        }
        let stopped = match r.array::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err(()),
        };
        let pending = r.blob(MAX_PENDING)?;
        let staged = r.blob(codec::MAX_PAGE_BODY)?;
        if r.at != raw.len() {
            return Err(());
        }
        let out = Self {
            binding,
            owner,
            initial: n[0],
            sent: n[1],
            cursor: n[2],
            attempts: n[3],
            wire_bytes: n[4],
            wall: n[5],
            retry_at: n[6],
            failures: n[7],
            retained: n[8],
            received: n[9],
            staged_after: n[10],
            applied: n[11],
            refused_total: 0,
            stop: if stopped { Stop::Refused } else { Stop::None },
            detail: if stopped { halt::LEGACY } else { 0 },
            blocked: 0,
            refused: Vec::new(),
            admissions: Vec::new(),
            pending,
            staged,
        };
        out.check()?;
        Ok(out)
    }
}
struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.at.checked_add(N).ok_or(())?;
        let v = self
            .raw
            .get(self.at..end)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        self.at = end;
        Ok(v)
    }
    fn blob(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > max {
            return Err(());
        }
        let end = self.at.checked_add(len).ok_or(())?;
        let v = self.raw.get(self.at..end).ok_or(())?.to_vec();
        self.at = end;
        Ok(v)
    }
}
