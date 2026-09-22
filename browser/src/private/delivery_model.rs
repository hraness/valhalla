//! Bounded durable delivery progress; credentials never enter this encoding.
use vhalla_private_relay::{codec, RelayItem};
const MAGIC: &[u8] = b"VHBRDEL\x01";
pub(crate) const ATTEMPTS: u64 = 4096;
pub(crate) const WIRE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const PAGE: usize = 4;
pub(crate) const MAX_PENDING: usize = codec::MAX_REQUEST;
pub(crate) const MAX_STATE: usize = codec::MAX_PAGE_BODY + MAX_PENDING + 512;
pub(crate) type Result<T> = core::result::Result<T, ()>;

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
    pub stopped: bool,
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
            stopped: false,
            pending: Vec::new(),
            staged: Vec::new(),
            staged_after: initial,
            applied: 0,
        }
    }
    pub fn check(&self) -> Result<()> {
        if self.binding == [0; 32]
            || self.owner == [0; 16]
            || self.initial > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || self.cursor > vhalla_private_relay::MAX_RELAY_ITEMS as u64
            || self.cursor < self.initial
            || self.attempts > ATTEMPTS
            || self.wire_bytes > WIRE_BYTES
            || self.failures > 10
            || self.pending.len() > MAX_PENDING
            || self.staged.len() > codec::MAX_PAGE_BODY
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
    pub fn reserve(&mut self, wall: u64, max_bytes: usize) -> Result<bool> {
        self.check()?;
        if wall < self.wall {
            return Err(());
        }
        self.wall = wall;
        if self.stopped || wall < self.retry_at {
            return Ok(false);
        }
        if self.failures == 10
            || self.attempts == ATTEMPTS
            || self
                .wire_bytes
                .checked_add(max_bytes as u64)
                .is_none_or(|v| v > WIRE_BYTES)
        {
            self.stopped = true;
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
    pub fn success(&mut self) {
        self.failures = 0;
        self.retry_at = 0;
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
        ] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.push(u8::from(self.stopped));
        for b in [&self.pending, &self.staged] {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_STATE || !raw.starts_with(MAGIC) {
            return Err(());
        }
        let mut r = Reader {
            raw,
            at: MAGIC.len(),
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
            stopped,
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
