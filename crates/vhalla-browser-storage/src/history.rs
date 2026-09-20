//! Opaque append-only certified-history framing.
//!
//! These are storage metadata, not verification tokens. The controller prepares a
//! CertifiedClient candidate before append, and re-verifies every retained bundle
//! against an independently selected bootstrap pin before using it after reopen.

use crate::Error;

/// Storage ceiling for an independently verified bootstrap response.
pub const MAX_HISTORY_BOOTSTRAP_BYTES: usize = 40 * 1024 * 1024;
/// Current journal bundle ceiling: six 64KiB fields plus canonical framing.
pub const MAX_HISTORY_BUNDLE_BYTES: usize = 6 * 64 * 1024 + 148;
/// Maximum records returned by one bounded history read.
pub const MAX_HISTORY_PAGE_RECORDS: usize = 16;
/// Maximum encoded record bytes returned by one bounded history read.
pub const MAX_HISTORY_PAGE_BYTES: usize = 2 * 1024 * 1024;
const HEAD_MAGIC: &[u8; 8] = b"VHBHED01";
const RECORD_MAGIC: &[u8; 8] = b"VHBHRC01";
const HEAD_BYTES: usize = 8 + 64 + 8 + 4 * 32 + 8 + 32;
const RECORD_HEADER_BYTES: usize = 8 + 2 * HEAD_BYTES + 4;
/// Maximum framed immutable history record bytes.
pub const MAX_HISTORY_RECORD_BYTES: usize = RECORD_HEADER_BYTES + MAX_HISTORY_BUNDLE_BYTES;

/// Exact network and complete bootstrap pin inside one host-selected profile.
/// Supplying these identifiers does not establish trust in either one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryScope {
    network: [u8; 32],
    bootstrap: [u8; 32],
}
impl HistoryScope {
    /// Use the controller's independently selected network/configuration scope.
    #[must_use]
    pub const fn new(network: [u8; 32], bootstrap_pin: [u8; 32]) -> Self {
        Self {
            network,
            bootstrap: bootstrap_pin,
        }
    }
    /// Full network identifier.
    #[must_use]
    pub const fn network(self) -> [u8; 32] {
        self.network
    }
    /// Independently selected full configuration pin.
    #[must_use]
    pub const fn bootstrap_pin(self) -> [u8; 32] {
        self.bootstrap
    }
}

/// Complete frontier metadata. Every field remains untrusted on storage read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryFrontier {
    /// Full consensus height; never represented by a JavaScript Number key.
    pub height: u64,
    /// Decided application value identifier.
    pub value: [u8; 32],
    /// Room registry commitment.
    pub registry: [u8; 32],
    /// Social archive commitment.
    pub social: [u8; 32],
    /// Control snapshot commitment.
    pub control: [u8; 32],
    /// Agreed application clock.
    pub time: u64,
}

/// Canonical exact-CAS head metadata, not proof of a certified frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryHead {
    scope: HistoryScope,
    frontier: HistoryFrontier,
    bundle: [u8; 32],
}
impl HistoryHead {
    /// Frame controller-supplied metadata. Height zero has no retained bundle.
    pub fn new(
        scope: HistoryScope,
        frontier: HistoryFrontier,
        bundle_id: [u8; 32],
    ) -> Result<Self, Error> {
        if frontier.height == 0 && bundle_id != [0; 32] {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            scope,
            frontier,
            bundle: bundle_id,
        })
    }
    /// Exact scope.
    #[must_use]
    pub const fn scope(self) -> HistoryScope {
        self.scope
    }
    /// Unverified full frontier metadata.
    #[must_use]
    pub const fn frontier(self) -> HistoryFrontier {
        self.frontier
    }
    /// Claimed bundle identifier; re-verification must compare it to the bundle.
    #[must_use]
    pub const fn bundle_id(self) -> [u8; 32] {
        self.bundle
    }
    /// Canonical bytes used by transaction-local compare-and-swap.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_BYTES);
        out.extend_from_slice(HEAD_MAGIC);
        out.extend_from_slice(&self.scope.network);
        out.extend_from_slice(&self.scope.bootstrap);
        out.extend_from_slice(&self.frontier.height.to_be_bytes());
        out.extend_from_slice(&self.frontier.value);
        out.extend_from_slice(&self.frontier.registry);
        out.extend_from_slice(&self.frontier.social);
        out.extend_from_slice(&self.frontier.control);
        out.extend_from_slice(&self.frontier.time.to_be_bytes());
        out.extend_from_slice(&self.bundle);
        out
    }
    /// Parse exact canonical framing only. This does not verify commitments.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() != HEAD_BYTES {
            return Err(Error::Corrupt);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != HEAD_MAGIC {
            return Err(Error::Corrupt);
        }
        let scope = HistoryScope::new(input.array()?, input.array()?);
        let frontier = HistoryFrontier {
            height: u64::from_be_bytes(input.array()?),
            value: input.array()?,
            registry: input.array()?,
            social: input.array()?,
            control: input.array()?,
            time: u64::from_be_bytes(input.array()?),
        };
        Self::new(scope, frontier, input.array()?)
    }
}

/// One immutable bounded bundle plus its complete before/after metadata.
/// Framing cannot prove that bundle bytes actually implement the claimed change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRecord {
    base: HistoryHead,
    head: HistoryHead,
    bytes: Vec<u8>,
}
impl HistoryRecord {
    /// Require exact scope and the next full height, then retain bounded bytes.
    pub fn new(base: HistoryHead, next: HistoryHead, bundle: &[u8]) -> Result<Self, Error> {
        if base.scope != next.scope {
            return Err(Error::WrongScope);
        }
        if base.frontier.height.checked_add(1) != Some(next.frontier.height) {
            return Err(Error::Corrupt);
        }
        if bundle.is_empty() || bundle.len() > MAX_HISTORY_BUNDLE_BYTES {
            return Err(Error::Bounds);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(RECORD_HEADER_BYTES + bundle.len())
            .map_err(|_| Error::Bounds)?;
        bytes.extend_from_slice(RECORD_MAGIC);
        bytes.extend_from_slice(&base.encode());
        bytes.extend_from_slice(&next.encode());
        bytes.extend_from_slice(&(bundle.len() as u32).to_be_bytes());
        bytes.extend_from_slice(bundle);
        Ok(Self {
            base,
            head: next,
            bytes,
        })
    }
    /// Parse bounded exact framing without accepting signatures or authority.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_HISTORY_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        let mut input = Reader(raw);
        if &input.array::<8>()? != RECORD_MAGIC {
            return Err(Error::Corrupt);
        }
        let base = HistoryHead::decode(input.take(HEAD_BYTES)?)?;
        let head = HistoryHead::decode(input.take(HEAD_BYTES)?)?;
        let length = u32::from_be_bytes(input.array()?) as usize;
        let bundle = input.take(length)?;
        if !input.0.is_empty() {
            return Err(Error::Corrupt);
        }
        Self::new(base, head, bundle)
    }
    /// Exact expected prior head.
    #[must_use]
    pub const fn base(&self) -> HistoryHead {
        self.base
    }
    /// Proposed next head, still not a durable receipt.
    #[must_use]
    pub const fn head(&self) -> HistoryHead {
        self.head
    }
    /// Exact bounded opaque bundle bytes for domain re-verification.
    #[must_use]
    pub fn bundle_bytes(&self) -> &[u8] {
        &self.bytes[RECORD_HEADER_BYTES..]
    }
    /// Canonical immutable storage record.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A transaction-consistent bounded page. All metadata and bytes need replay.
#[derive(Debug)]
pub struct HistoryPage {
    /// Head observed in the same read transaction as these records.
    pub head: HistoryHead,
    /// Contiguous retained heights, never above the observed head.
    pub records: Vec<HistoryRecord>,
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::Corrupt);
        }
        let (value, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt)
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn append_check(
    scope: HistoryScope,
    observed: Option<&[u8]>,
    expected: &HistoryHead,
    record: &HistoryRecord,
) -> Result<(), Error> {
    if expected.scope != scope || record.head.scope != scope {
        return Err(Error::WrongScope);
    }
    if record.base != *expected {
        return Err(Error::Stale);
    }
    crate::compare_exact(Some(&expected.encode()), observed)
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn page_bounds(start: u64, limit: usize, byte_budget: usize) -> Result<(), Error> {
    if start == 0
        || limit == 0
        || limit > MAX_HISTORY_PAGE_RECORDS
        || byte_budget == 0
        || byte_budget > MAX_HISTORY_PAGE_BYTES
    {
        return Err(Error::Bounds);
    }
    Ok(())
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn prefix(scope: HistoryScope) -> String {
    let hex = |raw: &[u8]| raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!(
        "history/v1/{}/{}/",
        hex(&scope.network),
        hex(&scope.bootstrap)
    )
}
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn record_key(scope: HistoryScope, height: u64) -> String {
    format!("{}height/{height:016x}", prefix(scope))
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn page_record(
    page: &HistoryPage,
    height: u64,
    raw: &[u8],
) -> Result<HistoryRecord, Error> {
    let record = HistoryRecord::decode(raw)?;
    if record.head().scope() != page.head.scope() {
        return Err(Error::WrongScope);
    }
    if height > page.head.frontier().height
        || record.head().frontier().height != height
        || page
            .records
            .last()
            .is_some_and(|previous| previous.head() != record.base())
        || (height == page.head.frontier().height && record.head() != page.head)
    {
        return Err(Error::Corrupt);
    }
    Ok(record)
}

#[cfg(test)]
mod tests;
