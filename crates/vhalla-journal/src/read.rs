//! Side-effect-free indexed reads below one observed published HEAD.
//!
//! This is journal structure validation, not certificate verification or proof
//! of global freshness. Readers never recover, repair, enumerate, lock or create
//! directories. The committed history must remain immutable while readers run.

use super::{Bundle, Journal, JournalError, Pin, Store, MAX_BUNDLE_BYTES, ZERO};
use std::fmt;

/// Maximum returned bundles in one published-range read.
pub const MAX_PUBLISHED_PAGE_BUNDLES: usize = 32;
/// Maximum sum of serialized bundle bytes returned in one page.
pub const MAX_PUBLISHED_PAGE_BYTES: usize = 2 * 1024 * 1024;

/// Explicit bounded continuation request; no caller-supplied path is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedRange {
    /// Last height already known to the caller; zero starts at genesis.
    pub after_height: u64,
    /// Optional complete frontier expected before the first returned bundle.
    /// Height zero is always anchored to the journal's configured genesis.
    pub expected_predecessor: Option<[u8; 32]>,
    /// Nonzero returned bundle limit, at most MAX_PUBLISHED_PAGE_BUNDLES.
    pub max_bundles: usize,
    /// Nonzero returned payload limit, at most MAX_PUBLISHED_PAGE_BYTES.
    pub max_bytes: usize,
}

/// A page under a single observed, locally published pin.
///
/// The pin describes one peer's publication, not a certificate or latest global
/// state. The caller still verifies consensus certificates and application
/// replay. Only the tip and requested contiguous range were read, not all
/// intervening history outside that range.
#[derive(Debug)]
pub struct PublishedPage {
    head: Pin,
    bundles: Vec<Bundle>,
    bytes: usize,
    next_after: u64,
}

impl PublishedPage {
    /// HEAD snapshot taken once before any indexed bundle reads.
    pub const fn observed_head(&self) -> Pin {
        self.head
    }
    /// Exact contiguous bundles in ascending height order.
    pub fn bundles(&self) -> &[Bundle] {
        &self.bundles
    }
    /// Move the bounded bundles into the serving adapter.
    pub fn into_bundles(self) -> Vec<Bundle> {
        self.bundles
    }
    /// Sum of canonical serialized bytes in bundles().
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
    /// Last returned height, or the requested cursor for an empty page.
    pub const fn next_after(&self) -> u64 {
        self.next_after
    }
    /// Whether more heights exist below this same observed local HEAD.
    pub const fn has_more(&self) -> bool {
        self.next_after < self.head.height
    }
}

/// Read-only failure; no failure triggers recovery or storage mutation.
#[derive(Debug)]
pub enum PublishedReadError {
    /// Caller count/byte limits are zero or exceed the hard ceilings.
    Limits,
    /// The requested cursor is beyond this peer's observed published height.
    CursorAhead {
        /// Caller-provided last known height.
        requested: u64,
        /// Height in the one observed HEAD snapshot.
        observed: u64,
    },
    /// No bundle fits the requested byte budget; increase it within the ceiling.
    BudgetTooSmall {
        /// Canonical byte length of the first required bundle.
        required: usize,
    },
    /// HEAD, its tip bundle or its height marker disagree.
    CorruptHead,
    /// A marker or bundle at a requested published height is absent.
    MissingHeight {
        /// First missing height; no partial page is returned.
        height: u64,
    },
    /// An indexed bundle has the wrong height or breaks predecessor continuity.
    Discontinuous {
        /// First inconsistent requested height.
        height: u64,
    },
    /// The supplied complete frontier does not match the first predecessor.
    FrontierMismatch {
        /// Height of the first expected bundle (or cursor when already at HEAD).
        height: u64,
    },
    /// A bounded store read, content-id verification or canonical decode failed.
    Journal(JournalError),
}

impl fmt::Display for PublishedReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits => write!(f, "published read limits exceeded"),
            Self::CursorAhead {
                requested,
                observed,
            } => write!(f, "cursor {requested} is beyond observed head {observed}"),
            Self::BudgetTooSmall { required } => {
                write!(f, "first bundle requires {required} bytes")
            }
            Self::CorruptHead => write!(f, "published head is inconsistent"),
            Self::MissingHeight { height } => write!(f, "missing published height {height}"),
            Self::Discontinuous { height } => write!(f, "discontinuous published height {height}"),
            Self::FrontierMismatch { height } => write!(f, "frontier mismatch at height {height}"),
            Self::Journal(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PublishedReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<JournalError> for PublishedReadError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl<S: Store> Journal<S> {
    /// Read a bounded contiguous page below a single published HEAD snapshot.
    ///
    /// Performs one pin read, validates its tip and marker, then reads only exact
    /// height indexes. It does not call recover(), list methods, locks, writes,
    /// directory creation, deletion or repair. Missing HEAD means configured
    /// genesis even if unpublished bundles/markers/temporary pins are present.
    ///
    /// max_bytes limits returned bytes. Bounded additional work includes one
    /// tip read and at most one lookahead bundle that does not fit the page.
    /// Each is at most MAX_BUNDLE_BYTES; decoder scratch is likewise bounded.
    /// Custom Store implementations must enforce the Store read-size contract.
    ///
    /// If the page reaches HEAD, its final frontier must match that pin. If it
    /// stops earlier, certificates/application replay remain the caller's trust
    /// boundary. A changing HEAD after the snapshot does not expand this page.
    pub fn read_published_range(
        &self,
        request: PublishedRange,
    ) -> Result<PublishedPage, PublishedReadError> {
        if request.max_bundles == 0
            || request.max_bundles > MAX_PUBLISHED_PAGE_BUNDLES
            || request.max_bytes == 0
            || request.max_bytes > MAX_PUBLISHED_PAGE_BYTES
        {
            return Err(PublishedReadError::Limits);
        }
        let (head, mut tip) = self.published_tip()?;
        if request.after_height > head.height {
            return Err(PublishedReadError::CursorAhead {
                requested: request.after_height,
                observed: head.height,
            });
        }
        let mut expected = request.expected_predecessor;
        if request.after_height == 0 {
            let genesis = self.genesis().next;
            if expected.is_some_and(|frontier| frontier != genesis) {
                return Err(PublishedReadError::FrontierMismatch { height: 1 });
            }
            expected = Some(genesis);
        }
        if request.after_height == head.height
            && expected.is_some_and(|frontier| frontier != head.next)
        {
            return Err(PublishedReadError::FrontierMismatch {
                height: head.height,
            });
        }
        let mut page = PublishedPage {
            head,
            bundles: Vec::with_capacity(request.max_bundles),
            bytes: 0,
            next_after: request.after_height,
        };
        while page.next_after < head.height && page.bundles.len() < request.max_bundles {
            let height = page
                .next_after
                .checked_add(1)
                .ok_or(PublishedReadError::Limits)?;
            let bundle = if height == head.height {
                tip.take().ok_or(PublishedReadError::CorruptHead)?
            } else {
                self.published_bundle(height)?
            };
            if let Some(frontier) = expected {
                if bundle.predecessor() != frontier {
                    return Err(if page.bundles.is_empty() {
                        PublishedReadError::FrontierMismatch { height }
                    } else {
                        PublishedReadError::Discontinuous { height }
                    });
                }
            }
            if bundle.len() > request.max_bytes - page.bytes {
                if page.bundles.is_empty() {
                    return Err(PublishedReadError::BudgetTooSmall {
                        required: bundle.len(),
                    });
                }
                break;
            }
            page.bytes += bundle.len();
            expected = Some(bundle.next());
            page.next_after = height;
            page.bundles.push(bundle);
        }
        Ok(page)
    }

    fn published_tip(&self) -> Result<(Pin, Option<Bundle>), PublishedReadError> {
        let Some(raw) = self.store.read_pin(&self.dir)? else {
            return Ok((self.genesis(), None));
        };
        let head = Pin::decode(&raw)?;
        if head.height == 0 {
            if head != self.genesis() {
                return Err(PublishedReadError::CorruptHead);
            }
            return Ok((head, None));
        }
        if head.bundle == ZERO
            || self.store.read_height_marker(&self.dir, head.height)? != Some(head.bundle)
        {
            return Err(PublishedReadError::CorruptHead);
        }
        let tip = self
            .bundle(head.bundle)?
            .ok_or(PublishedReadError::CorruptHead)?;
        if tip.height() != head.height
            || tip.predecessor() != head.predecessor
            || tip.next() != head.next
            || tip.len() > MAX_BUNDLE_BYTES
        {
            return Err(PublishedReadError::CorruptHead);
        }
        Ok((head, Some(tip)))
    }

    fn published_bundle(&self, height: u64) -> Result<Bundle, PublishedReadError> {
        let id = self
            .at_height(height)?
            .ok_or(PublishedReadError::MissingHeight { height })?;
        let bundle = self
            .bundle(id)?
            .ok_or(PublishedReadError::MissingHeight { height })?;
        if bundle.height() != height {
            return Err(PublishedReadError::Discontinuous { height });
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests;
