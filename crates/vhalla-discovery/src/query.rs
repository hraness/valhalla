//! Literal, bounded, portable text matching. No regex or executable expression.
use crate::{Error, MAX_DOCUMENTS};
use alloc::{string::String, vec::Vec};
use vhalla_core::RoomId;
use vhalla_social::{view::RecordState, AgentId, MentionTarget, OwnerId, RecordId};

/// Original parsed query; only private constructors may establish its bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    raw: String,
    terms: Vec<String>,
}
impl Query {
    /// Parse literal AND terms/quoted phrases, ASCII whitespace outside quotes,
    /// no escaping; non-ASCII text matches exact bytes with no normalization.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() > 256 {
            return Err(Error::Bounds);
        }
        let b = input.as_bytes();
        let mut i = 0;
        let mut terms = Vec::new();
        while i < b.len() {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == b.len() {
                break;
            }
            let quoted = b[i] == b'"';
            if quoted {
                i += 1;
            }
            let start = i;
            while i < b.len()
                && if quoted {
                    b[i] != b'"'
                } else {
                    !b[i].is_ascii_whitespace()
                }
            {
                if b[i] == b'\\' || !quoted && b[i] == b'"' {
                    return Err(Error::Encoding);
                }
                i += 1;
            }
            if quoted && i == b.len() || i == start {
                return Err(Error::Encoding);
            }
            if i - start > 96 || terms.len() == 8 {
                return Err(Error::Bounds);
            }
            terms.push(String::from(&input[start..i]));
            if quoted {
                i += 1;
                if i < b.len() && !b[i].is_ascii_whitespace() {
                    return Err(Error::Encoding);
                }
            }
        }
        Ok(Self {
            raw: String::from(input),
            terms,
        })
    }
    /// Exact bounded source query, including literal phrase whitespace.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
    /// Parsed literal terms.
    pub fn terms(&self) -> &[String] {
        &self.terms
    }
    pub(crate) fn matches(&self, text: &str, budget: &mut Budget) -> Result<bool, Error> {
        for term in &self.terms {
            if term.len() > text.len() {
                return Ok(false);
            }
            let mut found = false;
            for window in text.as_bytes().windows(term.len()) {
                let mut equal = true;
                for (a, b) in window.iter().zip(term.as_bytes()) {
                    budget.charge_steps(1)?;
                    if !a.eq_ignore_ascii_case(b) {
                        equal = false;
                        break;
                    }
                }
                if equal {
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Explicit typed metadata filters, validated again by each query.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Filters {
    /// Explicit committed/provisional filter. Other states are rejected because
    /// they are not admitted discovery documents.
    pub state: Option<RecordState>,
    /// Exact surface kind. Post/reply mean current originals; Repost means
    /// an admitted exact endorsement path, possibly to superseded content.
    pub kind: Option<Kind>,
    /// Original admitted owner, never a display label or reposter.
    pub owner: Option<OwnerId>,
    /// Exact admitted original agent incarnation.
    pub agent: Option<AgentId>,
    /// Realm-local channel placement.
    pub channel: Option<RoomId>,
    /// Exact conversation root.
    pub root: Option<RecordId>,
    /// Exact canonical signed tag, no lexical inference from legacy text.
    pub tag: Option<String>,
    /// Owner/agent distinction is part of the identity.
    pub mention: Option<MentionTarget>,
    /// Include only replies (true) or roots (false); None includes both.
    pub reply: Option<bool>,
    /// Include only rows reached by admitted reposts, retaining original authors.
    pub repost_only: bool,
}
/// Explicit discovery surface kind, not a heuristic from text or a tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Current original root, even when also reposted.
    Post,
    /// Current original reply, even when also reposted.
    Reply,
    /// Exact admitted repost path with original attribution.
    Repost,
}
impl Filters {
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self
            .state
            .is_some_and(|s| !matches!(s, RecordState::Committed | RecordState::Provisional))
        {
            return Err(Error::Bounds);
        }
        if let Some(tag) = &self.tag {
            crate::state::valid_tag(tag)?;
        }
        Ok(())
    }
}

/// Per-query work policy. Construction/view evaluation has separate fixed caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    /// Remaining examined documents, including filtered and unsuccessful rows.
    pub documents: usize,
    /// Remaining examined text bytes, including unsuccessful rows.
    pub bytes: usize,
    /// Remaining literal-byte comparisons and conservative metadata/scoring work.
    pub steps: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            documents: MAX_DOCUMENTS,
            bytes: 16 * 1024 * 1024,
            steps: 16 * 1024 * 1024,
        }
    }
}
impl Budget {
    /// Compact caller policy; overflow never silently falls back to a larger scan.
    pub const fn compact() -> Self {
        Self {
            documents: 256,
            bytes: 256 * 1024,
            steps: 1024 * 1024,
        }
    }
    pub(crate) fn check(self) -> Result<(), Error> {
        if self.documents > MAX_DOCUMENTS
            || self.bytes > 16 * 1024 * 1024
            || self.steps > 64 * 1024 * 1024
        {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }
    pub(crate) fn document(&mut self, bytes: usize, metadata: usize) -> Result<(), Error> {
        if self.documents == 0 || bytes > self.bytes || metadata > self.steps {
            return Err(Error::Budget);
        }
        self.documents -= 1;
        self.bytes -= bytes;
        self.steps -= metadata;
        Ok(())
    }
    pub(crate) fn charge_steps(&mut self, n: usize) -> Result<(), Error> {
        if n > self.steps {
            return Err(Error::Budget);
        }
        self.steps -= n;
        Ok(())
    }
}
