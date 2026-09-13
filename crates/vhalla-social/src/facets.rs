//! Signed exact-revision annotations. Display labels confer no identity or authority.
use crate::model::{AgentId, Error, OwnerId, Text};
use alloc::{collections::BTreeSet, string::String, vec::Vec};

/// Maximum combined signed annotations on one exact revision.
pub const MAX_FACETS: usize = 16;
/// Maximum distinct typed mention targets on one exact revision.
pub const MAX_MENTION_TARGETS: usize = 8;
/// Maximum distinct canonical tags on one exact revision.
pub const MAX_TAGS: usize = 8;
/// Maximum ASCII bytes in a canonical tag, excluding the visible hash sign.
pub const MAX_TAG_BYTES: usize = 48;

/// Immutable typed reference; existence and historical ownership require a view.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MentionTarget {
    /// Durable owner genesis identity.
    Owner(OwnerId),
    /// Exact owner-bound agent incarnation.
    Agent(AgentId),
}
/// Canonical ASCII topic key, independent from general Unicode fulltext search.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalTag(String);
impl CanonicalTag {
    /// Normalize locally authored ASCII case; reject invalid grammar or length.
    /// Grammar: `[a-z0-9_][a-z0-9_-]{0,47}` after ASCII-only lowercase.
    pub fn new(input: &str) -> Result<Self, Error> {
        let bytes = input.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_TAG_BYTES
            || (!bytes[0].is_ascii_alphanumeric() && bytes[0] != b'_')
            || bytes
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && *b != b'_' && *b != b'-')
        {
            return Err(Error::Encoding);
        }
        Ok(Self(input.to_ascii_lowercase()))
    }
    /// Borrow the normalized lowercase ASCII key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub(crate) fn canonical(input: &str) -> Result<Self, Error> {
        let tag = Self::new(input)?;
        if tag.as_str() != input {
            return Err(Error::Encoding);
        }
        Ok(tag)
    }
}
/// Meaning of a signed text span. Neither variant authorizes host effects.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FacetKind {
    /// Immutable recipient reference; the visible token remains untrusted.
    Mention(MentionTarget),
    /// Canonical topic matching this exact span's visible hash-prefixed text.
    Tag(CanonicalTag),
}
/// Locally assembled span; meaningful only after binding to validated text.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Facet {
    /// Inclusive UTF-8 byte boundary.
    pub start: u16,
    /// Exclusive UTF-8 byte boundary.
    pub end: u16,
    /// Typed reference or canonical topic.
    pub kind: FacetKind,
}
/// Validated text and immutable exact-revision facets, signed as a unit.
///
/// ```compile_fail
/// use vhalla_social::FacetedText;
/// fn alter(value: &mut FacetedText) { value.facets.clear(); }
/// ```
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FacetedText {
    text: Text,
    facets: Vec<Facet>,
}
impl FacetedText {
    /// Validate canonical order and UTF-8 spans before retaining the annotation set.
    /// Empty sets remove earlier annotations on this exact revision. Labels use
    /// fixed ASCII guards, never compiler-version Unicode normalization tables.
    pub fn new(text: Text, facets: Vec<Facet>) -> Result<Self, Error> {
        if facets.len() > MAX_FACETS {
            return Err(Error::Bounds);
        }
        let mut end = 0;
        let mut recipients = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for facet in &facets {
            let start = usize::from(facet.start);
            let next = usize::from(facet.end);
            if start < end || start >= next {
                return Err(Error::Encoding);
            }
            let label = text.as_str().get(start..next).ok_or(Error::Encoding)?;
            match &facet.kind {
                FacetKind::Mention(target) => {
                    if !label.starts_with('@')
                        || label.len() < 2
                        || label.bytes().any(|b| b <= 0x20 || b == 0x7f)
                    {
                        return Err(Error::Encoding);
                    }
                    recipients.insert(target);
                }
                FacetKind::Tag(tag) => {
                    let display = label.strip_prefix('#').ok_or(Error::Encoding)?;
                    if CanonicalTag::new(display)? != *tag {
                        return Err(Error::Encoding);
                    }
                    tags.insert(tag);
                }
            }
            end = next;
        }
        if recipients.len() > MAX_MENTION_TARGETS || tags.len() > MAX_TAGS {
            return Err(Error::Bounds);
        }
        Ok(Self { text, facets })
    }
    /// Exact untrusted post text.
    #[must_use]
    pub const fn text(&self) -> &Text {
        &self.text
    }
    /// Immutable annotations for this text only; never inherited from an ancestor.
    #[must_use]
    pub fn facets(&self) -> &[Facet] {
        &self.facets
    }
}
