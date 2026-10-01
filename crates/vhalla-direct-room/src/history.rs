use crate::{AuthorHead, ClosedPolicy, Error, EventId, PolicyId, RoomId, SealHead, VerifiedEvent};
use alloc::boxed::Box;

/// Maximum verified frames consumed atomically by one proof page.
pub const MAX_CHAIN_PAGE: usize = 32;

/// A closed policy either excludes a frame or requires exact ancestry proof.
#[derive(Clone, Debug)]
pub enum HistoryRequirement {
    /// Retain signed bytes for continuity; do not display them as an admitted post.
    ContinuityOnly,
    /// Numeric sequence bounds passed; hash ancestry still must be proved.
    Verify(Box<SealedHistoryVerifier>),
}

impl ClosedPolicy {
    /// Determine the proof needed under this event's own immutable policy seal.
    pub fn history_requirement(
        &self,
        candidate: VerifiedEvent,
    ) -> Result<HistoryRequirement, Error> {
        let claims = candidate.claims();
        if claims.room != self.room {
            return Err(Error::Scope);
        }
        if claims.policy != self.policy {
            return Err(Error::Policy);
        }
        if self.writers.binary_search(&claims.author).is_err() {
            return Ok(HistoryRequirement::ContinuityOnly);
        }
        let Ok(index) = self
            .seals
            .binary_search_by_key(&claims.author, |seal| seal.author)
        else {
            return Ok(HistoryRequirement::ContinuityOnly);
        };
        let seal = self.seals[index];
        if claims.sequence > seal.sequence {
            return Ok(HistoryRequirement::ContinuityOnly);
        }
        Ok(HistoryRequirement::Verify(Box::new(
            SealedHistoryVerifier {
                room: self.room,
                policy: self.policy,
                closing_policy: self.closing_policy,
                seal,
                candidate,
                head: AuthorHead::EMPTY,
                encountered: false,
                terminal_policy: None,
            },
        )))
    }
}

/// Constant-memory proof of exact signed ancestry from sequence one to an owner seal.
/// Frames naming other policies prove continuity only; this proof cannot endorse
/// their content under the candidate's policy.
#[derive(Clone, Debug)]
pub struct SealedHistoryVerifier {
    room: RoomId,
    policy: PolicyId,
    closing_policy: PolicyId,
    seal: SealHead,
    candidate: VerifiedEvent,
    head: AuthorHead,
    encountered: bool,
    terminal_policy: Option<PolicyId>,
}
impl SealedHistoryVerifier {
    /// Apply one nonempty bounded contiguous page. A failed page does not advance
    /// any proof state, so the caller can retry the original page exactly.
    pub fn push(&mut self, page: &[VerifiedEvent]) -> Result<(), Error> {
        if page.is_empty() || page.len() > MAX_CHAIN_PAGE {
            return Err(Error::Bounds);
        }
        let mut next = self.clone();
        for event in page {
            let claims = event.claims();
            if claims.room != next.room {
                return Err(Error::Scope);
            }
            if claims.author != next.seal.author {
                return Err(Error::Author);
            }
            if claims.sequence > next.seal.sequence {
                return Err(Error::Bounds);
            }
            if claims.sequence != next.head.sequence.checked_add(1).ok_or(Error::Exhausted)? {
                return Err(Error::Gap);
            }
            if claims.previous != next.head.event {
                return Err(Error::Fork);
            }
            if claims.sequence == next.candidate.claims().sequence {
                if event.id() != next.candidate.id() {
                    return Err(Error::Fork);
                }
                next.encountered = true;
            }
            next.head = AuthorHead {
                sequence: claims.sequence,
                event: event.id(),
            };
            if claims.sequence == next.seal.sequence {
                if event.id() != next.seal.event {
                    return Err(Error::Fork);
                }
                if claims.policy != next.policy {
                    return Err(Error::Policy);
                }
                next.terminal_policy = Some(claims.policy);
            }
        }
        *self = next;
        Ok(())
    }
    /// Finish only after reaching the exact sealed terminal through the candidate.
    pub fn finish(self) -> Result<VerifiedHistoricalEvent, Error> {
        if !self.encountered
            || self.head.sequence != self.seal.sequence
            || self.head.event != self.seal.event
            || self.terminal_policy != Some(self.policy)
        {
            return Err(Error::Gap);
        }
        Ok(VerifiedHistoricalEvent {
            event: self.candidate,
            closing_policy: self.closing_policy,
        })
    }
    /// Progress is a local verified position, never a remote completeness assertion.
    pub const fn head(&self) -> AuthorHead {
        self.head
    }
    /// Exact target the caller must reach before claiming this history verified.
    pub const fn target(&self) -> (u64, EventId) {
        (self.seal.sequence, self.seal.event)
    }
}

/// One historical event whose exact ancestry is endorsed by its owner-policy seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHistoricalEvent {
    event: VerifiedEvent,
    closing_policy: PolicyId,
}
impl VerifiedHistoricalEvent {
    /// Authenticated admitted historical message.
    pub const fn event(&self) -> &VerifiedEvent {
        &self.event
    }
    /// Owner update carrying the immutable boundary used by this proof.
    pub const fn closing_policy(&self) -> PolicyId {
        self.closing_policy
    }
}
