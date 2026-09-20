use super::*;

/// A peer's claimed locally observed certified checkpoint. A digest alone is not
/// a certificate or proof that this is the newest global checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observed {
    /// Locally observed height; zero is genesis.
    pub height: u64,
    /// Complete frontier commitment at that height.
    pub frontier: [u8; 32],
}
impl Observed {
    pub(super) fn check(self) -> Result<(), Error> {
        if self.frontier == [0; 32] {
            Err(Error::Encoding)
        } else {
            Ok(())
        }
    }
    pub(super) fn put(self, out: &mut Vec<u8>) {
        out.extend(self.height.to_be_bytes());
        out.extend(self.frontier);
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let p = Self {
            height: r.u64()?,
            frontier: r.array()?,
        };
        p.check()?;
        Ok(p)
    }
    fn covers(self, request: &Request) -> Result<(), Error> {
        self.check()?;
        let f = request.context.floor;
        if self.height < f.height || (self.height == f.height && self.frontier != f.frontier) {
            Err(Error::Request)
        } else {
            Ok(())
        }
    }
}
/// Temporary acknowledgement of THIS exact page, even if the current aggregate
/// tail is ahead on a retry. Neither the ticket nor this response is delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageAck {
    /// Locally observed checkpoint, not a global freshness proof.
    pub observed: Observed,
    /// Published base against which the stage is still hidden.
    pub base: Position,
    /// Current aggregate temporary status; may include other already sent pages.
    pub ticket: StageRef,
    /// End of the exact request page acknowledged by this response.
    pub submitted_end: Position,
    /// SHA-256 of that exact request body, not the aggregate stage contents.
    pub submitted_body: [u8; 32],
}
/// A single locally admitted terminal. This is deliberately not a whole-prefix
/// retention receipt and cannot be installed as a v1 consecutive delivery record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReceipt {
    /// Locally observed checkpoint when this response was made.
    pub observed: Observed,
    /// Exact terminal attributed by its author signature.
    pub event: VerifiedEvent,
    /// Nonzero local terminal feed cursor; ancestors have no feed cursors.
    pub cursor: u64,
    /// Frozen original registry evaluation basis, not current policy authority.
    pub registry: [u8; 32],
    /// Exact retry/recovery of an earlier decision, not new old-policy permission.
    pub reconciled: bool,
}
/// Author status is a peer assertion, not proof of every skipped predecessor.
/// Compare exact local frames through evidence before skipping chain upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Locally observed checkpoint.
    pub observed: Observed,
    /// Published author floor; never advanced by temporary staging.
    pub published: Position,
    /// Optional temporary hidden suffix relative to that exact floor.
    pub stage: Option<StageRef>,
}
/// Explicit immutable local evidence role and its terminal transaction ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Historical ancestors never become admitted terminals through this codec.
    pub role: EvidenceRole,
    /// Nonzero terminal transaction that retained this exact frame. For history,
    /// this is attribution to its retaining transaction, not a feed cursor.
    pub committed_by: u64,
    /// Frozen local registry evaluation basis; not proof of signing time.
    pub registry: [u8; 32],
    /// Separately signature-verified complete event.
    pub event: VerifiedEvent,
}
/// Room-wide terminal feed across all authors, in local publication order only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedPage {
    /// Locally observed checkpoint.
    pub observed: Observed,
    /// Snapshot local terminal tip; no global completeness promise.
    pub tip: u64,
    /// Only admitted-terminal entries, never historical-only ancestors.
    pub entries: Vec<Entry>,
}
/// Contiguous same-author evidence with explicit immutable roles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidencePage {
    /// Locally observed checkpoint.
    pub observed: Observed,
    /// Snapshot published author head, not a temporary stage tail.
    pub tip: Position,
    /// Bounded chain suffix linked to the request's exact preceding event.
    pub entries: Vec<Entry>,
}
/// Disjoint successful responses. Canonical encoding validates each against the
/// exact retained request. Bare decoded claims remain untrusted peer assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reply {
    /// Temporary checked page; no admitted or delivery floor movement.
    Staged(StageAck),
    /// One terminal locally admitted under the original policy basis.
    Committed(Box<TerminalReceipt>),
    /// Exact author published and temporary positions.
    Status(Status),
    /// Cross-author room-wide admitted terminal feed.
    Feed(FeedPage),
    /// Same-author immutable historical/admitted evidence.
    Evidence(EvidencePage),
}
impl Reply {
    fn check(&self, request: &Request) -> Result<(), Error> {
        match (self, request.kind) {
            (
                Self::Staged(a),
                Kind::Stage {
                    base,
                    prior,
                    end,
                    body,
                },
            ) => {
                a.observed.covers(request)?;
                request.author()?;
                a.ticket.check(base)?;
                let expected_pages = prior.map_or(1, |p| p.pages + 1);
                if a.base != base
                    || a.submitted_end != end
                    || a.submitted_body != body
                    || a.ticket.pages < expected_pages
                    || a.ticket.tail.sequence < end.sequence
                    || (a.ticket.tail.sequence == end.sequence && a.ticket.tail != end)
                    || prior.is_some_and(|p| p.id != a.ticket.id || p.expires != a.ticket.expires)
                {
                    return Err(Error::Request);
                }
            }
            (
                Self::Committed(c),
                Kind::Commit {
                    terminal,
                    terminal_frame,
                    ..
                },
            ) => {
                c.observed.covers(request)?;
                identity(&c.event, request.context.scope, Some(request.author()?))?;
                if c.cursor == 0
                    || c.registry == [0; 32]
                    || Position::of(&c.event) != terminal
                    || hash(&c.event.encode()) != terminal_frame
                {
                    return Err(Error::Request);
                }
            }
            (Self::Status(s), Kind::Status { minimum }) => {
                s.observed.covers(request)?;
                request.author()?;
                if s.published.sequence < minimum.sequence
                    || (s.published.sequence == minimum.sequence && s.published != minimum)
                {
                    return Err(Error::Request);
                }
                if let Some(stage) = s.stage {
                    stage.check(s.published)?;
                }
            }
            (Self::Feed(p), Kind::Feed { after, count }) => {
                if request.selection != Selection::RoomFeed {
                    return Err(Error::Request);
                }
                p.observed.covers(request)?;
                page_len(after, p.tip, count, p.entries.len())?;
                for (n, e) in p.entries.iter().enumerate() {
                    e.check(request.context.scope, None)?;
                    if e.role != EvidenceRole::CurrentAdmission
                        || after.checked_add(n as u64 + 1) != Some(e.committed_by)
                    {
                        return Err(Error::Request);
                    }
                    // The bounded mixed-author page may have sequence gaps,
                    // but cannot publish an exact event twice or regress/fork
                    // one author's sequence within the returned snapshot.
                    if p.entries[..n].iter().any(|prior| {
                        prior.event.id() == e.event.id()
                            || (prior.event.claims().author == e.event.claims().author
                                && prior.event.claims().sequence >= e.event.claims().sequence)
                    }) {
                        return Err(Error::Request);
                    }
                }
            }
            (Self::Evidence(p), Kind::Evidence { after, count }) => {
                p.observed.covers(request)?;
                page_len(after.sequence, p.tip.sequence, count, p.entries.len())?;
                if after.sequence == p.tip.sequence && after != p.tip {
                    return Err(Error::Request);
                }
                let mut tail = after;
                let mut previous: Option<&Entry> = None;
                for e in &p.entries {
                    e.check(request.context.scope, Some(request.author()?))?;
                    tail = tail.extension(&e.event)?;
                    if let Some(prior) = previous {
                        match prior.role {
                            EvidenceRole::HistoricalContinuity
                                if e.committed_by != prior.committed_by =>
                            {
                                return Err(Error::Request)
                            }
                            EvidenceRole::CurrentAdmission
                                if e.committed_by <= prior.committed_by =>
                            {
                                return Err(Error::Request)
                            }
                            _ => {}
                        }
                    }
                    previous = Some(e);
                }
                if tail.sequence == p.tip.sequence
                    && (tail != p.tip
                        || p.entries
                            .last()
                            .is_some_and(|e| e.role != EvidenceRole::CurrentAdmission))
                {
                    return Err(Error::Request);
                }
            }
            _ => return Err(Error::Request),
        }
        Ok(())
    }
    /// Canonical bounded response. No signer may bypass this typed validation.
    pub fn encode(&self, request: &Request) -> Result<Vec<u8>, Error> {
        self.check(request)?;
        let mut out = b"VHCR\x01".to_vec();
        match self {
            Self::Staged(a) => {
                out.push(0);
                a.observed.put(&mut out);
                a.base.put(&mut out);
                a.ticket.put(&mut out);
                a.submitted_end.put(&mut out);
                out.extend(a.submitted_body);
            }
            Self::Committed(c) => {
                out.push(1);
                c.observed.put(&mut out);
                out.extend(c.cursor.to_be_bytes());
                out.extend(c.registry);
                out.push(u8::from(c.reconciled));
                event_put(&c.event, &mut out);
            }
            Self::Status(s) => {
                out.push(2);
                s.observed.put(&mut out);
                s.published.put(&mut out);
                stage_put(s.stage, &mut out);
            }
            Self::Feed(p) => {
                out.push(3);
                p.observed.put(&mut out);
                out.extend(p.tip.to_be_bytes());
                entries_put(&p.entries, &mut out);
            }
            Self::Evidence(p) => {
                out.push(4);
                p.observed.put(&mut out);
                p.tip.put(&mut out);
                entries_put(&p.entries, &mut out);
            }
        }
        if out.len() > MAX_REPLY_BYTES {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    /// Bound counts and bytes before allocation; strictly verify every event and
    /// match scope, author, predecessor, role and page bounds to the request.
    pub fn decode(raw: &[u8], request: &Request) -> Result<Self, Error> {
        let mut r = Reader::framed(raw, b"VHCR\x01", MAX_REPLY_BYTES)?;
        let reply = match r.byte()? {
            0 => {
                let observed = Observed::read(&mut r)?;
                let base = Position::read(&mut r)?;
                Self::Staged(StageAck {
                    observed,
                    base,
                    ticket: StageRef::read(&mut r, base)?,
                    submitted_end: Position::read(&mut r)?,
                    submitted_body: r.array()?,
                })
            }
            1 => {
                let observed = Observed::read(&mut r)?;
                let cursor = r.u64()?;
                let registry = r.array()?;
                let reconciled = match r.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Encoding),
                };
                Self::Committed(Box::new(TerminalReceipt {
                    observed,
                    cursor,
                    registry,
                    reconciled,
                    event: event_read(&mut r)?,
                }))
            }
            2 => {
                let observed = Observed::read(&mut r)?;
                let published = Position::read(&mut r)?;
                Self::Status(Status {
                    observed,
                    published,
                    stage: stage_read(&mut r, published)?,
                })
            }
            3 => Self::Feed(FeedPage {
                observed: Observed::read(&mut r)?,
                tip: r.u64()?,
                entries: entries_read(&mut r)?,
            }),
            4 => Self::Evidence(EvidencePage {
                observed: Observed::read(&mut r)?,
                tip: Position::read(&mut r)?,
                entries: entries_read(&mut r)?,
            }),
            _ => return Err(Error::Encoding),
        };
        r.end()?;
        reply.check(request)?;
        Ok(reply)
    }
}
impl Entry {
    fn check(&self, scope: Scope, author: Option<[u8; 32]>) -> Result<(), Error> {
        if self.committed_by == 0 || self.registry == [0; 32] {
            return Err(Error::Bounds);
        }
        identity(&self.event, scope, author)
    }
}
fn page_len(after: u64, tip: u64, count: u8, len: usize) -> Result<(), Error> {
    if after > tip
        || len > usize::from(count)
        || after.checked_add(len as u64).is_none_or(|n| n > tip)
        || (len == 0 && after < tip)
    {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
fn entries_put(entries: &[Entry], out: &mut Vec<u8>) {
    out.push(entries.len() as u8);
    for e in entries {
        out.push(match e.role {
            EvidenceRole::HistoricalContinuity => 0,
            EvidenceRole::CurrentAdmission => 1,
        });
        out.extend(e.committed_by.to_be_bytes());
        out.extend(e.registry);
        event_put(&e.event, out);
    }
}
fn entries_read(r: &mut Reader<'_>) -> Result<Vec<Entry>, Error> {
    let n = usize::from(r.byte()?);
    if n > MAX_PAGE {
        return Err(Error::Bounds);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let role = match r.byte()? {
            0 => EvidenceRole::HistoricalContinuity,
            1 => EvidenceRole::CurrentAdmission,
            _ => return Err(Error::Encoding),
        };
        out.push(Entry {
            role,
            committed_by: r.u64()?,
            registry: r.array()?,
            event: event_read(r)?,
        });
    }
    Ok(out)
}
