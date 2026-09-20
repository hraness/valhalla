use super::*;

/// Exact author selection. A room feed has no synthetic all-zero author key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selection {
    /// Terminal feed across every author in this exact room.
    RoomFeed,
    /// One strictly checked full Ed25519 author for all other operations.
    Author([u8; 32]),
}
/// Caller-selected common context; validated when made into a Request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestContext {
    /// Complete immutable scope, independently pinned by the caller.
    pub scope: Scope,
    /// Fresh unpredictable nonce per exchange, supplied by the caller.
    pub nonce: [u8; 32],
    /// Nonzero operation identity, separate from an unpredictable request nonce.
    pub operation: [u8; 16],
    /// Minimum independently certified checkpoint retained by the requester.
    pub floor: Observed,
}
/// Complete operation semantics; constructing this enum alone grants no rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Exactly one 32-frame temporary historical page.
    Stage {
        /// Exact retained published author base.
        base: Position,
        /// Exact preceding temporary ticket, absent for the first page.
        prior: Option<StageRef>,
        /// Exact end of this submitted page, separate from later aggregate status.
        end: Position,
        /// SHA-256 of the entire canonical submitted body.
        body: [u8; 32],
    },
    /// Zero to 32 inline ancestors and exactly one current-policy terminal.
    Commit {
        /// Exact retained published author base.
        base: Position,
        /// Previously acknowledged temporary prefix, if any.
        stage: Option<StageRef>,
        /// Exact signed terminal position.
        terminal: Position,
        /// SHA-256 of the complete terminal frame, including its signature.
        terminal_frame: [u8; 32],
        /// Complete request-body digest, including all inline predecessors.
        body: [u8; 32],
    },
    /// One author's published floor and optional temporary stage status.
    Status {
        /// Known author floor; advanced status is not a proof of its ancestry.
        minimum: Position,
    },
    /// Room-wide admitted terminal feed, in this peer's local order only.
    Feed {
        /// Exclusive local terminal cursor, zero to start.
        after: u64,
        /// Count from one to32.
        count: u8,
    },
    /// Contiguous immutable role-tagged evidence for one author.
    Evidence {
        /// Exact previous author event; binds the first returned predecessor.
        after: Position,
        /// Count from one to32.
        count: u8,
    },
}
/// Checked immutable canonical request. No arbitrary HTTP methods or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub(super) context: RequestContext,
    pub(super) selection: Selection,
    pub(super) kind: Kind,
}
impl Request {
    /// Validate common context, author selection and all operation bounds.
    pub fn new(context: RequestContext, selection: Selection, kind: Kind) -> Result<Self, Error> {
        context.scope.check()?;
        context.floor.check()?;
        if context.nonce == [0; 32] {
            return Err(Error::Nonce);
        }
        if context.operation == [0; 16] {
            return Err(Error::Request);
        }
        match (selection, kind) {
            (Selection::RoomFeed, Kind::Feed { count, .. }) => count_check(count)?,
            (Selection::Author(author), k) => {
                crate::checked_key(&author).map_err(|_| Error::Peer)?;
                match k {
                    Kind::Stage {
                        base,
                        prior,
                        end,
                        body,
                    } => {
                        let tail = checked_tail(base, prior)?;
                        if tail.sequence.checked_add(32) != Some(end.sequence)
                            || body == [0; 32]
                            || prior.is_some_and(|s| s.pages >= 128)
                        {
                            return Err(Error::Bounds);
                        }
                    }
                    Kind::Commit {
                        base,
                        stage,
                        terminal,
                        terminal_frame,
                        body,
                    } => {
                        let tail = checked_tail(base, stage)?;
                        let count = terminal
                            .sequence
                            .checked_sub(tail.sequence)
                            .ok_or(Error::Bounds)?;
                        if !(1..=33).contains(&count)
                            || body == [0; 32]
                            || terminal_frame == [0; 32]
                        {
                            return Err(Error::Bounds);
                        }
                    }
                    Kind::Status { .. } => {}
                    Kind::Evidence { count, .. } => count_check(count)?,
                    Kind::Feed { .. } => return Err(Error::Request),
                }
            }
            _ => return Err(Error::Request),
        }
        Ok(Self {
            context,
            selection,
            kind,
        })
    }
    /// Construct and check an exact fixed historical stage body.
    pub fn stage(
        context: RequestContext,
        author: [u8; 32],
        base: Position,
        prior: Option<StageRef>,
        body: &Body,
    ) -> Result<Self, Error> {
        if body.terminal.is_some() {
            return Err(Error::Request);
        }
        let request = Self::new(
            context,
            Selection::Author(author),
            Kind::Stage {
                base,
                prior,
                end: body.end(),
                body: hash(&body.encode()),
            },
        )?;
        body.check(&request)?;
        Ok(request)
    }
    /// Construct and check inline ancestors and the exact signed terminal.
    pub fn commit(
        context: RequestContext,
        author: [u8; 32],
        base: Position,
        stage: Option<StageRef>,
        body: &Body,
    ) -> Result<Self, Error> {
        if body.terminal.is_none() {
            return Err(Error::Request);
        }
        let request = Self::new(
            context,
            Selection::Author(author),
            Kind::Commit {
                base,
                stage,
                terminal: body.end(),
                terminal_frame: hash(&body.terminal.as_ref().expect("checked terminal").encode()),
                body: hash(&body.encode()),
            },
        )?;
        body.check(&request)?;
        Ok(request)
    }
    /// Exact common scope, operation, nonce and requested certified floor.
    pub const fn context(&self) -> RequestContext {
        self.context
    }
    /// Room-wide feed versus exact strict author selection.
    pub const fn selection(&self) -> Selection {
        self.selection
    }
    /// Complete typed request semantics.
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Only mutations have a body; callers must reject GET bodies.
    pub const fn method(&self) -> &'static str {
        match self.kind {
            Kind::Stage { .. } | Kind::Commit { .. } => "POST",
            _ => "GET",
        }
    }
    /// Canonical binary frame, independently bounded by MAX_REQUEST_BYTES.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"VHCQ\x01".to_vec();
        self.context.scope.put(&mut out);
        out.extend(self.context.nonce);
        out.extend(self.context.operation);
        self.context.floor.put(&mut out);
        match self.selection {
            Selection::RoomFeed => out.push(0),
            Selection::Author(a) => {
                out.push(1);
                out.extend(a);
            }
        }
        match self.kind {
            Kind::Stage {
                base,
                prior,
                end,
                body,
            } => {
                out.push(0);
                base.put(&mut out);
                stage_put(prior, &mut out);
                end.put(&mut out);
                out.extend(body);
            }
            Kind::Commit {
                base,
                stage,
                terminal,
                terminal_frame,
                body,
            } => {
                out.push(1);
                base.put(&mut out);
                stage_put(stage, &mut out);
                terminal.put(&mut out);
                out.extend(terminal_frame);
                out.extend(body);
            }
            Kind::Status { minimum } => {
                out.push(2);
                minimum.put(&mut out);
            }
            Kind::Feed { after, count } => {
                out.push(3);
                out.extend(after.to_be_bytes());
                out.push(count);
            }
            Kind::Evidence { after, count } => {
                out.push(4);
                after.put(&mut out);
                out.push(count);
            }
        }
        out
    }
    /// Decode bounded canonical framing; rejects unknown fields and trailing data.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::framed(raw, b"VHCQ\x01", MAX_REQUEST_BYTES)?;
        let context = RequestContext {
            scope: Scope::read(&mut r)?,
            nonce: r.array()?,
            operation: r.array()?,
            floor: Observed::read(&mut r)?,
        };
        let selection = match r.byte()? {
            0 => Selection::RoomFeed,
            1 => Selection::Author(r.array()?),
            _ => return Err(Error::Encoding),
        };
        let kind = match r.byte()? {
            0 => {
                let base = Position::read(&mut r)?;
                Kind::Stage {
                    base,
                    prior: stage_read(&mut r, base)?,
                    end: Position::read(&mut r)?,
                    body: r.array()?,
                }
            }
            1 => {
                let base = Position::read(&mut r)?;
                Kind::Commit {
                    base,
                    stage: stage_read(&mut r, base)?,
                    terminal: Position::read(&mut r)?,
                    terminal_frame: r.array()?,
                    body: r.array()?,
                }
            }
            2 => Kind::Status {
                minimum: Position::read(&mut r)?,
            },
            3 => Kind::Feed {
                after: r.u64()?,
                count: r.byte()?,
            },
            4 => Kind::Evidence {
                after: Position::read(&mut r)?,
                count: r.byte()?,
            },
            _ => return Err(Error::Encoding),
        };
        r.end()?;
        Self::new(context, selection, kind)
    }
    /// Fixed origin-form route plus the lowercase canonical request frame.
    pub fn target(&self) -> String {
        format!("{TARGET}{}", crate::response::hex(&self.encode()))
    }
    /// Reject alternative ordering, encodings, fragments and query extensions.
    pub fn parse_target(raw: &str) -> Result<Self, Error> {
        if raw.len() > MAX_TARGET_BYTES {
            return Err(Error::Bounds);
        }
        let request = Self::decode(&unhex(
            raw.strip_prefix(TARGET).ok_or(Error::Encoding)?,
            MAX_REQUEST_BYTES,
        )?)?;
        if request.target() != raw {
            return Err(Error::Encoding);
        }
        Ok(request)
    }
    /// Decode and authenticate a mutation's exact signed frames and chain shape.
    /// This does not perform historical/current policy admission.
    pub fn check_body(&self, raw: &[u8]) -> Result<Body, Error> {
        let expected = match self.kind {
            Kind::Stage { body, .. } | Kind::Commit { body, .. } => body,
            _ => return Err(Error::Request),
        };
        if raw.len() > MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        if hash(raw) != expected {
            return Err(Error::Body);
        }
        let body = Body::decode(raw)?;
        body.check(self)?;
        Ok(body)
    }
    pub(super) fn author(&self) -> Result<[u8; 32], Error> {
        match self.selection {
            Selection::Author(a) => Ok(a),
            _ => Err(Error::Request),
        }
    }
}
fn count_check(n: u8) -> Result<(), Error> {
    if n == 0 || usize::from(n) > MAX_PAGE {
        Err(Error::Bounds)
    } else {
        Ok(())
    }
}
fn checked_tail(base: Position, stage: Option<StageRef>) -> Result<Position, Error> {
    if let Some(s) = stage {
        s.check(base)?;
        Ok(s.tail)
    } else {
        Ok(base)
    }
}

/// Strictly signed and bounded mutation content. No policy admission is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Body {
    history: Vec<VerifiedEvent>,
    terminal: Option<VerifiedEvent>,
}
impl Body {
    /// Exactly32 historical frames, each already signature-verified.
    pub fn stage(history: Vec<VerifiedEvent>) -> Result<Self, Error> {
        if history.len() != 32 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            history,
            terminal: None,
        })
    }
    /// Zero to32 historical frames plus one separately signed terminal.
    pub fn commit(history: Vec<VerifiedEvent>, terminal: VerifiedEvent) -> Result<Self, Error> {
        if history.len() > 32 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            history,
            terminal: Some(terminal),
        })
    }
    /// Historical-only ancestors; never silently relabel them as admitted posts.
    pub fn history(&self) -> &[VerifiedEvent] {
        &self.history
    }
    /// The sole proposed current-policy terminal, absent in a stage body.
    pub fn terminal(&self) -> Option<&VerifiedEvent> {
        self.terminal.as_ref()
    }
    /// Final signed point of this exact bounded body.
    pub fn end(&self) -> Position {
        Position::of(
            self.terminal
                .as_ref()
                .unwrap_or_else(|| self.history.last().expect("nonempty stage")),
        )
    }
    /// Canonical complete signed body; no normalization of event content.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = if self.terminal.is_some() {
            b"VHCC\x01".to_vec()
        } else {
            b"VHCS\x01".to_vec()
        };
        out.push(self.history.len() as u8);
        for e in &self.history {
            event_put(e, &mut out);
        }
        if let Some(e) = &self.terminal {
            event_put(e, &mut out);
        }
        out
    }
    /// Bounds/counts precede allocation and every frame is strictly verified.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() > MAX_BODY_BYTES {
            return Err(Error::Bounds);
        }
        let terminal = match raw.get(..5) {
            Some(b"VHCC\x01") => true,
            Some(b"VHCS\x01") => false,
            _ => return Err(Error::Encoding),
        };
        let mut r = Reader(&raw[5..]);
        let n = usize::from(r.byte()?);
        if n > 32 || (!terminal && n != 32) {
            return Err(Error::Bounds);
        }
        let mut history = Vec::with_capacity(n);
        for _ in 0..n {
            history.push(event_read(&mut r)?);
        }
        let terminal = if terminal {
            Some(event_read(&mut r)?)
        } else {
            None
        };
        r.end()?;
        Ok(Self { history, terminal })
    }
    fn check(&self, request: &Request) -> Result<(), Error> {
        let (mut tail, end) = match request.kind {
            Kind::Stage {
                base, prior, end, ..
            } if self.terminal.is_none() && self.history.len() == 32 => {
                (checked_tail(base, prior)?, end)
            }
            Kind::Commit {
                base,
                stage,
                terminal,
                terminal_frame,
                ..
            } if self.terminal.is_some() => {
                if hash(&self.terminal.as_ref().expect("checked terminal").encode())
                    != terminal_frame
                {
                    return Err(Error::Body);
                }
                (checked_tail(base, stage)?, terminal)
            }
            _ => return Err(Error::Request),
        };
        let author = request.author()?;
        for e in self.history.iter().chain(self.terminal.iter()) {
            identity(e, request.context.scope, Some(author))?;
            tail = tail.extension(e)?;
        }
        if tail != end {
            return Err(Error::Request);
        }
        Ok(())
    }
}
