//! Bounded local IPC only; never a public network or cryptographic authority format.
#[path = "types.rs"]
pub mod types;
pub use types::*;
use vhalla_private_kernel::{
    protocol::{
        AnchorId, ControlFloor, ControlId, Key, PrivateRoomScope, RoomId, SignedDeviceEnrollment,
        SignedOwnerControl, SignedOwnerSuccession, SignedRoomAnchor, Validity, MAX_RECORD_BYTES,
    },
    recovery::MAX_ARCHIVE_PAGE_BYTES,
    Context, OperationId, OutboxKind, Phase, Status, MAX_BODY_BYTES, MAX_MEMBERS, MAX_PAGE_RECORDS,
};
use zeroize::{Zeroize, Zeroizing};

/// Content-free refusal of malformed, noncanonical, mismatched, or oversized local IPC.
///
/// This type carries no parsed secret content and grants no authority to retry,
/// reset state, or bypass the worker's terminal failure behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The complete frame or a bounded typed field violates the closed codec.
    InvalidFrame,
}
type Result<T> = std::result::Result<T, CodecError>;
const MAGIC: &[u8] = b"VHBRPRIVATE\x01";
struct Writer(Vec<u8>);
impl Drop for Writer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Writer {
    fn new(tag: u8) -> Self {
        let mut v = MAGIC.to_vec();
        v.push(tag);
        Self(v)
    }
    fn put(&mut self, v: &[u8]) -> Result<()> {
        if self
            .0
            .len()
            .checked_add(v.len())
            .is_none_or(|n| n > MAX_FRAME)
        {
            return Err(CodecError::InvalidFrame);
        }
        self.0.extend_from_slice(v);
        Ok(())
    }
    fn byte(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    fn number(&mut self, n: u64) -> Result<()> {
        self.put(&n.to_be_bytes())
    }
    fn blob(&mut self, b: &[u8], max: usize) -> Result<()> {
        if b.len() > max {
            return Err(CodecError::InvalidFrame);
        }
        self.put(
            &u32::try_from(b.len())
                .map_err(|_| CodecError::InvalidFrame)?
                .to_be_bytes(),
        )?;
        self.put(b)
    }
    fn key(&mut self, k: Key) -> Result<()> {
        self.put(k.as_bytes())
    }
    fn op(&mut self, op: OperationId) -> Result<()> {
        self.put(op.as_bytes())
    }
    fn context(&mut self, c: Context) -> Result<()> {
        self.put(c.scope.room.as_bytes())?;
        self.put(c.scope.anchor.as_bytes())?;
        self.key(c.account)?;
        self.key(c.device)
    }
    fn validity(&mut self, v: Validity) -> Result<()> {
        self.number(v.not_before())?;
        self.number(v.expires_at())
    }
    fn floor(&mut self, f: ControlFloor) -> Result<()> {
        self.number(f.sequence())?;
        self.put(&f.id().map_or([0; 32], |id| *id.as_bytes()))
    }
    fn optional_number(&mut self, n: Option<u64>) -> Result<()> {
        self.byte(u8::from(n.is_some()))?;
        if let Some(n) = n {
            self.number(n)?;
        }
        Ok(())
    }
    fn optional_floor(&mut self, n: Option<ControlFloor>) -> Result<()> {
        self.byte(u8::from(n.is_some()))?;
        if let Some(n) = n {
            self.floor(n)?;
        }
        Ok(())
    }
    fn limit(&mut self, n: usize) -> Result<()> {
        if !(1..=MAX_PAGE_RECORDS).contains(&n) {
            return Err(CodecError::InvalidFrame);
        }
        self.byte(n as u8)
    }
    fn count(&mut self, n: usize) -> Result<()> {
        if n > MAX_PAGE_RECORDS {
            return Err(CodecError::InvalidFrame);
        }
        self.byte(n as u8)
    }
    fn consent(&mut self, c: &Consent) -> Result<()> {
        if c.id == 0 {
            return Err(CodecError::InvalidFrame);
        }
        self.number(c.id)?;
        self.context(c.context)?;
        self.number(c.epoch)?;
        self.put(&c.roster)?;
        self.blob(&c.body, MAX_BODY_BYTES)
    }
    fn status(&mut self, s: Status) -> Result<()> {
        self.context(s.context)?;
        self.byte(phase_tag(s.phase))?;
        self.number(s.epoch)?;
        self.floor(s.control_floor)?;
        self.number(s.outbox_head)?;
        self.number(s.inbox_head)?;
        self.floor(s.history_base)?;
        self.put(&s.roster)?;
        if s.members == 0
            || s.members > MAX_MEMBERS
            || s.control_sequence != s.control_floor.sequence()
        {
            return Err(CodecError::InvalidFrame);
        }
        self.byte(s.members as u8)?;
        self.byte(u8::from(s.quarantined))
    }
    fn enrollment(&mut self, e: &SignedDeviceEnrollment) -> Result<()> {
        self.blob(&e.encode(), 150)
    }
    fn artifact(&mut self, a: &Artifact) -> Result<()> {
        if a.sequence == 0 || (a.kind == OutboxKind::ContactOffer) != a.bytes.is_none() {
            return Err(CodecError::InvalidFrame);
        }
        self.number(a.sequence)?;
        self.op(a.operation)?;
        self.byte(kind_tag(a.kind))?;
        self.byte(u8::from(a.bytes.is_some()))?;
        if let Some(b) = &a.bytes {
            self.blob(b, MAX_ARTIFACT)?;
        }
        Ok(())
    }
    fn inbound(&mut self, m: &Inbound) -> Result<()> {
        if m.sequence == 0 {
            return Err(CodecError::InvalidFrame);
        }
        self.number(m.sequence)?;
        self.key(m.sender)?;
        self.blob(&m.body, MAX_BODY_BYTES)
    }
    fn finish(mut self) -> Bytes {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}
struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Result<Self> {
        if raw.len() > MAX_FRAME || !raw.starts_with(MAGIC) {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Self {
            raw,
            offset: MAGIC.len(),
        })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(n).ok_or(CodecError::InvalidFrame)?;
        let result = self
            .raw
            .get(self.offset..end)
            .ok_or(CodecError::InvalidFrame)?;
        self.offset = end;
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CodecError::InvalidFrame)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::InvalidFrame),
        }
    }
    fn number(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn blob(&mut self, max: usize) -> Result<Bytes> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > max {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Zeroizing::new(self.take(n)?.to_vec()))
    }
    fn key(&mut self) -> Result<Key> {
        Key::from_bytes(self.array()?).map_err(|_| CodecError::InvalidFrame)
    }
    fn op(&mut self) -> Result<OperationId> {
        OperationId::from_bytes(self.array()?).map_err(|_| CodecError::InvalidFrame)
    }
    fn context(&mut self) -> Result<Context> {
        Ok(Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(self.array()?).map_err(|_| CodecError::InvalidFrame)?,
                anchor: AnchorId::from_bytes(self.array()?)
                    .map_err(|_| CodecError::InvalidFrame)?,
            },
            account: self.key()?,
            device: self.key()?,
        })
    }
    fn validity(&mut self) -> Result<Validity> {
        Validity::new(self.number()?, self.number()?).map_err(|_| CodecError::InvalidFrame)
    }
    fn floor(&mut self) -> Result<ControlFloor> {
        let sequence = self.number()?;
        let id = self.array()?;
        let id = if sequence == 0 {
            if id != [0; 32] {
                return Err(CodecError::InvalidFrame);
            }
            None
        } else {
            Some(ControlId::from_bytes(id).map_err(|_| CodecError::InvalidFrame)?)
        };
        ControlFloor::new(sequence, id).map_err(|_| CodecError::InvalidFrame)
    }
    fn optional_number(&mut self) -> Result<Option<u64>> {
        if self.boolean()? {
            Ok(Some(self.number()?))
        } else {
            Ok(None)
        }
    }
    fn optional_floor(&mut self) -> Result<Option<ControlFloor>> {
        if self.boolean()? {
            Ok(Some(self.floor()?))
        } else {
            Ok(None)
        }
    }
    fn count(&mut self) -> Result<usize> {
        let n = self.byte()? as usize;
        if n > MAX_PAGE_RECORDS {
            Err(CodecError::InvalidFrame)
        } else {
            Ok(n)
        }
    }
    fn limit(&mut self) -> Result<usize> {
        let n = self.count()?;
        if n == 0 {
            Err(CodecError::InvalidFrame)
        } else {
            Ok(n)
        }
    }
    fn consent(&mut self) -> Result<Consent> {
        let id = self.number()?;
        if id == 0 {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Consent {
            id,
            context: self.context()?,
            epoch: self.number()?,
            roster: self.array()?,
            body: self.blob(MAX_BODY_BYTES)?,
        })
    }
    fn status(&mut self) -> Result<Status> {
        let context = self.context()?;
        let phase = phase(self.byte()?)?;
        let epoch = self.number()?;
        let control_floor = self.floor()?;
        let outbox_head = self.number()?;
        let inbox_head = self.number()?;
        let history_base = self.floor()?;
        let roster = self.array()?;
        let members = self.count()?;
        if members == 0 || history_base.sequence() > control_floor.sequence() {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Status {
            context,
            phase,
            epoch,
            control_sequence: control_floor.sequence(),
            control_floor,
            outbox_head,
            inbox_head,
            history_base,
            roster,
            members,
            quarantined: self.boolean()?,
        })
    }
    fn enrollment(&mut self) -> Result<SignedDeviceEnrollment> {
        let e = SignedDeviceEnrollment::decode(&self.blob(150)?)
            .map_err(|_| CodecError::InvalidFrame)?;
        e.verify().map_err(|_| CodecError::InvalidFrame)?;
        Ok(e)
    }
    fn anchor(&mut self) -> Result<SignedRoomAnchor> {
        let a = SignedRoomAnchor::decode(&self.blob(169)?).map_err(|_| CodecError::InvalidFrame)?;
        a.verify().map_err(|_| CodecError::InvalidFrame)?;
        Ok(a)
    }
    fn artifact(&mut self) -> Result<Artifact> {
        let sequence = self.number()?;
        let operation = self.op()?;
        let kind = kind(self.byte()?)?;
        let bytes = if self.boolean()? {
            Some(self.blob(MAX_ARTIFACT)?)
        } else {
            None
        };
        if sequence == 0 || (kind == OutboxKind::ContactOffer) != bytes.is_none() {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Artifact {
            sequence,
            operation,
            kind,
            bytes,
        })
    }
    fn inbound(&mut self) -> Result<Inbound> {
        let sequence = self.number()?;
        if sequence == 0 {
            return Err(CodecError::InvalidFrame);
        }
        Ok(Inbound {
            sequence,
            sender: self.key()?,
            body: self.blob(MAX_BODY_BYTES)?,
        })
    }
    fn end(self) -> Result<()> {
        if self.offset == self.raw.len() {
            Ok(())
        } else {
            Err(CodecError::InvalidFrame)
        }
    }
}
fn phase_tag(v: Phase) -> u8 {
    match v {
        Phase::OwnerGenesis => 1,
        Phase::AwaitingWelcome => 2,
        Phase::OwnerJoined => 3,
        Phase::MemberJoined => 4,
        Phase::OwnerAfterRemoval => 5,
        Phase::Removed => 6,
    }
}
fn phase(v: u8) -> Result<Phase> {
    match v {
        1 => Ok(Phase::OwnerGenesis),
        2 => Ok(Phase::AwaitingWelcome),
        3 => Ok(Phase::OwnerJoined),
        4 => Ok(Phase::MemberJoined),
        5 => Ok(Phase::OwnerAfterRemoval),
        6 => Ok(Phase::Removed),
        _ => Err(CodecError::InvalidFrame),
    }
}
fn kind_tag(v: OutboxKind) -> u8 {
    match v {
        OutboxKind::ContactOffer => 1,
        OutboxKind::ContactRequest => 2,
        OutboxKind::ContactInvitation => 3,
        OutboxKind::KeyPackage => 4,
        OutboxKind::Invitation => 5,
        OutboxKind::Application => 6,
        OutboxKind::Removal => 7,
        OutboxKind::OwnerUpdate => 8,
        OutboxKind::Succession => 9,
    }
}
fn kind(v: u8) -> Result<OutboxKind> {
    match v {
        1 => Ok(OutboxKind::ContactOffer),
        2 => Ok(OutboxKind::ContactRequest),
        3 => Ok(OutboxKind::ContactInvitation),
        4 => Ok(OutboxKind::KeyPackage),
        5 => Ok(OutboxKind::Invitation),
        6 => Ok(OutboxKind::Application),
        7 => Ok(OutboxKind::Removal),
        8 => Ok(OutboxKind::OwnerUpdate),
        9 => Ok(OutboxKind::Succession),
        _ => Err(CodecError::InvalidFrame),
    }
}

impl Request {
    /// Encode one complete bounded canonical frame; never publish it to a network.
    pub fn encode(&self) -> Result<Bytes> {
        let tag = match self {
            Self::Enter { .. } => 1,
            Self::PrepareOwner(_) => 2,
            Self::PrepareContact { .. } => 3,
            Self::CommitCreation(_) => 4,
            Self::Open(_) => 5,
            Self::Membership => 6,
            Self::PrepareMessage(_) => 7,
            Self::Send { .. } => 8,
            Self::Offer { .. } => 9,
            Self::ContactRequest { .. } => 10,
            Self::Accept { .. } => 11,
            Self::Join(_) => 12,
            Self::Receive(_) => 13,
            Self::Remove { .. } => 14,
            Self::Renew { .. } => 15,
            Self::ApplyControl(_) => 16,
            Self::Controls { .. } => 17,
            Self::Outbox { .. } => 18,
            Self::Inbox { .. } => 19,
            Self::ArchiveExport => 20,
            Self::ArchiveExportNext => 21,
            Self::ArchiveImportBegin { .. } => 22,
            Self::ArchiveImportFeed(_) => 23,
            Self::ArchiveImportFinish(_) => 24,
            Self::ArchiveOpen { .. } => 25,
            Self::ArchiveInspect => 26,
            Self::ArchiveInbox { .. } => 27,
            Self::ArchiveOutbox { .. } => 28,
            Self::ArchiveClose => 29,
            Self::ControlProofs { .. } => 30,
            Self::ObserveControl(_) => 31,
            Self::ForkEvidence => 32,
            #[cfg(feature = "local-qualification")]
            Self::Divergent { .. } => 33,
            #[cfg(feature = "local-qualification")]
            Self::ApplyControlAt { .. } => 34,
            Self::Succeed { .. } => 35,
        };
        let mut w = Writer::new(tag);
        match self {
            Self::Enter { vault, local_birth } => {
                w.blob(vault, 125)?;
                w.byte(u8::from(*local_birth))?;
            }
            Self::PrepareOwner(v) => w.validity(*v)?,
            Self::PrepareContact {
                offer,
                owner,
                validity,
            } => {
                w.key(*owner)?;
                w.validity(*validity)?;
                w.blob(offer, MAX_OFFER)?;
            }
            Self::CommitCreation(c) | Self::Open(c) => w.context(*c)?,
            Self::Membership => (),
            Self::PrepareMessage(b) => w.blob(b, MAX_BODY_BYTES)?,
            Self::Send { operation, consent } => {
                w.op(*operation)?;
                w.consent(consent)?;
            }
            Self::Offer {
                operation,
                recipient,
                validity,
            } => {
                w.op(*operation)?;
                w.key(*recipient)?;
                w.validity(*validity)?;
            }
            Self::ContactRequest { operation, offer } => {
                w.op(*operation)?;
                w.blob(offer, MAX_OFFER)?;
            }
            Self::Accept {
                operation,
                request,
                validity,
            } => {
                w.op(*operation)?;
                w.validity(*validity)?;
                w.blob(request, MAX_ARTIFACT)?;
            }
            Self::Join(b) | Self::Receive(b) | Self::ApplyControl(b) => w.blob(b, MAX_ARTIFACT)?,
            Self::Remove { operation, device } => {
                w.op(*operation)?;
                w.key(*device)?;
            }
            Self::Renew {
                operation,
                validity,
            } => {
                w.op(*operation)?;
                w.validity(*validity)?;
            }
            Self::Succeed {
                operation,
                successor,
                validity,
            } => {
                w.op(*operation)?;
                w.key(*successor)?;
                w.validity(*validity)?;
            }
            Self::Controls { after, limit } | Self::ControlProofs { after, limit } => {
                w.floor(*after)?;
                w.limit(*limit)?;
            }
            Self::ObserveControl(b) => w.blob(b, MAX_ARTIFACT)?,
            Self::ForkEvidence => (),
            #[cfg(feature = "local-qualification")]
            Self::Divergent { sequence } => w.number(*sequence)?,
            #[cfg(feature = "local-qualification")]
            Self::ApplyControlAt { envelope, at } => {
                w.blob(envelope, MAX_ARTIFACT)?;
                w.number(*at)?;
            }
            Self::Outbox { after, limit } | Self::Inbox { after, limit } => {
                w.number(*after)?;
                w.limit(*limit)?;
            }
            Self::ArchiveExport | Self::ArchiveExportNext | Self::ArchiveInspect => (),
            Self::ArchiveImportBegin {
                context,
                archive_id,
            } => {
                w.context(*context)?;
                w.put(archive_id)?;
            }
            Self::ArchiveImportFeed(page) | Self::ArchiveImportFinish(page) => {
                w.blob(page, MAX_ARCHIVE_PAGE_BYTES)?;
            }
            Self::ArchiveOpen {
                context,
                archive_id,
                final_page,
            } => {
                w.context(*context)?;
                w.put(archive_id)?;
                w.blob(final_page, MAX_ARCHIVE_PAGE_BYTES)?;
            }
            Self::ArchiveInbox { after, limit } | Self::ArchiveOutbox { after, limit } => {
                w.number(*after)?;
                w.limit(*limit)?;
            }
            Self::ArchiveClose => (),
        }
        Ok(w.finish())
    }
    /// Decode exactly one bounded frame, refusing unknown tags, trailing data and invalid typed fields.
    /// This validates local framing, not remote membership or delivery authority.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw)?;
        let out = match r.byte()? {
            1 => Self::Enter {
                vault: r.blob(125)?,
                local_birth: r.boolean()?,
            },
            2 => Self::PrepareOwner(r.validity()?),
            3 => Self::PrepareContact {
                owner: r.key()?,
                validity: r.validity()?,
                offer: r.blob(MAX_OFFER)?,
            },
            4 => Self::CommitCreation(r.context()?),
            5 => Self::Open(r.context()?),
            6 => Self::Membership,
            7 => Self::PrepareMessage(r.blob(MAX_BODY_BYTES)?),
            8 => Self::Send {
                operation: r.op()?,
                consent: Box::new(r.consent()?),
            },
            9 => Self::Offer {
                operation: r.op()?,
                recipient: r.key()?,
                validity: r.validity()?,
            },
            10 => Self::ContactRequest {
                operation: r.op()?,
                offer: r.blob(MAX_OFFER)?,
            },
            11 => Self::Accept {
                operation: r.op()?,
                validity: r.validity()?,
                request: r.blob(MAX_ARTIFACT)?,
            },
            12 => Self::Join(r.blob(MAX_ARTIFACT)?),
            13 => Self::Receive(r.blob(MAX_ARTIFACT)?),
            14 => Self::Remove {
                operation: r.op()?,
                device: r.key()?,
            },
            15 => Self::Renew {
                operation: r.op()?,
                validity: r.validity()?,
            },
            16 => Self::ApplyControl(r.blob(MAX_ARTIFACT)?),
            17 => Self::Controls {
                after: r.floor()?,
                limit: r.limit()?,
            },
            18 => Self::Outbox {
                after: r.number()?,
                limit: r.limit()?,
            },
            19 => Self::Inbox {
                after: r.number()?,
                limit: r.limit()?,
            },
            20 => Self::ArchiveExport,
            21 => Self::ArchiveExportNext,
            22 => Self::ArchiveImportBegin {
                context: r.context()?,
                archive_id: r.array()?,
            },
            23 => Self::ArchiveImportFeed(r.blob(MAX_ARCHIVE_PAGE_BYTES)?),
            24 => Self::ArchiveImportFinish(r.blob(MAX_ARCHIVE_PAGE_BYTES)?),
            25 => Self::ArchiveOpen {
                context: r.context()?,
                archive_id: r.array()?,
                final_page: r.blob(MAX_ARCHIVE_PAGE_BYTES)?,
            },
            26 => Self::ArchiveInspect,
            27 => Self::ArchiveInbox {
                after: r.number()?,
                limit: r.limit()?,
            },
            28 => Self::ArchiveOutbox {
                after: r.number()?,
                limit: r.limit()?,
            },
            29 => Self::ArchiveClose,
            30 => Self::ControlProofs {
                after: r.floor()?,
                limit: r.limit()?,
            },
            31 => Self::ObserveControl(r.blob(MAX_ARTIFACT)?),
            32 => Self::ForkEvidence,
            #[cfg(feature = "local-qualification")]
            33 => Self::Divergent {
                sequence: r.number()?,
            },
            #[cfg(feature = "local-qualification")]
            34 => Self::ApplyControlAt {
                envelope: r.blob(MAX_ARTIFACT)?,
                at: r.number()?,
            },
            35 => Self::Succeed {
                operation: r.op()?,
                successor: r.key()?,
                validity: r.validity()?,
            },
            _ => return Err(CodecError::InvalidFrame),
        };
        r.end()?;
        Ok(out)
    }
}

impl Response {
    /// Encode one complete bounded canonical frame; never publish it to a network.
    pub fn encode(&self) -> Result<Bytes> {
        let tag = match self {
            Self::Entered(_) => 101,
            Self::Prepared(_) => 102,
            Self::Membership(_) => 103,
            Self::Draft(_) => 104,
            Self::Artifact { .. } => 105,
            Self::Offer { .. } => 106,
            Self::Received { .. } => 107,
            Self::Controls { .. } => 108,
            Self::Outbox { .. } => 109,
            Self::Inbox { .. } => 110,
            Self::ArchiveBegin { .. } => 111,
            Self::ArchivePage { .. } => 112,
            Self::ArchiveProgress { .. } => 113,
            Self::ArchiveInspect { .. } => 114,
            Self::ArchiveClosed { .. } => 115,
            Self::ControlProofs { .. } => 116,
            Self::Observed { .. } => 117,
            Self::ForkEvidence { .. } => 118,
            #[cfg(feature = "local-qualification")]
            Self::Divergent { .. } => 119,
        };
        let mut w = Writer::new(tag);
        match self {
            Self::Entered(k) => w.key(*k)?,
            Self::Prepared(p) => {
                w.context(p.context)?;
                w.blob(&p.anchor.encode(), 169)?;
                w.enrollment(&p.enrollment)?;
            }
            Self::Membership(m) => {
                w.status(m.status)?;
                w.blob(&m.anchor.encode(), 169)?;
                w.enrollment(&m.owner)?;
                w.enrollment(&m.local)?;
                w.count(m.members.len())?;
                for e in &m.members {
                    w.enrollment(e)?;
                }
                w.count(m.successions.len())?;
                for grant in &m.successions {
                    w.blob(&grant.encode(), MAX_RECORD_BYTES)?;
                }
            }
            Self::Draft(c) => w.consent(c)?,
            Self::Artifact { context, artifact } => {
                w.context(*context)?;
                w.artifact(artifact)?;
            }
            Self::Offer {
                context,
                operation,
                secret,
            } => {
                w.context(*context)?;
                w.op(*operation)?;
                w.blob(secret, MAX_OFFER)?;
            }
            Self::Received { context, message } => {
                w.context(*context)?;
                w.inbound(message)?;
            }
            Self::Controls {
                context,
                base,
                head,
                next,
                records,
            }
            | Self::ControlProofs {
                context,
                base,
                head,
                next,
                records,
            } => {
                w.context(*context)?;
                w.floor(*base)?;
                w.floor(*head)?;
                w.optional_floor(*next)?;
                w.count(records.len())?;
                for c in records {
                    w.floor(c.floor)?;
                    w.blob(&c.bytes, MAX_ARTIFACT)?;
                }
            }
            Self::Observed { context, verdict } => {
                w.context(*context)?;
                w.byte(match verdict {
                    ObserveVerdict::Retained => 1,
                    ObserveVerdict::UnknownHistory => 2,
                    ObserveVerdict::BeforeBase => 3,
                })?;
            }
            Self::ForkEvidence { context, proof } => {
                w.context(*context)?;
                w.byte(u8::from(proof.is_some()))?;
                if let Some(proof) = proof {
                    w.floor(proof.accepted)?;
                    w.blob(&proof.conflicting, MAX_ARTIFACT)?;
                    w.blob(&proof.accepted_proof, MAX_ARTIFACT)?;
                    w.byte(u8::from(proof.accepted_from_checkpoint))?;
                }
            }
            Self::Outbox {
                context,
                head,
                next,
                records,
            } => {
                w.context(*context)?;
                w.number(*head)?;
                w.optional_number(*next)?;
                w.count(records.len())?;
                for a in records {
                    w.artifact(a)?;
                }
            }
            Self::Inbox {
                context,
                head,
                next,
                records,
            } => {
                w.context(*context)?;
                w.number(*head)?;
                w.optional_number(*next)?;
                w.count(records.len())?;
                for m in records {
                    w.inbound(m)?;
                }
            }
            Self::ArchiveBegin {
                context,
                archive_id,
            } => {
                w.context(*context)?;
                w.put(archive_id)?;
            }
            Self::ArchivePage { context, page } => {
                w.context(*context)?;
                w.byte(u8::from(page.is_some()))?;
                if let Some(page) = page {
                    w.blob(page, MAX_ARCHIVE_PAGE_BYTES)?;
                }
            }
            Self::ArchiveProgress {
                context,
                source_ready,
                next_page,
                records,
                bytes,
            } => {
                w.context(*context)?;
                w.byte(u8::from(*source_ready))?;
                w.number(*next_page)?;
                w.number(*records)?;
                w.number(*bytes)?;
            }
            Self::ArchiveInspect {
                context,
                archive_id,
                source_revision,
                status,
            } => {
                w.context(*context)?;
                w.put(archive_id)?;
                w.number(*source_revision)?;
                w.status(*status)?;
            }
            Self::ArchiveClosed { context } => w.context(*context)?,
            #[cfg(feature = "local-qualification")]
            Self::Divergent { context, control } => {
                w.context(*context)?;
                w.blob(control, MAX_ARTIFACT)?;
            }
        }
        Ok(w.finish())
    }
    /// Decode exactly one bounded frame, refusing unknown tags, trailing data and invalid typed fields.
    /// This validates local framing, not remote membership or delivery authority.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw)?;
        let out = match r.byte()? {
            101 => Self::Entered(r.key()?),
            102 => {
                let p = Preview {
                    context: r.context()?,
                    anchor: r.anchor()?,
                    enrollment: r.enrollment()?,
                };
                if p.anchor
                    .verify()
                    .map_err(|_| CodecError::InvalidFrame)?
                    .scope()
                    != p.context.scope
                    || p.enrollment.claims().account != p.context.account
                    || p.enrollment.claims().device != p.context.device
                {
                    return Err(CodecError::InvalidFrame);
                }
                Self::Prepared(Box::new(p))
            }
            103 => {
                let status = r.status()?;
                let anchor = r.anchor()?;
                let owner = r.enrollment()?;
                let local = r.enrollment()?;
                let count = r.count()?;
                if count != status.members {
                    return Err(CodecError::InvalidFrame);
                }
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(r.enrollment()?);
                }
                let count = r.count()?;
                let mut successions = Vec::with_capacity(count);
                for _ in 0..count {
                    successions.push(
                        SignedOwnerSuccession::decode(&r.blob(MAX_RECORD_BYTES)?[..])
                            .map_err(|_| CodecError::InvalidFrame)?,
                    );
                }
                let verified = anchor.verify().map_err(|_| CodecError::InvalidFrame)?;
                if verified.scope() != status.context.scope
                    || local.claims().account != status.context.account
                    || local.claims().device != status.context.device
                    || owner.claims().account != verified.claims().owner_account
                {
                    return Err(CodecError::InvalidFrame);
                }
                // The reported owner is the anchor device only before any
                // handoff; afterwards the verified grant chain must walk from
                // the anchor device to the reported owner without a gap. This
                // mirrors the kernel's retained-chain check: a grant is
                // historical evidence, so its successor need not still be
                // rostered (a promoted owner may later renew or be removed).
                let mut expected = verified.claims().owner_device;
                let mut prior_sequence = 0u64;
                for grant in &successions {
                    let grant = grant.verify().map_err(|_| CodecError::InvalidFrame)?;
                    let claims = grant.claims();
                    if claims.scope != status.context.scope
                        || claims.account != verified.claims().owner_account
                        || claims.predecessor != expected
                        || claims.sequence <= prior_sequence
                    {
                        return Err(CodecError::InvalidFrame);
                    }
                    prior_sequence = claims.sequence;
                    expected = claims.successor.claims().device;
                }
                if owner.claims().device != expected {
                    return Err(CodecError::InvalidFrame);
                }
                Self::Membership(Box::new(Membership {
                    status,
                    anchor,
                    owner,
                    local,
                    members,
                    successions,
                }))
            }
            104 => Self::Draft(Box::new(r.consent()?)),
            105 => Self::Artifact {
                context: r.context()?,
                artifact: r.artifact()?,
            },
            106 => Self::Offer {
                context: r.context()?,
                operation: r.op()?,
                secret: r.blob(MAX_OFFER)?,
            },
            107 => Self::Received {
                context: r.context()?,
                message: r.inbound()?,
            },
            108 => {
                let context = r.context()?;
                let base = r.floor()?;
                let head = r.floor()?;
                let next = r.optional_floor()?;
                let count = r.count()?;
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(Control {
                        floor: r.floor()?,
                        bytes: r.blob(MAX_ARTIFACT)?,
                    });
                }
                Self::Controls {
                    context,
                    base,
                    head,
                    next,
                    records,
                }
            }
            109 => {
                let context = r.context()?;
                let head = r.number()?;
                let next = r.optional_number()?;
                let count = r.count()?;
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(r.artifact()?);
                }
                Self::Outbox {
                    context,
                    head,
                    next,
                    records,
                }
            }
            110 => {
                let context = r.context()?;
                let head = r.number()?;
                let next = r.optional_number()?;
                let count = r.count()?;
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    records.push(r.inbound()?);
                }
                Self::Inbox {
                    context,
                    head,
                    next,
                    records,
                }
            }
            111 => Self::ArchiveBegin {
                context: r.context()?,
                archive_id: r.array()?,
            },
            112 => {
                let context = r.context()?;
                let page = if r.boolean()? {
                    Some(r.blob(MAX_ARCHIVE_PAGE_BYTES)?)
                } else {
                    None
                };
                Self::ArchivePage { context, page }
            }
            113 => Self::ArchiveProgress {
                context: r.context()?,
                source_ready: r.boolean()?,
                next_page: r.number()?,
                records: r.number()?,
                bytes: r.number()?,
            },
            114 => {
                let context = r.context()?;
                let archive_id = r.array()?;
                let source_revision = r.number()?;
                let status = r.status()?;
                if status.context != context {
                    return Err(CodecError::InvalidFrame);
                }
                Self::ArchiveInspect {
                    context,
                    archive_id,
                    source_revision,
                    status,
                }
            }
            115 => Self::ArchiveClosed {
                context: r.context()?,
            },
            116 => {
                let context = r.context()?;
                let base = r.floor()?;
                let head = r.floor()?;
                let next = r.optional_floor()?;
                let count = r.count()?;
                let mut records = Vec::with_capacity(count);
                for _ in 0..count {
                    let floor = r.floor()?;
                    let bytes = r.blob(MAX_ARTIFACT)?;
                    // Signed proofs decode and verify at the local wire
                    // boundary; a malformed or foreign-room proof is a corrupt
                    // worker report.
                    let control = SignedOwnerControl::decode(&bytes)
                        .and_then(|c| c.verify())
                        .map_err(|_| CodecError::InvalidFrame)?;
                    if control.claims().scope != context.scope
                        || control.id() != floor.id().ok_or(CodecError::InvalidFrame)?
                    {
                        return Err(CodecError::InvalidFrame);
                    }
                    records.push(Control { floor, bytes });
                }
                Self::ControlProofs {
                    context,
                    base,
                    head,
                    next,
                    records,
                }
            }
            117 => Self::Observed {
                context: r.context()?,
                verdict: match r.byte()? {
                    1 => ObserveVerdict::Retained,
                    2 => ObserveVerdict::UnknownHistory,
                    3 => ObserveVerdict::BeforeBase,
                    _ => return Err(CodecError::InvalidFrame),
                },
            },
            118 => {
                let context = r.context()?;
                let proof = if r.boolean()? {
                    let accepted = r.floor()?;
                    let conflicting = r.blob(MAX_ARTIFACT)?;
                    let accepted_proof = r.blob(MAX_ARTIFACT)?;
                    let accepted_from_checkpoint = r.boolean()?;
                    let control = SignedOwnerControl::decode(&conflicting)
                        .and_then(|c| c.verify())
                        .map_err(|_| CodecError::InvalidFrame)?;
                    // A real fork names a different valid control at the same
                    // accepted floor of this exact room.
                    if control.claims().scope != context.scope
                        || control.claims().sequence().ok() != Some(accepted.sequence())
                        || accepted.id() == Some(control.id())
                    {
                        return Err(CodecError::InvalidFrame);
                    }
                    // A retained-control accepted side must itself decode,
                    // verify, and commit to the reported floor; the private
                    // joining-checkpoint encoding is kernel-internal.
                    if !accepted_from_checkpoint {
                        let signed = SignedOwnerControl::decode(&accepted_proof)
                            .and_then(|c| c.verify())
                            .map_err(|_| CodecError::InvalidFrame)?;
                        if signed.claims().scope != context.scope
                            || signed.claims().sequence().ok() != Some(accepted.sequence())
                            || accepted.id() != Some(signed.id())
                        {
                            return Err(CodecError::InvalidFrame);
                        }
                    }
                    Some(ForkProof {
                        accepted,
                        conflicting,
                        accepted_proof,
                        accepted_from_checkpoint,
                    })
                } else {
                    None
                };
                Self::ForkEvidence { context, proof }
            }
            #[cfg(feature = "local-qualification")]
            119 => {
                let context = r.context()?;
                let control = r.blob(MAX_ARTIFACT)?;
                // The qualification divergent proof is still a real signed
                // owner control of this exact room at the wire boundary.
                let signed = SignedOwnerControl::decode(&control)
                    .and_then(|c| c.verify())
                    .map_err(|_| CodecError::InvalidFrame)?;
                if signed.claims().scope != context.scope {
                    return Err(CodecError::InvalidFrame);
                }
                Self::Divergent { context, control }
            }
            _ => return Err(CodecError::InvalidFrame),
        };
        r.end()?;
        Ok(out)
    }
}
