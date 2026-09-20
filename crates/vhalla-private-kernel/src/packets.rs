use crate::{
    codec::{Reader, Writer},
    protocol::*,
    CommittedOutbox, Context, Error, OperationId, OutboxEntry, OutboxKind, ReceivedMessage, Result,
    MAX_BODY_BYTES, MAX_STORED_RECORD_BYTES, MAX_WIRE_BYTES,
};
use zeroize::Zeroize;

pub(crate) const MAX_PACKET: usize = MAX_STORED_RECORD_BYTES - 256;

pub(crate) struct JoinRequest {
    pub(crate) scope: PrivateRoomScope,
    pub(crate) enrollment: VerifiedDeviceEnrollment,
    pub(crate) package: Vec<u8>,
}
impl JoinRequest {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(b"VHPKJOINREQ\x01", MAX_PACKET)?;
        put_scope(&mut w, self.scope)?;
        w.blob(&self.enrollment.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.package, MAX_WIRE_BYTES)?;
        Ok(w.finish())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, b"VHPKJOINREQ\x01", MAX_PACKET)?;
        let scope = scope(&mut r)?;
        let enrollment = SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let package = nonempty(r.blob(MAX_WIRE_BYTES)?)?.to_vec();
        r.end()?;
        Ok(Self {
            scope,
            enrollment,
            package,
        })
    }
}

pub(crate) struct InvitePacket {
    pub(crate) invitation: VerifiedInvitation,
    pub(crate) control: VerifiedOwnerControl,
    pub(crate) owner: VerifiedDeviceEnrollment,
    pub(crate) member: VerifiedDeviceEnrollment,
    pub(crate) commit: Vec<u8>,
    pub(crate) welcome: Vec<u8>,
    pub(crate) checkpoint: crate::checkpoint::Checkpoint,
}
impl InvitePacket {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(b"VHPKINVITE\x02", MAX_PACKET)?;
        w.blob(&self.invitation.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.control.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.owner.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.member.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(&self.commit, MAX_WIRE_BYTES)?;
        w.blob(&self.welcome, MAX_WIRE_BYTES)?;
        w.blob(&self.checkpoint.encode()?, MAX_RECORD_BYTES)?;
        Ok(w.finish())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, b"VHPKINVITE\x02", MAX_PACKET)?;
        let invitation = SignedInvitation::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let control = SignedOwnerControl::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let owner = SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let member = SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let commit = nonempty(r.blob(MAX_WIRE_BYTES)?)?.to_vec();
        let welcome = nonempty(r.blob(MAX_WIRE_BYTES)?)?.to_vec();
        let checkpoint = crate::checkpoint::Checkpoint::decode(r.blob(MAX_RECORD_BYTES)?)?;
        r.end()?;
        Ok(Self {
            invitation,
            control,
            owner,
            member,
            commit,
            welcome,
            checkpoint,
        })
    }
}

/// Canonical private control artifact. Membership authority still requires the
/// retained owner/floor and exact staged MLS proposal checks in the kernel.
pub(crate) struct ControlPacket {
    pub(crate) control: VerifiedOwnerControl,
    pub(crate) commit: Vec<u8>,
    pub(crate) invitation: Option<VerifiedInvitation>,
    pub(crate) enrollment: Option<VerifiedDeviceEnrollment>,
}
impl ControlPacket {
    pub(crate) fn validate(&self) -> Result<()> {
        let c = self.control.claims();
        if c.commit != CommitDigest::of_bytes(&self.commit)? {
            return Err(Error::Policy);
        }
        match &c.change {
            ControlChange::Membership {
                additions,
                removals,
            } if additions.len() == 1 && removals.is_empty() => {
                let invite = self.invitation.as_ref().ok_or(Error::Policy)?;
                let member = self.enrollment.as_ref().ok_or(Error::Policy)?;
                let a = &additions[0];
                let i = invite.claims();
                let e = member.claims();
                if i.scope != c.scope
                    || i.owner_device != c.owner_device
                    || i.floor != c.parent
                    || a.invitation != invite.id()
                    || a.device != i.recipient_device
                    || a.account != i.recipient_account
                    || a.key_package != i.key_package
                    || a.device != e.device
                    || a.account != e.account
                {
                    return Err(Error::Policy);
                }
            }
            ControlChange::Membership {
                additions,
                removals,
            } if additions.is_empty() && removals.len() == 1 => {
                if self.invitation.is_some() || self.enrollment.is_some() {
                    return Err(Error::Policy);
                }
            }
            ControlChange::OwnerUpdate => {
                let enrollment = self.enrollment.as_ref().ok_or(Error::Policy)?;
                if self.invitation.is_some() || enrollment.claims().device != c.owner_device {
                    return Err(Error::Policy);
                }
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut w = Writer::new(b"VHPKCONTROL\x01", MAX_PACKET)?;
        w.u64(self.control.claims().sequence()?)?;
        w.blob(&self.control.signed().encode(), MAX_RECORD_BYTES)?;
        w.blob(nonempty(&self.commit)?, MAX_WIRE_BYTES)?;
        match (&self.invitation, &self.enrollment) {
            (Some(i), Some(e)) => {
                w.byte(1)?;
                w.blob(&i.signed().encode(), MAX_RECORD_BYTES)?;
                w.blob(&e.signed().encode(), MAX_RECORD_BYTES)?;
            }
            (None, None) => w.byte(0)?,
            (None, Some(e)) => {
                w.byte(2)?;
                w.blob(&e.signed().encode(), MAX_RECORD_BYTES)?;
            }
            _ => return Err(Error::Policy),
        }
        Ok(w.finish())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, b"VHPKCONTROL\x01", MAX_PACKET)?;
        let seq = r.u64()?;
        let control = SignedOwnerControl::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        if seq != control.claims().sequence()? {
            return Err(Error::Encoding);
        }
        let commit = nonempty(r.blob(MAX_WIRE_BYTES)?)?.to_vec();
        let (invitation, enrollment) = match r.byte()? {
            0 => (None, None),
            1 => (
                Some(SignedInvitation::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?),
                Some(SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?),
            ),
            2 => (
                None,
                Some(SignedDeviceEnrollment::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?),
            ),
            _ => return Err(Error::Encoding),
        };
        r.end()?;
        let packet = Self {
            control,
            commit,
            invitation,
            enrollment,
        };
        packet.validate()?;
        Ok(packet)
    }
    pub(crate) fn floor(&self) -> Result<ControlFloor> {
        Ok(ControlFloor::new(
            self.control.claims().sequence()?,
            Some(self.control.id()),
        )?)
    }
}
pub(crate) struct Sent {
    pub(crate) sequence: u64,
    pub(crate) operation: OperationId,
    pub(crate) request: [u8; 32],
    pub(crate) kind: OutboxKind,
    pub(crate) bytes: Vec<u8>,
}
impl Drop for Sent {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl Sent {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Encoding);
        }
        let mut w = Writer::new(b"VHPKOUT\x01", MAX_STORED_RECORD_BYTES - 40)?;
        w.u64(self.sequence)?;
        w.put(self.operation.as_bytes())?;
        w.put(&self.request)?;
        w.byte(kind_byte(self.kind))?;
        w.blob(nonempty(&self.bytes)?, MAX_PACKET)?;
        Ok(w.finish())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, b"VHPKOUT\x01", MAX_STORED_RECORD_BYTES - 40)?;
        let sequence = r.u64()?;
        if sequence == 0 {
            return Err(Error::Encoding);
        }
        let operation = OperationId::from_bytes(r.array()?)?;
        let request = r.array()?;
        let kind = decode_kind(r.byte()?)?;
        let bytes = nonempty(r.blob(MAX_PACKET)?)?;
        r.end()?;
        let bytes = bytes.to_vec();
        Ok(Self {
            sequence,
            operation,
            request,
            kind,
            bytes,
        })
    }
    pub(crate) fn committed(mut self) -> Result<CommittedOutbox> {
        if self.kind == OutboxKind::ContactOffer {
            self.bytes.zeroize();
            return Err(Error::Policy);
        }
        Ok(CommittedOutbox {
            sequence: self.sequence,
            operation: self.operation,
            kind: self.kind,
            bytes: std::mem::take(&mut self.bytes),
        })
    }
    pub(crate) fn entry(mut self) -> Result<OutboxEntry> {
        if self.kind == OutboxKind::ContactOffer {
            self.bytes.zeroize();
            return Ok(OutboxEntry::ConfidentialOffer {
                sequence: self.sequence,
                operation: self.operation,
            });
        }
        Ok(OutboxEntry::Artifact(self.committed()?))
    }
}

pub(crate) struct Received {
    pub(crate) sequence: u64,
    pub(crate) wire: Vec<u8>,
    pub(crate) sender: Key,
    pub(crate) body: Vec<u8>,
}
impl Received {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.sequence == 0 {
            return Err(Error::Encoding);
        }
        let mut w = Writer::new(b"VHPKIN\x01", MAX_STORED_RECORD_BYTES - 40)?;
        w.u64(self.sequence)?;
        w.put(self.sender.as_bytes())?;
        w.blob(nonempty(&self.wire)?, MAX_WIRE_BYTES)?;
        w.blob(nonempty(&self.body)?, MAX_BODY_BYTES)?;
        Ok(w.finish())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, b"VHPKIN\x01", MAX_STORED_RECORD_BYTES - 40)?;
        let sequence = r.u64()?;
        if sequence == 0 {
            return Err(Error::Encoding);
        }
        let sender = Key::from_bytes(r.array()?)?;
        let wire = nonempty(r.blob(MAX_WIRE_BYTES)?)?.to_vec();
        let body = nonempty(r.blob(MAX_BODY_BYTES)?)?.to_vec();
        r.end()?;
        Ok(Self {
            sequence,
            wire,
            sender,
            body,
        })
    }
    pub(crate) fn committed(self) -> ReceivedMessage {
        ReceivedMessage {
            sequence: self.sequence,
            sender: self.sender,
            body: self.body,
        }
    }
}

pub(crate) fn request(context: Context, kind: OutboxKind, parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut w = Writer::new(b"VHPKREQ\x01", MAX_PACKET + 256)?;
    w.put(&context.encode())?;
    w.byte(kind_byte(kind))?;
    for part in parts {
        w.blob(part, MAX_PACKET)?;
    }
    Ok(crate::codec::hash(
        b"vhalla/private-kernel/request/v1\0",
        &w.finish(),
    ))
}
pub(crate) fn nonempty(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.is_empty() {
        Err(Error::Bounds)
    } else {
        Ok(bytes)
    }
}
fn put_scope(w: &mut Writer, scope: PrivateRoomScope) -> Result<()> {
    w.put(scope.room.as_bytes())?;
    w.put(scope.anchor.as_bytes())
}
fn scope(r: &mut Reader<'_>) -> Result<PrivateRoomScope> {
    Ok(PrivateRoomScope {
        room: RoomId::from_bytes(r.array()?)?,
        anchor: AnchorId::from_bytes(r.array()?)?,
    })
}
fn kind_byte(kind: OutboxKind) -> u8 {
    match kind {
        OutboxKind::KeyPackage => 0,
        OutboxKind::Invitation => 1,
        OutboxKind::Application => 2,
        OutboxKind::Removal => 3,
        OutboxKind::OwnerUpdate => 4,
        OutboxKind::ContactOffer => 5,
        OutboxKind::ContactRequest => 6,
        OutboxKind::ContactInvitation => 7,
    }
}
fn decode_kind(value: u8) -> Result<OutboxKind> {
    match value {
        0 => Ok(OutboxKind::KeyPackage),
        1 => Ok(OutboxKind::Invitation),
        2 => Ok(OutboxKind::Application),
        3 => Ok(OutboxKind::Removal),
        4 => Ok(OutboxKind::OwnerUpdate),
        5 => Ok(OutboxKind::ContactOffer),
        6 => Ok(OutboxKind::ContactRequest),
        7 => Ok(OutboxKind::ContactInvitation),
        _ => Err(Error::Encoding),
    }
}
