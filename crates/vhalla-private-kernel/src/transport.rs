//! Closed confidential control envelope. No generic exporter or encryption API.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use openmls::prelude::MlsGroup;
use openmls_traits::OpenMlsProvider;
use zeroize::Zeroizing;

use crate::{
    codec::{self, Reader, Writer},
    model::Working,
    packets::{ControlPacket, MAX_PACKET},
    protocol::*,
    Error, Result, MAX_STORED_RECORD_BYTES,
};

const MAGIC: &[u8] = b"VHPKCTRL\x01";
const RECORD: &[u8] = b"VHPKCTRLREC\x01";
const LABEL: &str = "vhalla/private/control-envelope/v1";
const HEADER: usize = MAGIC.len() + 1 + 8 + 8 + 24 + 4;

/// Exact encrypted control read from authenticated committed history. It proves
/// local publication, not relay receipt, current membership or global freshness.
///
/// ```compile_fail
/// use vhalla_private_kernel::CommittedEncryptedControl;
/// let uncommitted = CommittedEncryptedControl { bytes: vec![] };
/// ```
pub struct CommittedEncryptedControl {
    pub(crate) scope: PrivateRoomScope,
    pub(crate) floor: ControlFloor,
    pub(crate) bytes: Vec<u8>,
}
impl CommittedEncryptedControl {
    /// Full private scope; never use it as a public routing address.
    pub fn scope(&self) -> PrivateRoomScope {
        self.scope
    }
    /// Exact accepted owner control represented by this retained artifact.
    pub fn floor(&self) -> ControlFloor {
        self.floor
    }
    /// Original envelope bytes; no old exporter is retained or used on retry.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Bounded encrypted suffix. A fresh joiner's base is its joining floor: it does
/// not have the predecessor epoch key or an independently verified old envelope.
pub struct EncryptedControlPage {
    /// Oldest predecessor for which this device can supply a complete suffix.
    pub base: ControlFloor,
    /// Exact locally accepted head observed before reading immutable history.
    pub head: ControlFloor,
    /// Exclusive continuation cursor, or none when this snapshot is exhausted.
    pub next: Option<ControlFloor>,
    /// Exact committed encrypted artifacts, in ascending order.
    pub records: Vec<CommittedEncryptedControl>,
}

pub(crate) fn kind(control: &VerifiedOwnerControl) -> Result<u8> {
    match &control.claims().change {
        ControlChange::Membership {
            additions,
            removals,
        } if additions.len() == 1 && removals.is_empty() => Ok(1),
        ControlChange::Membership {
            additions,
            removals,
        } if additions.is_empty() && removals.len() == 1 => Ok(2),
        ControlChange::OwnerUpdate => Ok(3),
        _ => Err(Error::Unsupported),
    }
}

pub(crate) struct Envelope<'a> {
    pub(crate) raw: &'a [u8],
    pub(crate) kind: u8,
    pub(crate) prior: u64,
    pub(crate) sequence: u64,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}
impl<'a> Envelope<'a> {
    pub(crate) fn decode(raw: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(raw, MAGIC, MAX_PACKET)?;
        let kind = r.byte()?;
        if !(1..=3).contains(&kind) {
            return Err(Error::Encoding);
        }
        let prior = r.u64()?;
        let sequence = r.u64()?;
        if prior.checked_add(1) != Some(sequence) {
            return Err(Error::Encoding);
        }
        let nonce = r.take(24)?;
        let ciphertext = r.blob(MAX_PACKET - HEADER)?;
        if ciphertext.len() < 16 {
            return Err(Error::Encoding);
        }
        r.end()?;
        Ok(Self {
            raw,
            kind,
            prior,
            sequence,
            nonce,
            ciphertext,
        })
    }
    fn matches(&self, control: &VerifiedOwnerControl) -> Result<()> {
        if self.kind != kind(control)?
            || self.prior != control.claims().prior_epoch
            || self.sequence != control.claims().sequence()?
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
}

fn context(work: &Working) -> Vec<u8> {
    let state = &work.state;
    let mut out = Vec::with_capacity(176);
    out.extend(state.context().scope.room.as_bytes());
    out.extend(state.context().scope.anchor.as_bytes());
    out.extend(state.epoch.to_be_bytes());
    out.extend(state.floor.sequence().to_be_bytes());
    out.extend(
        state
            .floor
            .id()
            .as_ref()
            .map_or(&[0; 32], |id| id.as_bytes()),
    );
    out.extend(state.roster_digest());
    out.extend(state.owner.claims().device.as_bytes());
    out
}
fn cipher(work: &Working, group: &MlsGroup, context: &[u8]) -> Result<XChaCha20Poly1305> {
    if group.epoch().as_u64() != work.state.epoch {
        return Err(Error::Scope);
    }
    let key = Zeroizing::new(
        group
            .export_secret(work.provider.crypto(), LABEL, context, 32)
            .map_err(|_| Error::Mls)?,
    );
    XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::Authentication)
}
fn aad(context: &[u8], header: &[u8]) -> Vec<u8> {
    let mut out = LABEL.as_bytes().to_vec();
    out.extend(context);
    out.extend(header);
    out
}

pub(crate) fn seal(work: &Working, group: &MlsGroup, packet: &ControlPacket) -> Result<Vec<u8>> {
    let clear = Zeroizing::new(packet.encode()?);
    let total = HEADER
        .checked_add(clear.len())
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::Bounds)?;
    // Reserve the exact proof + framing + storage AEAD inside the fixed record
    // ceiling, before key derivation or ciphertext allocation.
    let proof = packet.control.signed().encode();
    if total > MAX_PACKET
        || RECORD.len() + 4 + proof.len() + 1 + 4 + total + 40 > MAX_STORED_RECORD_BYTES
    {
        return Err(Error::Bounds);
    }
    let mut w = Writer::new(MAGIC, MAX_PACKET)?;
    w.byte(kind(&packet.control)?)?;
    w.u64(work.state.epoch)?;
    w.u64(work.state.floor.next_sequence()?)?;
    let nonce: [u8; 24] = codec::random()?;
    w.put(&nonce)?;
    w.put(
        &u32::try_from(clear.len() + 16)
            .map_err(|_| Error::Bounds)?
            .to_be_bytes(),
    )?;
    let mut raw = w.finish();
    let context = context(work);
    let ciphertext = cipher(work, group, &context)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &clear,
                aad: &aad(&context, &raw),
            },
        )
        .map_err(|_| Error::Authentication)?;
    raw.extend(ciphertext);
    Envelope::decode(&raw)?.matches(&packet.control)?;
    Ok(raw)
}

pub(crate) fn open(work: &Working, envelope: &Envelope<'_>) -> Result<ControlPacket> {
    if envelope.prior != work.state.epoch
        || envelope.sequence != work.state.floor.next_sequence()?
    {
        return Err(Error::Policy);
    }
    let context = context(work);
    let group = work.group()?;
    let clear = Zeroizing::new(
        cipher(work, &group, &context)?
            .decrypt(
                XNonce::from_slice(envelope.nonce),
                Payload {
                    msg: envelope.ciphertext,
                    aad: &aad(&context, &envelope.raw[..HEADER]),
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let packet = ControlPacket::decode(&clear)?;
    envelope.matches(&packet.control)?;
    Ok(packet)
}

/// Authenticated local publication provenance binds the proof to these exact
/// envelope bytes. Never decode this type from a peer or expose arbitrary seal.
pub(crate) struct RetainedControl {
    pub(crate) control: VerifiedOwnerControl,
    pub(crate) envelope: Option<Vec<u8>>,
}
impl RetainedControl {
    pub(crate) fn new(control: VerifiedOwnerControl, envelope: Option<Vec<u8>>) -> Result<Self> {
        if let Some(raw) = &envelope {
            Envelope::decode(raw)?.matches(&control)?;
        }
        Ok(Self { control, envelope })
    }
    pub(crate) fn floor(&self) -> Result<ControlFloor> {
        Ok(ControlFloor::new(
            self.control.claims().sequence()?,
            Some(self.control.id()),
        )?)
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(RECORD, MAX_STORED_RECORD_BYTES - 40)?;
        w.blob(&self.control.signed().encode(), MAX_RECORD_BYTES)?;
        if let Some(raw) = &self.envelope {
            Envelope::decode(raw)?.matches(&self.control)?;
            w.byte(1)?;
            w.blob(raw, MAX_PACKET)?;
        } else {
            w.byte(0)?;
        }
        Ok(w.finish())
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw, RECORD, MAX_STORED_RECORD_BYTES - 40)?;
        let control = SignedOwnerControl::decode(r.blob(MAX_RECORD_BYTES)?)?.verify()?;
        let envelope = match r.byte()? {
            0 => None,
            1 => Some(r.blob(MAX_PACKET)?.to_vec()),
            _ => return Err(Error::Encoding),
        };
        r.end()?;
        Self::new(control, envelope)
    }
}
