//! Canonical codec for `RoomContext` wire and WAL types.
//!
//! One bounded, length-prefixed big-endian format covers every message the
//! engine moves: streamed proposal parts, signed consensus messages,
//! liveness rebroadcasts, polka certificates, validator proofs, sync
//! status/request/response, and WAL `ProposedValue`s. Decoding is strict —
//! bounds are enforced and trailing bytes are rejected.

use bytes::Bytes;
use core::fmt;

use arc_malachitebft_codec::Codec;
use arc_malachitebft_core_consensus::{LivenessMsg, ProposedValue, SignedConsensusMsg};
use arc_malachitebft_core_types::{
    ExtendedCommitCertificate, ExtendedCommitSignature, NilOrVal, PolkaCertificate, PolkaSignature,
    Round, RoundCertificate, RoundCertificateType, RoundSignature, SignedExtension, SignedMessage,
    SigningScheme, ValidatorProof, Validity, VoteType,
};
use arc_malachitebft_engine::util::streaming::{StreamContent, StreamMessage};
use arc_malachitebft_peer::PeerId;
use arc_malachitebft_sync::{
    RawDecidedValue, Request, Response, Status, ValueRequest, ValueResponse,
};

use crate::{Address, Ed25519, Height, Signature};
use crate::{
    ProposalFin, ProposalInit, RoomContext, RoomPart, RoomProposal, RoomValue, RoomValueId,
    RoomVote, MAX_VALUE_BYTES,
};

/// Maximum signatures inside a certificate on the wire.
const MAX_SIGNATURES: usize = 64;
/// Maximum decided values in a single sync response.
const MAX_SYNC_VALUES: usize = 128;

/// Codec error: a static description of the rejected input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError(pub &'static str);

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CodecError {}

/// The room wire codec: canonical length-prefixed encoding.
#[derive(Copy, Clone, Debug, Default)]
pub struct RoomCodec;

// ---- canonical encoding primitives ----------------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_round(out: &mut Vec<u8>, r: Round) {
    put_u32(out, r.as_u32().unwrap_or(u32::MAX));
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

fn put_addr(out: &mut Vec<u8>, a: &Address) {
    out.extend_from_slice(&a.into_inner());
}

fn put_sig(out: &mut Vec<u8>, s: &Signature) {
    out.extend_from_slice(&Ed25519::encode_signature(s));
}

fn put_value_id(out: &mut Vec<u8>, v: &NilOrVal<RoomValueId>) {
    match v {
        NilOrVal::Nil => out.push(0),
        NilOrVal::Val(id) => {
            out.push(1);
            out.extend_from_slice(&id.0);
        }
    }
}

fn put_height(out: &mut Vec<u8>, h: Height) {
    put_u64(out, h.as_u64());
}

struct Rd<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Rd { buf, pos: 0 }
    }

    fn done(&self) -> Result<(), CodecError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(CodecError("trailing bytes"))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.buf.len() - self.pos < n {
            return Err(CodecError("short input"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self, max: usize) -> Result<&'a [u8], CodecError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(CodecError("overlong field"));
        }
        self.take(len)
    }

    fn addr(&mut self) -> Result<Address, CodecError> {
        Ok(Address::new(self.take(20)?.try_into().unwrap()))
    }

    fn height(&mut self) -> Result<Height, CodecError> {
        Ok(Height::new(self.u64()?))
    }

    fn round(&mut self) -> Result<Round, CodecError> {
        let v = self.u32()?;
        Ok(if v == u32::MAX {
            Round::Nil
        } else {
            Round::new(v)
        })
    }

    fn sig(&mut self) -> Result<Signature, CodecError> {
        Ed25519::decode_signature(self.take(64)?).map_err(|_| CodecError("bad signature"))
    }

    fn value_id(&mut self) -> Result<NilOrVal<RoomValueId>, CodecError> {
        match self.u8()? {
            0 => Ok(NilOrVal::Nil),
            1 => Ok(NilOrVal::Val(RoomValueId(
                self.take(32)?.try_into().unwrap(),
            ))),
            _ => Err(CodecError("bad nil-or-val tag")),
        }
    }

    fn peer_id(&mut self) -> Result<PeerId, CodecError> {
        PeerId::from_bytes(self.bytes(1024)?).map_err(|_| CodecError("bad peer id"))
    }
}

fn put_peer_id(out: &mut Vec<u8>, p: &PeerId) {
    put_bytes(out, &p.to_bytes());
}

fn put_vote(out: &mut Vec<u8>, v: &RoomVote) {
    out.push(match v.vote_type {
        VoteType::Prevote => 0,
        VoteType::Precommit => 1,
    });
    put_height(out, v.height);
    put_round(out, v.round);
    put_value_id(out, &v.value);
    put_addr(out, &v.address);
    match &v.extension {
        None => out.push(0),
        Some(ext) => {
            out.push(1);
            put_sig(out, &ext.signature);
        }
    }
}

fn get_vote(rd: &mut Rd<'_>) -> Result<RoomVote, CodecError> {
    let vote_type = match rd.u8()? {
        0 => VoteType::Prevote,
        1 => VoteType::Precommit,
        _ => return Err(CodecError("bad vote type")),
    };
    let height = rd.height()?;
    let round = rd.round()?;
    let value = rd.value_id()?;
    let address = rd.addr()?;
    let extension = match rd.u8()? {
        0 => None,
        1 => Some(SignedExtension {
            message: (),
            signature: rd.sig()?,
        }),
        _ => return Err(CodecError("bad extension tag")),
    };
    Ok(RoomVote {
        vote_type,
        height,
        round,
        value,
        address,
        extension,
    })
}

// The wire proposal carries ONLY the value commitment: the canonical
// bytes travel in the proposal-part stream (`ProposalAndParts` mode).
// Embedding the bytes here would put an unbounded-size message on the
// consensus channel — observed to exceed the per-write ceiling of
// relayed transports (tailcat/DERP ~1.2 KiB) and wedge the connection.
fn put_proposal(out: &mut Vec<u8>, p: &RoomProposal) {
    put_height(out, p.height);
    put_round(out, p.round);
    put_round(out, p.pol_round);
    put_addr(out, &p.proposer);
    out.extend_from_slice(&p.value.id.0);
}

fn get_proposal(rd: &mut Rd<'_>) -> Result<RoomProposal, CodecError> {
    let height = rd.height()?;
    let round = rd.round()?;
    let pol_round = rd.round()?;
    let proposer = rd.addr()?;
    let id = RoomValueId(rd.take(32)?.try_into().unwrap());
    Ok(RoomProposal {
        height,
        round,
        value: RoomValue {
            id,
            bytes: Bytes::new(),
        },
        pol_round,
        proposer,
    })
}

fn put_round_sig(out: &mut Vec<u8>, s: &RoundSignature<RoomContext>) {
    out.push(match s.vote_type {
        VoteType::Prevote => 0,
        VoteType::Precommit => 1,
    });
    put_value_id(out, &s.value_id);
    put_addr(out, &s.address);
    put_sig(out, &s.signature);
}

fn get_round_sig(rd: &mut Rd<'_>) -> Result<RoundSignature<RoomContext>, CodecError> {
    let vote_type = match rd.u8()? {
        0 => VoteType::Prevote,
        1 => VoteType::Precommit,
        _ => return Err(CodecError("bad round-sig vote type")),
    };
    Ok(RoundSignature {
        vote_type,
        value_id: rd.value_id()?,
        address: rd.addr()?,
        signature: rd.sig()?,
    })
}

fn put_round_cert(out: &mut Vec<u8>, c: &RoundCertificate<RoomContext>) {
    put_height(out, c.height);
    put_round(out, c.round);
    out.push(match c.cert_type {
        RoundCertificateType::Skip => 0,
        RoundCertificateType::Precommit => 1,
    });
    put_u32(out, c.round_signatures.len() as u32);
    for s in &c.round_signatures {
        put_round_sig(out, s);
    }
}

fn get_round_cert(rd: &mut Rd<'_>) -> Result<RoundCertificate<RoomContext>, CodecError> {
    let height = rd.height()?;
    let round = rd.round()?;
    let cert_type = match rd.u8()? {
        0 => RoundCertificateType::Skip,
        1 => RoundCertificateType::Precommit,
        _ => return Err(CodecError("bad cert type")),
    };
    let count = rd.u32()? as usize;
    if count > MAX_SIGNATURES {
        return Err(CodecError("too many round signatures"));
    }
    let mut sigs = Vec::with_capacity(count);
    for _ in 0..count {
        sigs.push(get_round_sig(rd)?);
    }
    Ok(RoundCertificate {
        height,
        round,
        cert_type,
        round_signatures: sigs,
    })
}

fn put_polka(out: &mut Vec<u8>, c: &PolkaCertificate<RoomContext>) {
    put_height(out, c.height);
    put_round(out, c.round);
    out.extend_from_slice(&c.value_id.0);
    put_u32(out, c.polka_signatures.len() as u32);
    for s in &c.polka_signatures {
        put_addr(out, &s.address);
        put_sig(out, &s.signature);
    }
}

fn get_polka(rd: &mut Rd<'_>) -> Result<PolkaCertificate<RoomContext>, CodecError> {
    let height = rd.height()?;
    let round = rd.round()?;
    let value_id = RoomValueId(rd.take(32)?.try_into().unwrap());
    let count = rd.u32()? as usize;
    if count > MAX_SIGNATURES {
        return Err(CodecError("too many polka signatures"));
    }
    let mut sigs = Vec::with_capacity(count);
    for _ in 0..count {
        sigs.push(PolkaSignature::new(rd.addr()?, rd.sig()?));
    }
    Ok(PolkaCertificate {
        height,
        round,
        value_id,
        polka_signatures: sigs,
    })
}

fn put_ext_cert(out: &mut Vec<u8>, c: &ExtendedCommitCertificate<RoomContext>) {
    put_height(out, c.height);
    put_round(out, c.round);
    out.extend_from_slice(&c.value_id.0);
    put_u32(out, c.commit_signatures.len() as u32);
    for s in &c.commit_signatures {
        put_addr(out, &s.address);
        put_sig(out, &s.signature);
        match &s.extension {
            None => out.push(0),
            Some(ext) => {
                out.push(1);
                put_sig(out, &ext.signature);
            }
        }
    }
}

fn get_ext_cert(rd: &mut Rd<'_>) -> Result<ExtendedCommitCertificate<RoomContext>, CodecError> {
    let height = rd.height()?;
    let round = rd.round()?;
    let value_id = RoomValueId(rd.take(32)?.try_into().unwrap());
    let count = rd.u32()? as usize;
    if count > MAX_SIGNATURES {
        return Err(CodecError("too many commit signatures"));
    }
    let mut sigs = Vec::with_capacity(count);
    for _ in 0..count {
        let address = rd.addr()?;
        let signature = rd.sig()?;
        let extension = match rd.u8()? {
            0 => None,
            1 => Some(SignedMessage {
                message: (),
                signature: rd.sig()?,
            }),
            _ => return Err(CodecError("bad extension tag")),
        };
        sigs.push(ExtendedCommitSignature {
            address,
            signature,
            extension,
        });
    }
    Ok(ExtendedCommitCertificate {
        height,
        round,
        value_id,
        commit_signatures: sigs,
    })
}

impl RoomCodec {
    /// Encodes a `RoomValue` for `RawDecidedValue::value_bytes`.
    pub fn encode_value(value: &RoomValue) -> Bytes {
        let mut out = Vec::with_capacity(36 + value.bytes.len());
        out.extend_from_slice(&value.id.0);
        put_bytes(&mut out, &value.bytes);
        Bytes::from(out)
    }

    /// Decodes a `RoomValue` from `RawDecidedValue::value_bytes`.
    pub fn decode_value(bytes: Bytes) -> Result<RoomValue, CodecError> {
        let mut rd = Rd::new(&bytes);
        let id = RoomValueId(rd.take(32)?.try_into().unwrap());
        let data = Bytes::copy_from_slice(rd.bytes(MAX_VALUE_BYTES)?);
        rd.done()?;
        Ok(RoomValue { id, bytes: data })
    }
}

impl Codec<RoomPart> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<RoomPart, CodecError> {
        let mut rd = Rd::new(&bytes);
        let part = match rd.u8()? {
            0x01 => RoomPart::Init(ProposalInit {
                height: rd.height()?,
                round: rd.round()?,
                pol_round: rd.round()?,
                proposer: rd.addr()?,
            }),
            0x02 => RoomPart::Data(Bytes::copy_from_slice(rd.bytes(MAX_VALUE_BYTES)?)),
            0x03 => RoomPart::Fin(ProposalFin {
                signature: rd.sig()?,
            }),
            _ => return Err(CodecError("bad part tag")),
        };
        rd.done()?;
        Ok(part)
    }

    fn encode(&self, msg: &RoomPart) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        match msg {
            RoomPart::Init(init) => {
                out.push(0x01);
                put_height(&mut out, init.height);
                put_round(&mut out, init.round);
                put_round(&mut out, init.pol_round);
                put_addr(&mut out, &init.proposer);
            }
            RoomPart::Data(data) => {
                out.push(0x02);
                put_bytes(&mut out, data);
            }
            RoomPart::Fin(fin) => {
                out.push(0x03);
                put_sig(&mut out, &fin.signature);
            }
        }
        Ok(Bytes::from(out))
    }
}

impl Codec<SignedConsensusMsg<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<SignedConsensusMsg<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let msg = match rd.u8()? {
            0x01 => SignedConsensusMsg::Vote(SignedMessage {
                message: get_vote(&mut rd)?,
                signature: rd.sig()?,
            }),
            0x02 => SignedConsensusMsg::Proposal(SignedMessage {
                message: get_proposal(&mut rd)?,
                signature: rd.sig()?,
            }),
            _ => return Err(CodecError("bad consensus msg tag")),
        };
        rd.done()?;
        Ok(msg)
    }

    fn encode(&self, msg: &SignedConsensusMsg<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        match msg {
            SignedConsensusMsg::Vote(v) => {
                out.push(0x01);
                put_vote(&mut out, &v.message);
                put_sig(&mut out, &v.signature);
            }
            SignedConsensusMsg::Proposal(p) => {
                out.push(0x02);
                put_proposal(&mut out, &p.message);
                put_sig(&mut out, &p.signature);
            }
        }
        Ok(Bytes::from(out))
    }
}

impl Codec<LivenessMsg<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<LivenessMsg<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let msg = match rd.u8()? {
            0x01 => LivenessMsg::Vote(SignedMessage {
                message: get_vote(&mut rd)?,
                signature: rd.sig()?,
            }),
            0x02 => LivenessMsg::PolkaCertificate(get_polka(&mut rd)?),
            0x03 => LivenessMsg::SkipRoundCertificate(get_round_cert(&mut rd)?),
            _ => return Err(CodecError("bad liveness tag")),
        };
        rd.done()?;
        Ok(msg)
    }

    fn encode(&self, msg: &LivenessMsg<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        match msg {
            LivenessMsg::Vote(v) => {
                out.push(0x01);
                put_vote(&mut out, &v.message);
                put_sig(&mut out, &v.signature);
            }
            LivenessMsg::PolkaCertificate(c) => {
                out.push(0x02);
                put_polka(&mut out, c);
            }
            LivenessMsg::SkipRoundCertificate(c) => {
                out.push(0x03);
                put_round_cert(&mut out, c);
            }
        }
        Ok(Bytes::from(out))
    }
}

impl Codec<StreamMessage<RoomPart>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<StreamMessage<RoomPart>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let stream_id = rd.bytes(64)?.to_vec();
        let sequence = rd.u64()?;
        let content = match rd.u8()? {
            0x00 => StreamContent::Data(<Self as Codec<RoomPart>>::decode(
                self,
                Bytes::copy_from_slice(rd.bytes(MAX_VALUE_BYTES + 64)?),
            )?),
            0x01 => StreamContent::Fin,
            _ => return Err(CodecError("bad stream content tag")),
        };
        rd.done()?;
        Ok(StreamMessage::new(
            arc_malachitebft_engine::util::streaming::StreamId::new(Bytes::from(stream_id)),
            sequence,
            content,
        ))
    }

    fn encode(&self, msg: &StreamMessage<RoomPart>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        put_bytes(&mut out, &msg.stream_id.to_bytes());
        put_u64(&mut out, msg.sequence);
        match &msg.content {
            StreamContent::Data(part) => {
                out.push(0x00);
                let inner = <Self as Codec<RoomPart>>::encode(self, part)?;
                put_bytes(&mut out, &inner);
            }
            StreamContent::Fin => out.push(0x01),
        }
        Ok(Bytes::from(out))
    }
}

impl Codec<ValidatorProof<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<ValidatorProof<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let proof =
            ValidatorProof::new(rd.bytes(64)?.to_vec(), rd.bytes(1024)?.to_vec(), rd.sig()?);
        rd.done()?;
        Ok(proof)
    }

    fn encode(&self, msg: &ValidatorProof<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        put_bytes(&mut out, &msg.public_key);
        put_bytes(&mut out, &msg.peer_id);
        put_sig(&mut out, &msg.signature);
        Ok(Bytes::from(out))
    }
}

impl Codec<Status<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Status<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let status = Status {
            peer_id: rd.peer_id()?,
            tip_height: rd.height()?,
            history_min_height: rd.height()?,
        };
        rd.done()?;
        Ok(status)
    }

    fn encode(&self, msg: &Status<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        put_peer_id(&mut out, &msg.peer_id);
        put_height(&mut out, msg.tip_height);
        put_height(&mut out, msg.history_min_height);
        Ok(Bytes::from(out))
    }
}

impl Codec<Request<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Request<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let req = match rd.u8()? {
            0x01 => Request::ValueRequest(ValueRequest::new(rd.height()?..=rd.height()?)),
            _ => return Err(CodecError("bad request tag")),
        };
        rd.done()?;
        Ok(req)
    }

    fn encode(&self, msg: &Request<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        match msg {
            Request::ValueRequest(r) => {
                out.push(0x01);
                put_height(&mut out, *r.range.start());
                put_height(&mut out, *r.range.end());
            }
        }
        Ok(Bytes::from(out))
    }
}

impl Codec<Response<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<Response<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let resp = match rd.u8()? {
            0x01 => {
                let start_height = rd.height()?;
                let count = rd.u32()? as usize;
                if count > MAX_SYNC_VALUES {
                    return Err(CodecError("too many sync values"));
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let value_bytes = Bytes::copy_from_slice(rd.bytes(MAX_VALUE_BYTES + 64)?);
                    let cert_len = rd.u32()? as usize;
                    let mut cert_rd = Rd::new(rd.take(cert_len)?);
                    let certificate = get_ext_cert(&mut cert_rd)?;
                    cert_rd.done()?;
                    values.push(RawDecidedValue {
                        value_bytes,
                        certificate,
                    });
                }
                Response::ValueResponse(ValueResponse::new(start_height, values))
            }
            _ => return Err(CodecError("bad response tag")),
        };
        rd.done()?;
        Ok(resp)
    }

    fn encode(&self, msg: &Response<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        match msg {
            Response::ValueResponse(r) => {
                out.push(0x01);
                put_height(&mut out, r.start_height);
                put_u32(&mut out, r.values.len() as u32);
                for v in &r.values {
                    put_bytes(&mut out, &v.value_bytes);
                    let mut cert = Vec::new();
                    put_ext_cert(&mut cert, &v.certificate);
                    put_bytes(&mut out, &cert);
                }
            }
        }
        Ok(Bytes::from(out))
    }
}

impl arc_malachitebft_codec::HasEncodedLen<Response<RoomContext>> for RoomCodec {
    fn encoded_len(&self, msg: &Response<RoomContext>) -> Result<usize, CodecError> {
        <Self as Codec<Response<RoomContext>>>::encode(self, msg).map(|b| b.len())
    }
}

impl Codec<ProposedValue<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<ProposedValue<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let pv = ProposedValue {
            height: rd.height()?,
            round: rd.round()?,
            valid_round: rd.round()?,
            proposer: rd.addr()?,
            value: {
                let id = RoomValueId(rd.take(32)?.try_into().unwrap());
                let data = Bytes::copy_from_slice(rd.bytes(MAX_VALUE_BYTES)?);
                RoomValue { id, bytes: data }
            },
            validity: match rd.u8()? {
                0 => Validity::Valid,
                1 => Validity::Invalid,
                _ => return Err(CodecError("bad validity")),
            },
        };
        rd.done()?;
        Ok(pv)
    }

    fn encode(&self, msg: &ProposedValue<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        put_height(&mut out, msg.height);
        put_round(&mut out, msg.round);
        put_round(&mut out, msg.valid_round);
        put_addr(&mut out, &msg.proposer);
        out.extend_from_slice(&msg.value.id.0);
        put_bytes(&mut out, &msg.value.bytes);
        out.push(match msg.validity {
            Validity::Valid => 0,
            Validity::Invalid => 1,
        });
        Ok(Bytes::from(out))
    }
}

impl Codec<PolkaCertificate<RoomContext>> for RoomCodec {
    type Error = CodecError;

    fn decode(&self, bytes: Bytes) -> Result<PolkaCertificate<RoomContext>, CodecError> {
        let mut rd = Rd::new(&bytes);
        let cert = get_polka(&mut rd)?;
        rd.done()?;
        Ok(cert)
    }

    fn encode(&self, msg: &PolkaCertificate<RoomContext>) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        put_polka(&mut out, msg);
        Ok(Bytes::from(out))
    }
}
