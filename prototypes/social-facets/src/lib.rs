#![no_std]
#![forbid(unsafe_code)]
//! Disposable facet-wire model. Signature verification is not social admission.
extern crate alloc;
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use vhalla_social::{
    AgentId, Body, Error, Operation, OwnerId, RecordId, SignedRecord, Text, UnsignedRecord,
    MAX_RECORD_BYTES,
};

pub const MAX_FACETS: usize = 16;
pub const MAX_MENTIONS: usize = 8;
pub const MAX_TAGS: usize = 8;
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    Owner(OwnerId),
    Agent(AgentId),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Mention(Target),
    Tag(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facet {
    pub start: u16,
    pub end: u16,
    pub kind: Kind,
}
/// Validated exact text plus immutable annotation array; no foreign mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FacetedText {
    text: Text,
    facets: Vec<Facet>,
}
impl FacetedText {
    pub fn new(text: Text, facets: Vec<Facet>) -> Result<Self, Error> {
        if facets.len() > MAX_FACETS {
            return Err(Error::Bounds);
        }
        let mut end = 0;
        let mut recipients = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for facet in &facets {
            let start = usize::from(facet.start);
            let next_end = usize::from(facet.end);
            if start < end || start >= next_end {
                return Err(Error::Encoding);
            }
            let label = text.as_str().get(start..next_end).ok_or(Error::Encoding)?;
            match &facet.kind {
                Kind::Mention(target) => {
                    // This is the author's untrusted display token, never a verified alias.
                    if !label.starts_with('@')
                        || label.len() < 2
                        || label.bytes().any(|b| b <= 0x20 || b == 0x7f)
                    {
                        return Err(Error::Encoding);
                    }
                    recipients.insert(target);
                }
                Kind::Tag(canonical) => {
                    let display = label.strip_prefix('#').ok_or(Error::Encoding)?;
                    if canonical_tag(display)? != *canonical {
                        return Err(Error::Encoding);
                    }
                    tags.insert(canonical);
                }
            }
            end = next_end;
        }
        if recipients.len() > MAX_MENTIONS || tags.len() > MAX_TAGS {
            return Err(Error::Bounds);
        }
        Ok(Self { text, facets })
    }
    pub fn text(&self) -> &str {
        self.text.as_str()
    }
    pub fn facets(&self) -> &[Facet] {
        &self.facets
    }
    pub fn untrusted_label(&self, facet: &Facet) -> Option<&str> {
        self.text()
            .get(usize::from(facet.start)..usize::from(facet.end))
    }
}
pub fn canonical_tag(input: &str) -> Result<String, Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 48
        || !bytes[0].is_ascii_alphanumeric() && bytes[0] != b'_'
        || bytes
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && *b != b'_' && *b != b'-')
    {
        return Err(Error::Encoding);
    }
    Ok(input.to_ascii_lowercase())
}
/// A local authoring check; foreign annotations cannot prove alias ownership.
pub fn resolve_alias(
    label: &str,
    claimed: &Target,
    address_book: &[(&str, Target)],
) -> Result<Target, Error> {
    let mut entries = address_book.iter().filter(|(alias, _)| *alias == label);
    let first = entries.next().ok_or(Error::Missing)?;
    if entries.next().is_some() || &first.1 != claimed {
        return Err(Error::Context);
    }
    Ok(first.1.clone())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    NewOpcodesV1,
    EnvelopeV2,
}
fn domains(encoding: Encoding) -> (&'static [u8], &'static [u8]) {
    match encoding {
        Encoding::NewOpcodesV1 => (
            b"vhalla/social/content-id/v1",
            b"vhalla/social/signature/v1",
        ),
        Encoding::EnvelopeV2 => (
            b"vhalla/social/content-id/v2",
            b"vhalla/social/signature/v2",
        ),
    }
}
fn digest(bytes: &[u8], encoding: Encoding) -> RecordId {
    let mut h = Sha256::new();
    h.update(domains(encoding).0);
    h.update(bytes);
    RecordId::from_bytes(h.finalize().into())
}
fn transcript(id: RecordId, encoding: Encoding) -> Vec<u8> {
    let mut v = domains(encoding).1.to_vec();
    v.extend_from_slice(id.as_bytes());
    v
}
/// Exact signature-verified candidate revision. No Archive or control admission.
#[derive(Debug)]
pub struct Revision {
    id: RecordId,
    body: Body,
    annotated: FacetedText,
    encoding: Encoding,
}
impl Revision {
    pub fn id(&self) -> RecordId {
        self.id
    }
    pub fn body(&self) -> &Body {
        &self.body
    }
    pub fn annotated(&self) -> &FacetedText {
        &self.annotated
    }
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
}
fn body_text(body: &Body) -> Result<&Text, Error> {
    match body {
        Body::Social {
            operation: Operation::Post { text, .. } | Operation::Revise { text, .. },
            ..
        } => Ok(text),
        _ => Err(Error::Encoding),
    }
}
fn put_facets(facets: &[Facet], out: &mut Vec<u8>) {
    out.push(facets.len() as u8);
    for facet in facets {
        out.extend_from_slice(&facet.start.to_be_bytes());
        out.extend_from_slice(&facet.end.to_be_bytes());
        match &facet.kind {
            Kind::Mention(Target::Owner(id)) => {
                out.push(0);
                out.extend_from_slice(id.as_bytes());
            }
            Kind::Mention(Target::Agent(id)) => {
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
            Kind::Tag(tag) => {
                out.push(2);
                out.push(tag.len() as u8);
                out.extend_from_slice(tag.as_bytes());
            }
        }
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let result = self
            .bytes
            .get(self.offset..self.offset.checked_add(n).ok_or(Error::Bounds)?)
            .ok_or(Error::Encoding)?;
        self.offset += n;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }
    fn id(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::Encoding)
    }
    fn optional(&mut self, bytes: usize) -> Result<(), Error> {
        match self.byte()? {
            0 => Ok(()),
            1 => {
                self.take(bytes)?;
                Ok(())
            }
            _ => Err(Error::Encoding),
        }
    }
    fn text(&mut self) -> Result<(), Error> {
        let len = usize::from(self.u16()?);
        self.take(len)?;
        Ok(())
    }
}
/// Locate the two bounded legacy operation layouts, sharing their validated codec.
fn offsets(unsigned: &[u8]) -> Result<(usize, usize), Error> {
    let mut r = Reader {
        bytes: unsigned,
        offset: 37,
    };
    if r.byte()? != 3 {
        return Err(Error::Encoding);
    }
    match r.byte()? {
        0 => {
            r.take(64)?;
        }
        1 => {
            r.take(96)?;
        }
        _ => return Err(Error::Encoding),
    }
    r.take(24)?;
    r.optional(32)?;
    let opcode = r.offset;
    match r.byte()? {
        0 | 8 => {
            match r.byte()? {
                0 => (),
                1 => {
                    r.take(16)?;
                }
                _ => return Err(Error::Encoding),
            };
            r.text()?;
            r.optional(96)?;
            r.optional(64)?;
        }
        1 | 9 => {
            r.take(32)?;
            r.text()?;
            let n = usize::from(r.byte()?);
            r.take(n * 32)?;
        }
        _ => return Err(Error::Encoding),
    }
    Ok((opcode, r.offset))
}
pub fn sign_revision(
    key: &SigningKey,
    body: Body,
    facets: Vec<Facet>,
    encoding: Encoding,
) -> Result<Vec<u8>, Error> {
    let annotated = FacetedText::new(body_text(&body)?.clone(), facets)?;
    let legacy = UnsignedRecord::new(key.verifying_key().to_bytes(), body)?
        .sign_with_key(key)?
        .finish()?
        .encode();
    let n = u32::from_be_bytes(legacy[..4].try_into().map_err(|_| Error::Encoding)?) as usize;
    let mut unsigned = legacy[4..4 + n].to_vec();
    let (opcode, end) = offsets(&unsigned)?;
    if end != unsigned.len() {
        return Err(Error::Encoding);
    }
    unsigned[opcode] += 8;
    if encoding == Encoding::EnvelopeV2 {
        unsigned[4] = 2;
    }
    put_facets(annotated.facets(), &mut unsigned);
    if unsigned.len() + 69 > MAX_RECORD_BYTES {
        return Err(Error::Bounds);
    }
    let signature = key
        .sign(&transcript(digest(&unsigned, encoding), encoding))
        .to_bytes();
    let mut result = (unsigned.len() as u32).to_be_bytes().to_vec();
    result.extend_from_slice(&unsigned);
    result.extend_from_slice(&signature);
    result.push(0);
    Ok(result)
}
pub fn verify_revision(bytes: &[u8]) -> Result<Revision, Error> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::Bounds);
    }
    let mut r = Reader { bytes, offset: 0 };
    let n = u32::from_be_bytes(r.take(4)?.try_into().map_err(|_| Error::Encoding)?) as usize;
    let unsigned = r.take(n)?;
    let signature = Signature::from_bytes(r.take(64)?.try_into().map_err(|_| Error::Encoding)?);
    if r.byte()? != 0 || r.offset != bytes.len() || unsigned.len() < 37 || &unsigned[..4] != b"VHSO"
    {
        return Err(Error::Encoding);
    }
    let encoding = match unsigned[4] {
        1 => Encoding::NewOpcodesV1,
        2 => Encoding::EnvelopeV2,
        _ => return Err(Error::Encoding),
    };
    let (opcode, base_end) = offsets(unsigned)?;
    if ![8, 9].contains(&unsigned[opcode]) {
        return Err(Error::Encoding);
    }
    let mut fr = Reader {
        bytes: unsigned,
        offset: base_end,
    };
    let count = usize::from(fr.byte()?);
    if count > MAX_FACETS {
        return Err(Error::Bounds);
    }
    let mut facets = Vec::with_capacity(count);
    for _ in 0..count {
        let start = fr.u16()?;
        let end = fr.u16()?;
        let kind = match fr.byte()? {
            0 => Kind::Mention(Target::Owner(OwnerId::from_bytes(fr.id()?))),
            1 => Kind::Mention(Target::Agent(AgentId::from_bytes(fr.id()?))),
            2 => {
                let n = usize::from(fr.byte()?);
                if n > 48 {
                    return Err(Error::Bounds);
                }
                Kind::Tag(String::from(
                    core::str::from_utf8(fr.take(n)?).map_err(|_| Error::Encoding)?,
                ))
            }
            _ => return Err(Error::Encoding),
        };
        facets.push(Facet { start, end, kind });
    }
    if fr.offset != unsigned.len() {
        return Err(Error::Encoding);
    }
    // Reconstruct only for the existing structural validator. Zero signature is
    // never verified or exposed as evidence; original candidate transcript is verified below.
    let mut legacy_unsigned = unsigned[..base_end].to_vec();
    legacy_unsigned[4] = 1;
    legacy_unsigned[opcode] -= 8;
    let mut legacy = (legacy_unsigned.len() as u32).to_be_bytes().to_vec();
    legacy.extend_from_slice(&legacy_unsigned);
    legacy.extend_from_slice(&[0; 65]);
    let structural = SignedRecord::decode(&legacy)?;
    let annotated = FacetedText::new(body_text(structural.body())?.clone(), facets)?;
    let key = VerifyingKey::from_bytes(unsigned[5..37].try_into().map_err(|_| Error::Encoding)?)
        .map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    let id = digest(unsigned, encoding);
    key.verify_strict(&transcript(id, encoding), &signature)
        .map_err(|_| Error::Signature)?;
    Ok(Revision {
        id,
        body: structural.body().clone(),
        annotated,
        encoding,
    })
}

/// Frozen legacy operation-vocabulary adapter. The maintained decoder now knows
/// opcodes8/9; this explicit gate models the pre-extension vocabulary while
/// sharing the unchanged v1 structural codec. It is not a second full decoder.
pub fn decode_legacy(raw: &[u8]) -> Result<SignedRecord, Error> {
    let record = SignedRecord::decode(raw)?;
    if let Body::Social { operation, .. } = record.body() {
        match operation {
            Operation::Post { .. }
            | Operation::Revise { .. }
            | Operation::Retract { .. }
            | Operation::Repost { .. }
            | Operation::React { .. }
            | Operation::Follow { .. }
            | Operation::AgentBio { .. }
            | Operation::OwnerProfile { .. } => (),
            _ => return Err(Error::Encoding),
        }
    }
    Ok(record)
}
