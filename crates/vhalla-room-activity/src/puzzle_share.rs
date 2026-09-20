//! Optional multipart puzzle artifacts carried as ordinary signed room text.
//!
//! This codec does not change the activity protocol or authorize publication.
//! A collector authenticates only that the selected application key signed all
//! collected parts in the selected full room scope. It proves no room admission,
//! current policy, Clankdar issuer identity, answer authorship beyond those signed
//! bytes, successful solve, or complete history. Adapters must publish only safe
//! public projections: this opaque byte codec cannot detect private tickets,
//! seeds, answers intended to remain private, or hidden-pool labels.
//!
//! A receiver explicitly selects one artifact. Its derived partial assembly can
//! be discarded and rebuilt without deleting any signed event or author floor.
//! No incoming part creates another collector or grows an unbounded registry.

use alloc::{format, string::String, vec, vec::Vec};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use crate::{checked_key, Content, RoomScope, Text, VerifiedEvent, MAX_TEXT_BYTES};

const PREFIX: &str = "vhalla-puzzle-share/1";
/// Exact raw bytes in every nonfinal part.
pub const CHUNK_BYTES: usize = 2800;
/// Maximum nonempty artifact, checked before packing or assembly allocation.
pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
/// Maximum parts, derived from the fixed artifact and chunk bounds (94).
pub const MAX_PARTS: usize = MAX_ARTIFACT_BYTES.div_ceil(CHUNK_BYTES);

/// Public artifact roles only; these labels do not validate the enclosed JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Public challenge projection, never issuer-private session/ticket state.
    PublicChallenges,
    /// Responses to a public session, deliberately shared with the room.
    Responses,
    /// Existing signed Clankdar admission; validity is checked separately.
    Admission,
}
impl Kind {
    /// Canonical inert-text tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicChallenges => "public-challenges",
            Self::Responses => "responses",
            Self::Admission => "admission",
        }
    }
    fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "public-challenges" => Ok(Self::PublicChallenges),
            "responses" => Ok(Self::Responses),
            "admission" => Ok(Self::Admission),
            _ => Err(Error::Encoding),
        }
    }
}
/// Bounded codec or explicitly selected assembly refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Empty/oversized artifact, part, or impossible chunk geometry.
    Bounds,
    /// Noncanonical text, integer, digest, base64url, or unknown format/kind.
    Encoding,
    /// Invalid explicitly selected full room scope or author key.
    Selection,
    /// This event does not belong to the selected full room scope and author.
    Scope,
    /// This part names another kind or digest; the collector is unchanged.
    Artifact,
    /// Selected parts disagree on metadata or exact bytes at an index.
    Conflict,
    /// All parts arrived but their exact assembled digest does not match.
    Digest,
    /// No complete verified artifact is available yet.
    Incomplete,
    /// A prior selected conflict/digest mismatch poisoned this collector.
    Failed,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl core::error::Error for Error {}

/// One bounded canonical part. Parsing authenticates neither source nor content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Part {
    kind: Kind,
    digest: [u8; 32],
    artifact_len: usize,
    index: usize,
    count: usize,
    data: Vec<u8>,
}
impl Part {
    /// Parse six exact ASCII lines with no final newline. All size and geometry
    /// checks occur before decoded-data allocation; the scratch buffer is fixed.
    pub fn decode(raw: &str) -> Result<Self, Error> {
        if raw.len() > MAX_TEXT_BYTES {
            return Err(Error::Bounds);
        }
        let mut lines = raw.split('\n');
        if lines.next() != Some(PREFIX) {
            return Err(Error::Encoding);
        }
        let kind = Kind::parse(lines.next().ok_or(Error::Encoding)?)?;
        let digest = parse_digest(lines.next().ok_or(Error::Encoding)?)?;
        let artifact_len = decimal(lines.next().ok_or(Error::Encoding)?)?;
        if artifact_len == 0 || artifact_len > MAX_ARTIFACT_BYTES {
            return Err(Error::Bounds);
        }
        let (index, count) = lines
            .next()
            .and_then(|line| line.split_once('/'))
            .ok_or(Error::Encoding)?;
        let index = decimal(index)?;
        let count = decimal(count)?;
        if count != artifact_len.div_ceil(CHUNK_BYTES) || count > MAX_PARTS || index >= count {
            return Err(Error::Bounds);
        }
        let encoded = lines.next().ok_or(Error::Encoding)?;
        if lines.next().is_some() {
            return Err(Error::Encoding);
        }
        let expected = chunk_len(artifact_len, index);
        // ceil(raw_bits / 6) without padding. Fixed bounds make arithmetic safe.
        if encoded.len() != (expected * 8).div_ceil(6) {
            return Err(Error::Bounds);
        }
        let mut decoded = [0u8; CHUNK_BYTES + 2];
        let written = URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut decoded)
            .map_err(|_| Error::Encoding)?;
        if written != expected {
            return Err(Error::Bounds);
        }
        Ok(Self {
            kind,
            digest,
            artifact_len,
            index,
            count,
            data: decoded[..written].to_vec(),
        })
    }
    /// Canonical claimed artifact role.
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Full exact-byte SHA-256, unverified until collection completes.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Exact total raw bytes claimed for this artifact.
    pub const fn artifact_len(&self) -> usize {
        self.artifact_len
    }
    /// Zero-based part index.
    pub const fn index(&self) -> usize {
        self.index
    }
    /// Exact derived part count, at most 94.
    pub const fn count(&self) -> usize {
        self.count
    }
    /// This part's decoded bytes, at most 2800; no artifact validity is implied.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// Return the canonical ordinary Text carried by an existing activity event.
    pub fn encode(&self) -> Text {
        let encoded = format!(
            "{PREFIX}\n{}\n{}\n{}\n{}/{}\n{}",
            self.kind.as_str(),
            digest_hex(&self.digest),
            self.artifact_len,
            self.index,
            self.count,
            URL_SAFE_NO_PAD.encode(&self.data)
        );
        // Private constructors bound every field; the largest output is below 4096 bytes.
        Text(encoded)
    }
}

/// Split a nonempty bounded artifact without interpreting or transforming bytes.
/// Every result must still use the existing reserve-before-sign/outbox workflow.
pub fn pack(kind: Kind, raw: &[u8]) -> Result<Vec<Text>, Error> {
    if raw.is_empty() || raw.len() > MAX_ARTIFACT_BYTES {
        return Err(Error::Bounds);
    }
    let digest: [u8; 32] = Sha256::digest(raw).into();
    let count = raw.len().div_ceil(CHUNK_BYTES);
    Ok(raw
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, data)| {
            Part {
                kind,
                digest,
                artifact_len: raw.len(),
                index,
                count,
                data: data.to_vec(),
            }
            .encode()
        })
        .collect())
}

/// Effect of one matching, signature-verified event on the selected collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectStatus {
    /// A previously absent part was retained; more parts are needed.
    Added,
    /// Exact bytes were already retained; no progress or storage growth occurred.
    Duplicate,
    /// All parts are present and the exact assembled SHA-256 matches.
    Complete,
}
/// Volatile, one-artifact assembly; it grants no policy or execution authority.
/// Conflicting selected evidence or a wrong final digest permanently poisons it.
/// Dropping it discards only derived assembly, never original signed evidence.
pub struct Collector {
    scope: RoomScope,
    author: [u8; 32],
    kind: Kind,
    digest: [u8; 32],
    data: Vec<u8>,
    present: [bool; MAX_PARTS],
    total: Option<usize>,
    received: usize,
    complete: bool,
    failed: bool,
}
impl Collector {
    /// Explicitly select one exact full scope/key/kind/digest without allocating
    /// artifact storage. The first matching canonical part fixes length/count.
    pub fn new(
        scope: RoomScope,
        author: [u8; 32],
        kind: Kind,
        digest: [u8; 32],
    ) -> Result<Self, Error> {
        scope.check().map_err(|_| Error::Selection)?;
        checked_key(&author).map_err(|_| Error::Selection)?;
        Ok(Self {
            scope,
            author,
            kind,
            digest,
            data: Vec::new(),
            present: [false; MAX_PARTS],
            total: None,
            received: 0,
            complete: false,
            failed: false,
        })
    }
    /// Consume only an already strictly signature-verified event. Signature
    /// verification alone does not establish admission, policy or author-chain order.
    /// Parts may arrive reordered or interleaved with other ordinary activity.
    pub fn push(&mut self, event: &VerifiedEvent) -> Result<CollectStatus, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        let claims = event.claims();
        if claims.scope != self.scope || claims.author != self.author {
            return Err(Error::Scope);
        }
        let Content::Text(text) = &claims.content;
        let part = Part::decode(text.as_str())?;
        if part.kind != self.kind || part.digest != self.digest {
            return Err(Error::Artifact);
        }
        if let Some(total) = self.total {
            if total != part.count || self.data.len() != part.artifact_len {
                self.failed = true;
                return Err(Error::Conflict);
            }
        } else {
            self.data = vec![0; part.artifact_len];
            self.total = Some(part.count);
        }
        let start = part.index * CHUNK_BYTES;
        let end = start + part.data.len();
        if self.present[part.index] {
            if self.data[start..end] != part.data {
                self.failed = true;
                return Err(Error::Conflict);
            }
            return Ok(CollectStatus::Duplicate);
        }
        self.data[start..end].copy_from_slice(&part.data);
        self.present[part.index] = true;
        self.received += 1;
        if self.received == part.count {
            let digest: [u8; 32] = Sha256::digest(&self.data).into();
            if digest != self.digest {
                self.failed = true;
                return Err(Error::Digest);
            }
            self.complete = true;
            Ok(CollectStatus::Complete)
        } else {
            Ok(CollectStatus::Added)
        }
    }
    /// Number of distinct retained part indexes; duplicate copies do not count.
    pub const fn received(&self) -> usize {
        self.received
    }
    /// First matching part's exact total, or None before any part is retained.
    pub const fn total(&self) -> Option<usize> {
        self.total
    }
    /// Borrow exact assembled bytes only after completion and absent conflicts.
    pub fn bytes(&self) -> Option<&[u8]> {
        (self.complete && !self.failed).then_some(self.data.as_slice())
    }
    /// Consume a completed collector without another artifact-size allocation.
    pub fn into_bytes(self) -> Result<Vec<u8>, Error> {
        if self.failed {
            Err(Error::Failed)
        } else if self.complete {
            Ok(self.data)
        } else {
            Err(Error::Incomplete)
        }
    }
}

fn chunk_len(length: usize, index: usize) -> usize {
    (length - index * CHUNK_BYTES).min(CHUNK_BYTES)
}
fn decimal(raw: &str) -> Result<usize, Error> {
    if raw.is_empty()
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Encoding);
    }
    raw.parse().map_err(|_| Error::Bounds)
}
fn parse_digest(raw: &str) -> Result<[u8; 32], Error> {
    if raw.len() != 64 {
        return Err(Error::Encoding);
    }
    let mut digest = [0; 32];
    for (out, pair) in digest.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
        let nibble = |v| match v {
            b'0'..=b'9' => Ok(v - b'0'),
            b'a'..=b'f' => Ok(v - b'a' + 10),
            _ => Err(Error::Encoding),
        };
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(digest)
}
fn digest_hex(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
    }
    out
}

#[cfg(test)]
#[path = "puzzle_share_tests.rs"]
mod tests;
