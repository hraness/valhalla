//! Locally authenticated verified-state checkpoints, never peer snapshot trust.
//!
//! The authentication key is a private local storage capability. A public peer's
//! signature, snapshot checksum, or caller-supplied frontier cannot replace it.
//! Complete malicious rollback of the key and profile remains a host concern.

use crate::{Bootstrap, CertifiedClient, Error};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use vhalla_rooms::registry::{Registry, MAX_SNAPSHOT_BYTES as MAX_REGISTRY_BYTES};
use vhalla_rooms_consensus::{Application, Frontier};
use vhalla_social::archive::{Archive, MAX_SNAPSHOT_BYTES as MAX_ARCHIVE_BYTES};

const MAGIC: &[u8; 8] = b"VHRCP001";
const DOMAIN: &[u8] = b"vhalla/local-certified-checkpoint/v1\0";
const HEAD_BYTES: usize = 176;
/// Fixed authenticated frame prefix, before the bounded snapshot payload.
pub const CHECKPOINT_HEADER_BYTES: usize = 8 + 8 + 32 + 32 + 32 + 8;
/// Maximum complete authenticated image, independent of journal lifetime.
pub const MAX_CHECKPOINT_BYTES: usize =
    CHECKPOINT_HEADER_BYTES + HEAD_BYTES * 2 + 1 + 8 + MAX_REGISTRY_BYTES + MAX_ARCHIVE_BYTES + 32;
const MIN_PAYLOAD: usize = HEAD_BYTES + 1 + 8 + 40 + 28;

/// Full verified-position metadata. Constructing it alone grants no trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointHead {
    frontier: Frontier,
    bundle: [u8; 32],
}
impl CheckpointHead {
    /// Frame an expected full frontier and exact canonical bundle identity.
    pub fn new(frontier: Frontier, bundle: [u8; 32]) -> Result<Self, Error> {
        if (frontier.height == 0) != (bundle == [0; 32]) {
            return Err(Error::Checkpoint);
        }
        Ok(Self { frontier, bundle })
    }
    /// Complete frontier, not merely its height.
    pub const fn frontier(self) -> Frontier {
        self.frontier
    }
    /// Exact canonical bundle ID; zero only at genesis.
    pub const fn bundle_id(self) -> [u8; 32] {
        self.bundle
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.frontier.height.to_be_bytes());
        for value in [
            self.frontier.value,
            self.frontier.registry,
            self.frontier.social,
            self.frontier.control,
        ] {
            out.extend_from_slice(&value);
        }
        out.extend_from_slice(&self.frontier.time.to_be_bytes());
        out.extend_from_slice(&self.bundle);
    }
    fn read(input: &mut Reader<'_>) -> Result<Self, Error> {
        let frontier = Frontier {
            height: input.u64()?,
            value: input.array()?,
            registry: input.array()?,
            social: input.array()?,
            control: input.array()?,
            time: input.u64()?,
        };
        Self::new(frontier, input.array()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Anchor {
    pub head: CheckpointHead,
    pub matched: bool,
}

/// Snapshot issued only from a client that consumed verified certificates.
/// There is deliberately no constructor from arbitrary snapshot bytes.
pub struct CheckpointImage {
    network: [u8; 32],
    pin: [u8; 32],
    payload: Vec<u8>,
}
impl CheckpointImage {
    /// Authenticate this client-issued image with a storage-only secret.
    /// Generation and prior image hash are local CAS metadata, not consensus.
    pub fn seal(&self, key: &[u8; 32], generation: u64, previous: [u8; 32]) -> Vec<u8> {
        let mut raw = prefix(self.network, self.pin, generation, previous);
        raw.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        raw.extend_from_slice(&self.payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
        mac.update(DOMAIN);
        mac.update(&raw);
        raw.extend_from_slice(&mac.finalize().into_bytes());
        raw
    }
}

/// A successfully authenticated local frame. Private fields prevent constructing
/// this restoration token from an unverified snapshot or peer response.
pub struct AuthenticatedCheckpoint {
    raw: Vec<u8>,
    network: [u8; 32],
    pin: [u8; 32],
    generation: u64,
    previous: [u8; 32],
}
impl AuthenticatedCheckpoint {
    /// Authenticate bounded bytes before allocation or expensive snapshot decode.
    /// The key MUST come from the independently opened local custody profile.
    pub fn open(
        raw: &[u8],
        key: &[u8; 32],
        network: [u8; 32],
        pin: [u8; 32],
    ) -> Result<Self, Error> {
        if raw.len() < CHECKPOINT_HEADER_BYTES + MIN_PAYLOAD + 32
            || raw.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(Error::Bounds);
        }
        let mut input = Reader(raw);
        if input.take(8)? != MAGIC {
            return Err(Error::Encoding);
        }
        let generation = input.u64()?;
        let previous = input.array()?;
        if input.array::<32>()? != network || input.array::<32>()? != pin {
            return Err(Error::BootstrapPin);
        }
        let length = usize::try_from(input.u64()?).map_err(|_| Error::Bounds)?;
        if !(MIN_PAYLOAD..=MAX_CHECKPOINT_BYTES - CHECKPOINT_HEADER_BYTES - 32).contains(&length)
            || length != raw.len() - CHECKPOINT_HEADER_BYTES - 32
        {
            return Err(Error::Bounds);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed HMAC key");
        mac.update(DOMAIN);
        mac.update(&raw[..raw.len() - 32]);
        mac.verify_slice(&raw[raw.len() - 32..])
            .map_err(|_| Error::Authentication)?;
        Ok(Self {
            raw: raw.to_vec(),
            network,
            pin,
            generation,
            previous,
        })
    }
    /// Authenticated local generation, not adversarial disk rollback protection.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact preceding local image hash for a protected replacement.
    pub const fn previous(&self) -> [u8; 32] {
        self.previous
    }
    /// Content hash of this entire authenticated local image.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.raw).into()
    }
    /// Reconstruct bounded canonical states under the independently pinned origin.
    /// Historical authority was established by prior local certified replay, not
    /// by signatures inside the snapshots; the authentication above preserves it.
    pub fn restore(
        self,
        bootstrap: Bootstrap,
        expected_pin: [u8; 32],
    ) -> Result<CertifiedClient, Error> {
        if self.pin != expected_pin
            || bootstrap.pin != expected_pin
            || bootstrap.network != self.network
        {
            return Err(Error::BootstrapPin);
        }
        let mut input = Reader(&self.raw[CHECKPOINT_HEADER_BYTES..self.raw.len() - 32]);
        let head = CheckpointHead::read(&mut input)?;
        let tag = input.take(1)?[0];
        let anchor = match tag {
            0 => None,
            1 | 2 => Some(Anchor {
                head: CheckpointHead::read(&mut input)?,
                matched: tag == 1,
            }),
            _ => return Err(Error::Encoding),
        };
        if let Some(anchor) = anchor {
            if anchor.matched {
                if anchor.head.frontier.height > head.frontier.height
                    || (anchor.head.frontier.height == head.frontier.height && anchor.head != head)
                {
                    return Err(Error::Anchor);
                }
            } else if anchor.head.frontier.height <= head.frontier.height {
                return Err(Error::Anchor);
            }
        }
        let registry_raw = input.part(MAX_REGISTRY_BYTES)?;
        let social_raw = input.part(MAX_ARCHIVE_BYTES)?;
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        let registry = Registry::restore(registry_raw).map_err(|_| Error::Checkpoint)?;
        let social = Archive::from_snapshot(
            bootstrap.genesis.realm,
            bootstrap.genesis.limits,
            social_raw,
        )
        .map_err(|_| Error::Checkpoint)?;
        if registry.snapshot() != registry_raw
            || social.snapshot() != social_raw
            || registry.realm() != bootstrap.genesis.realm
            || registry.directory() != bootstrap.genesis.directory
            || registry.policy() != &bootstrap.genesis.policy
        {
            return Err(Error::Checkpoint);
        }
        if head.frontier.height == 0 {
            let genesis_registry = bootstrap.genesis.registry().map_err(|_| Error::Bootstrap)?;
            let genesis_app =
                Application::genesis(bootstrap.genesis.archive.clone(), genesis_registry);
            if head.frontier != genesis_app.frontier()
                || social_raw != bootstrap.genesis.archive.snapshot()
            {
                return Err(Error::Checkpoint);
            }
        }
        let application =
            Application::restore_locally_authenticated(social, registry, head.frontier)
                .map_err(|_| Error::Checkpoint)?;
        Ok(CertifiedClient {
            network: self.network,
            bootstrap: self.pin,
            application,
            schedule: bootstrap.schedule,
            last_bundle: head.bundle,
            anchor,
        })
    }
}

impl CertifiedClient {
    /// Exact installed verified position, including canonical bundle identity.
    pub fn checkpoint_head(&self) -> CheckpointHead {
        CheckpointHead {
            frontier: self.frontier(),
            bundle: self.last_bundle,
        }
    }
    /// Require exact retained policy ancestry. An unrelated earlier head cannot
    /// be blessed by merely locating it in a journal. A future head is compared
    /// during ordinary verified advancement, before installing that height.
    pub fn require_anchor(&mut self, head: CheckpointHead) -> Result<(), Error> {
        let current = self.checkpoint_head();
        if current == head {
            self.anchor = Some(Anchor {
                head,
                matched: true,
            });
        } else if self.anchor.is_some_and(|a| a.head == head && a.matched) {
            return Ok(());
        } else if head.frontier.height > current.frontier.height {
            self.anchor = Some(Anchor {
                head,
                matched: false,
            });
        } else {
            return Err(Error::Anchor);
        }
        Ok(())
    }
    /// Retained exact anchor and whether ordinary local replay established it.
    pub fn retained_anchor(&self) -> Option<(CheckpointHead, bool)> {
        self.anchor.map(|a| (a.head, a.matched))
    }
    /// Whether the requested retained anchor is established on this exact chain.
    pub fn anchor_matched(&self) -> bool {
        self.anchor.is_none_or(|a| a.matched)
    }
    /// Make a bounded canonical image from current verified in-memory state.
    /// This is not a persistence receipt; the host must authenticate/publish it.
    pub fn checkpoint_image(&self) -> Result<CheckpointImage, Error> {
        let registry = self.registry().snapshot();
        let social = self.archive().snapshot();
        if registry.len() > MAX_REGISTRY_BYTES || social.len() > MAX_ARCHIVE_BYTES {
            return Err(Error::Bounds);
        }
        let mut payload = Vec::new();
        self.checkpoint_head().encode(&mut payload);
        if let Some(anchor) = self.anchor {
            payload.push(if anchor.matched { 1 } else { 2 });
            anchor.head.encode(&mut payload);
        } else {
            payload.push(0);
        }
        for raw in [registry, social] {
            payload.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            payload.extend_from_slice(&raw);
        }
        Ok(CheckpointImage {
            network: self.network,
            pin: self.bootstrap,
            payload,
        })
    }
}

fn prefix(network: [u8; 32], pin: [u8; 32], generation: u64, previous: [u8; 32]) -> Vec<u8> {
    let mut raw = MAGIC.to_vec();
    raw.extend_from_slice(&generation.to_be_bytes());
    raw.extend_from_slice(&previous);
    raw.extend_from_slice(&network);
    raw.extend_from_slice(&pin);
    raw
}
/// Classify only an incomplete, unpublished successor scratch. Unknown scope,
/// stale predecessor/generation, complete frames and invalid length framing fail.
/// No accepted application or author state is inferred from this classification.
pub fn incomplete_successor(
    raw: &[u8],
    network: [u8; 32],
    pin: [u8; 32],
    generation: u64,
    previous: [u8; 32],
) -> Result<bool, Error> {
    if raw.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::Bounds);
    }
    let expected = prefix(network, pin, generation, previous);
    let available = raw.len().min(expected.len());
    if raw[..available] != expected[..available] {
        return Err(Error::Checkpoint);
    }
    let available_length =
        &raw[expected.len().min(raw.len())..raw.len().min(CHECKPOINT_HEADER_BYTES)];
    feasible_length(
        available_length,
        8,
        MIN_PAYLOAD,
        MAX_CHECKPOINT_BYTES - CHECKPOINT_HEADER_BYTES - 32,
    )?;
    if raw.len() < CHECKPOINT_HEADER_BYTES {
        return Ok(true);
    }
    let length = u64::from_be_bytes(
        raw[expected.len()..CHECKPOINT_HEADER_BYTES]
            .try_into()
            .map_err(|_| Error::Encoding)?,
    );
    let payload_len = usize::try_from(length).map_err(|_| Error::Bounds)?;
    let total = CHECKPOINT_HEADER_BYTES + payload_len + 32;
    if raw.len() > total {
        return Err(Error::Encoding);
    }
    let payload = &raw[CHECKPOINT_HEADER_BYTES..raw.len().min(total - 32)];
    partial_payload(payload, payload_len)?;
    Ok(raw.len() < total)
}
fn feasible_length(raw: &[u8], width: usize, min: usize, max: usize) -> Result<(), Error> {
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    high[8 - width..].fill(255);
    low[8 - width..8 - width + raw.len()].copy_from_slice(raw);
    high[8 - width..8 - width + raw.len()].copy_from_slice(raw);
    if u64::from_be_bytes(low) > max as u64 || u64::from_be_bytes(high) < min as u64 {
        return Err(Error::Bounds);
    }
    Ok(())
}
fn partial_payload(raw: &[u8], declared: usize) -> Result<(), Error> {
    if raw.len() < HEAD_BYTES {
        return Ok(());
    }
    let current = CheckpointHead::read(&mut Reader(raw))?;
    if raw.len() == HEAD_BYTES {
        return Ok(());
    }
    let tag = raw[HEAD_BYTES];
    let mut at = match tag {
        0 => HEAD_BYTES + 1,
        1 | 2 => HEAD_BYTES * 2 + 1,
        _ => return Err(Error::Encoding),
    };
    if declared < at + 8 + 40 + 28 {
        return Err(Error::Encoding);
    }
    if raw.len() < at {
        return Ok(());
    }
    if tag != 0 {
        let anchor = CheckpointHead::read(&mut Reader(&raw[HEAD_BYTES + 1..]))?;
        if (tag == 2 && anchor.frontier.height <= current.frontier.height)
            || (tag == 1
                && (anchor.frontier.height > current.frontier.height
                    || (anchor.frontier.height == current.frontier.height && anchor != current)))
        {
            return Err(Error::Anchor);
        }
    }
    for (index, (min, max)) in [(40, MAX_REGISTRY_BYTES), (28, MAX_ARCHIVE_BYTES)]
        .into_iter()
        .enumerate()
    {
        let available = raw.len().saturating_sub(at).min(4);
        feasible_length(
            &raw[at.min(raw.len())..at.min(raw.len()) + available],
            4,
            min,
            max,
        )?;
        if available < 4 {
            return Ok(());
        }
        let length = usize::try_from(u32::from_be_bytes(
            raw[at..at + 4].try_into().map_err(|_| Error::Encoding)?,
        ))
        .map_err(|_| Error::Bounds)?;
        at = at
            .checked_add(4)
            .and_then(|v| v.checked_add(length))
            .ok_or(Error::Bounds)?;
        if (index == 0 && at.checked_add(4 + 28).is_none_or(|v| v > declared))
            || (index == 1 && at != declared)
        {
            return Err(Error::Encoding);
        }
        if raw.len() < at {
            return Ok(());
        }
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if count > self.0.len() {
            return Err(Error::Encoding);
        }
        let (head, tail) = self.0.split_at(count);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn part(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let length =
            usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| Error::Bounds)?;
        if length > max {
            return Err(Error::Bounds);
        }
        self.take(length)
    }
}
