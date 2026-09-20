//! Encrypted transaction contract for backend implementers. This module does not
//! implement filesystem or IndexedDB durability. A backend must pass independent
//! crash, quota, cancellation and concurrency qualification before product use.

use core::future::Future;

use crate::{Context, Error, OperationId, MAX_IMAGE_BYTES, MAX_STORED_RECORD_BYTES};

/// Opaque authenticated current-state bytes. Never contains plaintext provider
/// state, wire output, an application message, or a raw key accessible by this API.
#[derive(Clone, Eq, PartialEq)]
pub struct Image(pub(crate) Vec<u8>);
impl Image {
    /// Apply a fixed input budget before copying untrusted stored bytes. The
    /// kernel, not this constructor, authenticates their meaning and context.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 40 || bytes.len() > MAX_IMAGE_BYTES {
            return Err(Error::Bounds);
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Borrow only encrypted storage bytes for exact CAS and persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Closed immutable record-key vocabulary. Metadata is not hidden from the
/// trusted local backend; the backend must never expose it via public discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RecordKey {
    /// Published outbox index, starting at one.
    Outbox(u64),
    /// Published inbox index, starting at one.
    Inbox(u64),
    /// Exact operation-to-outbox index; retries cannot overwrite it.
    Operation(OperationId),
    /// Exact received-wire commitment-to-inbox index.
    Received([u8; 32]),
    /// Nonzero owner-control sequence. Its encrypted payload still requires
    /// private protocol and retained-state verification by the kernel.
    Control(u64),
}
impl RecordKey {
    /// Validate counter/sentinel shape before a backend chooses any path or key.
    pub fn validate(self) -> Result<(), Error> {
        match self {
            Self::Outbox(0) | Self::Inbox(0) | Self::Control(0) => Err(Error::Encoding),
            Self::Received(hash) if hash == [0; 32] => Err(Error::Encoding),
            _ => Ok(()),
        }
    }
    /// Canonical closed key encoding; call validate before accepting an offered
    /// key. No untrusted strings or filesystem path components are carried.
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Outbox(n) => {
                out.push(1);
                out.extend(n.to_be_bytes());
            }
            Self::Inbox(n) => {
                out.push(2);
                out.extend(n.to_be_bytes());
            }
            Self::Operation(id) => {
                out.push(3);
                out.extend(id.0);
            }
            Self::Received(hash) => {
                out.push(4);
                out.extend(hash);
            }
            Self::Control(n) => {
                out.push(5);
                out.extend(n.to_be_bytes());
            }
        }
        out
    }
}

/// One encrypted immutable record, inaccessible as wire/plaintext without the
/// kernel's custody key and exact room/device/key AAD.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredRecord {
    pub(crate) key: RecordKey,
    pub(crate) bytes: Vec<u8>,
}
impl StoredRecord {
    /// Bound raw bytes before copying. This does not authenticate the payload.
    pub fn from_bytes(key: RecordKey, bytes: &[u8]) -> Result<Self, Error> {
        key.validate()?;
        if bytes.len() < 40 || bytes.len() > MAX_STORED_RECORD_BYTES {
            return Err(Error::Bounds);
        }
        Ok(Self {
            key,
            bytes: bytes.to_vec(),
        })
    }
    /// Exact immutable key, including the full operation ID where applicable.
    pub fn key(&self) -> RecordKey {
        self.key
    }
    /// Borrow encrypted bytes only.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Backend failure classification. Never report an uncertain write as refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Exact image CAS or immutable record collision refused without effects.
    Conflict,
    /// The complete transaction certainly had no effects.
    Refused,
    /// Some effects may have committed; reopen/reconcile is mandatory.
    Uncertain,
    /// Damaged, foreign, missing-half or otherwise ambiguous existing state.
    Corrupt,
}

/// Trusted atomic encrypted-state store, exclusively borrowed during each call.
///
/// Implementations receive encrypted bytes only. They must never reenter custody,
/// invoke application/network callbacks, or claim persistence before transaction
/// completion. `publish` must atomically compare the entire expected image,
/// preserve every existing immutable key, append all offered records and replace
/// the current image. `expected=None` requires a completely unused namespace,
/// including no orphan records: an absent head is never reset authorization.
///
/// Success requires the backend's qualified durable completion barrier. Rejected
/// CAS or immutable-key collision must have no effects. Interrupted/canceled
/// transactions with uncertain results must preserve evidence and require reopen;
/// reads never repair or discard malformed state. Exactly scoped records remain
/// immutable and queryable for the lifetime of the store; no implicit pruning or
/// rollback is authorized. AEAD cannot detect a coherently rolled-back store.
///
/// A malicious implementation could lie about persistence. This interface is a
/// contract, not a claim of hardware durability or protection from the host.
pub trait Store {
    /// Read the exact authoritative image without repair. An absent value means
    /// genuinely unused state only; malformed or orphaned data must return error.
    fn load(&mut self, context: Context)
        -> impl Future<Output = Result<Option<Image>, StoreError>>;
    /// Read one immutable, fully scoped record without repairing anything. None
    /// means never published, not merely that a file is absent: the backend must
    /// retain a durable publication index/journal and refuse a missing published
    /// record. Otherwise a lost operation index could masquerade as a new request.
    fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> impl Future<Output = Result<Option<StoredRecord>, StoreError>>;
    /// Exact whole-image CAS plus at most MAX_TRANSACTION_RECORDS new encrypted
    /// immutable records (currently three). Preflight every key before any write.
    /// Never publish a record before its corresponding state transition.
    fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> impl Future<Output = Result<(), StoreError>>;
}
