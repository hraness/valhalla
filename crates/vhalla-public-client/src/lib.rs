#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Portable certified room-directory replay with independently pinned genesis.
//!
//! This crate is a bounded full application replica, not a network stack,
//! validator, succinct light proof, storage engine or public room-activity
//! admission protocol. Preparing a candidate performs no persistence and never
//! advances the visible frontier. The caller owns durable publication.

mod bootstrap;
pub mod checkpoint;
pub use bootstrap::{
    Bootstrap, Validator, ValidatorActivation, MAX_BOOTSTRAP_BYTES, MAX_VALIDATORS,
    MAX_VALIDATOR_SETS,
};

use vhalla_journal::{Bundle, MAX_BUNDLE_BYTES};
use vhalla_rooms::registry::Registry;
use vhalla_rooms_consensus::{Application, Batch, Checked, Frontier};
use vhalla_rooms_node::{cert::verify_canonical_certificate, RoomValidatorSet, RoomValueId};
use vhalla_social::archive::Archive;

/// A closed rejection before state installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Byte/count bound, checked conversion or height capacity exceeded.
    Bounds,
    /// Unsupported, truncated, trailing or noncanonical encoding.
    Encoding,
    /// Full configuration does not match the independently retained pin.
    BootstrapPin,
    /// Invalid or internally inconsistent genesis configuration/evidence.
    Bootstrap,
    /// Invalid activation schedule, identity or checked voting-power arithmetic.
    Validators,
    /// Caller-supplied network differs from the immutable pinned origin.
    Network,
    /// Bundle does not name the exact next height; old/duplicate/future rejected.
    Height,
    /// Batch or bundle does not extend the complete current frontier.
    Frontier,
    /// Certificate, batch value or pinned validator quorum failed verification.
    Certificate,
    /// Deterministic signed application replay or its claimed result failed.
    Replay,
    /// A bundle annotation differs from the exact supported producer contract.
    BundleFields,
    /// Candidate was prepared under a different configuration or base frontier.
    StaleCandidate,
    /// Local checkpoint authentication failed.
    Authentication,
    /// Checkpoint state or canonical framing is inconsistent.
    Checkpoint,
    /// Exact retained policy ancestry does not match this chain.
    Anchor,
}

/// A private, move-only verified application candidate, not a durable receipt.
///
/// The host must atomically persist bundle_bytes() together with network_id(),
/// bootstrap_pin() and next_frontier() before calling commit_after_persist().
/// Dropping this value or a failed storage transaction leaves the client intact.
///
/// ```compile_fail
/// use vhalla_public_client::VerifiedCandidate;
/// fn forge() -> VerifiedCandidate { VerifiedCandidate { } }
/// ```
pub struct VerifiedCandidate {
    network: [u8; 32],
    bootstrap: [u8; 32],
    base: Frontier,
    checked: Checked,
    bundle: Bundle,
    anchor: Option<checkpoint::Anchor>,
}

impl VerifiedCandidate {
    /// Stable network scope to include in the host's storage transaction.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }
    /// Exact trusted configuration used to verify this candidate.
    pub const fn bootstrap_pin(&self) -> [u8; 32] {
        self.bootstrap
    }
    /// Exact prior frontier for host compare-and-swap publication.
    pub const fn base_frontier(&self) -> Frontier {
        self.base
    }
    /// Verified resulting frontier; it is not installed yet.
    pub fn next_frontier(&self) -> Frontier {
        self.checked.next()
    }
    /// Content identity of the exact verified bundle bytes.
    pub fn bundle_id(&self) -> [u8; 32] {
        self.bundle.id()
    }
    /// Exact immutable bytes to retain for incremental restart replay.
    pub fn bundle_bytes(&self) -> &[u8] {
        self.bundle.bytes()
    }
}

/// A portable read replica whose only advancement path consumes a checked bundle.
///
/// No unverified snapshot/frontier setter exists. Restart recovery uses retained
/// certified bundles from genesis or a locally authenticated checkpoint.
/// Caller budgets bound total work and retained disk history across operations.
pub struct CertifiedClient {
    network: [u8; 32],
    bootstrap: [u8; 32],
    application: Application,
    schedule: Vec<(u64, RoomValidatorSet)>,
    last_bundle: [u8; 32],
    anchor: Option<checkpoint::Anchor>,
}

impl CertifiedClient {
    /// Consume a validated bootstrap matching an independently retained full pin.
    ///
    /// Passing bootstrap.pin() without comparing independently trusted evidence
    /// is an explicit trust decision by the caller, not peer authentication.
    pub fn new(bootstrap: Bootstrap, expected_pin: [u8; 32]) -> Result<Self, Error> {
        if bootstrap.pin != expected_pin {
            return Err(Error::BootstrapPin);
        }
        let registry = bootstrap.genesis.registry().map_err(|_| Error::Bootstrap)?;
        let application = Application::genesis(bootstrap.genesis.archive, registry);
        Ok(Self {
            network: bootstrap.network,
            bootstrap: bootstrap.pin,
            application,
            schedule: bootstrap.schedule,
            last_bundle: [0; 32],
            anchor: None,
        })
    }

    /// Independently pinned immutable network origin.
    pub const fn network_id(&self) -> [u8; 32] {
        self.network
    }
    /// Exact complete configuration identity, including future rotations.
    pub const fn bootstrap_pin(&self) -> [u8; 32] {
        self.bootstrap
    }
    /// Current installed complete application frontier.
    pub fn frontier(&self) -> Frontier {
        self.application.frontier()
    }
    /// Current replayed directory, suitable for local bounded projections.
    pub fn registry(&self) -> &Registry {
        self.application.registry()
    }
    /// Current replayed signed social evidence; current meaning uses its views.
    pub fn archive(&self) -> &Archive {
        self.application.social()
    }

    /// Verify one next-height bundle without mutating the client or doing I/O.
    ///
    /// network identifies the response/request scope, independently of the
    /// supplying peer. Peers cannot substitute a validator schedule or genesis.
    /// Duplicate and reordered heights are rejected with Height and consume no
    /// retained queue; resume requesting from frontier().height + 1.
    pub fn prepare(&self, network: [u8; 32], raw: &[u8]) -> Result<VerifiedCandidate, Error> {
        if network != self.network {
            return Err(Error::Network);
        }
        if raw.len() > MAX_BUNDLE_BYTES {
            return Err(Error::Bounds);
        }
        let base = self.frontier();
        let height = base.height.checked_add(1).ok_or(Error::Bounds)?;
        let bundle = Bundle::decode(raw).map_err(|_| Error::Encoding)?;
        if bundle.height() != height {
            return Err(Error::Height);
        }
        if bundle.predecessor() != base.commitment() {
            return Err(Error::Frontier);
        }
        let batch_raw = bundle.field(3).ok_or(Error::Encoding)?;
        let batch = Batch::decode(batch_raw).map_err(|_| Error::Encoding)?;
        if batch.encode() != batch_raw {
            return Err(Error::Encoding);
        }
        if batch.parent != base {
            return Err(Error::Frontier);
        }
        let value = batch.value_id();
        if bundle.field(4) != Some(value.as_slice()) {
            return Err(Error::Certificate);
        }
        let certificate = bundle.field(0).ok_or(Error::Encoding)?;
        let validators = self
            .schedule
            .iter()
            .rev()
            .find(|(from, _)| *from <= height)
            .map(|(_, set)| set)
            .ok_or(Error::Validators)?;
        if !verify_canonical_certificate(certificate, height, &RoomValueId(value), validators) {
            return Err(Error::Certificate);
        }
        let checked = self
            .application
            .validate(&batch)
            .map_err(|_| Error::Replay)?;
        let next = checked.next();
        if next.height != height || bundle.next() != next.commitment() {
            return Err(Error::Frontier);
        }
        // Compare EVERY field against the maintained producer contract. A
        // valid certificate authenticates the batch; it does not independently
        // authenticate arbitrary journal annotations, so substitutions must be
        // rejected. Bundle::decode already proved canonical framing (magic,
        // nine length-prefixed fields, bounds, no trailing bytes); the
        // certificate, both frontiers, the batch bytes, the value id and the
        // height are verified above. Checking the remaining annotation fields
        // in place is byte-equality with the rebuilt canonical bundle without
        // copying and re-serializing every field again.
        if bundle.field(5) != Some(self.registry().policy().id().as_bytes().as_slice())
            || bundle.field(6) != Some(next.control.as_slice())
            || bundle.field(7) != Some(next.value.as_slice())
        {
            return Err(Error::BundleFields);
        }
        let next_head = checkpoint::CheckpointHead::new(next, bundle.id())?;
        if self.anchor.is_some_and(|anchor| {
            !anchor.matched
                && anchor.head.frontier().height == next.height
                && anchor.head != next_head
        }) {
            return Err(Error::Anchor);
        }
        Ok(VerifiedCandidate {
            network: self.network,
            bootstrap: self.bootstrap,
            base,
            checked,
            bundle,
            anchor: self.anchor,
        })
    }

    /// Install a candidate AFTER the host reports its storage transaction complete.
    ///
    /// Calling this function is the caller's explicit acknowledgement of durable
    /// publication; portable Rust cannot observe IndexedDB/filesystem durability.
    /// Store exact bundle bytes and the scoped next frontier atomically using the
    /// candidate's base as a compare-and-swap guard. On uncertain storage outcome,
    /// reconcile retained bytes before calling this or accepting another write.
    ///
    /// Foreign-network/configuration and stale-base candidates cannot install,
    /// even if another client produced the private candidate. Identical pinned
    /// configuration and exact base state intentionally permit safe transfer.
    pub fn commit_after_persist(
        &mut self,
        candidate: VerifiedCandidate,
    ) -> Result<Frontier, Error> {
        if candidate.network != self.network
            || candidate.bootstrap != self.bootstrap
            || candidate.base != self.frontier()
            || candidate.anchor != self.anchor
            || candidate.checked.batch().parent != self.frontier()
        {
            return Err(Error::StaleCandidate);
        }
        let next =
            checkpoint::CheckpointHead::new(candidate.checked.next(), candidate.bundle.id())?;
        if self.anchor.is_some_and(|anchor| {
            !anchor.matched
                && anchor.head.frontier().height == next.frontier().height
                && anchor.head != next
        }) {
            return Err(Error::Anchor);
        }
        self.last_bundle = candidate.bundle.id();
        self.application.apply_locally(candidate.checked);
        if let Some(anchor) = &mut self.anchor {
            if anchor.head == next {
                anchor.matched = true;
            }
        }
        Ok(self.frontier())
    }
}

#[cfg(test)]
mod tests;
