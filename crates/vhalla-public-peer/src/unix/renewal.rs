//! Durable monotone advertisement publication owned by the serving process.
use super::*;
use sha2::{Digest, Sha256};
use std::{fs, io::Write};
use vhalla_custody as custody;
use vhalla_public_protocol::{AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION};

/// Signed route lifetime (24 hours); renewal is attempted after half its lifetime.
pub const ADVERTISEMENT_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const RENEW_MARGIN: u64 = ADVERTISEMENT_LIFETIME_SECONDS / 2;
const MAGIC: &[u8; 5] = b"VHPS\x01";
const RESERVATION_BYTES: usize = 5 + 32 * 3 + 8 * 2 + 32;
const ADVERTISEMENT: &str = "advertisement";
const SEQUENCE: &str = "sequence";

/// A process-owned advertisement publisher; activity requires explicit opt-in.
/// State and custody locks are retained until all owner references are dropped.
/// Only create() creates a state directory; open() never reconstructs a missing
/// reservation from an advertisement or resets a counter.
pub struct ManagedPeer {
    peer: Arc<Peer>,
    publisher: Mutex<Publisher>,
}
impl ManagedPeer {
    /// Create an entirely new private publisher state directory. The configured
    /// advertisement_file must be STATE/advertisement. Existing paths fail.
    /// Reservation and publication are durably completed before any bind.
    pub fn create(config: Config, state_dir: impl AsRef<Path>) -> Result<Self, Error> {
        Self::start(config, state_dir.as_ref(), true)
    }
    /// Reopen existing private state, reconcile fully validated reservation/temp
    /// evidence, skip every reserved sequence, and publish a fresh higher one.
    /// Interrupted unpublished preparation is discarded only against validated
    /// committed state. Corrupt authoritative evidence, a missing reservation,
    /// changed scope or clock rollback fail closed without resetting a floor.
    pub fn open(config: Config, state_dir: impl AsRef<Path>) -> Result<Self, Error> {
        Self::start(config, state_dir.as_ref(), false)
    }
    /// Create NEW publisher state explicitly advertising durable public activity.
    /// Stores must already exist; this never migrates a READ publisher in place.
    pub fn create_with_activity(
        config: Config,
        state_dir: impl AsRef<Path>,
        activity: ActivityConfig,
    ) -> Result<Self, Error> {
        Self::start_mode(config, state_dir.as_ref(), true, Some(activity))
    }
    /// Reopen with the exact retained activity configuration. Ordinary open
    /// refuses this mode rather than silently downgrading a PUBLISH claim.
    pub fn open_with_activity(
        config: Config,
        state_dir: impl AsRef<Path>,
        activity: ActivityConfig,
    ) -> Result<Self, Error> {
        Self::start_mode(config, state_dir.as_ref(), false, Some(activity))
    }
    fn start(config: Config, state_dir: &Path, create: bool) -> Result<Self, Error> {
        Self::start_mode(config, state_dir, create, None)
    }
    fn start_mode(
        config: Config,
        state_dir: &Path,
        create: bool,
        activity: Option<ActivityConfig>,
    ) -> Result<Self, Error> {
        let state_dir = custody::absolute(state_dir).map_err(Error::Custody)?;
        if custody::absolute(&config.advertisement_file).map_err(Error::Custody)?
            != state_dir.join(ADVERTISEMENT)
        {
            return Err(Error::Config);
        }
        let loaded = Peer::load(&config)?;
        let identity = Identity::open(&config.identity_dir).map_err(Error::Identity)?;
        let scope = Scope {
            network: loaded.network,
            key: identity.public_key(),
            endpoint: config.public_endpoint.clone(),
        };
        let mode = activity
            .as_ref()
            .map(activity_mode::config_digest)
            .transpose()?;
        let open_activity = || {
            activity
                .as_ref()
                .map(|activity| {
                    super::activity::ActivityService::open(
                        &loaded.raw,
                        config.bootstrap_pin,
                        activity.clone(),
                    )
                })
                .transpose()
        };
        let clock = now()?;
        let (mut publisher, service) = if create {
            // Refuse missing/foreign stores before creating a new publisher.
            let service = open_activity()?;
            let mut publisher = Publisher::create(&state_dir, scope, clock)?;
            if let Some(mode) = mode {
                publisher.create_activity_mode(mode)?;
            }
            (publisher, service)
        } else {
            // Validate retained mode before opening stores: their recovery must
            // never run for a configuration rejected by this publisher.
            let publisher = Publisher::open_mode(&state_dir, scope, clock, mode)?;
            (publisher, open_activity()?)
        };
        let raw = publisher.publish(&identity, clock, None)?;
        let peer = Arc::new(Peer::finish_with_activity(
            config, loaded, identity, raw, true, service,
        )?);
        Ok(Self {
            peer,
            publisher: Mutex::new(publisher),
        })
    }
    /// Explicitly enable bounded peer discovery; publication mode is unchanged.
    pub fn enable_discovery(&self, config: DiscoveryConfig) -> Result<(), Error> {
        self.peer.enable_discovery(config)
    }

    /// The exact currently served signed route, after freshness and publisher
    /// health checks. This is a route hint, never room or validator authority.
    pub fn current_public_advertisement(&self) -> Result<PeerAdvertisement, Error> {
        let raw = self
            .peer
            .current_advertisement()
            .map_err(|_| Error::Advertisement)?;
        PeerAdvertisement::decode(&raw).map_err(|_| Error::Advertisement)
    }
    /// Sign only the current exact advertisement under a fully verified remote
    /// discovery challenge and solved work nonce. Renewal while solving causes
    /// an exact-advertisement mismatch; fetch a new challenge rather than reuse it.
    pub fn sign_discovery_registration(
        &self,
        challenge: vhalla_public_protocol::discovery::VerifiedRegistrationChallenge,
        nonce: u64,
    ) -> Result<vhalla_public_protocol::discovery::Registration, Error> {
        let unsigned = vhalla_public_protocol::discovery::UnsignedRegistration::new(
            self.current_public_advertisement()?,
            challenge,
            nonce,
        )
        .map_err(|_| Error::Advertisement)?;
        self.peer
            .identity
            .sign_peer_registration(unsigned)
            .map_err(|_| Error::Advertisement)
    }

    /// Complete application key for independent client proof selection.
    pub fn application_key(&self) -> [u8; 32] {
        self.peer.application_key()
    }
    /// Stable immutable-origin network scope.
    pub fn network_id(&self) -> [u8; 32] {
        self.peer.network_id()
    }
    /// Current fully published advertisement sequence (not wall-clock derived).
    pub fn advertisement_sequence(&self) -> Result<u64, Error> {
        Ok(self
            .publisher
            .lock()
            .map_err(|_| Error::State("publisher lock poisoned"))?
            .reservation
            .sequence)
    }
    /// Bind the checked loopback address; run() owns automatic renewal/shutdown.
    pub async fn bind(self: Arc<Self>) -> Result<ManagedBoundPeer, Error> {
        let bound = self.peer.clone().bind().await?;
        Ok(ManagedBoundPeer { owner: self, bound })
    }
    /// Explicitly reserve and publish a fresh advertisement under the current
    /// custody owner. After any uncertain write, this owner becomes unusable;
    /// reopen the state to reconcile it before trying again.
    pub fn renew(&self) -> Result<u64, Error> {
        self.renew_at(now()?, false, None)
    }
    fn renew_at(&self, clock: u64, only_if_due: bool, fault: Option<Fault>) -> Result<u64, Error> {
        let mut publisher = self
            .publisher
            .lock()
            .map_err(|_| Error::State("publisher lock poisoned"))?;
        let mut retained = self
            .peer
            .advertisement
            .lock()
            .map_err(|_| Error::State("advertisement lock poisoned"))?;
        if publisher.poisoned || !retained.serving {
            return Err(Error::State("publication uncertain; reopen state"));
        }
        if clock < publisher.reservation.issued {
            retained.serving = false;
            publisher.poisoned = true;
            return Err(Error::ClockRollback);
        }
        if only_if_due
            && clock.saturating_add(RENEW_MARGIN)
                < publisher
                    .reservation
                    .issued
                    .saturating_add(ADVERTISEMENT_LIFETIME_SECONDS)
        {
            return Ok(publisher.reservation.sequence);
        }
        // Managed reads use only this cache, never an unsynced visible rename.
        retained.serving = false;
        let raw = publisher.publish(&self.peer.identity, clock, fault)?;
        let parsed = PeerAdvertisement::decode(&raw).map_err(|_| Error::Advertisement)?;
        let floor = parsed
            .restore_sequence_anchor(self.peer.network)
            .map_err(|_| Error::Advertisement)?;
        *retained = RetainedAdvertisement {
            raw: Bytes::from(raw),
            floor,
            serving: true,
        };
        Ok(publisher.reservation.sequence)
    }
}

/// Bound loopback service with one owned, bounded renewal loop.
pub struct ManagedBoundPeer {
    owner: Arc<ManagedPeer>,
    bound: BoundPeer,
}
impl ManagedBoundPeer {
    /// Actual checked listener address.
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.bound.local_addr()
    }
    /// Serve until explicit shutdown or any publication/clock failure. Check
    /// renewal once per minute and renew with 12 hours remaining. No sequence is
    /// derived from the clock. A failed/timed-out renewal stops serving, and a
    /// bounded disk task can retain custody until its OS operation completes.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = self.bound.run(async {
            let _ = stopped.await;
        });
        let renewal = async {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let owner = self.owner.clone();
                let work = tokio::task::spawn_blocking(move || owner.renew_at(now()?, true, None));
                timeout(READ_TIMEOUT, work)
                    .await
                    .map_err(|_| Error::State("renewal timed out; reopen state"))?
                    .map_err(|_| Error::State("renewal task failed"))??;
            }
            #[allow(unreachable_code)]
            Ok::<(), Error>(())
        };
        tokio::pin!(server, renewal, shutdown);
        let outcome = tokio::select! {
            result = &mut server => return result,
            result = &mut renewal => result,
            _ = &mut shutdown => Ok(()),
        };
        let _ = stop.send(());
        let drain = server.await;
        outcome.and(drain)
    }
}

#[derive(Clone)]
struct Scope {
    network: [u8; 32],
    key: [u8; 32],
    endpoint: Endpoint,
}
impl Scope {
    fn unsigned_ad(
        &self,
        reservation: Reservation,
        capabilities: Capabilities,
    ) -> Result<UnsignedAdvertisement, Error> {
        UnsignedAdvertisement::new(AdvertisementClaims {
            network: self.network,
            application_key: self.key,
            sequence: reservation.sequence,
            issued_at: reservation.issued,
            expires_at: reservation
                .issued
                .checked_add(ADVERTISEMENT_LIFETIME_SECONDS)
                .ok_or(Error::State("clock overflow"))?,
            protocol: PROTOCOL_VERSION,
            capabilities,
            endpoints: vec![self.endpoint.clone()],
        })
        .map_err(|_| Error::Advertisement)
    }
    fn route_hash(&self) -> [u8; 32] {
        digest(
            b"vhalla/public-peer-route/v1\0",
            self.endpoint.as_str().as_bytes(),
        )
    }
    fn check_ad(&self, raw: &[u8], capabilities: Capabilities) -> Result<PeerAdvertisement, Error> {
        let ad = PeerAdvertisement::decode(raw)
            .map_err(|_| Error::State("invalid signed advertisement"))?;
        ad.restore_sequence_anchor(self.network)
            .map_err(|_| Error::State("invalid advertisement signature/scope"))?;
        let claims = ad.unverified_claims();
        if claims.application_key != self.key
            || claims.endpoints.as_slice() != [self.endpoint.clone()]
            || claims.capabilities != capabilities
        {
            return Err(Error::State("advertisement identity or route changed"));
        }
        Ok(ad)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Reservation {
    sequence: u64,
    issued: u64,
}
impl Reservation {
    fn encode(self, scope: &Scope) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&scope.network);
        out.extend_from_slice(&scope.key);
        out.extend_from_slice(&scope.route_hash());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.issued.to_be_bytes());
        out.extend_from_slice(&digest(b"vhalla/public-peer-sequence/v1\0", &out));
        out
    }
    fn decode(raw: &[u8], scope: &Scope) -> Result<Self, Error> {
        if raw.len() != RESERVATION_BYTES
            || &raw[..5] != MAGIC
            || raw[5..37] != scope.network
            || raw[37..69] != scope.key
            || raw[69..101] != scope.route_hash()
            || raw[117..] != digest(b"vhalla/public-peer-sequence/v1\0", &raw[..117])
        {
            return Err(Error::State("corrupt or foreign reservation"));
        }
        let sequence = u64::from_be_bytes(
            raw[101..109]
                .try_into()
                .map_err(|_| Error::State("sequence"))?,
        );
        let issued = u64::from_be_bytes(
            raw[109..117]
                .try_into()
                .map_err(|_| Error::State("issued"))?,
        );
        if sequence == 0 {
            return Err(Error::State("zero reservation"));
        }
        Ok(Self { sequence, issued })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    ReserveCreated,
    ReservePartial,
    ReserveFileSync,
    ReserveRename,
    ReserveDirSync,
    AdvertisementCreated,
    AdvertisementPartial,
    AdvertisementFileSync,
    AdvertisementRename,
    AdvertisementDirSync,
}
fn inject(selected: Option<Fault>, at: Fault) -> Result<(), Error> {
    if selected == Some(at) {
        Err(Error::State("injected uncertain publication"))
    } else {
        Ok(())
    }
}
struct Publisher {
    dir: PathBuf,
    directory: File,
    uid: u32,
    _lock: File,
    scope: Scope,
    reservation: Reservation,
    persisted: Option<Vec<u8>>,
    advertisement: Option<Vec<u8>>,
    poisoned: bool,
    activity_mode: Option<Vec<u8>>,
}
impl Publisher {
    fn create(dir: &Path, scope: Scope, clock: u64) -> Result<Self, Error> {
        let (directory, uid) = custody::create_private_directory(dir).map_err(Error::Custody)?;
        let lock = custody::create_private_file(&dir.join("lock")).map_err(Error::Custody)?;
        custody::acquire_exclusive(&lock).map_err(Error::Custody)?;
        lock.sync_all()?;
        directory.sync_all()?;
        File::open(dir.parent().ok_or(Error::Config)?)?.sync_all()?;
        Ok(Self {
            dir: dir.into(),
            directory,
            uid,
            _lock: lock,
            scope,
            reservation: Reservation {
                sequence: 0,
                issued: clock,
            },
            persisted: None,
            advertisement: None,
            poisoned: false,
            activity_mode: None,
        })
    }
    #[cfg(test)]
    fn open(dir: &Path, scope: Scope, clock: u64) -> Result<Self, Error> {
        Self::open_mode(dir, scope, clock, None)
    }
    fn open_mode(
        dir: &Path,
        scope: Scope,
        clock: u64,
        mode: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        let (directory, uid) = custody::open_private_directory(dir).map_err(Error::Custody)?;
        let lock = custody::open_private_file(&dir.join("lock"), uid, 0).map_err(Error::Custody)?;
        custody::acquire_exclusive(&lock).map_err(Error::Custody)?;
        let activity_mode = activity_mode::read_mode(dir, uid, &scope, mode)?;
        let capabilities = activity_mode::capabilities(activity_mode.is_some())?;
        for (index, entry) in fs::read_dir(dir)?.enumerate() {
            let entry = entry?;
            if index >= 6
                || (![
                    "lock",
                    SEQUENCE,
                    "sequence.tmp",
                    ADVERTISEMENT,
                    "advertisement.tmp",
                ]
                .iter()
                .any(|name| entry.file_name() == *name)
                    && !(activity_mode.is_some() && entry.file_name() == activity_mode::MODE))
            {
                return Err(Error::State("unexpected publisher artifact"));
            }
        }
        let committed = read_optional(dir, uid, SEQUENCE, RESERVATION_BYTES)?;
        let pending = read_optional(dir, uid, "sequence.tmp", RESERVATION_BYTES)?;
        let old = committed
            .as_deref()
            .map(|raw| Reservation::decode(raw, &scope))
            .transpose()?;
        let partial_sequence = pending
            .as_deref()
            .is_some_and(|raw| raw.len() < RESERVATION_BYTES);
        let next = if partial_sequence {
            let basis = old.ok_or(Error::State("partial reservation without a durable base"))?;
            check_partial_reservation(pending.as_deref().unwrap_or_default(), &scope, basis)?;
            None
        } else {
            pending
                .as_deref()
                .map(|raw| Reservation::decode(raw, &scope))
                .transpose()?
        };
        let reservation = match (old, next) {
            (None, None) => {
                return Err(Error::State(
                    "missing reservation; never reconstruct from advertisement",
                ))
            }
            (Some(a), Some(b)) => {
                if (a.sequence == b.sequence && a != b)
                    || (b.sequence > a.sequence && b.issued < a.issued)
                    || (a.sequence > b.sequence && a.issued < b.issued)
                {
                    return Err(Error::State("conflicting reservations"));
                }
                if b.sequence > a.sequence {
                    b
                } else {
                    a
                }
            }
            (Some(a), None) | (None, Some(a)) => a,
        };
        if clock < reservation.issued {
            return Err(Error::ClockRollback);
        }
        let advertisement = read_optional(dir, uid, ADVERTISEMENT, MAX_ADVERTISEMENT_BYTES)?;
        let pending_ad = read_optional(dir, uid, "advertisement.tmp", MAX_ADVERTISEMENT_BYTES)?;
        let partial_ad = if let Some(raw) = pending_ad.as_deref() {
            let expected = scope
                .unsigned_ad(reservation, capabilities)?
                .encoded_claims();
            if raw.len() < expected.len() + 64 {
                if pending.is_some() {
                    return Err(Error::State(
                        "partial advertisement with uncommitted reservation",
                    ));
                }
                let present = raw.len().min(expected.len());
                if raw[..present] != expected[..present] {
                    return Err(Error::State("foreign or conflicting partial advertisement"));
                }
                true
            } else {
                false
            }
        } else {
            false
        };
        if partial_sequence && pending_ad.is_some() {
            return Err(Error::State(
                "advertisement exists before its reservation publication",
            ));
        }
        let mut ads = Vec::new();
        for raw in [
            advertisement.as_deref(),
            pending_ad.as_deref().filter(|_| !partial_ad),
        ]
        .into_iter()
        .flatten()
        {
            let ad = scope.check_ad(raw, capabilities)?;
            let claims = ad.unverified_claims();
            if claims.sequence > reservation.sequence || claims.issued_at > reservation.issued {
                return Err(Error::State("advertisement exceeds durable reservation"));
            }
            ads.push(ad);
        }
        if ads.len() == 2
            && ads[0].unverified_claims().sequence == ads[1].unverified_claims().sequence
            && advertisement != pending_ad
        {
            return Err(Error::State(
                "conflicting signed advertisement at same sequence",
            ));
        }
        // Only validated artifacts are reconciled. Persist the highest floor
        // before discarding a temp; all later publications skip above it.
        if next == Some(reservation) && old != Some(reservation) {
            custody::open_private_file(&dir.join("sequence.tmp"), uid, RESERVATION_BYTES)
                .map_err(Error::Custody)?
                .sync_all()?;
            fs::rename(dir.join("sequence.tmp"), dir.join(SEQUENCE))?;
            directory.sync_all()?;
        } else {
            custody::open_private_file(&dir.join(SEQUENCE), uid, RESERVATION_BYTES)
                .map_err(Error::Custody)?
                .sync_all()?;
            directory.sync_all()?;
            if pending.is_some() {
                fs::remove_file(dir.join("sequence.tmp"))?;
                directory.sync_all()?;
            }
        }
        if pending_ad.is_some() {
            fs::remove_file(dir.join("advertisement.tmp"))?;
            directory.sync_all()?;
        }
        Ok(Self {
            dir: dir.into(),
            directory,
            uid,
            _lock: lock,
            scope: scope.clone(),
            reservation,
            persisted: Some(reservation.encode(&scope)),
            advertisement,
            poisoned: false,
            activity_mode,
        })
    }
    fn publish(
        &mut self,
        identity: &Identity,
        clock: u64,
        fault: Option<Fault>,
    ) -> Result<Vec<u8>, Error> {
        if self.poisoned {
            return Err(Error::State("uncertain publisher; reopen required"));
        }
        // Every failure after this point poisons this instance. Reopen is the
        // only recovery path; no blind retry can reuse a reserved sequence.
        self.poisoned = true;
        if clock < self.reservation.issued {
            return Err(Error::ClockRollback);
        }
        if read_optional(
            &self.dir,
            self.uid,
            activity_mode::MODE,
            activity_mode::MODE_BYTES,
        )? != self.activity_mode
            || read_optional(&self.dir, self.uid, SEQUENCE, RESERVATION_BYTES)? != self.persisted
            || read_optional(&self.dir, self.uid, ADVERTISEMENT, MAX_ADVERTISEMENT_BYTES)?
                != self.advertisement
            || read_optional(&self.dir, self.uid, "sequence.tmp", RESERVATION_BYTES)?.is_some()
            || read_optional(
                &self.dir,
                self.uid,
                "advertisement.tmp",
                MAX_ADVERTISEMENT_BYTES,
            )?
            .is_some()
        {
            return Err(Error::State("publisher changed outside its custody owner"));
        }
        let reservation = Reservation {
            sequence: self
                .reservation
                .sequence
                .checked_add(1)
                .ok_or(Error::State("sequence exhausted"))?,
            issued: clock,
        };
        let unsigned = self.scope.unsigned_ad(
            reservation,
            activity_mode::capabilities(self.activity_mode.is_some())?,
        )?;
        let reserved = reservation.encode(&self.scope);
        self.atomic(
            SEQUENCE,
            &reserved,
            fault,
            [
                Fault::ReserveCreated,
                Fault::ReservePartial,
                Fault::ReserveFileSync,
                Fault::ReserveRename,
                Fault::ReserveDirSync,
            ],
        )?;
        // Signing starts only after durable reservation publication succeeds.
        let raw = identity
            .sign_public_advertisement(unsigned)
            .map_err(|_| Error::Advertisement)?
            .encode();
        self.atomic(
            ADVERTISEMENT,
            &raw,
            fault,
            [
                Fault::AdvertisementCreated,
                Fault::AdvertisementPartial,
                Fault::AdvertisementFileSync,
                Fault::AdvertisementRename,
                Fault::AdvertisementDirSync,
            ],
        )?;
        self.reservation = reservation;
        self.persisted = Some(reserved);
        self.advertisement = Some(raw.clone());
        self.poisoned = false;
        Ok(raw)
    }
    fn atomic(
        &self,
        name: &str,
        raw: &[u8],
        fault: Option<Fault>,
        points: [Fault; 5],
    ) -> Result<(), Error> {
        let pending = self.dir.join(format!("{name}.tmp"));
        let mut file = custody::create_private_file(&pending).map_err(Error::Custody)?;
        inject(fault, points[0])?;
        let split = raw.len() / 2;
        file.write_all(&raw[..split])?;
        inject(fault, points[1])?;
        file.write_all(&raw[split..])?;
        file.sync_all()?;
        inject(fault, points[2])?;
        fs::rename(pending, self.dir.join(name))?;
        inject(fault, points[3])?;
        self.directory.sync_all()?;
        inject(fault, points[4])
    }
}
// A truncated temp precedes reservation rename and therefore cannot have
// authorized signing. Only an exact available scope/next-sequence prefix can
// be discarded, after all committed state and the caller clock pass validation.
fn check_partial_reservation(raw: &[u8], scope: &Scope, old: Reservation) -> Result<(), Error> {
    let sequence = old
        .sequence
        .checked_add(1)
        .ok_or(Error::State("sequence exhausted"))?;
    let expected = Reservation {
        sequence,
        issued: old.issued,
    }
    .encode(scope);
    let present = raw.len().min(109);
    if raw[..present] != expected[..present] {
        return Err(Error::State("foreign or conflicting partial reservation"));
    }
    if raw.len() >= 117 {
        let issued = u64::from_be_bytes(
            raw[109..117]
                .try_into()
                .map_err(|_| Error::State("issued"))?,
        );
        if issued < old.issued {
            return Err(Error::ClockRollback);
        }
        let exact = Reservation { sequence, issued }.encode(scope);
        if raw != &exact[..raw.len()] {
            return Err(Error::State("corrupt partial reservation checksum"));
        }
    }
    Ok(())
}
fn read_optional(dir: &Path, uid: u32, name: &str, max: usize) -> Result<Option<Vec<u8>>, Error> {
    match custody::read_private_file(&dir.join(name), uid, max) {
        Ok(raw) => Ok(Some(raw)),
        Err(custody::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Custody(error)),
    }
}
fn digest(domain: &[u8], raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    hash.finalize().into()
}

#[cfg(test)]
mod tests;

mod activity_mode;
