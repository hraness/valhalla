//! Finite private discovery registry. No path, dial target or DNS operation is
//! derived from a registration. A complete signed advertisement is only a hint.
use super::*;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, time::Instant};
use vhalla_custody::{self as custody, Owner};
use vhalla_public_protocol::discovery::{
    DiscoveryKind, DiscoveryRequest, PeerPage, Registration, RegistrationReceipt,
    UnsignedDiscoveryResponse, UnsignedRegistrationChallenge, MAX_REGISTRATION_BYTES,
};

/// Hard total of active descriptors AND cooling sequence floors.
pub const MAX_DISCOVERY_PEERS: usize = 512;
const SNAPSHOT: &str = "registry";
const TEMP: &str = "registry.tmp";
const SNAPSHOT_BYTES: usize =
    5 + 64 + 24 + 2 + MAX_DISCOVERY_PEERS * (32 + 16 + 2 + MAX_ADVERTISEMENT_BYTES) + 32;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const GLOBAL_REQUESTS: usize = 240;
const IP_REQUESTS: usize = 60;
const RATE_IPS: usize = 256;

/// Explicit activation of a task-owned private registry, separate from keys and journals.
#[derive(Clone, Debug)]
pub struct DiscoveryConfig {
    /// Operator-selected private directory, never a request-supplied path.
    pub directory: PathBuf,
    /// Create only a completely new directory. False opens existing state only.
    pub create_new: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    accepted_at: u64,
    generation: u64,
    advertisement: PeerAdvertisement,
}
impl Entry {
    fn check(
        &self,
        network: [u8; 32],
        key: [u8; 32],
        generation: u64,
        clock: u64,
    ) -> Result<(), Error> {
        let c = self.advertisement.unverified_claims();
        if key != c.application_key
            || self.accepted_at > clock
            || self.generation == 0
            || self.generation > generation
            || c.issued_at > self.issue_horizon()?
            || c.expires_at > self.retire_at()?
        {
            return Err(Error::State("corrupt discovery entry; preserve state"));
        }
        self.advertisement
            .restore_sequence_anchor(network)
            .map_err(|_| Error::State("invalid retained discovery advertisement"))?;
        Ok(())
    }
    fn retire_at(&self) -> Result<u64, Error> {
        self.accepted_at
            .checked_add(MAX_CLOCK_SKEW_SECONDS)
            .and_then(|n| n.checked_add(MAX_TTL_SECONDS))
            .ok_or(Error::State("discovery clock overflow"))
    }
    fn issue_horizon(&self) -> Result<u64, Error> {
        self.accepted_at
            .checked_add(MAX_CLOCK_SKEW_SECONDS)
            .ok_or(Error::State("discovery clock overflow"))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Snapshot {
    network: [u8; 32],
    receiver: [u8; 32],
    generation: u64,
    clock: u64,
    cutoff: u64,
    entries: BTreeMap<[u8; 32], Entry>,
}
impl Snapshot {
    fn encode(&self) -> Vec<u8> {
        let mut o = b"VHDS\x01".to_vec();
        o.extend_from_slice(&self.network);
        o.extend_from_slice(&self.receiver);
        for v in [self.generation, self.clock, self.cutoff] {
            o.extend_from_slice(&v.to_be_bytes());
        }
        o.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for (key, e) in &self.entries {
            o.extend_from_slice(key);
            o.extend_from_slice(&e.accepted_at.to_be_bytes());
            o.extend_from_slice(&e.generation.to_be_bytes());
            let ad = e.advertisement.encode();
            o.extend_from_slice(&(ad.len() as u16).to_be_bytes());
            o.extend_from_slice(&ad);
        }
        let sum = Sha256::digest(&o);
        o.extend_from_slice(&sum);
        o
    }
    fn decode(raw: &[u8], network: [u8; 32], receiver: [u8; 32]) -> Result<Self, Error> {
        let corrupt = || Error::State("corrupt discovery snapshot; preserve state");
        if raw.len() > SNAPSHOT_BYTES
            || raw.len() < 5 + 64 + 24 + 2 + 32
            || &raw[..5] != b"VHDS\x01"
        {
            return Err(corrupt());
        }
        let (body, sum) = raw.split_at(raw.len() - 32);
        if Sha256::digest(body).as_slice() != sum {
            return Err(corrupt());
        }
        let mut r = DiskReader(&body[5..]);
        if r.array::<32>()? != network || r.array::<32>()? != receiver {
            return Err(Error::State("discovery scope mismatch"));
        }
        let generation = r.u64()?;
        let clock = r.u64()?;
        let cutoff = r.u64()?;
        let count = usize::from(u16::from_be_bytes(r.array()?));
        if generation == 0 || cutoff > clock || count > MAX_DISCOVERY_PEERS {
            return Err(corrupt());
        }
        let mut entries = BTreeMap::new();
        let mut prior = [0u8; 32];
        for _ in 0..count {
            let key = r.array::<32>()?;
            let accepted_at = r.u64()?;
            let admitted = r.u64()?;
            let n = usize::from(u16::from_be_bytes(r.array()?));
            let ad = PeerAdvertisement::decode(r.take(n)?).map_err(|_| corrupt())?;
            let e = Entry {
                accepted_at,
                generation: admitted,
                advertisement: ad,
            };
            if key <= prior {
                return Err(corrupt());
            }
            e.check(network, key, generation, clock)?;
            prior = key;
            entries.insert(key, e);
        }
        if !r.0.is_empty() {
            return Err(corrupt());
        }
        Ok(Self {
            network,
            receiver,
            generation,
            clock,
            cutoff,
            entries,
        })
    }
    fn advance(&mut self, now: u64) -> Result<bool, Error> {
        if now < self.clock {
            return Err(Error::ClockRollback);
        }
        if now == self.clock {
            return Ok(false);
        }
        let mut changed = false;
        let mut cutoff = self.cutoff;
        for e in self.entries.values() {
            let expires = e.advertisement.unverified_claims().expires_at;
            if expires > self.clock && expires <= now {
                changed = true;
            }
            if e.retire_at()? <= now {
                changed = true;
                cutoff = cutoff.max(e.issue_horizon()?);
            }
        }
        self.entries
            .retain(|_, e| e.retire_at().is_ok_and(|retire| retire > now));
        self.cutoff = cutoff;
        self.clock = now;
        if changed {
            self.bump()?;
        }
        Ok(true)
    }
    fn bump(&mut self) -> Result<(), Error> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::State("discovery generation exhausted"))?;
        Ok(())
    }
    // Pending publication can only advance existing durable evidence. This is
    // crash reconciliation, not protection from an owner rolling back all files.
    fn succeeds(&self, old: &Self) -> Result<(), Error> {
        if self.network != old.network
            || self.receiver != old.receiver
            || self.clock < old.clock
            || self.cutoff < old.cutoff
            || self.generation < old.generation
        {
            return Err(Error::State(
                "discovery pending state rolls back durable evidence",
            ));
        }
        if self.generation == old.generation
            && (self.cutoff != old.cutoff || self.entries != old.entries)
        {
            return Err(Error::State("discovery generation conflict"));
        }
        for (key, e) in &old.entries {
            if let Some(next) = self.entries.get(key) {
                let seq = e.advertisement.unverified_claims().sequence;
                let ns = next.advertisement.unverified_claims().sequence;
                if ns < seq || (ns == seq && next != e) || next.accepted_at < e.accepted_at {
                    return Err(Error::State("discovery sequence rollback"));
                }
            } else if self.clock < e.retire_at()? || self.cutoff < e.issue_horizon()? {
                return Err(Error::State("discovery floor retired too early"));
            }
        }
        for (key, e) in &self.entries {
            if !old.entries.contains_key(key)
                && e.advertisement.unverified_claims().issued_at <= old.cutoff
            {
                return Err(Error::State("discovery retired evidence returned"));
            }
        }
        Ok(())
    }
    // Accept only a structurally incomplete canonical successor prefix. This
    // grants no authority to the uncommitted bytes: the verified stable image
    // remains unchanged. Every complete entry and already-determined omission
    // must nevertheless preserve its replay floors before scratch is removed.
    fn check_incomplete(&self, raw: &[u8], now: u64) -> Result<(), Error> {
        if now < self.clock {
            return Err(Error::ClockRollback);
        }
        if raw.len() > SNAPSHOT_BYTES {
            return Err(Error::State("oversized discovery preparation"));
        }
        let mut scope = b"VHDS\x01".to_vec();
        scope.extend_from_slice(&self.network);
        scope.extend_from_slice(&self.receiver);
        let n = raw.len().min(scope.len());
        if raw[..n] != scope[..n] {
            return Err(Error::State("foreign discovery preparation"));
        }
        if raw.len() < scope.len() {
            return Ok(());
        }
        let mut r = DiskReader(&raw[scope.len()..]);
        let Some(generation) = r.partial_u64(self.generation, u64::MAX)? else {
            return Ok(());
        };
        let Some(clock) = r.partial_u64(self.clock, now)? else {
            return Ok(());
        };
        let max_cutoff = if generation == self.generation {
            self.cutoff
        } else {
            clock
        };
        let Some(cutoff) = r.partial_u64(self.cutoff, max_cutoff)? else {
            return Ok(());
        };
        let (min_count, max_count) = if generation == self.generation {
            (self.entries.len() as u16, self.entries.len() as u16)
        } else {
            (0, MAX_DISCOVERY_PEERS as u16)
        };
        let Some(count) = r.partial_array(min_count.to_be_bytes(), max_count.to_be_bytes())? else {
            return Ok(());
        };
        let count = usize::from(u16::from_be_bytes(count));
        let mut next = Self {
            network: self.network,
            receiver: self.receiver,
            generation,
            clock,
            cutoff,
            entries: BTreeMap::new(),
        };
        let mut prior = [0u8; 32];
        for _ in 0..count {
            // Canonical keys are strictly increasing and nonzero.
            let mut lower = prior;
            let mut carry = true;
            for byte in lower.iter_mut().rev() {
                if !carry {
                    break;
                }
                (*byte, carry) = byte.overflowing_add(1);
            }
            if carry {
                return Err(Error::State("discovery preparation key overflow"));
            }
            let Some(key) = r.partial_array(lower, [u8::MAX; 32])? else {
                // Available leading bytes may already prove an old key was
                // omitted. Do not fill that key back in as an unknown suffix.
                let mut minimum = [0u8; 32];
                minimum[..r.0.len()].copy_from_slice(r.0);
                return next.check_prefix(self, minimum.max(lower));
            };
            let old = self.entries.get(&key);
            let Some(accepted_at) = r.partial_u64(
                old.map_or(0, |e| e.accepted_at),
                clock.min(u64::MAX - MAX_CLOCK_SKEW_SECONDS - MAX_TTL_SECONDS),
            )?
            else {
                return next.check_prefix(self, key);
            };
            let Some(admitted) = r.partial_u64(old.map_or(1, |e| e.generation), generation)? else {
                return next.check_prefix(self, key);
            };
            let Some(size) = r.partial_array(
                1u16.to_be_bytes(),
                (MAX_ADVERTISEMENT_BYTES as u16).to_be_bytes(),
            )?
            else {
                return next.check_prefix(self, key);
            };
            let size = usize::from(u16::from_be_bytes(size));
            if r.0.len() < size {
                check_ad_prefix(r.0, self.network, key, old, accepted_at, admitted)?;
                return next.check_prefix(self, key);
            }
            let advertisement = PeerAdvertisement::decode(r.take(size)?)
                .map_err(|_| Error::State("malformed discovery preparation advertisement"))?;
            let entry = Entry {
                accepted_at,
                generation: admitted,
                advertisement,
            };
            entry.check(self.network, key, generation, clock)?;
            next.entries.insert(key, entry);
            prior = key;
        }
        next.succeeds(self)?;
        // Once all entries exist, only the checksum may be incomplete. Reject
        // malformed complete frames and mismatching checksum prefixes as evidence.
        if r.0.len() >= 32 {
            return Err(Error::State("malformed complete discovery preparation"));
        }
        let sum = Sha256::digest(&raw[..raw.len() - r.0.len()]);
        if r.0 != &sum[..r.0.len()] {
            return Err(Error::State(
                "invalid discovery preparation checksum prefix",
            ));
        }
        Ok(())
    }
    fn check_prefix(&self, old: &Self, unfinished_key: [u8; 32]) -> Result<(), Error> {
        // Entries at or after the unfinished key have not been claimed or
        // omitted yet. Preserve them for the ordinary monotonicity check.
        let mut prefix = self.clone();
        prefix.entries.extend(
            old.entries
                .range(unfinished_key..)
                .map(|(k, e)| (*k, e.clone())),
        );
        prefix.succeeds(old)
    }
}
fn check_ad_prefix(
    raw: &[u8],
    network: [u8; 32],
    key: [u8; 32],
    old: Option<&Entry>,
    accepted_at: u64,
    generation: u64,
) -> Result<(), Error> {
    let mut scope = b"VHPA\x01".to_vec();
    scope.extend_from_slice(&network);
    scope.extend_from_slice(&key);
    let n = raw.len().min(scope.len());
    if raw[..n] != scope[..n] {
        return Err(Error::State("foreign discovery advertisement preparation"));
    }
    if raw.len() >= scope.len() {
        let mut r = DiskReader(&raw[scope.len()..]);
        let previous = old.map(|e| e.advertisement.unverified_claims().sequence);
        if let Some(sequence) = r.partial_u64(previous.unwrap_or(1), u64::MAX)? {
            if previous == Some(sequence) {
                let retained = old.ok_or(Error::Config)?;
                let known = retained.advertisement.encode();
                if retained.accepted_at != accepted_at
                    || retained.generation != generation
                    || !known.starts_with(raw)
                {
                    return Err(Error::State(
                        "changed discovery advertisement at retained sequence",
                    ));
                }
            }
        }
    }
    Ok(())
}
struct DiskReader<'a>(&'a [u8]);
impl<'a> DiskReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::State("truncated discovery state"));
        }
        let (v, r) = self.0.split_at(n);
        self.0 = r;
        Ok(v)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::State("truncated discovery state"))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn partial_array<const N: usize>(
        &mut self,
        min: [u8; N],
        max: [u8; N],
    ) -> Result<Option<[u8; N]>, Error> {
        let n = self.0.len().min(N);
        if min > max || self.0[..n] < min[..n] || self.0[..n] > max[..n] {
            return Err(Error::State("invalid discovery preparation field prefix"));
        }
        if n < N {
            return Ok(None);
        }
        self.array().map(Some)
    }
    fn partial_u64(&mut self, min: u64, max: u64) -> Result<Option<u64>, Error> {
        Ok(self
            .partial_array(min.to_be_bytes(), max.to_be_bytes())?
            .map(u64::from_be_bytes))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    StableFileSync,
    StableDirectorySync,
    Create,
    PartialWrite,
    Write,
    FileSync,
    Rename,
    DirectorySync,
}
struct Registry {
    path: PathBuf,
    directory: File,
    _lock: File,
    owner: Owner,
    state: Snapshot,
    poisoned: bool,
}
impl Registry {
    fn start(
        config: DiscoveryConfig,
        network: [u8; 32],
        receiver: [u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        Self::start_with_fault(config, network, receiver, now, None)
    }
    fn start_with_fault(
        config: DiscoveryConfig,
        network: [u8; 32],
        receiver: [u8; 32],
        now: u64,
        fault: Option<Fault>,
    ) -> Result<Self, Error> {
        let path = custody::absolute(&config.directory).map_err(Error::Custody)?;
        let (directory, owner) = if config.create_new {
            custody::create_private_directory(&path)
        } else {
            custody::open_private_directory(&path)
        }
        .map_err(Error::Custody)?;
        let lock = if config.create_new {
            custody::create_private_file(&path.join("lock"))
        } else {
            custody::open_private_file(&path.join("lock"), owner, 0)
        }
        .map_err(Error::Custody)?;
        custody::acquire_exclusive(&lock).map_err(Error::Custody)?;
        let empty = Snapshot {
            network,
            receiver,
            generation: 1,
            clock: now,
            cutoff: 0,
            entries: BTreeMap::new(),
        };
        let mut out = Self {
            path,
            directory,
            _lock: lock,
            owner,
            state: empty,
            poisoned: false,
        };
        if config.create_new {
            out._lock.sync_all()?;
            out.directory.sync_all()?;
            File::open(out.path.parent().ok_or(Error::Config)?)?.sync_all()?;
            out.persist(out.state.clone(), None)?;
        } else {
            let stable = out.read_optional(SNAPSHOT)?;
            let pending = out.read_optional(TEMP)?;
            let old = stable
                .as_deref()
                .map(|r| Snapshot::decode(r, network, receiver))
                .transpose()?;
            if old.as_ref().is_some_and(|old| now < old.clock) {
                return Err(Error::ClockRollback);
            }
            let mut incomplete = false;
            let new = match pending.as_deref() {
                Some(raw) => match Snapshot::decode(raw, network, receiver) {
                    Ok(new) => Some(new),
                    Err(error) => {
                        let Some(old) = old.as_ref() else {
                            return Err(error);
                        };
                        old.check_incomplete(raw, now)?;
                        incomplete = true;
                        None
                    }
                },
                None => None,
            };
            let state = match (old, new) {
                (Some(old), Some(new)) => {
                    new.succeeds(&old)?;
                    new
                }
                (Some(old), None) => old,
                (None, Some(new))
                    if new.generation == 1 && new.entries.is_empty() && new.cutoff == 0 =>
                {
                    new
                }
                _ => {
                    return Err(Error::State(
                        "missing discovery publication; preserve directory",
                    ))
                }
            };
            if now < state.clock {
                return Err(Error::ClockRollback);
            }
            out.state = state;
            if stable.is_some() {
                // A previous publisher may have died after final rename but
                // before directory sync. Re-establish the validated stable
                // image's durability even when time has not advanced.
                custody::open_private_file(&out.path.join(SNAPSHOT), owner, SNAPSHOT_BYTES)
                    .map_err(Error::Custody)?
                    .sync_all()?;
                inject(fault, Fault::StableFileSync)?;
                out.directory.sync_all()?;
                inject(fault, Fault::StableDirectorySync)?;
            }
            if incomplete {
                fs::remove_file(out.path.join(TEMP))?;
                out.directory.sync_all()?;
            } else if pending.is_some() {
                custody::open_private_file(&out.path.join(TEMP), owner, SNAPSHOT_BYTES)
                    .map_err(Error::Custody)?
                    .sync_all()?;
                fs::rename(out.path.join(TEMP), out.path.join(SNAPSHOT))?;
                out.directory.sync_all()?;
            }
            out.advance(now)?;
        }
        Ok(out)
    }
    fn read_optional(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        match fs::symlink_metadata(self.path.join(name)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
            Ok(_) => custody::read_private_file(&self.path.join(name), self.owner, SNAPSHOT_BYTES)
                .map(Some)
                .map_err(Error::Custody),
        }
    }
    fn ensure(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::State(
                "discovery publication uncertain; reopen state",
            ))
        } else {
            Ok(())
        }
    }
    fn persist(&mut self, next: Snapshot, fault: Option<Fault>) -> Result<(), Error> {
        self.ensure()?;
        self.poisoned = true;
        let raw = next.encode();
        let mut f = custody::create_private_file(&self.path.join(TEMP)).map_err(Error::Custody)?;
        inject(fault, Fault::Create)?;
        if fault == Some(Fault::PartialWrite) {
            f.write_all(&raw[..raw.len() / 2])?;
            inject(fault, Fault::PartialWrite)?;
        }
        f.write_all(&raw)?;
        inject(fault, Fault::Write)?;
        f.sync_all()?;
        inject(fault, Fault::FileSync)?;
        drop(f);
        fs::rename(self.path.join(TEMP), self.path.join(SNAPSHOT))?;
        inject(fault, Fault::Rename)?;
        self.directory.sync_all()?;
        inject(fault, Fault::DirectorySync)?;
        self.state = next;
        self.poisoned = false;
        Ok(())
    }
    fn advance(&mut self, now: u64) -> Result<(), Error> {
        self.ensure()?;
        let mut next = self.state.clone();
        if next.advance(now)? {
            self.persist(next, None)?;
        }
        Ok(())
    }
    fn page(&self, request: DiscoveryRequest) -> Result<PeerPage, StatusCode> {
        self.ensure().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let DiscoveryKind::List {
            generation,
            after,
            count,
        } = request.kind()
        else {
            return Err(StatusCode::BAD_REQUEST);
        };
        if generation != 0 && generation != self.state.generation {
            return Err(StatusCode::CONFLICT);
        }
        let mut candidates = self
            .state
            .entries
            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
            .filter(|(_, e)| e.advertisement.unverified_claims().expires_at > self.state.clock);
        let ads = candidates
            .by_ref()
            .take(usize::from(count))
            .map(|(_, e)| e.advertisement.clone())
            .collect();
        let more = candidates.next().is_some();
        PeerPage::new(self.state.network, self.state.generation, after, more, ads)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
    fn receipt(&self, key: [u8; 32]) -> Result<RegistrationReceipt, StatusCode> {
        let e = self
            .state
            .entries
            .get(&key)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let c = e.advertisement.unverified_claims();
        RegistrationReceipt::new(
            self.state.network,
            self.state.receiver,
            key,
            c.sequence,
            e.generation,
            c.expires_at,
            e.retire_at().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
    fn register(
        &mut self,
        registration: Registration,
        fault: Option<Fault>,
    ) -> Result<RegistrationReceipt, StatusCode> {
        self.ensure().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let ad = registration.advertisement();
        let key = ad.unverified_claims().application_key;
        // An exact previously admitted descriptor changes no timestamp, replay
        // floor or receipt generation, even after an uncertain client outcome.
        if self
            .state
            .entries
            .get(&key)
            .is_some_and(|e| e.advertisement == *ad)
        {
            return self.receipt(key);
        }
        let previous = self.state.entries.get(&key);
        let known = previous.is_some();
        if !known && self.state.entries.len() >= MAX_DISCOVERY_PEERS {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let verified = registration
            .verify(
                self.state.network,
                self.state.receiver,
                self.state.clock,
                known,
            )
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if let Some(previous) = previous {
            if verified.claims().sequence <= previous.advertisement.unverified_claims().sequence {
                return Err(StatusCode::CONFLICT);
            }
        } else if verified.claims().issued_at <= self.state.cutoff {
            return Err(StatusCode::CONFLICT);
        }
        let mut next = self.state.clone();
        next.bump().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let entry = Entry {
            accepted_at: next.clock,
            generation: next.generation,
            advertisement: ad.clone(),
        };
        entry
            .retire_at()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        next.entries.insert(key, entry);
        self.persist(next, fault)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        self.receipt(key)
    }
}
fn inject(actual: Option<Fault>, point: Fault) -> Result<(), Error> {
    if actual == Some(point) {
        Err(Error::State("injected discovery publication fault"))
    } else {
        Ok(())
    }
}
struct Rate {
    started: Instant,
    total: usize,
    ips: BTreeMap<IpAddr, usize>,
}
impl Rate {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            total: 0,
            ips: BTreeMap::new(),
        }
    }
    fn admit(&mut self, ip: IpAddr, at: Instant) -> bool {
        if at.saturating_duration_since(self.started) >= RATE_WINDOW {
            self.started = at;
            self.total = 0;
            self.ips.clear();
        }
        if self.total >= GLOBAL_REQUESTS
            || (!self.ips.contains_key(&ip) && self.ips.len() >= RATE_IPS)
            || self.ips.get(&ip).copied().unwrap_or(0) >= IP_REQUESTS
        {
            return false;
        }
        self.total += 1;
        *self.ips.entry(ip).or_default() += 1;
        true
    }
}
pub(super) struct DiscoveryService {
    registry: Registry,
    rate: Rate,
}
impl Peer {
    /// Explicitly activate finite public route registration/listing. This grants
    /// no validators, room rights, remote dialing or application write authority.
    pub fn enable_discovery(&self, config: DiscoveryConfig) -> Result<(), Error> {
        let mut slot = self
            .discovery
            .lock()
            .map_err(|_| Error::State("discovery lock poisoned"))?;
        if slot.is_some() {
            return Err(Error::State("discovery already configured"));
        }
        let registry = Registry::start(config, self.network, self.identity.public_key(), now()?)?;
        *slot = Some(DiscoveryService {
            registry,
            rate: Rate::new(),
        });
        Ok(())
    }
    /// Programmatic native registration/listing path for a local operator or CLI.
    /// Remote publishers use the same typed HTTP requests; this never dials peers.
    pub fn discovery_exchange(
        &self,
        request: DiscoveryRequest,
        body: &[u8],
    ) -> Result<(Vec<u8>, String), Error> {
        self.discovery_answer(request, body, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .map(|(body, proof)| (body.to_vec(), proof))
            .map_err(|_| Error::State("discovery request refused"))
    }
    fn discovery_answer(
        &self,
        request: DiscoveryRequest,
        body: &[u8],
        source: IpAddr,
    ) -> Result<(Bytes, String), StatusCode> {
        self.current_advertisement()?;
        let mut slot = self
            .discovery
            .try_lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let svc = slot.as_mut().ok_or(StatusCode::NOT_FOUND)?;
        if !svc.rate.admit(source, Instant::now()) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        svc.registry
            .advance(now().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let body = match request.kind() {
            DiscoveryKind::List { .. } => {
                if !body.is_empty() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                svc.registry.page(request)?.encode()
            }
            DiscoveryKind::Challenge { publisher, .. } => {
                if !body.is_empty() {
                    return Err(StatusCode::BAD_REQUEST);
                }
                let known = svc.registry.state.entries.contains_key(&publisher);
                if !known && svc.registry.state.entries.len() >= MAX_DISCOVERY_PEERS {
                    return Err(StatusCode::SERVICE_UNAVAILABLE);
                }
                let unsigned = UnsignedRegistrationChallenge::new(
                    self.network,
                    self.identity.public_key(),
                    request,
                    svc.registry.state.clock,
                    known,
                )
                .map_err(|_| StatusCode::BAD_REQUEST)?;
                self.identity
                    .sign_discovery_challenge(unsigned)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                    .encode()
            }
            DiscoveryKind::Register { .. } => {
                request
                    .check_body(body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                let reg = Registration::decode(body).map_err(|_| StatusCode::BAD_REQUEST)?;
                svc.registry.register(reg, None)?.encode()
            }
        };
        let proof = self
            .identity
            .sign_discovery_response(
                UnsignedDiscoveryResponse::new(
                    self.network,
                    self.identity.public_key(),
                    request,
                    &body,
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            )
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok((Bytes::from(body), hex(&proof.encode())))
    }
    fn check_discovery_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<(DiscoveryRequest, bool, Option<usize>), StatusCode> {
        if request.version() != hyper::Version::HTTP_11
            || request.uri().scheme().is_some()
            || request.uri().authority().is_some()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let h = request.headers();
        for name in [
            header::COOKIE,
            header::AUTHORIZATION,
            header::PROXY_AUTHORIZATION,
            header::EXPECT,
            header::UPGRADE,
            header::CONTENT_ENCODING,
        ] {
            if h.contains_key(name) {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
        let host = self
            .config
            .public_endpoint
            .as_str()
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix("/vhalla/v1"))
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let got = single(h, header::HOST.as_str())?;
        if got.is_none() || (got != Some(host) && got != host.strip_suffix(":443")) {
            return Err(StatusCode::MISDIRECTED_REQUEST);
        }
        if single(h, header::ORIGIN.as_str())?
            .is_some_and(|o| o != self.config.allowed_origin.as_str())
        {
            return Err(StatusCode::FORBIDDEN);
        }
        let typed = DiscoveryRequest::parse_target(
            request.uri().path_and_query().map_or("", |p| p.as_str()),
        )
        .map_err(|_| StatusCode::BAD_REQUEST)?;
        let post = matches!(typed.kind(), DiscoveryKind::Register { .. });
        let method = if post { Method::POST } else { Method::GET };
        let preflight = request.method() == Method::OPTIONS;
        if !preflight && request.method() != method {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        let transfer = single(h, header::TRANSFER_ENCODING.as_str())?;
        let length = single(h, header::CONTENT_LENGTH.as_str())?
            .map(|s| {
                if s.is_empty()
                    || !s.bytes().all(|b| b.is_ascii_digit())
                    || (s.len() > 1 && s.starts_with('0'))
                {
                    return Err(StatusCode::BAD_REQUEST);
                }
                s.parse::<usize>()
                    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)
            })
            .transpose()?;
        if transfer.is_some_and(|t| t != "chunked") || (transfer.is_some() && length.is_some()) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if preflight {
            if single(h, header::ORIGIN.as_str())?.is_none()
                || single(h, header::ACCESS_CONTROL_REQUEST_METHOD.as_str())?
                    != Some(method.as_str())
                || single(h, header::ACCESS_CONTROL_REQUEST_HEADERS.as_str())?
                    .is_some_and(|s| s != "content-type")
                || transfer.is_some()
                || length.is_some_and(|n| n != 0)
            {
                return Err(StatusCode::BAD_REQUEST);
            }
        } else if post {
            if single(h, header::CONTENT_TYPE.as_str())? != Some("application/octet-stream") {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            if length.is_some_and(|n| n == 0 || n > MAX_REGISTRATION_BYTES) {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            if length.is_none() && transfer.is_none() {
                return Err(StatusCode::LENGTH_REQUIRED);
            }
        } else if transfer.is_some() || length.is_some_and(|n| n != 0) {
            return Err(StatusCode::BAD_REQUEST);
        }
        Ok((typed, preflight, length))
    }
    pub(super) async fn handle_discovery(
        self: Arc<Self>,
        request: Request<Incoming>,
        permit: Arc<Permit>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let (typed, preflight, length) = match self.check_discovery_request(&request) {
            Ok(r) => r,
            Err(s) => return Ok(failure(s)),
        };
        let origin = self.config.allowed_origin.as_str().to_owned();
        match self.discovery.try_lock() {
            Ok(slot) if slot.is_none() => {
                return Ok(discovery_failure(StatusCode::NOT_FOUND, &origin))
            }
            Err(_) => return Ok(discovery_failure(StatusCode::SERVICE_UNAVAILABLE, &origin)),
            Ok(_) => {}
        }
        if preflight {
            let mut r = Response::new(Full::new(Bytes::new()));
            *r.status_mut() = StatusCode::NO_CONTENT;
            cors(r.headers_mut(), &origin);
            r.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                header::HeaderValue::from_static("GET, POST"),
            );
            r.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::HeaderValue::from_static("content-type"),
            );
            return Ok(r);
        }
        let body = match timeout(
            Duration::from_secs(5),
            read_body(
                request.into_body(),
                length,
                matches!(typed.kind(), DiscoveryKind::Register { .. }),
            ),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(s)) => return Ok(discovery_failure(s, &origin)),
            Err(_) => return Ok(discovery_failure(StatusCode::REQUEST_TIMEOUT, &origin)),
        };
        let source = permit.ip;
        let job = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            self.discovery_answer(typed, &body, source)
        });
        let result = timeout(READ_TIMEOUT, job).await;
        Ok(match result {
            Ok(Ok(Ok((body, proof)))) => {
                let mut r = Response::new(Full::new(body));
                cors(r.headers_mut(), &origin);
                if let Ok(proof) = header::HeaderValue::from_str(&proof) {
                    r.headers_mut().insert(PROOF_HEADER, proof);
                    r
                } else {
                    discovery_failure(StatusCode::INTERNAL_SERVER_ERROR, &origin)
                }
            }
            Ok(Ok(Err(s))) => discovery_failure(s, &origin),
            _ => discovery_failure(StatusCode::SERVICE_UNAVAILABLE, &origin),
        })
    }
}
async fn read_body(
    mut body: Incoming,
    expected: Option<usize>,
    post: bool,
) -> Result<Vec<u8>, StatusCode> {
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let data = frame
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .into_data()
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if out
            .len()
            .checked_add(data.len())
            .is_none_or(|n| n > if post { MAX_REGISTRATION_BYTES } else { 0 })
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        out.try_reserve(data.len())
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        out.extend_from_slice(&data);
    }
    if expected.is_some_and(|n| n != out.len()) || (post && out.is_empty()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(out)
}
fn cors(h: &mut HeaderMap, origin: &str) {
    for (name, value) in [
        (header::CONTENT_TYPE, "application/octet-stream"),
        (header::CACHE_CONTROL, "no-store"),
        (header::CONNECTION, "close"),
        (header::VARY, "Origin"),
        (header::ACCESS_CONTROL_EXPOSE_HEADERS, "x-vhalla-proof"),
    ] {
        h.insert(name, header::HeaderValue::from_static(value));
    }
    h.insert(
        "x-content-type-options",
        header::HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = header::HeaderValue::from_str(origin) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
}
fn discovery_failure(status: StatusCode, origin: &str) -> Response<Full<Bytes>> {
    let mut r = failure(status);
    cors(r.headers_mut(), origin);
    r
}

#[cfg(test)]
mod tests;
