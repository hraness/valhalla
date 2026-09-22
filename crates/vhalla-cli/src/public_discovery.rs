//! Explicit bounded discovery serving and registration to selected seed routes.
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_public_client::{Bootstrap, MAX_BOOTSTRAP_BYTES};
use vhalla_public_peer::{Config, CorsOrigin, DiscoveryConfig, ManagedPeer, DEFAULT_LISTEN};
use vhalla_public_protocol::{
    discovery::{
        DiscoveryKind, DiscoveryRequest, RegistrationChallenge, RegistrationReceipt,
        MAX_SOLVE_ATTEMPTS, REGISTRATION_CHALLENGE_BYTES, REGISTRATION_RECEIPT_BYTES,
    },
    response::{hex, ReadKind, ReadRequest},
    Capabilities, Endpoint, PeerAdvertisement, SequenceAnchor, VerificationPolicy,
    MAX_ADVERTISEMENT_BYTES, MAX_CLOCK_SKEW_SECONDS, MAX_TTL_SECONDS,
};

#[path = "public_discovery/http.rs"]
pub(super) mod http;

pub(super) fn resolve_child(args: &[OsString]) -> Result<(), String> {
    http::resolve_child(args)
}

pub const HELP: &str = "vhalla public discovery-serve BOOTSTRAP PIN64 KEY_DIR JOURNAL PEER_STATE HTTPS_ENDPOINT ALLOWED_ORIGIN DISCOVERY_DIR [--new-state] [--new-discovery] [--listen LOOPBACK_IP:PORT] [--dev-origin] [--seed SIGNED_SEED_AD_FILE EXACT_HTTPS_ENDPOINT] [--solve-attempts N]\nServe READ plus bounded discovery on loopback behind your HTTPS proxy. Zero to four explicit seed routes; never dials discovered hints. Registration uses /usr/bin/curl with system TLS and bounded public-only DNS address pinning, no curl configuration, proxy or redirects. Input seed files pin full seed keys and restart sequence floors; keep them current. Each registration has a bounded work/time budget. Publisher and discovery directories are created only with their separate --new flags. No activity PUBLISH mode is enabled.";
const MAX_SEEDS: usize = 4;
const DEFAULT_ATTEMPTS: u64 = 1 << 22;
const SOLVE_TIME: Duration = Duration::from_secs(10);
const SOLVE_CHUNK: u64 = 8192;
const POLL: Duration = Duration::from_secs(60);

struct Options {
    config: Config,
    state: PathBuf,
    discovery: DiscoveryConfig,
    create: bool,
    network: [u8; 32],
    seeds: Vec<Seed>,
    attempts: u64,
}
struct Seed {
    endpoint: Endpoint,
    key: [u8; 32],
    floor: SequenceAnchor,
    advertisement: PeerAdvertisement,
    registered: Option<u64>,
    clock: u64,
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock precedes Unix epoch".into())
}
fn policy(network: [u8; 32], at: u64) -> VerificationPolicy {
    VerificationPolicy {
        network,
        now: at,
        max_clock_skew_seconds: MAX_CLOCK_SKEW_SECONDS,
        max_ttl_seconds: MAX_TTL_SECONDS,
    }
}
fn nonce() -> Result<[u8; 32], String> {
    for _ in 0..2 {
        let mut value = [0; 32];
        getrandom::fill(&mut value).map_err(|_| "secure nonce source unavailable")?;
        if value != [0; 32] {
            return Ok(value);
        }
    }
    Err("secure nonce source returned zero twice".into())
}
impl Seed {
    fn load(path: &Path, endpoint: Endpoint, network: [u8; 32], at: u64) -> Result<Self, String> {
        let raw = super::bytes(path, MAX_ADVERTISEMENT_BYTES)?;
        let advertisement =
            PeerAdvertisement::decode(&raw).map_err(|e| format!("seed descriptor: {e:?}"))?;
        let verified = advertisement
            .verify(&policy(network, at), None)
            .map_err(|e| format!("seed descriptor rejected: {e:?}"))?;
        if !verified.claims().capabilities.contains(Capabilities::READ)
            || !verified.claims().endpoints.contains(&endpoint)
        {
            return Err("selected seed must advertise READ and the exact selected endpoint".into());
        }
        Ok(Self {
            endpoint,
            key: verified.claims().application_key,
            floor: verified.sequence_anchor(),
            advertisement,
            registered: None,
            clock: at,
        })
    }
    fn check_clock(&mut self) -> Result<u64, String> {
        let at = now()?;
        if at < self.clock {
            return Err(
                "clock rollback during seed registration; restart with reviewed clock/state".into(),
            );
        }
        self.clock = at;
        Ok(at)
    }
    fn refresh(&mut self, network: [u8; 32], cancel: &AtomicBool) -> Result<(), String> {
        let request = ReadRequest::new(nonce()?, ReadKind::Advertisement)
            .map_err(|e| format!("read request: {e:?}"))?;
        let (body, proof) = http::exchange(
            &self.endpoint,
            &request.target(),
            None,
            MAX_ADVERTISEMENT_BYTES,
            cancel,
        )?;
        vhalla_public_protocol::response::proof_from_hex(&proof)
            .and_then(|proof| proof.verify(network, self.key, &request, &body))
            .map_err(|e| format!("seed read proof: {e:?}"))?;
        let fresh =
            PeerAdvertisement::decode(&body).map_err(|e| format!("seed advertisement: {e:?}"))?;
        let at = self.check_clock()?;
        let verified = fresh
            .verify(
                &policy(network, at),
                if fresh == self.advertisement {
                    None
                } else {
                    Some(&self.floor)
                },
            )
            .map_err(|e| format!("seed sequence/freshness: {e:?}"))?;
        if verified.claims().application_key != self.key
            || !verified.claims().capabilities.contains(Capabilities::READ)
            || !verified.claims().endpoints.contains(&self.endpoint)
        {
            return Err("seed no longer advertises the selected key/READ route; select a new route explicitly".into());
        }
        self.floor = verified.sequence_anchor();
        self.advertisement = fresh;
        Ok(())
    }
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() < 10 {
        return Err(HELP.into());
    }
    let text = |i: usize| args[i].to_str().ok_or("arguments must be UTF-8");
    let pin = super::hex32(text(3)?)?;
    let bootstrap = Bootstrap::decode(
        &super::bytes(Path::new(&args[2]), MAX_BOOTSTRAP_BYTES)?,
        pin,
    )
    .map_err(|e| format!("bootstrap pin: {e:?}"))?;
    let network = bootstrap.network_id();
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .map_err(|_| "invalid default listen")?;
    let (mut create, mut new_discovery, mut dev, mut saw_listen, mut saw_attempts) =
        (false, false, false, false, false);
    let mut attempts = DEFAULT_ATTEMPTS;
    let mut selected = Vec::new();
    let mut index = 10;
    while index < args.len() {
        match text(index)? {
            "--new-state" if !create => {
                create = true;
                index += 1;
            }
            "--new-discovery" if !new_discovery => {
                new_discovery = true;
                index += 1;
            }
            "--dev-origin" if !dev => {
                dev = true;
                index += 1;
            }
            "--listen" if !saw_listen && index + 1 < args.len() => {
                listen = text(index + 1)?
                    .parse()
                    .map_err(|_| "invalid loopback listen")?;
                saw_listen = true;
                index += 2;
            }
            "--solve-attempts" if !saw_attempts && index + 1 < args.len() => {
                let raw = text(index + 1)?;
                attempts = raw.parse::<u64>().map_err(|_| "invalid solve budget")?;
                if attempts == 0 || attempts > MAX_SOLVE_ATTEMPTS || attempts.to_string() != raw {
                    return Err("solve budget must be canonical decimal 1..16777216".into());
                }
                saw_attempts = true;
                index += 2;
            }
            "--seed" if selected.len() < MAX_SEEDS && index + 2 < args.len() => {
                selected.push((
                    PathBuf::from(&args[index + 1]),
                    Endpoint::parse(text(index + 2)?)
                        .map_err(|e| format!("selected seed HTTPS endpoint: {e:?}"))?,
                ));
                index += 3;
            }
            _ => return Err(HELP.into()),
        }
    }
    if !listen.ip().is_loopback() {
        return Err("listener must be a literal loopback address".into());
    }
    let origin = if dev {
        CorsOrigin::loopback_development(
            text(8)?
                .strip_prefix("http://")
                .ok_or("--dev-origin needs http://LOOPBACK_IP:PORT")?
                .parse()
                .map_err(|_| "invalid development origin")?,
        )
    } else {
        CorsOrigin::https(text(8)?)
    }
    .map_err(|e| e.to_string())?;
    let at = now()?;
    let mut keys = BTreeSet::new();
    let mut seeds = Vec::new();
    for (path, endpoint) in selected {
        let seed = Seed::load(&path, endpoint, network, at)?;
        if !keys.insert(seed.key) {
            return Err("each full seed key may be selected only once".into());
        }
        seeds.push(seed);
    }
    let state = PathBuf::from(&args[6]);
    Ok(Options {
        config: Config {
            bootstrap_file: PathBuf::from(&args[2]),
            bootstrap_pin: pin,
            identity_dir: PathBuf::from(&args[4]),
            journal_dir: PathBuf::from(&args[5]),
            advertisement_file: state.join("advertisement"),
            public_endpoint: Endpoint::parse(text(7)?)
                .map_err(|e| format!("public endpoint: {e:?}"))?,
            allowed_origin: origin,
            listen,
        },
        state,
        discovery: DiscoveryConfig {
            directory: PathBuf::from(&args[9]),
            create_new: new_discovery,
        },
        create,
        network,
        seeds,
        attempts,
    })
}

fn register(
    peer: &ManagedPeer,
    seed: &mut Seed,
    attempts: u64,
    cancel: &AtomicBool,
) -> Result<Option<RegistrationReceipt>, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("registration cancelled".into());
    }
    let advertisement = peer
        .current_public_advertisement()
        .map_err(|e| e.to_string())?;
    let sequence = advertisement.unverified_claims().sequence;
    if seed.registered == Some(sequence) {
        return Ok(None);
    }
    let network = peer.network_id();
    seed.refresh(network, cancel)?;
    let request = DiscoveryRequest::new(
        nonce()?,
        DiscoveryKind::Challenge {
            publisher: peer.application_key(),
            advertisement: Sha256::digest(advertisement.encode()).into(),
        },
    )
    .map_err(|e| format!("challenge request: {e:?}"))?;
    let (body, proof) = http::exchange(
        &seed.endpoint,
        &request.target(),
        None,
        REGISTRATION_CHALLENGE_BYTES,
        cancel,
    )?;
    vhalla_public_protocol::discovery::proof_from_hex(&proof)
        .and_then(|proof| proof.verify(network, seed.key, request, &body))
        .map_err(|e| format!("challenge response proof: {e:?}"))?;
    let challenge =
        RegistrationChallenge::decode(&body).map_err(|e| format!("challenge framing: {e:?}"))?;
    let at = seed.check_clock()?;
    let verified = challenge
        .verify(network, seed.key, request, at)
        .map_err(|e| format!("challenge authority/scope: {e:?}"))?;
    let deadline = Instant::now() + SOLVE_TIME;
    let mut start = 0;
    let work = loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("registration cancelled".into());
        }
        if Instant::now() >= deadline
            || start >= attempts
            || seed.check_clock()? >= challenge.expires_at()
        {
            return Err("explicit registration work/time budget exhausted; no post sent".into());
        }
        let count = SOLVE_CHUNK.min(attempts - start);
        if let Some(work) = verified
            .solve_range(start, count)
            .map_err(|e| format!("work solver: {e:?}"))?
        {
            break work;
        }
        start += count;
    };
    let registration = peer
        .sign_discovery_registration(verified, work)
        .map_err(|e| format!("registration signing (advertisement may have renewed): {e}"))?;
    if registration.advertisement() != &advertisement {
        return Err("publisher renewed during registration; retry exact new descriptor".into());
    }
    let raw = registration.encode();
    let request = DiscoveryRequest::new(
        nonce()?,
        DiscoveryKind::Register {
            registration: Sha256::digest(&raw).into(),
        },
    )
    .map_err(|e| format!("registration request: {e:?}"))?;
    let (body, proof) = http::exchange(
        &seed.endpoint,
        &request.target(),
        Some(&raw),
        REGISTRATION_RECEIPT_BYTES,
        cancel,
    )?;
    vhalla_public_protocol::discovery::proof_from_hex(&proof)
        .and_then(|proof| proof.verify(network, seed.key, request, &body))
        .map_err(|e| format!("registration receipt proof: {e:?}"))?;
    let receipt =
        RegistrationReceipt::decode(&body).map_err(|e| format!("receipt framing: {e:?}"))?;
    receipt
        .check(network, seed.key, &advertisement)
        .map_err(|e| format!("receipt exact descriptor binding: {e:?}"))?;
    if seed.check_clock()? >= receipt.expires_at() {
        return Err("registration receipt already expired; retry after renewal".into());
    }
    seed.registered = Some(sequence);
    Ok(Some(receipt))
}

pub fn run(args: &[OsString]) -> Result<(), String> {
    let options = parse(args)?;
    // External dependency preflight precedes every state creation or listener.
    if !options.seeds.is_empty() {
        http::preflight()?;
    }
    let peer = Arc::new(
        if options.create {
            ManagedPeer::create(options.config, &options.state)
        } else {
            ManagedPeer::open(options.config, &options.state)
        }
        .map_err(|e| format!("publisher startup: {e}; preserve state"))?,
    );
    if peer.network_id() != options.network {
        return Err("bootstrap changed during startup".into());
    }
    peer.enable_discovery(options.discovery)
        .map_err(|e| format!("discovery startup: {e}; preserve state"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let cancel = Arc::new(AtomicBool::new(false));
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| format!("SIGTERM: {e}"))?;
        let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).map_err(|e| format!("SIGINT: {e}"))?;
        let bound = peer.clone().bind().await.map_err(|e| e.to_string())?;
        println!("network-id {}", hex(&peer.network_id()));
        println!("peer-key {}", hex(&peer.application_key()));
        println!("advertisement-file {}", options.state.join("advertisement").display());
        println!("listen {}", bound.local_addr().map_err(|e| e.to_string())?);
        println!("discovery explicit-read-mode-local-registry");
        println!("registration-seeds {}", options.seeds.len());
        println!("registration-dependency /usr/bin/curl-system-tls-no-config-proxy-redirects");
        std::io::stdout().flush().map_err(|e| format!("stdout: {e}"))?;
        let registrar_peer = peer.clone(); let registrar_cancel = cancel.clone();
        let registrar = tokio::spawn(async move {
            let mut seeds = options.seeds;
            loop {
                let peer = registrar_peer.clone(); let cancel = registrar_cancel.clone();
                let job = tokio::task::spawn_blocking(move || {
                    for (index, seed) in seeds.iter_mut().enumerate() {
                        if cancel.load(Ordering::Relaxed) { break; }
                        match register(&peer, seed, options.attempts, &cancel) {
                            Ok(Some(receipt)) => println!("seed-registered {} receiver={} sequence={} generation={} scope=local-registry-only", index + 1, hex(&receipt.receiver()), receipt.sequence(), receipt.generation()),
                            Ok(None) => {},
                            Err(error) => eprintln!("seed-registration {}: {error}", index + 1),
                        }
                    }
                    seeds
                });
                match job.await { Ok(next) => seeds = next, Err(_) => { eprintln!("seed-registration worker failed; serving continues without new outgoing registrations"); break; } }
                tokio::time::sleep(POLL).await;
            }
        });
        let outcome = bound.run(async { tokio::select! { _ = term.recv() => {}, _ = interrupt.recv() => {} } }).await.map_err(|e| e.to_string());
        cancel.store(true, Ordering::Relaxed);
        registrar.abort();
        let _ = registrar.await;
        outcome
    });
    cancel.store(true, Ordering::Relaxed);
    runtime.shutdown_timeout(Duration::from_secs(15));
    result
}

#[cfg(test)]
#[path = "public_discovery/tests.rs"]
mod tests;
