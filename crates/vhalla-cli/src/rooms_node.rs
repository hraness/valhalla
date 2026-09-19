//! The `rooms node` service command: hosts a room-consensus validator.
//!
//! `vhalla rooms node SOCIAL_STORE NODE_HOME REALM --config FILE` opens a
//! `vhalla_rooms_node::RoomNode` seeded from the committed social snapshot
//! and the shared genesis parameters in FILE (JSON). The node runs until
//! interrupted; producers submit canonical batches by dropping `*.batch`
//! files into `NODE_HOME/intake/`.

use std::collections::BTreeMap;
use std::ffi::OsString;

use serde::Deserialize;
use vhalla_core::RealmId;
use vhalla_journal::Store as _;
use vhalla_rooms::{registry::DirectoryPolicy, DirectoryId};
use vhalla_rooms_node::{
    net_peer_id, service_config, NodeSpec, PeerSpec, PrivateKey, PublicKey, RoomNode,
    RoomValidator, RoomValidatorSet,
};
use vhalla_social::archive::Limits;
use vhalla_social::OwnerId;

use vhalla_social_store::read_archive;

use crate::json;
use crate::rooms::{hex32, Args};

/// The JSON node file: local identity and networking plus the shared
/// genesis parameters every validator must carry identically.
#[derive(Deserialize)]
struct NodeFile {
    /// Ed25519 consensus seed, 64 hex characters.
    node_key: String,
    /// libp2p TCP listen port.
    port: usize,
    /// Optional interface to bind, as a bare host — an IP or resolvable
    /// name, never `host:port`. Default `127.0.0.1`; a non-loopback bind
    /// keeps malachite's default per-IP connection bound instead of the
    /// single-host ceiling lift.
    #[serde(default)]
    listen: Option<String>,
    /// Persistent peers as `host:port` strings, optionally pinned to the
    /// peer node's consensus public key as `KEY64@host:port` — the same
    /// key `validators[].key` carries for a validator peer. A pinned
    /// peer is dialed with its deterministic libp2p peer id on the
    /// multiaddr, so the connection authenticates that identity during
    /// the Noise handshake; an unpinned peer accepts whatever answers.
    #[serde(default)]
    peers: Vec<String>,
    /// Close the mesh: reject connections to and from peers outside the
    /// persistent set. Requires every `peers` entry to carry a `KEY@`
    /// pin — an unpinned address cannot authenticate an inbound peer, so
    /// the decode fails rather than silently never admitting it.
    #[serde(default)]
    peers_only: bool,
    /// Optional shared realm, 32 hex characters. When present it must
    /// equal the REALM positional — `node-init` writes it so a member
    /// cannot boot against the wrong realm by argument.
    #[serde(default)]
    realm: Option<String>,
    /// Validator activations — `{from, key, power}` entries grouped by
    /// the height at which the set becomes active.
    validators: Vec<ValidatorEntry>,
    /// The shared directory identifier, 64 hex characters.
    directory: String,
    /// The shared directory policy.
    policy: PolicyFile,
    /// Eligible award-source owners, 64 hex each.
    #[serde(default)]
    eligible: Vec<String>,
    /// The shared archive bounds.
    limits: LimitsFile,
}

/// The shared-params file `rooms network-init` writes and `rooms
/// node-init` consumes: every genesis field that must be identical
/// across the set, minus member-local identity and networking.
#[derive(Deserialize)]
struct NetworkFile {
    /// The shared realm, 32 hex characters.
    realm: String,
    /// The shared directory identifier, 64 hex characters.
    directory: String,
    /// The shared directory policy.
    policy: PolicyFile,
    /// Eligible award-source owners, 64 hex each.
    #[serde(default)]
    eligible: Vec<String>,
    /// The shared archive bounds.
    limits: LimitsFile,
    /// Validator activations — `{from, key, power}` entries.
    validators: Vec<ValidatorEntry>,
}

#[derive(Clone, Deserialize)]
struct ValidatorEntry {
    /// Activation height.
    from: u64,
    /// Ed25519 public key, 64 hex characters.
    key: String,
    /// Voting power.
    power: u64,
}

#[derive(Deserialize)]
struct PolicyFile {
    base_cost: u64,
    window_seconds: u64,
    max_in_window: u16,
    support_epoch_seconds: u64,
    max_lifetime_rooms: u32,
}

#[derive(Deserialize)]
struct LimitsFile {
    records: usize,
    control_reserve: usize,
    data_per_owner: usize,
    data_per_writer: usize,
    control_per_owner: usize,
    pending: usize,
    pending_per_signer: usize,
}

/// A peer entry is `host:port`, optionally pinned to the peer node's
/// consensus public key as `KEY64@host:port` — the pin names the same
/// Ed25519 key `validators[].key` carries, never the libp2p peer id
/// itself: the node derives the peer id from the key (`net_peer_id`),
/// so the pin cannot drift from the identity the remote's signed
/// validator proof binds to its consensus key.
fn peers(raw: &[String]) -> Result<Vec<PeerSpec>, String> {
    raw.iter()
        .map(|p| {
            let (pin, addr) = match p.split_once('@') {
                Some((key, addr)) => (Some(key), addr),
                None => (None, p.as_str()),
            };
            let (host, port) = addr
                .rsplit_once(':')
                .ok_or_else(|| format!("peer {p:?} must be host:port or KEY@host:port"))?;
            if host.is_empty() || host.contains('@') {
                return Err(format!("peer {p:?} must be host:port or KEY@host:port"));
            }
            let key = pin
                .map(|k| {
                    let bytes = hex32(k).map_err(|_| format!("peer {p:?} key must be 64 hex"))?;
                    PublicKey::from_bytes(bytes)
                        .map_err(|_| format!("peer {p:?} key is not an Ed25519 public key"))
                })
                .transpose()?;
            Ok(PeerSpec {
                host: host.to_owned(),
                port: port.parse().map_err(|_| format!("peer {p:?} port"))?,
                key,
            })
        })
        .collect()
}

/// The parsed node config plus the decoded genesis inputs: everything
/// `node` needs to build a `NodeSpec` and everything `node check`
/// reports on, decoded through the identical path so `check` is a real
/// pre-flight rather than a parallel implementation.
struct Loaded {
    file: NodeFile,
    node_key: PrivateKey,
    /// Activation height → sorted, deduplicated validator set.
    validator_sets: BTreeMap<u64, RoomValidatorSet>,
    /// Parsed persistent peers, each optionally pinned to the peer
    /// node's consensus public key.
    peers: Vec<PeerSpec>,
    limits: Limits,
    policy: DirectoryPolicy,
    eligible: Vec<OwnerId>,
    /// The committed genesis archive read under a shared hold.
    archive: vhalla_social::archive::Archive,
    directory: DirectoryId,
}

/// The consensus-visible quorum boundary: strict `weight * 3 > total * 2`
/// per decided value. Returns `(quorum_power, absent_power_tolerated)`.
fn quorum(total: u64) -> (u64, u64) {
    let needed = total * 2 / 3 + 1;
    (needed, total.saturating_sub(needed))
}

/// The genesis fingerprint two members compare: a SHA-256 commitment over
/// the canonical (order- and duplication-insensitive) encoding of every
/// shared parameter — realm, directory, policy, limits, eligible set and
/// every validator activation. Two members with the same fingerprint boot
/// the same registry and validator sets; a difference means a shared
/// field diverged before any networking happened.
fn genesis_fingerprint(
    realm: RealmId,
    directory: &DirectoryId,
    policy: &DirectoryPolicy,
    eligible: &[OwnerId],
    limits: &Limits,
    validator_sets: &BTreeMap<u64, RoomValidatorSet>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"vhalla/rooms/genesis/v1\0");
    hash.update(realm.0.to_be_bytes());
    hash.update(directory.as_bytes());
    for field in [
        policy.base_cost,
        policy.window_seconds,
        u64::from(policy.max_in_window),
        policy.support_epoch_seconds,
        u64::from(policy.max_lifetime_rooms),
    ] {
        hash.update(field.to_be_bytes());
    }
    for field in [
        limits.records as u64,
        limits.control_reserve as u64,
        limits.data_per_owner as u64,
        limits.data_per_writer as u64,
        limits.control_per_owner as u64,
        limits.pending as u64,
        limits.pending_per_signer as u64,
    ] {
        hash.update(field.to_be_bytes());
    }
    // Eligibility is a BTreeSet in the registry: canonicalize order and
    // duplicates so a re-sorted file fingerprints identically.
    let mut eligible: Vec<[u8; 32]> = eligible.iter().map(|id| *id.as_bytes()).collect();
    eligible.sort_unstable();
    eligible.dedup();
    hash.update((eligible.len() as u32).to_be_bytes());
    for id in &eligible {
        hash.update(id);
    }
    // Validator sets are already sorted (power desc, address asc) and
    // deduplicated by `RoomValidatorSet::new` — hashing the built sets
    // binds exactly what consensus sees.
    hash.update((validator_sets.len() as u32).to_be_bytes());
    for (from, set) in validator_sets {
        hash.update(from.to_be_bytes());
        hash.update((set.validators.len() as u32).to_be_bytes());
        for validator in &set.validators {
            hash.update(validator.public_key.as_bytes());
            hash.update(validator.power.to_be_bytes());
        }
    }
    hash.finalize().into()
}

/// Parse a `--policy` CSV in the `rooms init` order: base, window,
/// max-in-window, epoch, lifetime.
fn parse_policy(raw: &str) -> Result<DirectoryPolicy, String> {
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() != 5 {
        return Err("--policy takes BASE,WINDOW,MAXWIN,EPOCH,LIFETIME".into());
    }
    let parse = |s: &str, name: &str| -> Result<u64, String> {
        s.parse().map_err(|_| format!("invalid --policy {name}"))
    };
    Ok(DirectoryPolicy {
        base_cost: parse(parts[0], "base")?,
        window_seconds: parse(parts[1], "window")?,
        max_in_window: parse(parts[2], "maxwin")?
            .try_into()
            .map_err(|_| "--policy maxwin out of range")?,
        support_epoch_seconds: parse(parts[3], "epoch")?,
        max_lifetime_rooms: parse(parts[4], "lifetime")?
            .try_into()
            .map_err(|_| "--policy lifetime out of range")?,
    })
}

/// Parse a `--limits` CSV in field order, or the `Limits::default()`
/// bounds when the flag is absent/`default`.
fn parse_limits(raw: Option<&str>) -> Result<Limits, String> {
    let raw = match raw {
        None | Some("default") => return Ok(Limits::default()),
        Some(raw) => raw,
    };
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() != 7 {
        return Err(
            "--limits takes RECORDS,CONTROL_RESERVE,DATA_PER_OWNER,DATA_PER_WRITER,CONTROL_PER_OWNER,PENDING,PENDING_PER_SIGNER".into(),
        );
    }
    let mut fields = [0usize; 7];
    for (i, part) in parts.iter().enumerate() {
        fields[i] = part.parse().map_err(|_| "invalid --limits value")?;
    }
    Limits {
        records: fields[0],
        control_reserve: fields[1],
        data_per_owner: fields[2],
        data_per_writer: fields[3],
        control_per_owner: fields[4],
        pending: fields[5],
        pending_per_signer: fields[6],
    }
    .check()
    .map_err(|e| format!("--limits: {e:?}"))
}

/// Parse `--validators` entries as `FROM:KEY64:POWER` CSV.
fn parse_validators(raw: &str) -> Result<Vec<ValidatorEntry>, String> {
    raw.split(',')
        .map(|entry| {
            let mut parts = entry.split(':');
            let from = parts
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or("validator needs FROM:KEY:POWER")?;
            let key = parts.next().ok_or("validator needs FROM:KEY:POWER")?;
            if hex32(key).is_err() {
                return Err("validator key must be 64 hex".into());
            }
            let power = parts
                .next()
                .and_then(|p| p.parse().ok())
                .ok_or("validator needs FROM:KEY:POWER")?;
            if parts.next().is_some() {
                return Err("validator needs FROM:KEY:POWER".into());
            }
            Ok(ValidatorEntry {
                from,
                key: key.to_owned(),
                power,
            })
        })
        .collect()
}

/// Group validator entries into sorted sets — the decode both `load` and
/// the scaffolding commands share so a fingerprint binds the exact sets
/// consensus would see.
fn build_validator_sets(
    entries: &[ValidatorEntry],
) -> Result<BTreeMap<u64, RoomValidatorSet>, String> {
    let mut grouped: BTreeMap<u64, Vec<RoomValidator>> = BTreeMap::new();
    for entry in entries {
        if entry.from == 0 {
            return Err("validator activation heights start at 1".into());
        }
        let key =
            PublicKey::from_bytes(hex32(&entry.key)?).map_err(|e| format!("validator key: {e}"))?;
        if entry.power == 0 {
            return Err("validator power must be positive".into());
        }
        grouped
            .entry(entry.from)
            .or_default()
            .push(RoomValidator::new(key, entry.power));
    }
    grouped
        .into_iter()
        .map(|(from, set)| {
            RoomValidatorSet::try_new(set)
                .map(|set| (from, set))
                .map_err(|error| format!("validator set at height {from}: {error:?}"))
        })
        .collect()
}

/// The typed genesis inputs of a `node.json` — everything `load` decodes
/// except the social archive, so `node-update` re-validates the shared
/// fields without opening the store.
struct DecodedNode {
    node_key: PrivateKey,
    /// Activation height → sorted, deduplicated validator set.
    validator_sets: BTreeMap<u64, RoomValidatorSet>,
    /// Parsed persistent peers, each optionally pinned to the peer
    /// node's consensus public key.
    peers: Vec<PeerSpec>,
    limits: Limits,
    policy: DirectoryPolicy,
    eligible: Vec<OwnerId>,
    directory: DirectoryId,
    /// The file's optional shared realm, decoded when present.
    realm: Option<u128>,
}

/// The shared decode of a `NodeFile`: identical for `node`, `node-check`
/// and `node-update`, so a config any of them accepts is one all of them
/// accept.
fn decode_node(file: &NodeFile) -> Result<DecodedNode, String> {
    let realm = file
        .realm
        .as_deref()
        .map(crate::rooms::hex128)
        .transpose()?;
    let node_key = PrivateKey::from(hex32(&file.node_key)?);
    let validator_sets = build_validator_sets(&file.validators)?;
    if validator_sets.is_empty() {
        return Err("config names no validators".into());
    }
    let limits = Limits {
        records: file.limits.records,
        control_reserve: file.limits.control_reserve,
        data_per_owner: file.limits.data_per_owner,
        data_per_writer: file.limits.data_per_writer,
        control_per_owner: file.limits.control_per_owner,
        pending: file.limits.pending,
        pending_per_signer: file.limits.pending_per_signer,
    };
    let policy = DirectoryPolicy {
        base_cost: file.policy.base_cost,
        window_seconds: file.policy.window_seconds,
        max_in_window: file.policy.max_in_window,
        support_epoch_seconds: file.policy.support_epoch_seconds,
        max_lifetime_rooms: file.policy.max_lifetime_rooms,
    };
    policy
        .validate()
        .map_err(|e| format!("config policy: {e:?}"))?;
    limits
        .check()
        .map_err(|e| format!("config limits: {e:?}"))?;
    let eligible: Vec<OwnerId> = file
        .eligible
        .iter()
        .map(|id| hex32(id).map(OwnerId::from_bytes))
        .collect::<Result<_, _>>()?;
    if eligible.len() > vhalla_rooms::registry::MAX_OWNERS {
        return Err("config names too many eligible owners".into());
    }
    let directory = DirectoryId::from_bytes(hex32(&file.directory)?);
    let peers = peers(&file.peers)?;
    if file.peers_only && peers.iter().any(|p| p.key.is_none()) {
        return Err(
            "peers_only requires every peer to carry a KEY@host:port pin - an unpinned address cannot authenticate an inbound peer".into(),
        );
    }
    Ok(DecodedNode {
        node_key,
        validator_sets,
        peers,
        limits,
        policy,
        eligible,
        directory,
        realm,
    })
}

/// Parse the config file into typed values and read the genesis archive
/// under a shared hold — identical to what `node` would do, so `check`
/// catches every boot-time failure short of opening the port.
fn load(args: &Args) -> Result<Loaded, String> {
    let path = args.config.as_deref().ok_or("node needs --config FILE")?;
    let raw = std::fs::read(path).map_err(|e| format!("config: {e}"))?;
    if raw.len() > 64 * 1024 {
        return Err("config exceeds 64KiB".into());
    }
    let file: NodeFile = serde_json::from_slice(&raw).map_err(|e| format!("config JSON: {e}"))?;
    let decoded = decode_node(&file)?;
    if let Some(realm) = decoded.realm {
        if realm != args.realm.0 {
            return Err("config realm does not match the REALM argument".into());
        }
    }

    // Genesis seeds from the committed social snapshot, decoded under the
    // configured limits — the archive's own bounds are a genesis parameter,
    // not the reader's default. A shared read waits out a concurrent owner
    // command instead of dying on its exclusive lock.
    let archive =
        read_archive(&args.social_store, args.realm, decoded.limits).map_err(|e| match e {
            vhalla_social_store::Error::RecoveryRequired => {
                "social store requires explicit social recover first".to_string()
            }
            e => e.to_string(),
        })?;
    Ok(Loaded {
        file,
        node_key: decoded.node_key,
        validator_sets: decoded.validator_sets,
        peers: decoded.peers,
        limits: decoded.limits,
        policy: decoded.policy,
        eligible: decoded.eligible,
        archive,
        directory: decoded.directory,
    })
}

/// The `node` subcommand entry point: parse the config, seed genesis from
/// the committed social snapshot, host the validator until interrupted.
/// `RUST_LOG` enables malachite's internal tracing on stderr.
pub fn run(args: &Args) -> Result<(), String> {
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }
    let loaded = load(args)?;

    let spec = NodeSpec {
        home: args.rooms_store.clone().into(),
        config: service_config(
            "vhalla-rooms-node",
            loaded.file.listen.as_deref().unwrap_or("127.0.0.1"),
            loaded.file.port,
            &loaded.peers,
            loaded.file.peers_only,
        ),
        node_key: loaded.node_key,
        validator_sets: loaded.validator_sets,
        held: BTreeMap::new(),
        genesis: vhalla_rooms_consensus::Genesis {
            directory: loaded.directory,
            realm: args.realm,
            policy: loaded.policy,
            eligible: loaded.eligible,
            limits: loaded.limits,
            archive: loaded.archive,
        },
        wal_faults: None,
        net_gate: None,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(8)
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    runtime.block_on(async move {
        let node = RoomNode::start(spec).await;
        println!(
            "{{\"listening\":{},\"address\":\"{:?}\",\"committed\":{}}}",
            loaded.file.port,
            node.address,
            node.committed_height()
        );
        let _ = tokio::signal::ctrl_c().await;
        node.crash().await;
    });
    Ok(())
}

/// The `eligible` subcommand: emit an operator intake file carrying a
/// replacement eligible award-source set into `NODE_HOME/intake/`. The node
/// drains it as a config-only body and the transition commits — applying
/// after that batch's records — at the next decided height. The social
/// store and realm arguments are unused; they keep the shared rooms
/// argument shape.
pub fn eligible(args: &Args) -> Result<(), String> {
    if args.value(1).is_some() {
        return Err("eligible takes exactly OWNER64,... - the replacement set".into());
    }
    let owners: Vec<OwnerId> = args
        .value(0)
        .ok_or("eligible takes OWNER64,... - the replacement set")?
        .split(',')
        .map(|id| hex32(id).map(OwnerId::from_bytes))
        .collect::<Result<_, _>>()?;
    if owners.is_empty() || owners.len() > vhalla_rooms::registry::MAX_OWNERS {
        return Err("eligible takes 1..=256 owner ids".into());
    }
    let bytes = vhalla_rooms_consensus::encode_eligible_update(&owners);
    let intake = std::path::Path::new(&args.rooms_store).join("intake");
    std::fs::create_dir_all(&intake).map_err(|e| format!("intake: {e}"))?;
    // Name the file deterministically from the canonical bytes so a repeated
    // command converges on one pending marker rather than duplicating work.
    // Plain hex, never `json::id` — the intake stem filter admits only
    // `[a-zA-Z0-9._-]`, and a quoted id would rename the drop `.rejected`.
    let stem = format!("eligible-{}", crate::json::hex(&bytes[8..24]));
    let target = intake.join(format!("{stem}.eligible"));
    let tmp = intake.join(format!("{stem}.tmp"));
    std::fs::write(&tmp, &bytes).map_err(|e| format!("write: {e}"))?;
    std::fs::rename(&tmp, &target).map_err(|e| format!("rename: {e}"))?;
    println!(
        "{}",
        json::object(vec![
            ("intake", json::string(&target.display().to_string())),
            ("owners", owners.len().to_string()),
        ])
    );
    Ok(())
}

/// The `node-check` subcommand: run the full `node` decode path — config
/// parse, genesis-parameter build, shared archive read — then report the
/// genesis fingerprint, archive root, quorum arithmetic and this key's
/// voting status instead of serving. Two members whose `genesis` and
/// `archive` fields match carry identical genesis bases; a member whose
/// `node_key_votes_from` is null follows but never votes.
pub fn check(args: &Args) -> Result<(), String> {
    if args.value(0).is_some() {
        return Err("node-check takes no positional arguments".into());
    }
    let loaded = load(args)?;
    let genesis = genesis_fingerprint(
        args.realm,
        &loaded.directory,
        &loaded.policy,
        &loaded.eligible,
        &loaded.limits,
        &loaded.validator_sets,
    );
    let public = loaded.node_key.public_key();
    let votes_from = loaded
        .validator_sets
        .iter()
        .find(|(_, set)| {
            set.validators
                .iter()
                .any(|v| v.public_key.as_bytes() == public.as_bytes())
        })
        .map(|(from, _)| *from);
    let mut warnings = Vec::new();
    let mut sets_json = Vec::new();
    for (from, set) in &loaded.validator_sets {
        let total: u64 = set.validators.iter().map(|v| v.power).sum();
        let (needed, tolerated) = quorum(total);
        if tolerated == 0 {
            warnings.push(format!(
                "validator set active from height {from} cannot lose any member and still decide (strict >2/3 quorum)"
            ));
        }
        if let Some(v) = set.validators.iter().find(|v| v.power >= needed) {
            warnings.push(format!(
                "validator {} alone meets quorum in the set active from height {from}",
                json::hex(v.public_key.as_bytes())
            ));
        }
        sets_json.push(json::object(vec![
            ("from", from.to_string()),
            ("validators", set.validators.len().to_string()),
            ("total_power", total.to_string()),
            ("quorum_power", needed.to_string()),
            ("absent_power_tolerated", tolerated.to_string()),
        ]));
    }
    if votes_from.is_none() {
        warnings.push(
            "node_key is not in any validator set - the node follows but never votes".to_string(),
        );
    }
    let pinned = loaded.peers.iter().filter(|p| p.key.is_some()).count();
    for p in loaded.peers.iter().filter(|p| p.key.is_none()) {
        warnings.push(format!(
            "peer {}:{} has no key pin - its transport identity is not authenticated on dial",
            p.host, p.port
        ));
    }
    println!(
        "{}",
        json::object(vec![
            ("genesis", json::id(&genesis)),
            ("archive", json::id(loaded.archive.root().as_bytes())),
            ("validator_sets", json::array(sets_json)),
            ("public_key", json::string(&json::hex(public.as_bytes()))),
            ("node_peer_id", json::string(&net_peer_id(&public))),
            (
                "node_key_votes_from",
                votes_from.map_or("null".into(), |f| f.to_string())
            ),
            ("eligible", loaded.eligible.len().to_string()),
            (
                "listen",
                json::string(loaded.file.listen.as_deref().unwrap_or("127.0.0.1"))
            ),
            ("port", loaded.file.port.to_string()),
            ("peers", loaded.peers.len().to_string()),
            ("pinned_peers", pinned.to_string()),
            ("peers_only", loaded.file.peers_only.to_string()),
            (
                "warnings",
                json::array(warnings.iter().map(|w| json::string(w)))
            ),
        ])
    );
    Ok(())
}

/// Minimal flag parser for the scaffolding commands, which don't fit the
/// shared four-positional rooms shape. Returns `(positionals, flags)`;
/// every `--name` needs a value, unknown or repeated flags are rejected.
fn flags(
    raw: &[OsString],
    allowed: &[&str],
) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
    let mut positionals = Vec::new();
    let mut flags = BTreeMap::new();
    let mut literal = false;
    let mut args = raw.iter();
    while let Some(raw) = args.next() {
        let value = raw.to_str().ok_or("arguments must be UTF-8")?;
        if value.len() > 8192 {
            return Err("argument exceeds 8192 bytes".into());
        }
        if !literal && value == "--" {
            literal = true;
            continue;
        }
        if !literal && value.starts_with("--") {
            let name = &value[2..];
            if !allowed.contains(&name) {
                return Err(format!("unknown option --{name}"));
            }
            let next = args.next().ok_or(format!("--{name} needs a value"))?;
            let next = next.to_str().ok_or("option values must be UTF-8")?;
            if flags.insert(name.to_owned(), next.to_owned()).is_some() {
                return Err(format!("--{name} given twice"));
            }
            continue;
        }
        positionals.push(value.to_owned());
    }
    Ok((positionals, flags))
}

/// The canonical shared-params JSON both `network-init` writes and
/// `node-init` reads back — serialization is fixed-field so the file
/// itself is diffable across operators.
fn network_json(file: &NetworkFile) -> String {
    let validators: Vec<String> = file
        .validators
        .iter()
        .map(|v| {
            json::object(vec![
                ("from", v.from.to_string()),
                ("key", json::string(&v.key)),
                ("power", v.power.to_string()),
            ])
        })
        .collect();
    let eligible: Vec<String> = file.eligible.iter().map(|o| json::string(o)).collect();
    format!(
        "{{\n  \"realm\": {},\n  \"directory\": {},\n  \"policy\": {},\n  \"eligible\": {},\n  \"limits\": {},\n  \"validators\": {}\n}}\n",
        json::string(&file.realm),
        json::string(&file.directory),
        json::object(vec![
            ("base_cost", file.policy.base_cost.to_string()),
            ("window_seconds", file.policy.window_seconds.to_string()),
            ("max_in_window", file.policy.max_in_window.to_string()),
            (
                "support_epoch_seconds",
                file.policy.support_epoch_seconds.to_string()
            ),
            (
                "max_lifetime_rooms",
                file.policy.max_lifetime_rooms.to_string()
            ),
        ]),
        json::array(eligible),
        json::object(vec![
            ("records", file.limits.records.to_string()),
            ("control_reserve", file.limits.control_reserve.to_string()),
            ("data_per_owner", file.limits.data_per_owner.to_string()),
            ("data_per_writer", file.limits.data_per_writer.to_string()),
            (
                "control_per_owner",
                file.limits.control_per_owner.to_string()
            ),
            ("pending", file.limits.pending.to_string()),
            (
                "pending_per_signer",
                file.limits.pending_per_signer.to_string()
            ),
        ]),
        json::array(validators),
    )
}

/// The decoded shared-params file: the typed genesis inputs every
/// member's `node.json` derives from, alongside the file itself for
/// re-encoding.
struct Network {
    file: NetworkFile,
    realm: RealmId,
    directory: DirectoryId,
    policy: DirectoryPolicy,
    eligible: Vec<OwnerId>,
    limits: Limits,
    /// Activation height → sorted, deduplicated validator set.
    validator_sets: BTreeMap<u64, RoomValidatorSet>,
}

/// Decode a `NetworkFile` into the typed genesis inputs — the validation
/// `network-init` reporting, `node-init`, and `node-check` share so a
/// tampered or hand-edited file fails before it seeds a config.
fn decode_network(file: NetworkFile) -> Result<Network, String> {
    let realm = RealmId(crate::rooms::hex128(&file.realm)?);
    let directory = DirectoryId::from_bytes(hex32(&file.directory)?);
    let policy = DirectoryPolicy {
        base_cost: file.policy.base_cost,
        window_seconds: file.policy.window_seconds,
        max_in_window: file.policy.max_in_window,
        support_epoch_seconds: file.policy.support_epoch_seconds,
        max_lifetime_rooms: file.policy.max_lifetime_rooms,
    };
    policy
        .validate()
        .map_err(|e| format!("network policy: {e:?}"))?;
    let limits = Limits {
        records: file.limits.records,
        control_reserve: file.limits.control_reserve,
        data_per_owner: file.limits.data_per_owner,
        data_per_writer: file.limits.data_per_writer,
        control_per_owner: file.limits.control_per_owner,
        pending: file.limits.pending,
        pending_per_signer: file.limits.pending_per_signer,
    };
    limits
        .check()
        .map_err(|e| format!("network limits: {e:?}"))?;
    let eligible: Vec<OwnerId> = file
        .eligible
        .iter()
        .map(|id| hex32(id).map(OwnerId::from_bytes))
        .collect::<Result<_, _>>()?;
    if eligible.len() > vhalla_rooms::registry::MAX_OWNERS {
        return Err("network file names too many eligible owners".into());
    }
    let validator_sets = build_validator_sets(&file.validators)?;
    if validator_sets.is_empty() {
        return Err("network file names no validators".into());
    }
    Ok(Network {
        file,
        realm,
        directory,
        policy,
        eligible,
        limits,
        validator_sets,
    })
}

/// Read and decode the shared-params file.
fn read_network(path: &str) -> Result<Network, String> {
    let raw = std::fs::read(path).map_err(|e| format!("network file: {e}"))?;
    if raw.len() > 64 * 1024 {
        return Err("network file exceeds 64KiB".into());
    }
    let file: NetworkFile =
        serde_json::from_slice(&raw).map_err(|e| format!("network JSON: {e}"))?;
    decode_network(file)
}

/// The `network-init` subcommand — the operator-side half of validator-set
/// setup. Writes one canonical shared-params file every member consumes
/// through `node-init`, so no member hand-assembles the fields that must
/// agree byte-for-byte.
///
/// `vhalla rooms network-init OUT --realm R32 --directory D64
///  --policy BASE,WINDOW,MAXWIN,EPOCH,LIFETIME --validators FROM:KEY:POWER,...
///  [--eligible OWNER64,...] [--limits default|R,CR,DPO,DPW,CPO,P,PPS]`
pub fn network_init(raw: &[OsString]) -> Result<(), String> {
    let (positional, flags) = flags(
        raw,
        &[
            "realm",
            "directory",
            "policy",
            "validators",
            "eligible",
            "limits",
        ],
    )?;
    if positional.len() != 1 {
        return Err("network-init takes exactly one output path".into());
    }
    let out = std::path::Path::new(&positional[0]);
    if out.exists() {
        return Err("network-init never overwrites an existing file".into());
    }
    let realm = flags.get("realm").ok_or("network-init needs --realm")?;
    crate::rooms::hex128(realm)?;
    let directory = flags
        .get("directory")
        .ok_or("network-init needs --directory")?;
    hex32(directory)?;
    let policy = parse_policy(flags.get("policy").ok_or("network-init needs --policy")?)?;
    policy.validate().map_err(|e| format!("--policy: {e:?}"))?;
    let validators_raw = flags
        .get("validators")
        .ok_or("network-init needs --validators")?;
    let validators = parse_validators(validators_raw)?;
    let eligible: Vec<String> = match flags.get("eligible") {
        None => Vec::new(),
        Some(csv) if csv.is_empty() => Vec::new(),
        Some(csv) => csv
            .split(',')
            .map(|id| {
                hex32(id)?;
                Ok(id.to_owned())
            })
            .collect::<Result<_, String>>()?,
    };
    let limits = parse_limits(flags.get("limits").map(String::as_str))?;
    let file = NetworkFile {
        realm: realm.clone(),
        directory: directory.clone(),
        policy: PolicyFile {
            base_cost: policy.base_cost,
            window_seconds: policy.window_seconds,
            max_in_window: policy.max_in_window,
            support_epoch_seconds: policy.support_epoch_seconds,
            max_lifetime_rooms: policy.max_lifetime_rooms,
        },
        eligible,
        limits: LimitsFile {
            records: limits.records,
            control_reserve: limits.control_reserve,
            data_per_owner: limits.data_per_owner,
            data_per_writer: limits.data_per_writer,
            control_per_owner: limits.control_per_owner,
            pending: limits.pending,
            pending_per_signer: limits.pending_per_signer,
        },
        validators,
    };
    let network = decode_network(file)?;
    let genesis = genesis_fingerprint(
        network.realm,
        &network.directory,
        &network.policy,
        &network.eligible,
        &network.limits,
        &network.validator_sets,
    );
    std::fs::write(out, network_json(&network.file)).map_err(|e| format!("write: {e}"))?;
    let total: u64 = network
        .validator_sets
        .values()
        .next()
        .map(|s| s.validators.iter().map(|v| v.power).sum())
        .unwrap_or(0);
    let (needed, tolerated) = quorum(total);
    println!(
        "{}",
        json::object(vec![
            ("wrote", json::string(&out.display().to_string())),
            ("genesis", json::id(&genesis)),
            (
                "validators",
                network
                    .validator_sets
                    .values()
                    .map(|s| s.validators.len())
                    .sum::<usize>()
                    .to_string()
            ),
            ("quorum_power", needed.to_string()),
            ("absent_power_tolerated", tolerated.to_string()),
        ])
    );
    Ok(())
}

/// The `node-init` subcommand — the member-side half. Merges the shared
/// network file with the member's own key and networking into
/// `NODE_HOME/node.json` and creates `NODE_HOME/intake/`. The file is
/// never overwritten; a second run against the same home fails. On unix a
/// scaffolded home is owner-private: the home itself when init creates it,
/// `intake/` always, and `node.json` at 0600 — it carries the seed.
///
/// `vhalla rooms node-init NODE_HOME --network FILE --port N
///  [--node-key HEX64] [--listen HOST] [--peers [KEY64@]HOST:PORT,...]
///  [--peers-only true]`
pub fn node_init(raw: &[OsString]) -> Result<(), String> {
    let (positional, flags) = flags(
        raw,
        &[
            "network",
            "node-key",
            "port",
            "listen",
            "peers",
            "peers-only",
        ],
    )?;
    if positional.len() != 1 {
        return Err("node-init takes exactly one NODE_HOME".into());
    }
    let home = std::path::Path::new(&positional[0]);
    let target = home.join("node.json");
    if target.exists() {
        return Err("node-init never overwrites an existing node.json".into());
    }
    let network_path = flags
        .get("network")
        .ok_or("node-init needs --network FILE")?;
    let network = read_network(network_path)?;
    let port: usize = flags
        .get("port")
        .ok_or("node-init needs --port N")?
        .parse()
        .map_err(|_| "invalid --port")?;
    if port == 0 || port > u16::MAX as usize {
        return Err("--port must be 1..65535".into());
    }
    let (seed, generated) = match flags.get("node-key") {
        Some(raw) => (hex32(raw)?, false),
        None => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|_| "node-init: OS entropy unavailable")?;
            (seed, true)
        }
    };
    let key = PrivateKey::from(seed);
    let public = key.public_key();
    let votes_from = network
        .validator_sets
        .iter()
        .find(|(_, set)| {
            set.validators
                .iter()
                .any(|v| v.public_key.as_bytes() == public.as_bytes())
        })
        .map(|(from, _)| *from);
    let listen = flags.get("listen").cloned();
    let peer_list: Vec<String> = match flags.get("peers") {
        None => Vec::new(),
        Some(csv) if csv.is_empty() => Vec::new(),
        Some(csv) => csv.split(',').map(|p| p.to_owned()).collect(),
    };
    // The scaffold validates through the same parser `node`/`node-check`
    // decode — a malformed entry or a non-Ed25519 pin fails here, not at
    // first boot.
    let parsed_peers = peers(&peer_list)?;
    let peers_only = match flags.get("peers-only").map(String::as_str) {
        None => false,
        Some("true") => true,
        Some("false") => false,
        Some(_) => return Err("--peers-only must be true or false".into()),
    };
    if peers_only && parsed_peers.iter().any(|p| p.key.is_none()) {
        return Err("--peers-only requires every peer to carry a KEY@host:port pin".into());
    }
    let genesis = genesis_fingerprint(
        network.realm,
        &network.directory,
        &network.policy,
        &network.eligible,
        &network.limits,
        &network.validator_sets,
    );
    // The node file carries realm so `node`/`node-check` reject a REALM
    // argument that disagrees with the shared params it was scaffolded
    // from.
    let node = node_json(
        &json::hex(&seed),
        port,
        listen.as_deref(),
        &peer_list,
        peers_only,
        &network,
    );
    // node.json carries the validator seed and intake/ is the producer
    // drop boundary, so a scaffolded home is owner-private from creation.
    // A pre-existing home keeps the operator's own mode.
    #[cfg(unix)]
    let fresh_home = !home.exists();
    std::fs::create_dir_all(home.join("intake")).map_err(|e| format!("node home: {e}"))?;
    #[cfg(unix)]
    {
        if fresh_home {
            restrict(home, 0o700)?;
        }
        restrict(&home.join("intake"), 0o700)?;
    }
    write_node_json(&target, &node)?;
    let mut warnings = Vec::new();
    if votes_from.is_none() {
        warnings.push(
            "this key is not in the validator set - the node follows but never votes; share public_key with the operator to join"
                .to_string(),
        );
    }
    println!(
        "{}",
        json::object(vec![
            ("config", json::string(&target.display().to_string())),
            ("public_key", json::string(&json::hex(public.as_bytes()))),
            ("genesis", json::id(&genesis)),
            ("node_key_generated", generated.to_string()),
            (
                "node_key_votes_from",
                votes_from.map_or("null".into(), |f| f.to_string())
            ),
            (
                "warnings",
                json::array(warnings.iter().map(|w| json::string(w)))
            ),
        ])
    );
    Ok(())
}

/// Restrict `path` to `mode` — the owner-private boundary `node-init`
/// scaffolds around the seed file and the producer drop dir.
#[cfg(unix)]
fn restrict(path: &std::path::Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Write `node.json` atomically (same-directory temp + rename), 0600 on
/// unix — the file carries the validator seed, and the rename replaces
/// the inode, so every write must restate the mode.
fn write_node_json(target: &std::path::Path, node: &serde_json::Value) -> Result<(), String> {
    let tmp = target.with_file_name(format!(".node.json.tmp-{}", std::process::id()));
    let write = || -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .and_then(|mut f| {
                    f.write_all(&serde_json::to_vec_pretty(node).unwrap())
                        .and_then(|()| f.sync_all())
                })
                .map_err(|e| format!("write: {e}"))?;
        }
        #[cfg(not(unix))]
        std::fs::write(&tmp, serde_json::to_vec_pretty(node).unwrap())
            .map_err(|e| format!("write: {e}"))?;
        std::fs::rename(&tmp, target).map_err(|e| format!("write: {e}"))
    };
    if let Err(error) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

/// The `node.json` object `node-init` and `node-update` both emit: local
/// fields verbatim, every shared genesis field from the decoded network
/// params so the file is exactly what `node`/`node-check` read back.
fn node_json(
    node_key: &str,
    port: usize,
    listen: Option<&str>,
    peers: &[String],
    peers_only: bool,
    network: &Network,
) -> serde_json::Value {
    serde_json::json!({
        "node_key": node_key,
        "port": port,
        "listen": listen.unwrap_or("127.0.0.1"),
        "peers": peers,
        "peers_only": peers_only,
        "realm": json::hex(&network.realm.0.to_be_bytes()),
        "validators": network
            .validator_sets
            .iter()
            .flat_map(|(from, set)| {
                set.validators.iter().map(move |v| {
                    serde_json::json!({
                        "from": *from,
                        "key": json::hex(v.public_key.as_bytes()),
                        "power": v.power,
                    })
                })
            })
            .collect::<Vec<_>>(),
        "directory": json::hex(network.directory.as_bytes()),
        "policy": {
            "base_cost": network.policy.base_cost,
            "window_seconds": network.policy.window_seconds,
            "max_in_window": network.policy.max_in_window,
            "support_epoch_seconds": network.policy.support_epoch_seconds,
            "max_lifetime_rooms": network.policy.max_lifetime_rooms,
        },
        "eligible": network
            .eligible
            .iter()
            .map(|id| json::hex(id.as_bytes()))
            .collect::<Vec<_>>(),
        "limits": {
            "records": network.limits.records,
            "control_reserve": network.limits.control_reserve,
            "data_per_owner": network.limits.data_per_owner,
            "data_per_writer": network.limits.data_per_writer,
            "control_per_owner": network.limits.control_per_owner,
            "pending": network.limits.pending,
            "pending_per_signer": network.limits.pending_per_signer,
        },
    })
}

/// The `network-extend` subcommand — the operator-side half of a
/// validator-set rotation. Copies an existing shared-params file and
/// appends one complete replacement set activating at `--from`, so the
/// operator never re-types the fields that must stay identical.
///
/// `vhalla rooms network-extend IN OUT --from HEIGHT --validators KEY:POWER,...`
pub fn network_extend(raw: &[OsString]) -> Result<(), String> {
    let (positional, flags) = flags(raw, &["from", "validators"])?;
    if positional.len() != 2 {
        return Err("network-extend takes IN OUT".into());
    }
    let out = std::path::Path::new(&positional[1]);
    if out.exists() {
        return Err("network-extend never overwrites an existing file".into());
    }
    let network = read_network(&positional[0])?;
    let from: u64 = flags
        .get("from")
        .ok_or("network-extend needs --from HEIGHT")?
        .parse()
        .map_err(|_| "invalid --from HEIGHT")?;
    if network.file.validators.iter().any(|v| v.from == from) {
        return Err(format!(
            "network already schedules an activation at height {from}"
        ));
    }
    // The activation names the complete set from HEIGHT on — joining keys
    // add, absent keys leave, powers restate. `parse_validators` wants a
    // FROM field per entry; prepend it so the one --from applies to all.
    let set = flags
        .get("validators")
        .ok_or("network-extend needs --validators KEY:POWER,...")?;
    let entries = parse_validators(
        &set.split(',')
            .map(|entry| format!("{from}:{entry}"))
            .collect::<Vec<_>>()
            .join(","),
    )?;
    let mut file = NetworkFile {
        realm: network.file.realm.clone(),
        directory: network.file.directory.clone(),
        policy: network.file.policy,
        eligible: network.file.eligible.clone(),
        limits: network.file.limits,
        validators: network.file.validators.clone(),
    };
    file.validators.extend(entries);
    let network = decode_network(file)?;
    std::fs::write(out, network_json(&network.file)).map_err(|e| format!("write: {e}"))?;
    let genesis = genesis_fingerprint(
        network.realm,
        &network.directory,
        &network.policy,
        &network.eligible,
        &network.limits,
        &network.validator_sets,
    );
    let set = &network.validator_sets[&from];
    let total: u64 = set.validators.iter().map(|v| v.power).sum();
    let (needed, tolerated) = quorum(total);
    println!(
        "{}",
        json::object(vec![
            ("wrote", json::string(&out.display().to_string())),
            ("genesis", json::id(&genesis)),
            ("activation_from", from.to_string()),
            ("validators", set.validators.len().to_string()),
            ("quorum_power", needed.to_string()),
            ("absent_power_tolerated", tolerated.to_string()),
        ])
    );
    Ok(())
}

/// The highest committed height under a node home's journal, or 0 before
/// the first decision — the bound below which validator activations are
/// immutable history.
fn committed_height(journal: &std::path::Path) -> Result<u64, String> {
    if !journal.is_dir() {
        return Ok(0);
    }
    let markers = vhalla_journal::FsStore
        .list_height_markers(journal)
        .map_err(|e| format!("journal heights: {e:?}"))?;
    Ok(markers.into_iter().max().unwrap_or(0))
}

/// The `node-update` subcommand — the member-side half of a rotation.
/// Replaces `NODE_HOME/node.json`'s shared fields with an extended
/// network file while preserving the member's own key and networking.
/// The new file must carry the same realm, directory, policy, limits and
/// eligible set — those are genesis-fixed — and agree with the existing
/// config on every validator activation at or below the committed
/// height: decided history cannot be rescheduled. A running node picks
/// the new schedule up on restart; activations stay future-dated so the
/// whole set can converge before the switch.
///
/// `vhalla rooms node-update NODE_HOME --network FILE`
pub fn node_update(raw: &[OsString]) -> Result<(), String> {
    let (positional, flags) = flags(raw, &["network"])?;
    if positional.len() != 1 {
        return Err("node-update takes exactly one NODE_HOME".into());
    }
    let home = std::path::Path::new(&positional[0]);
    let target = home.join("node.json");
    let raw = std::fs::read(&target).map_err(|e| format!("node.json: {e}"))?;
    if raw.len() > 64 * 1024 {
        return Err("node.json exceeds 64KiB".into());
    }
    let file: NodeFile = serde_json::from_slice(&raw).map_err(|e| format!("node.json: {e}"))?;
    let existing = decode_node(&file)?;
    let network = read_network(
        flags
            .get("network")
            .ok_or("node-update needs --network FILE")?,
    )?;

    // Shared fields are genesis-fixed — a changed one names a different
    // network, not an update of this one.
    if let Some(realm) = existing.realm {
        if realm != network.realm.0 {
            return Err("network file names a different realm".into());
        }
    }
    if existing.directory != network.directory
        || existing.policy != network.policy
        || existing.limits != network.limits
    {
        return Err(
            "network file changed a genesis field (directory, policy or limits) - that is a new network, not an update".into(),
        );
    }
    let eligible_same = {
        let a: std::collections::BTreeSet<_> = existing.eligible.iter().collect();
        let b: std::collections::BTreeSet<_> = network.eligible.iter().collect();
        a == b
    };
    if !eligible_same {
        return Err(
            "network file changed the eligible set - eligible owners move in-band via `rooms eligible`, not config".into(),
        );
    }

    // Activations at or below the committed height decided real history:
    // the new file must reproduce that prefix exactly.
    let committed = committed_height(&home.join("app").join("journal"))?;
    for from in existing
        .validator_sets
        .keys()
        .chain(network.validator_sets.keys())
        .filter(|from| **from <= committed)
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        if existing.validator_sets.get(&from) != network.validator_sets.get(&from) {
            return Err(format!(
                "network file changes the validator set active at decided height {from}"
            ));
        }
    }

    let node = node_json(
        &file.node_key,
        file.port,
        file.listen.as_deref(),
        &file.peers,
        file.peers_only,
        &network,
    );
    write_node_json(&target, &node)?;

    let genesis = genesis_fingerprint(
        network.realm,
        &network.directory,
        &network.policy,
        &network.eligible,
        &network.limits,
        &network.validator_sets,
    );
    let public = existing.node_key.public_key();
    let votes_from = network
        .validator_sets
        .iter()
        .find(|(_, set)| {
            set.validators
                .iter()
                .any(|v| v.public_key.as_bytes() == public.as_bytes())
        })
        .map(|(from, _)| *from);
    let future: Vec<String> = network
        .validator_sets
        .range(committed + 1..)
        .map(|(from, set)| {
            json::object(vec![
                ("from", from.to_string()),
                ("validators", set.validators.len().to_string()),
            ])
        })
        .collect();
    let mut warnings = Vec::new();
    if votes_from.is_none() {
        warnings.push(
            "node_key is not in any validator set - the node follows but never votes".to_string(),
        );
    }
    println!(
        "{}",
        json::object(vec![
            ("config", json::string(&target.display().to_string())),
            ("genesis", json::id(&genesis)),
            ("committed", committed.to_string()),
            ("scheduled", json::array(future)),
            (
                "node_key_votes_from",
                votes_from.map_or("null".into(), |f| f.to_string())
            ),
            (
                "warnings",
                json::array(warnings.iter().map(|w| json::string(w)))
            ),
        ])
    );
    Ok(())
}

/// The `keygen` subcommand: print a fresh Ed25519 consensus seed and its
/// public key for a node config's `node_key`/`validators` entries. The
/// `node_key` line is the secret seed — keep it in the private config;
/// only `public_key` is shared with the set's other operators.
pub fn keygen() -> Result<(), String> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| "keygen: OS entropy unavailable")?;
    let key = PrivateKey::from(seed);
    println!(
        "{}",
        json::object(vec![
            ("node_key", json::string(&json::hex(&seed))),
            (
                "public_key",
                json::string(&json::hex(key.public_key().as_bytes()))
            ),
        ])
    );
    Ok(())
}

#[cfg(test)]
mod validator_config_tests {
    use super::*;

    #[test]
    fn reject_overflowing_or_conflicting_validator_config() {
        let key = json::hex(PrivateKey::from([1; 32]).public_key().as_bytes());
        let entry = |power| ValidatorEntry {
            from: 1,
            key: key.clone(),
            power,
        };
        assert!(build_validator_sets(&[entry(u64::MAX)]).is_err());
        assert!(build_validator_sets(&[entry(1), entry(2)]).is_err());
        let sets = build_validator_sets(&[entry(1), entry(1)]).unwrap();
        assert_eq!(sets[&1].validators.len(), 1);
    }
}
