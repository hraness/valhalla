//! The `rooms node` service command: hosts a room-consensus validator.
//!
//! `vhalla rooms node SOCIAL_STORE NODE_HOME REALM --config FILE` opens a
//! `vhalla_rooms_node::RoomNode` seeded from the committed social snapshot
//! and the shared genesis parameters in FILE (JSON). The node runs until
//! interrupted; producers submit canonical batches by dropping `*.batch`
//! files into `NODE_HOME/intake/`.

use std::collections::BTreeMap;

use serde::Deserialize;
use vhalla_rooms::{registry::DirectoryPolicy, DirectoryId};
use vhalla_rooms_node::{
    service_config, NodeSpec, PrivateKey, PublicKey, RoomNode, RoomValidator, RoomValidatorSet,
};
use vhalla_social::archive::Limits;
use vhalla_social::OwnerId;

use vhalla_social_store::Store as SocialStore;

use crate::json;
use crate::rooms::{hex32, Args};

/// The JSON node file: local identity and networking plus the shared
/// genesis parameters every validator must carry identically.
#[derive(Deserialize)]
struct NodeFile {
    /// Ed25519 consensus seed, 64 hex characters.
    node_key: String,
    /// libp2p TCP listen port on localhost.
    port: usize,
    /// Persistent peers as `host:port` strings.
    #[serde(default)]
    peers: Vec<String>,
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

#[derive(Deserialize)]
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

fn peers(raw: &[String]) -> Result<Vec<(String, usize)>, String> {
    raw.iter()
        .map(|p| {
            let (host, port) = p
                .rsplit_once(':')
                .ok_or_else(|| format!("peer {p:?} must be host:port"))?;
            Ok((
                host.to_owned(),
                port.parse().map_err(|_| format!("peer {p:?} port"))?,
            ))
        })
        .collect()
}

/// The `node` subcommand entry point: parse the config, seed genesis from
/// the committed social snapshot, host the validator until interrupted.
pub fn run(args: &Args) -> Result<(), String> {
    let path = args.config.as_deref().ok_or("node needs --config FILE")?;
    let raw = std::fs::read(path).map_err(|e| format!("config: {e}"))?;
    if raw.len() > 64 * 1024 {
        return Err("config exceeds 64KiB".into());
    }
    let file: NodeFile = serde_json::from_slice(&raw).map_err(|e| format!("config JSON: {e}"))?;

    let node_key = PrivateKey::from(hex32(&file.node_key)?);
    let mut validator_sets: BTreeMap<u64, Vec<RoomValidator>> = BTreeMap::new();
    for entry in &file.validators {
        let key =
            PublicKey::from_bytes(hex32(&entry.key)?).map_err(|e| format!("validator key: {e}"))?;
        validator_sets
            .entry(entry.from)
            .or_default()
            .push(RoomValidator::new(key, entry.power));
    }
    let validator_sets: BTreeMap<u64, RoomValidatorSet> = validator_sets
        .into_iter()
        .map(|(from, set)| (from, RoomValidatorSet::new(set)))
        .collect();
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
    let eligible: Vec<OwnerId> = file
        .eligible
        .iter()
        .map(|id| hex32(id).map(OwnerId::from_bytes))
        .collect::<Result<_, _>>()?;

    // Genesis seeds from the committed social snapshot, decoded under the
    // configured limits — the archive's own bounds are a genesis parameter,
    // not the reader's default. The lock drops with this store so owner
    // commands keep working on the same directory.
    let archive = {
        let social = SocialStore::open(&args.social_store, args.realm, limits, None)
            .map_err(|e| e.to_string())?;
        if social.recovery_required().map_err(|e| e.to_string())? {
            return Err("social store requires explicit social recover first".into());
        }
        social.archive().clone()
    };

    let spec = NodeSpec {
        home: args.rooms_store.clone().into(),
        config: service_config("vhalla-rooms-node", file.port, &peers(&file.peers)?),
        node_key,
        validator_sets,
        held: BTreeMap::new(),
        genesis: vhalla_rooms_consensus::Genesis {
            directory: DirectoryId::from_bytes(hex32(&file.directory)?),
            realm: args.realm,
            policy,
            eligible,
            limits,
            archive,
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
            file.port,
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
        return Err("eligible takes exactly OWNER64,... — the replacement set".into());
    }
    let owners: Vec<OwnerId> = args
        .value(0)
        .ok_or("eligible takes OWNER64,... — the replacement set")?
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
    let stem = format!("eligible-{}", &crate::json::id(&bytes[8..24])[..16]);
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
