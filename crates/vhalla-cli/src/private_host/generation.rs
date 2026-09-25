//! Explicit, recoverable drained mailbox maintenance. Private inventory never
//! enters relay protocol records or ordinary status output.
use super::{
    config::{self, Config, Loaded, RetainedGeneration},
    REFUSED,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, net::SocketAddr, path::Path};
use vhalla_custody as custody;
use vhalla_private_native::{
    client::generation::ControllerPauseReceipt,
    relay::{
        tls::{CredentialAllowance, Service},
        FileStore, GenerationFence, Limits, RelayNamespace,
    },
};

const PENDING: &str = "generation.pending";
const MAX_CONTROLLERS: usize = 32;
const MAX_GENERATIONS: usize = 16;
const TRANSITION_ERROR: &str = "generation transition refused; preserve its private plan, controller receipts, intent and both mailboxes";

mod publication;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Controller {
    credential_id: String,
    room: String,
    anchor: String,
    account: String,
    device: String,
    controller_id: String,
    original_profile_binding: String,
    profile_binding: String,
    endpoint: String,
    receipt_commitment: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowance {
    credential_id: String,
    additional_items: u64,
    additional_bytes: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    /// Explicit owner assertion: membership cannot enumerate controllers.
    complete_controller_inventory: bool,
    config_sha256: String,
    transition: String,
    generation: u64,
    predecessor: String,
    successor: String,
    successor_address: SocketAddr,
    expected_head: u64,
    items_commitment: String,
    controllers: Vec<Controller>,
    allowances: Vec<Allowance>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    plan: Plan,
    predecessor_config: Config,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    generation: u64,
    intent_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceDocument {
    version: u32,
    transition: String,
    predecessor: String,
    successor: String,
    head: String,
    items_commitment: String,
    fence_commitment: String,
    predecessor_address: SocketAddr,
    successor_address: SocketAddr,
    tls_name: String,
    ca_sha256: String,
    receipt_commitments: Vec<String>,
}
fn ns(text: &str) -> Result<RelayNamespace, String> {
    RelayNamespace::from_bytes(config::decode_hex(text)?).map_err(|_| TRANSITION_ERROR.into())
}
fn nonzero(text: &str) -> Result<[u8; 32], String> {
    let value = config::decode_hex(text)?;
    if value == [0; 32] {
        return Err(TRANSITION_ERROR.into());
    }
    Ok(value)
}
fn intent_name(generation: u64) -> String {
    format!("generation-{}.intent.json", generation + 1)
}
fn receipt_name(generation: u64, controller: &str) -> String {
    format!("generation-{}-{controller}.receipt", generation + 1)
}
fn fence_name(generation: u64) -> String {
    format!("generation-{}.fence.json", generation + 1)
}
fn successor_mailbox(generation: u64) -> String {
    format!("mailbox-{}", generation + 2)
}
fn present(home: &Path, name: &str, limit: usize) -> Result<bool, String> {
    let (_, uid) = custody::open_private_directory(home).map_err(|_| REFUSED)?;
    custody::private_file_present(&home.join(name), uid, limit).map_err(|_| REFUSED.into())
}
fn immutable(home: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    publication::publish(home, name, bytes)
}
pub(super) fn require_idle(home: &Path) -> Result<(), String> {
    if present(home, PENDING, 65536)? {
        Err("generation transition is pending; finish its exact fence/cutover or recover it before serving or other maintenance".into())
    } else {
        Ok(())
    }
}

/// Structural validation also runs on historical configs used by seal recovery.
pub(super) fn validate_selection(config: &Config) -> Result<(), String> {
    if config.version < 3 {
        return if config.retained_generations.is_empty() {
            Ok(())
        } else {
            Err(REFUSED.into())
        };
    }
    if config.retained_generations.is_empty()
        || config.retained_generations.len() >= MAX_GENERATIONS
        || !super::loopback(config.listen)
    {
        return Err(REFUSED.into());
    }
    let mut namespaces = BTreeSet::from([config.namespace.as_str()]);
    let mut mailboxes = BTreeSet::from([config.mailbox.as_str()]);
    let mut addresses = BTreeSet::from([config.listen]);
    for (index, old) in config.retained_generations.iter().enumerate() {
        if old.generation != index as u64
            || old.mailbox
                != if index == 0 {
                    "mailbox".to_owned()
                } else {
                    format!("mailbox-{}", index + 1)
                }
            || !super::loopback(old.listen)
            || old.listen.port() == 0
            || !namespaces.insert(&old.namespace)
            || !mailboxes.insert(&old.mailbox)
            || !addresses.insert(old.listen)
            || old.credential_ids.is_empty()
            || old.credential_ids.iter().collect::<BTreeSet<_>>().len() != old.credential_ids.len()
            || old
                .credential_ids
                .iter()
                .any(|id| !config.credential_ids.contains(id))
        {
            return Err(REFUSED.into());
        }
        ns(&old.namespace)?;
        nonzero(&old.transition)?;
        nonzero(&old.intent_sha256)?;
    }
    if config.mailbox != format!("mailbox-{}", config.retained_generations.len() + 1) {
        return Err(REFUSED.into());
    }
    Ok(())
}
fn validate_plan(plan: &Plan, loaded: &Loaded) -> Result<(), String> {
    let config = &loaded.config;
    // Successors are loopback listeners on this machine; moving the clients of
    // a LAN or public listener is the separate host-change design.
    if !super::loopback(config.listen) {
        return Err("mailbox generations need a host on a loopback listener; a LAN or public host keeps its current mailbox".into());
    }
    if plan.version != 1
        || !plan.complete_controller_inventory
        || plan.generation != config.retained_generations.len() as u64
        || plan.generation >= (MAX_GENERATIONS - 1) as u64
        || config
            .credential_ids
            .iter()
            .all(|id| config.revoked_credential_ids.contains(id))
        || plan.predecessor != config.namespace
        || plan.config_sha256 != config::digest(&config::read(&loaded.home, "config.json", 65536)?)
        || plan.successor == plan.predecessor
        || !super::loopback(plan.successor_address)
        || plan.successor_address.port() == 0
        || plan.successor_address == config.listen
        || config
            .retained_generations
            .iter()
            .any(|old| old.namespace == plan.successor || old.listen == plan.successor_address)
        || plan.controllers.is_empty()
        || plan.controllers.len() > MAX_CONTROLLERS
        || plan.allowances.len() > 64
    {
        return Err(TRANSITION_ERROR.into());
    }
    ns(&plan.successor)?;
    nonzero(&plan.transition)?;
    nonzero(&plan.items_commitment)?;
    let mut ids = BTreeSet::new();
    let mut contexts = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for c in &plan.controllers {
        for value in [
            &c.room,
            &c.anchor,
            &c.account,
            &c.device,
            &c.controller_id,
            &c.original_profile_binding,
            &c.profile_binding,
            &c.endpoint,
            &c.receipt_commitment,
        ] {
            nonzero(value)?;
        }
        config::decode_hex::<16>(&c.credential_id)?;
        if !config.credential_ids.contains(&c.credential_id)
            || !ids.insert(&c.controller_id)
            || !contexts.insert((&c.room, &c.anchor, &c.account, &c.device))
        {
            return Err(TRANSITION_ERROR.into());
        }
        credentials.insert(&c.credential_id);
    }
    if credentials != config.credential_ids.iter().collect() {
        return Err("every enrolled transport identity, including revoked identities, needs its complete private controller inventory and drained receipts".into());
    }
    let mut additions = BTreeSet::new();
    for a in &plan.allowances {
        if !config.credential_ids.contains(&a.credential_id)
            || !additions.insert(&a.credential_id)
            || a.additional_items > 4096
            || a.additional_bytes > 256 * 1024 * 1024
        {
            return Err(TRANSITION_ERROR.into());
        }
    }
    Ok(())
}
fn validate_receipt(raw: &[u8], c: &Controller, plan: &Plan) -> Result<(), String> {
    let r = ControllerPauseReceipt::decode(raw).map_err(|_| TRANSITION_ERROR)?;
    let fields = [
        (r.context.scope.room.as_bytes(), &c.room),
        (r.context.scope.anchor.as_bytes(), &c.anchor),
        (r.context.account.as_bytes(), &c.account),
        (r.context.device.as_bytes(), &c.device),
        (&r.controller_id, &c.controller_id),
        (&r.original_profile_binding, &c.original_profile_binding),
        (&r.profile_binding, &c.profile_binding),
        (&r.endpoint, &c.endpoint),
        (&r.transition, &plan.transition),
        (&r.namespace, &plan.predecessor),
        (&r.items_commitment, &plan.items_commitment),
    ];
    if fields
        .iter()
        .any(|(bytes, text)| config::hex(*bytes) != **text)
        || r.generation != plan.generation
        || r.terminal_head != plan.expected_head
        || config::hex(&r.commitment().map_err(|_| TRANSITION_ERROR)?) != c.receipt_commitment
    {
        return Err(TRANSITION_ERROR.into());
    }
    Ok(())
}
fn read_external(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    custody::read_private_file(path, rustix::process::geteuid().as_raw(), limit)
        .map_err(|_| TRANSITION_ERROR.into())
}

/// Write one owner-private, non-authoritative view of a pause receipt. The
/// credential ID is intentionally absent: the operator must select and verify
/// that mapping separately when composing the complete controller inventory.
pub(super) fn inspect(receipt: &Path, output: &Path) -> Result<(), String> {
    let raw = read_external(receipt, 1024)?;
    let receipt = ControllerPauseReceipt::decode(&raw).map_err(|_| TRANSITION_ERROR)?;
    let commitment = config::hex(&receipt.commitment().map_err(|_| TRANSITION_ERROR)?);
    let ledger = |value: vhalla_private_native::relay::delivery::LedgerSnapshot| {
        serde_json::json!({
            "outgoing": value.outgoing,
            "applied": value.applied,
            "retained_jobs": value.retained_jobs,
            "canonical_bytes": value.canonical_bytes,
            "charged_attempts": value.charged_attempts,
            "outages": value.outages,
            "resumes": value.resumes,
            "commitment": config::hex(&value.commitment),
        })
    };
    let accounting = match receipt.accounting {
        vhalla_private_native::client::generation::Accounting::NativeSplit {
            normal,
            controls,
            normal_total_byte_ceiling,
            control_total_byte_ceiling,
        } => serde_json::json!({
            "mode": "native_split",
            "normal": ledger(normal),
            "controls": ledger(controls),
            "normal_total_byte_ceiling": normal_total_byte_ceiling,
            "control_total_byte_ceiling": control_total_byte_ceiling,
        }),
        vhalla_private_native::client::generation::Accounting::BrowserShared(value) => {
            serde_json::json!({
                "mode": "browser_shared",
                "attempts": value.attempts,
                "wire_bytes": value.wire_bytes,
                "retained": value.retained,
                "received": value.received,
                "refused_total": value.refused_total,
                "total_byte_ceiling": value.total_byte_ceiling,
                "total_attempt_ceiling": value.total_attempt_ceiling,
                "commitment": config::hex(&value.commitment),
            })
        }
    };
    let document = serde_json::json!({
        "version": 1,
        "transition": config::hex(&receipt.transition),
        "generation": receipt.generation,
        "predecessor": config::hex(&receipt.namespace),
        "expected_head": receipt.terminal_head,
        "items_commitment": config::hex(&receipt.items_commitment),
        "outbox_head": receipt.outbox_head,
        "control_head": receipt.control_head,
        "image_commitment": config::hex(&receipt.image_commitment),
        "receipt_commitment": commitment,
        "accounting": accounting,
        "controller": {
            "room": config::hex(receipt.context.scope.room.as_bytes()),
            "anchor": config::hex(receipt.context.scope.anchor.as_bytes()),
            "account": config::hex(receipt.context.account.as_bytes()),
            "device": config::hex(receipt.context.device.as_bytes()),
            "controller_id": config::hex(&receipt.controller_id),
            "original_profile_binding": config::hex(&receipt.original_profile_binding),
            "profile_binding": config::hex(&receipt.profile_binding),
            "endpoint": config::hex(&receipt.endpoint),
            "receipt_commitment": commitment,
        },
    });
    let bytes = serde_json::to_vec_pretty(&document).map_err(|_| TRANSITION_ERROR)?;
    let absolute = config::resolve(output)?;
    let parent = absolute.parent().ok_or(TRANSITION_ERROR)?;
    let name = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TRANSITION_ERROR)?;
    config::write(parent, name, &bytes)
}

fn check_inputs(
    home: &Path,
    plan_path: &Path,
    receipts: &Path,
) -> Result<(Loaded, Plan, Vec<Vec<u8>>), String> {
    let loaded = config::load(home)?;
    let plan: Plan =
        serde_json::from_slice(&read_external(plan_path, 32768)?).map_err(|_| TRANSITION_ERROR)?;
    validate_plan(&plan, &loaded)?;
    match fs::symlink_metadata(loaded.home.join(successor_mailbox(plan.generation))) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(
            "successor path already exists; preserve it and select a separately reviewed recovery"
                .into(),
        ),
    }
    custody::open_private_directory(receipts).map_err(|_| TRANSITION_ERROR)?;
    let expected: BTreeSet<_> = plan
        .controllers
        .iter()
        .map(|c| format!("{}.receipt", c.controller_id))
        .collect();
    let names: BTreeSet<_> = fs::read_dir(receipts)
        .map_err(|_| TRANSITION_ERROR)?
        .map(|entry| {
            entry
                .map_err(|_| TRANSITION_ERROR.to_owned())
                .and_then(|e| {
                    e.file_name()
                        .into_string()
                        .map_err(|_| TRANSITION_ERROR.to_owned())
                })
        })
        .collect::<Result<_, _>>()?;
    if names != expected {
        return Err("receipt directory must contain exactly one private receipt for every inventoried controller, without unknown or omitted files".into());
    }
    let mut evidence = Vec::new();
    for c in &plan.controllers {
        let raw = read_external(&receipts.join(format!("{}.receipt", c.controller_id)), 1024)?;
        validate_receipt(&raw, c, &plan)?;
        evidence.push(raw);
    }
    let store = FileStore::open(
        loaded.home.join(&loaded.config.mailbox),
        ns(&plan.predecessor)?,
    )
    .map_err(|_| TRANSITION_ERROR)?;
    if store.retained_head().map_err(|_| TRANSITION_ERROR)?
        != (
            plan.expected_head,
            config::decode_hex(&plan.items_commitment)?,
        )
        || store
            .generation_fence()
            .map_err(|_| TRANSITION_ERROR)?
            .is_some()
    {
        return Err("mailbox changed or was already fenced; preserve controller pauses and all evidence for a separately reviewed recovery".into());
    }
    let spend = Service::credential_spend(&store).map_err(|_| TRANSITION_ERROR)?;
    if spend
        .iter()
        .map(|c| config::hex(&c.id()))
        .collect::<BTreeSet<_>>()
        != loaded.config.credential_ids.iter().cloned().collect()
    {
        return Err("configured credentials are not all enrolled in this mailbox; complete a normal service start before draining and preparing a transition".into());
    }
    for credential in &spend {
        if credential.limits().max_items != 2048
            || credential.limits().max_bytes != 128 * 1024 * 1024
        {
            return Err(TRANSITION_ERROR.into());
        }
        let addition = plan
            .allowances
            .iter()
            .find(|a| a.credential_id == config::hex(&credential.id()));
        if credential
            .authorized_items()
            .checked_add(addition.map_or(0, |a| a.additional_items))
            .is_none_or(|v| v > i64::MAX as u64)
            || credential
                .authorized_bytes()
                .checked_add(addition.map_or(0, |a| a.additional_bytes))
                .is_none_or(|v| v > i64::MAX as u64)
        {
            return Err(TRANSITION_ERROR.into());
        }
    }
    Ok((loaded, plan, evidence))
}
pub(super) fn check(
    home: &Path,
    plan: &Path,
    receipts: &Path,
    prepare: bool,
) -> Result<(), String> {
    let _guard = config::maintenance_lock(home)?;
    require_idle(home)?;
    let (loaded, plan, evidence) = check_inputs(home, plan, receipts)?;
    if config::digest(&serde_json::to_vec(&loaded.config).map_err(|_| TRANSITION_ERROR)?)
        != plan.config_sha256
    {
        return Err("host config.json is not in the canonical encoding this release writes, for example because an older release wrote it; rewrite it once with `vhalla private-host renew HOME --leaf-days N`, which keeps the CA, TLS name, credentials and mailbox, then recompute config_sha256 from the rewritten file".into());
    }
    let generation = plan.generation;
    let intent = Intent {
        version: 1,
        plan,
        predecessor_config: loaded.config,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| TRANSITION_ERROR)?;
    if bytes.len() > 65536 {
        return Err("private generation inventory exceeds the retained intent limit".into());
    }
    planned_selection(&loaded.home, &intent, &config::digest(&bytes))?;
    if !prepare {
        return Ok(());
    }
    for (c, raw) in intent.plan.controllers.iter().zip(&evidence) {
        immutable(
            &loaded.home,
            &receipt_name(generation, &c.controller_id),
            raw,
        )?;
    }
    immutable(&loaded.home, &intent_name(generation), &bytes)?;
    immutable(
        &loaded.home,
        PENDING,
        &serde_json::to_vec(&Pending {
            generation,
            intent_sha256: config::digest(&bytes),
        })
        .map_err(|_| TRANSITION_ERROR)?,
    )
}
fn pending(home: &Path) -> Result<(Pending, Intent), String> {
    let p: Pending = serde_json::from_slice(&config::read(home, PENDING, 1024)?)
        .map_err(|_| TRANSITION_ERROR)?;
    if p.generation >= (MAX_GENERATIONS - 1) as u64 {
        return Err(TRANSITION_ERROR.into());
    }
    let raw = config::read(home, &intent_name(p.generation), 65536)?;
    if config::digest(&raw) != p.intent_sha256 {
        return Err(TRANSITION_ERROR.into());
    }
    let intent: Intent = serde_json::from_slice(&raw).map_err(|_| TRANSITION_ERROR)?;
    if intent.version != 1
        || intent.plan.generation != p.generation
        || intent.plan.config_sha256
            != config::digest(
                &serde_json::to_vec(&intent.predecessor_config).map_err(|_| TRANSITION_ERROR)?,
            )
    {
        return Err(TRANSITION_ERROR.into());
    }
    for c in &intent.plan.controllers {
        validate_receipt(
            &config::read(home, &receipt_name(p.generation, &c.controller_id), 1024)?,
            c,
            &intent.plan,
        )?;
    }
    Ok((p, intent))
}
fn fence_document(intent: &Intent, fence: GenerationFence) -> Result<FenceDocument, String> {
    let mut receipt_commitments: Vec<_> = intent
        .plan
        .controllers
        .iter()
        .map(|c| c.receipt_commitment.clone())
        .collect();
    receipt_commitments.sort();
    // A predecessor config without its CA digest is refused, never a panic.
    let ca_sha256 = intent
        .predecessor_config
        .files
        .get("ca.der")
        .cloned()
        .ok_or_else(|| TRANSITION_ERROR.to_string())?;
    Ok(FenceDocument {
        version: 1,
        transition: intent.plan.transition.clone(),
        predecessor: intent.plan.predecessor.clone(),
        successor: intent.plan.successor.clone(),
        head: fence.head().to_string(),
        items_commitment: config::hex(&fence.items_commitment()),
        fence_commitment: config::hex(&fence.commitment()),
        predecessor_address: intent.predecessor_config.listen,
        successor_address: intent.plan.successor_address,
        tls_name: intent.predecessor_config.tls_name.clone(),
        ca_sha256,
        receipt_commitments,
    })
}
fn old_store(home: &Path, intent: &Intent) -> Result<FileStore, String> {
    FileStore::open(
        home.join(&intent.predecessor_config.mailbox),
        ns(&intent.plan.predecessor)?,
    )
    .map_err(|_| TRANSITION_ERROR.into())
}
fn exact_fence(store: &FileStore, intent: &Intent) -> Result<GenerationFence, String> {
    let f = store
        .generation_fence()
        .map_err(|_| TRANSITION_ERROR)?
        .ok_or(
            "predecessor is not fenced; explicitly run generation-fence after the complete drain",
        )?;
    if f.transition() != config::decode_hex(&intent.plan.transition)?
        || f.predecessor() != ns(&intent.plan.predecessor)?
        || f.successor() != ns(&intent.plan.successor)?
        || f.head() != intent.plan.expected_head
        || f.items_commitment() != config::decode_hex(&intent.plan.items_commitment)?
    {
        return Err(TRANSITION_ERROR.into());
    }
    Ok(f)
}
pub(super) fn fence(home: &Path) -> Result<(), String> {
    let _guard = config::maintenance_lock(home)?;
    let (_, intent) = pending(home)?;
    let loaded = config::load(home)?;
    validate_plan(&intent.plan, &loaded)?;
    let mut store = old_store(&loaded.home, &intent)?;
    if store.retained_head().map_err(|_| TRANSITION_ERROR)?
        != (
            intent.plan.expected_head,
            config::decode_hex(&intent.plan.items_commitment)?,
        )
    {
        return Err("mailbox head changed; no fence was published; preserve the pending plan and controller pauses for a separately reviewed recovery".into());
    }
    store
        .upgrade_generation_format()
        .map_err(|_| TRANSITION_ERROR)?;
    Service::upgrade_ledger(&mut store).map_err(|_| TRANSITION_ERROR)?;
    let f = store
        .fence(
            config::decode_hex(&intent.plan.transition)?,
            ns(&intent.plan.successor)?,
            intent.plan.expected_head,
        )
        .map_err(|_| TRANSITION_ERROR)?;
    immutable(
        &loaded.home,
        &fence_name(intent.plan.generation),
        &serde_json::to_vec(&fence_document(&intent, f)?).map_err(|_| TRANSITION_ERROR)?,
    )
}

pub(super) fn cutover(home: &Path) -> Result<(), String> {
    cutover_with(home, |_| Ok(()))
}
fn cutover_with(
    home: &Path,
    mut after: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    let _guard = config::maintenance_lock(home)?;
    if !present(home, PENDING, 65536)? {
        let loaded = config::load(home)?;
        let retained = loaded
            .config
            .retained_generations
            .last()
            .ok_or("no generation transition is pending")?;
        validate_retained(&loaded.home, retained)?;
        drop(super::service(&loaded.home, &loaded.config)?);
        return Ok(());
    }
    let (p, intent) = pending(home)?;
    // A torn sealed selection may restore the old config. The permanent fence
    // and exact intent remain, and this command rolls only forward from them.
    config::recover_seal(home)?;
    let loaded = config::load(home)?;
    let already_selected = loaded.config.namespace == intent.plan.successor;
    if !already_selected {
        validate_plan(&intent.plan, &loaded)?;
    }
    let store = old_store(&loaded.home, &intent)?;
    let f = exact_fence(&store, &intent)?;
    immutable(
        &loaded.home,
        &fence_name(p.generation),
        &serde_json::to_vec(&fence_document(&intent, f)?).map_err(|_| TRANSITION_ERROR)?,
    )?;
    let snapshot = Service::fenced_spend(&store).map_err(|_| TRANSITION_ERROR)?;
    let ids: BTreeSet<_> = snapshot
        .credentials()
        .iter()
        .map(|c| config::hex(&c.id()))
        .collect();
    if ids
        != intent
            .predecessor_config
            .credential_ids
            .iter()
            .cloned()
            .collect()
    {
        return Err("credential ledger and private inventory differ; preserve the fenced predecessor for diagnosis".into());
    }
    let mailbox = successor_mailbox(p.generation);
    let new_path = loaded.home.join(&mailbox);
    let mut successor = FileStore::create_successor(
        &new_path,
        Limits {
            max_items: 4096,
            max_bytes: 256 * 1024 * 1024,
        },
        f,
        config::decode_hex(&p.intent_sha256)?,
    )
    .map_err(|_| TRANSITION_ERROR)?;
    let allowances: Vec<_> = intent
        .plan
        .allowances
        .iter()
        .map(|a| {
            Ok(CredentialAllowance {
                id: config::decode_hex(&a.credential_id)?,
                additional_items: a.additional_items,
                additional_bytes: a.additional_bytes,
            })
        })
        .collect::<Result<_, String>>()?;
    Service::initialize_successor(&mut successor, &snapshot, &allowances)
        .map_err(|_| TRANSITION_ERROR)?;
    drop(successor);
    drop(store);
    after("successor-seeded")?;
    let (next, connection) = planned_selection(&loaded.home, &intent, &p.intent_sha256)?;
    if already_selected {
        if serde_json::to_vec(&loaded.config).map_err(|_| TRANSITION_ERROR)?
            != serde_json::to_vec(&next).map_err(|_| TRANSITION_ERROR)?
        {
            return Err(TRANSITION_ERROR.into());
        }
    } else {
        config::begin_seal(&loaded.home, &["connection.json"])?;
        config::rewrite(&loaded.home, "connection.json", &connection)?;
        after("connection-written")?;
        config::seal_files(&loaded.home)?;
        after("selection-committing")?;
        config::commit_seal(&loaded.home, &next)?;
        after("selection-committed")?;
    }
    // Opening the exact selected service checks credential/cumulative budgets.
    drop(super::service(&loaded.home, &next)?);
    fs::remove_file(loaded.home.join(PENDING)).map_err(|_| TRANSITION_ERROR)?;
    let (directory, _) =
        custody::open_private_directory(&loaded.home).map_err(|_| TRANSITION_ERROR)?;
    directory.sync_all().map_err(|_| TRANSITION_ERROR.into())
}

/// Retained selections are usable only with their exact private intent and
/// permanent fence. This opens and releases custody before serving acquires it.
pub(super) fn validate_retained(home: &Path, selected: &RetainedGeneration) -> Result<(), String> {
    let raw = config::read(home, &intent_name(selected.generation), 65536)?;
    if config::digest(&raw) != selected.intent_sha256 {
        return Err(TRANSITION_ERROR.into());
    }
    let intent: Intent = serde_json::from_slice(&raw).map_err(|_| TRANSITION_ERROR)?;
    if intent.version != 1
        || intent.plan.generation != selected.generation
        || intent.plan.predecessor != selected.namespace
        || intent.plan.transition != selected.transition
        || intent.predecessor_config.listen != selected.listen
        || intent.predecessor_config.mailbox != selected.mailbox
        || intent.predecessor_config.credential_ids != selected.credential_ids
    {
        return Err(TRANSITION_ERROR.into());
    }
    let store = old_store(home, &intent)?;
    let fence = exact_fence(&store, &intent)?;
    let expected =
        serde_json::to_vec(&fence_document(&intent, fence)?).map_err(|_| TRANSITION_ERROR)?;
    if config::read(home, &fence_name(selected.generation), 65536)?.as_slice() != expected {
        return Err(TRANSITION_ERROR.into());
    }
    for c in &intent.plan.controllers {
        validate_receipt(
            &config::read(
                home,
                &receipt_name(selected.generation, &c.controller_id),
                1024,
            )?,
            c,
            &intent.plan,
        )?;
    }
    Ok(())
}

fn planned_selection(
    home: &Path,
    intent: &Intent,
    intent_sha256: &str,
) -> Result<(Config, Vec<u8>), String> {
    let mut next = intent.predecessor_config.clone();
    config::upgrade_config(&mut next);
    next.version = 3;
    next.retained_generations.push(RetainedGeneration {
        generation: intent.plan.generation,
        namespace: next.namespace.clone(),
        mailbox: next.mailbox.clone(),
        listen: next.listen,
        credential_ids: next.credential_ids.clone(),
        transition: intent.plan.transition.clone(),
        intent_sha256: intent_sha256.to_owned(),
    });
    next.namespace = intent.plan.successor.clone();
    next.mailbox = successor_mailbox(intent.plan.generation);
    next.listen = intent.plan.successor_address;
    let connection = config::connection_document(home, &next, Some(&intent.plan.predecessor))?;
    next.files
        .insert("connection.json".into(), config::digest(&connection));
    validate_selection(&next)?;
    if serde_json::to_vec(&next)
        .map_err(|_| TRANSITION_ERROR)?
        .len()
        > 65536
        || connection.len() > 65536
    {
        return Err("successor configuration exceeds retained limits".into());
    }
    Ok((next, connection))
}

#[cfg(test)]
mod tests;
