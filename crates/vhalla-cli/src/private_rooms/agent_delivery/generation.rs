//! Trusted operator maintenance. Private receipts never enter agent tools.
use super::*;
use vhalla_private_native::client::{
    generation::{controller_id, Accounting, ControllerPauseReceipt},
    RoomSession,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lineage {
    generation: u64,
    original_profile_binding: String,
    predecessor_receipt: PathBuf,
    predecessor_state: PathBuf,
    selection: PathBuf,
}

pub(super) fn check_selection(path: &Path, config: &Config) -> Result<(), String> {
    let Some(lineage) = &config.lineage else {
        return Ok(());
    };
    if !(1..16).contains(&lineage.generation)
        || !lineage.selection.is_absolute()
        || !lineage.predecessor_receipt.is_absolute()
        || !lineage.predecessor_state.is_absolute()
        || unhex::<32>(&lineage.original_profile_binding)? == [0; 32]
    {
        return Err(REFUSED.into());
    }
    // A stale copy must not become a second selector. Reading the current
    // selection is local only and occurs before any transport effect.
    let current = files::read(&lineage.selection, 16384, false)?;
    if current.as_slice() != config.encoded
        || custody::absolute(path).map_err(|_| REFUSED)? != lineage.selection
    {
        return Err(REFUSED.into());
    }
    Ok(())
}

pub(super) fn check_active(config: &Config) -> Result<(), String> {
    for name in ["generation.pause", "generation.intent"] {
        match config.state.join(name).symlink_metadata() {
            Err(error) if error.kind() == ErrorKind::NotFound => (),
            _ => return Err(REFUSED.into()),
        }
    }
    if let Some(lineage) = &config.lineage {
        let prior =
            ControllerPauseReceipt::decode(&files::read(&lineage.predecessor_receipt, 650, false)?)
                .map_err(|_| REFUSED)?;
        if prior.generation + 1 != lineage.generation
            || hex(&prior.original_profile_binding) != lineage.original_profile_binding
        {
            return Err(REFUSED.into());
        }
    }
    Ok(())
}

pub(super) fn verify_baselines(
    config: &Config,
    context: Context,
    normal: &DeliveryStore,
    controls: &DeliveryStore,
) -> Result<(), String> {
    match &config.lineage {
        None => {
            if normal
                .predecessor_baseline()
                .map_err(|_| REFUSED)?
                .is_some()
                || controls
                    .predecessor_baseline()
                    .map_err(|_| REFUSED)?
                    .is_some()
            {
                return Err(REFUSED.into());
            }
        }
        Some(lineage) => {
            let raw = files::read(&lineage.predecessor_receipt, 650, false)?;
            if files::read(&config.state.join("generation.predecessor"), 650, false)?.as_slice()
                != raw.as_slice()
            {
                return Err(REFUSED.into());
            }
            let prior = ControllerPauseReceipt::decode(&raw).map_err(|_| REFUSED)?;
            let commitment = prior.commitment().map_err(|_| REFUSED)?;
            if prior.context != context
                || prior.generation + 1 != lineage.generation
                || files::read(&config.state.join("generation.ready"), 32, false)?.as_slice()
                    != commitment
                || normal.predecessor_baseline().map_err(|_| REFUSED)?
                    != Some((prior.outbox_head, commitment))
                || controls.predecessor_baseline().map_err(|_| REFUSED)?
                    != Some((prior.control_head, commitment))
            {
                return Err(REFUSED.into());
            }
        }
    }
    Ok(())
}

fn profile(
    context: Context,
    namespace: RelayNamespace,
    relay: &TlsRelay,
    config: &Config,
) -> [u8; 32] {
    Sha256::digest(binding(context, namespace, relay, config)).into()
}
fn lineage(config: &Config, binding: [u8; 32]) -> Result<(u64, [u8; 32], [u8; 32]), String> {
    match &config.lineage {
        None => Ok((0, binding, [0; 32])),
        Some(lineage) => {
            let prior = ControllerPauseReceipt::decode(&files::read(
                &lineage.predecessor_receipt,
                650,
                false,
            )?)
            .map_err(|_| REFUSED)?;
            Ok((
                lineage.generation,
                prior.original_profile_binding,
                prior.commitment().map_err(|_| REFUSED)?,
            ))
        }
    }
}

fn locked(
    config: &Config,
    context: Context,
    ns: RelayNamespace,
    relay: &TlsRelay,
) -> Result<(File, DeliveryStore, DeliveryStore, ScanDirectory), String> {
    let (_, owner) = custody::open_private_directory(&config.state).map_err(|_| REFUSED)?;
    let lock =
        custody::open_private_file(&config.state.join("lock"), owner, 0).map_err(|_| REFUSED)?;
    custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
    if config.initial_cursor != 0
        || ![2, 3].contains(&config.version)
        || files::read(&config.state.join("binding"), 1024, false)?.as_slice()
            != binding(context, ns, relay, config)
        || files::read(&config.state.join("controls.enabled"), 1024, false)?.as_slice()
            != control_binding(config, context, ns, relay)
    {
        return Err(REFUSED.into());
    }
    let normal = DeliveryStore::open(config.state.join("jobs"), context, ns, relay.endpoint_id())
        .map_err(|_| REFUSED)?;
    let controls = DeliveryStore::open(
        config.state.join("controls"),
        context,
        ns,
        relay.endpoint_id(),
    )
    .map_err(|_| REFUSED)?;
    if normal.policy() != (config.limits(), config.retry())
        || controls.policy() != (config.limits(), config.retry())
    {
        return Err(REFUSED.into());
    }
    let scan = retained_scan(&config.state.join("scan"), ns, 0)?;
    Ok((lock, normal, controls, scan))
}

/// Pause is a read/verify pass followed by one durable kernel-store barrier.
/// It never drains by authoring new work under an operator's old grant.
pub(in crate::private_rooms) async fn pause(
    args: &super::super::Args,
    mut room: RoomSession,
) -> Result<(), String> {
    let context = room.status().map_err(|_| REFUSED)?.context;
    let (config, ns, relay) = Config::load(Path::new(args.value("config")?), context)?;
    let transition = unhex::<32>(args.text("transition")?)?;
    let terminal = args.number("head")?;
    let (_lock, normal, controls, scan) = locked(&config, context, ns, &relay)?;
    let status = room.status().map_err(|_| REFUSED)?;
    let normal_snapshot = normal.drained_snapshot().map_err(|_| REFUSED)?;
    let controls_snapshot = controls.drained_snapshot().map_err(|_| REFUSED)?;
    if normal_snapshot.outgoing != status.outbox_head
        || controls_snapshot.outgoing != status.control_floor.sequence()
        || normal_snapshot.applied != terminal
        || scan.cursor() != terminal
        || terminal > MAX_RELAY_ITEMS as u64
    {
        return Err(REFUSED.into());
    }
    // Authenticate the complete local outbox and control suffix, including the
    // exact predecessor baselines when this is already a successor.
    let mut after = normal
        .predecessor_baseline()
        .map_err(|_| REFUSED)?
        .map_or(0, |(n, _)| n);
    loop {
        let page = room.outbox(after, OUTBOX_PAGE).await.map_err(|_| REFUSED)?;
        if page.head != status.outbox_head {
            return Err(REFUSED.into());
        }
        for entry in &page.records {
            if let Some(artifact) = entry
                .artifact()
                .filter(|a| super::super::relay_kind(a.kind()))
            {
                let item = RelayItem::from_artifact(ns, artifact).map_err(|_| REFUSED)?;
                if normal
                    .job(item.digest())
                    .map_err(|_| REFUSED)?
                    .is_none_or(|job| job.state != JobState::Retained)
                {
                    return Err(REFUSED.into());
                }
            }
            after = entry.sequence();
        }
        if page.records.is_empty() {
            break;
        }
    }
    let baseline = controls
        .predecessor_baseline()
        .map_err(|_| REFUSED)?
        .map_or(0, |(n, _)| n);
    // Page from this device's retained wire-history base, exactly as the
    // driver does. A checkpoint member holds no encrypted history below its
    // joining floor, so `status.history_base` would be refused as missing.
    let mut after = None;
    loop {
        let page = room
            .encrypted_controls_from(after, OUTBOX_PAGE)
            .await
            .map_err(|_| REFUSED)?;
        if page.head != status.control_floor {
            return Err(REFUSED.into());
        }
        for control in &page.records {
            if control.floor().sequence() > baseline {
                let item = RelayItem::from_control(ns, control).map_err(|_| REFUSED)?;
                if controls
                    .job(item.digest())
                    .map_err(|_| REFUSED)?
                    .is_none_or(|job| job.state != JobState::Retained)
                {
                    return Err(REFUSED.into());
                }
            }
            after = Some(control.floor().sequence());
        }
        if page.records.is_empty() {
            break;
        }
    }
    let reviewed: Vec<String> = if args.flags.contains_key("reviewed-bootstrap") {
        serde_json::from_slice(&args.input("reviewed-bootstrap", 32768, false)?)
            .map_err(|_| REFUSED)?
    } else {
        Vec::new()
    };
    if reviewed.len() > MAX_RELAY_ITEMS
        || !reviewed.windows(2).all(|pair| pair[0] < pair[1])
        || reviewed
            .iter()
            .any(|digest| unhex::<32>(digest).is_err() || digest.to_lowercase() != *digest)
    {
        return Err(REFUSED.into());
    }
    let mut bootstrap = BTreeSet::new();
    let applied_dir = config.state.join("applied");
    applied_restore(&applied_dir, 0, terminal, terminal)?;
    if std::fs::read_dir(&applied_dir)
        .map_err(|_| REFUSED)?
        .any(|entry| {
            entry.map_or(true, |entry| {
                entry.file_name().to_string_lossy().ends_with(".pending")
            })
        })
    {
        return Err(REFUSED.into());
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/relay-generation-items/v1\0");
    hash.update(ns.as_bytes());
    let mut position = 0;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if Instant::now() >= deadline {
            return Err(REFUSED.into());
        }
        let page = relay
            .page_until(position, PAGE, deadline)
            .map_err(|_| REFUSED)?;
        if page.head != terminal {
            return Err(REFUSED.into());
        }
        let empty = page.records.is_empty();
        for record in page.records {
            if record.position != position + 1
                || scan.read(record.position).map_err(|_| REFUSED)? != record.item
            {
                return Err(REFUSED.into());
            }
            position = record.position;
            let item = &record.item;
            let own_echo = normal.job(item.digest()).map_err(|_| REFUSED)?.is_some()
                || controls.job(item.digest()).map_err(|_| REFUSED)?.is_some();
            let marker = files::read(
                &applied_dir.join(format!("{position:016x}.json")),
                2048,
                false,
            )?;
            let value: serde_json::Value = serde_json::from_slice(&marker).map_err(|_| REFUSED)?;
            if value["state"] == "dedicated-bootstrap-command-required" {
                bootstrap.insert(hex(&item.digest()));
            }
            if applied::validate(
                &marker,
                item,
                position,
                status,
                own_echo,
                config.emit_acceptance,
            )? {
                reauthenticate(&mut room, item, &marker, config.emit_acceptance).await?;
            }
            hash.update(position.to_be_bytes());
            hash.update(item.digest());
        }
        if position == terminal {
            break;
        }
        if empty {
            return Err(REFUSED.into());
        }
    }
    if bootstrap.into_iter().collect::<Vec<_>>() != reviewed {
        return Err("review each retained bootstrap item privately and supply its exact sorted digest list with --reviewed-bootstrap before pausing".into());
    }
    hash.update(terminal.to_be_bytes());
    let binding = profile(context, ns, &relay, &config);
    let (generation, original_profile_binding, prior_ledger_commitment) =
        lineage(&config, binding)?;
    let mut maintenance = room.into_delivery_maintenance().map_err(|_| REFUSED)?;
    let receipt = ControllerPauseReceipt {
        context,
        controller_id: controller_id(context, original_profile_binding),
        original_profile_binding,
        transition,
        generation,
        namespace: *ns.as_bytes(),
        endpoint: *relay.endpoint_id().as_bytes(),
        profile_binding: binding,
        terminal_head: terminal,
        items_commitment: hash.finalize().into(),
        outbox_head: status.outbox_head,
        control_head: status.control_floor.sequence(),
        image_commitment: maintenance.image_commitment().map_err(|_| REFUSED)?,
        accounting: Accounting::NativeSplit {
            normal: normal_snapshot,
            controls: controls_snapshot,
            normal_total_byte_ceiling: config.max_bytes as u64,
            control_total_byte_ceiling: config.max_bytes as u64,
        },
        prior_ledger_commitment,
    };
    let encoded = receipt.encode().map_err(|_| REFUSED)?;
    maintenance.pause(&receipt).map_err(|_| REFUSED)?;
    exact(
        &config.state.join("generation.bootstrap"),
        &serde_json::to_vec(&reviewed).map_err(|_| REFUSED)?,
    )?;
    exact(&config.state.join("generation.pause"), &encoded)?;
    files::write(Path::new(args.value("out")?), &encoded)
}

async fn reauthenticate(
    room: &mut RoomSession,
    item: &RelayItem,
    bytes: &[u8],
    emit: bool,
) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    let state = value["state"].as_str().ok_or(REFUSED)?;
    if state == "locally-applied-control" {
        return if room
            .retained_control(item.payload())
            .await
            .map_err(|_| REFUSED)?
        {
            Ok(())
        } else {
            Err(REFUSED.into())
        };
    }
    let received = room
        .retained_received(item.payload())
        .await
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?;
    if value["inbox_sequence"].as_str() != Some(received.sequence().to_string().as_str()) {
        return Err(REFUSED.into());
    }
    let mut verified = None;
    if let Some(hash) = MemberAcceptance::claimed_ciphertext(received.body()) {
        if let Some(original) = room.original(&hash).await.map_err(|_| REFUSED)? {
            if let Ok(Some(claim)) = MemberAcceptance::verify(
                room.status().map_err(|_| REFUSED)?.context,
                &original,
                &received,
            ) {
                verified = Some((original.sequence(), claim));
            }
        }
    }
    match state {
        "locally-received" if !MemberAcceptance::is_receipt(received.body()) => {
            if emit {
                let sequence = value["receipt_outbox_sequence"]
                    .as_str()
                    .ok_or(REFUSED)?
                    .parse::<u64>()
                    .map_err(|_| REFUSED)?;
                let page = room
                    .outbox(sequence.checked_sub(1).ok_or(REFUSED)?, 1)
                    .await
                    .map_err(|_| REFUSED)?;
                let receipt = page
                    .records
                    .first()
                    .and_then(|r| r.artifact())
                    .ok_or(REFUSED)?;
                if receipt.sequence() != sequence
                    || receipt.kind() != OutboxKind::Application
                    || receipt.operation()
                        != acceptance_operation(
                            room.status().map_err(|_| REFUSED)?.context,
                            item.payload(),
                        )?
                {
                    return Err(REFUSED.into());
                }
            }
        }
        "unmatched-receipt-content"
            if MemberAcceptance::is_receipt(received.body()) && verified.is_none() => {}
        "recipient-device-claim" => {
            let (sequence, claim) = verified.ok_or(REFUSED)?;
            if value["outbox_sequence"].as_str() != Some(sequence.to_string().as_str())
                || value["recipient"] != hex(claim.recipient().as_bytes())
                || value["recipient_inbox_sequence"].as_str()
                    != Some(claim.received_sequence().to_string().as_str())
                || !room
                    .acceptances(sequence)
                    .await
                    .map_err(|_| REFUSED)?
                    .iter()
                    .any(|retained| retained == &claim)
            {
                return Err(REFUSED.into());
            }
        }
        _ => return Err(REFUSED.into()),
    }
    Ok(())
}

fn exact(path: &Path, expected: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    if expected.len() > 32768 {
        return Err(REFUSED.into());
    }
    let parent = path.parent().ok_or(REFUSED)?;
    let (directory, owner) = custody::open_private_directory(parent).map_err(|_| REFUSED)?;
    let present = custody::private_file_present(path, owner, 32768).map_err(|_| REFUSED)?;
    let prior = if present {
        files::read(path, 32768, false)?.to_vec()
    } else {
        Vec::new()
    };
    if !expected.starts_with(&prior) {
        return Err(REFUSED.into());
    }
    let mut file = if present {
        custody::open_private_file(path, owner, 32768)
    } else {
        custody::create_private_file(path)
    }
    .map_err(|_| REFUSED)?;
    file.seek(SeekFrom::End(0))
        .and_then(|_| file.write_all(&expected[prior.len()..]))
        .and_then(|_| file.sync_all())
        .and_then(|_| directory.sync_all())
        .map_err(|_| REFUSED)?;
    if files::read(path, 32768, false)?.as_slice() != expected {
        return Err(REFUSED.into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
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

/// Exact-cutover recovery is explicit. A copied old profile cannot select itself.
pub(in crate::private_rooms) async fn transition(
    args: &super::super::Args,
    room: RoomSession,
) -> Result<(), String> {
    let context = room.status().map_err(|_| REFUSED)?.context;
    let selected = custody::absolute(Path::new(args.value("config")?)).map_err(|_| REFUSED)?;
    let raw_receipt = files::read(Path::new(args.value("receipt")?), 650, false)?;
    let receipt = ControllerPauseReceipt::decode(&raw_receipt).map_err(|_| REFUSED)?;
    if receipt.context != context || receipt.generation >= 15 {
        return Err(REFUSED.into());
    }
    let fence: Fence =
        serde_json::from_slice(&files::read(Path::new(args.value("fence")?), 32768, false)?)
            .map_err(|_| REFUSED)?;
    let selected_bytes = files::read(&selected, 16384, false)?;
    let selected_value: serde_json::Value =
        serde_json::from_slice(&selected_bytes).map_err(|_| REFUSED)?;
    let already_selected = selected_value["version"] == 3
        && selected_value["lineage"]["generation"] == receipt.generation + 1;
    // Before selection, config bytes are the predecessor. After selection,
    // resume reads their exact retained copy named by the successor lineage.
    let old_path = if already_selected {
        let state = selected_value["lineage"]["predecessor_state"]
            .as_str()
            .ok_or(REFUSED)?;
        PathBuf::from(state).join("generation.config")
    } else {
        selected.clone()
    };
    let old_raw = files::read(&old_path, 16384, false)?;
    let mut old: Config = serde_json::from_slice(&old_raw).map_err(|_| REFUSED)?;
    old.encoded = old_raw.to_vec();
    // Retained predecessor configs do not select themselves during recovery;
    // parse their transport through a private temporary-free helper.
    let (old_ns, old_relay) = retained_transport(&old, context)?;
    let (_lock, normal, controls, _scan) = locked(&old, context, old_ns, &old_relay)?;
    if files::read(&old.state.join("generation.pause"), 650, false)?.as_slice()
        != raw_receipt.as_slice()
        || profile(context, old_ns, &old_relay, &old) != receipt.profile_binding
    {
        return Err(REFUSED.into());
    }
    let Accounting::NativeSplit {
        normal: prior_normal,
        controls: prior_controls,
        ..
    } = receipt.accounting
    else {
        return Err(REFUSED.into());
    };
    if normal.drained_snapshot().map_err(|_| REFUSED)? != prior_normal
        || controls.drained_snapshot().map_err(|_| REFUSED)? != prior_controls
    {
        return Err(REFUSED.into());
    }
    let (mut next, next_ns, next_relay) =
        Config::load(Path::new(args.value("successor")?), context)?;
    if next.version != 2
        || next.lineage.is_some()
        || next.initial_cursor != 0
        || next.state == old.state
        || next_ns == old_ns
        || next.max_bytes < old.max_bytes
        || next.max_bytes > 1024 * 1024 * 1024
        || next.max_attempts != old.max_attempts
        || next.max_jobs != old.max_jobs
        || next.initial_backoff_secs != old.initial_backoff_secs
        || next.max_backoff_secs != old.max_backoff_secs
        || next.emit_acceptance != old.emit_acceptance
    {
        return Err(REFUSED.into());
    }
    check_fence(&fence, &receipt, &old, &next, next_ns)?;
    let mut maintenance = room.into_delivery_maintenance().map_err(|_| REFUSED)?;
    if maintenance.image_commitment().map_err(|_| REFUSED)? != receipt.image_commitment {
        return Err(REFUSED.into());
    }
    let receipt_path = old.state.join("generation.pause");
    next.version = 3;
    next.lineage = Some(Lineage {
        generation: receipt.generation + 1,
        original_profile_binding: hex(&receipt.original_profile_binding),
        predecessor_receipt: receipt_path,
        predecessor_state: old.state.clone(),
        selection: selected.clone(),
    });
    let next_bytes = serde_json::to_vec(&next).map_err(|_| REFUSED)?;
    let intent = serde_json::to_vec(&json!({"version":1,"receipt":hex(&receipt.commitment().map_err(|_| REFUSED)?),"fence":fence.fence_commitment,"successor":hex(&Sha256::digest(&next_bytes))})).map_err(|_| REFUSED)?;
    exact(&old.state.join("generation.config"), &old_raw)?;
    exact(&old.state.join("generation.intent"), &intent)?;
    initialize_successor(
        &next,
        context,
        next_ns,
        &next_relay,
        &receipt,
        already_selected,
    )?;
    replace_selected(&selected, &old_raw, &next_bytes)?;
    maintenance
        .select_successor(&receipt, profile(context, next_ns, &next_relay, &next))
        .map_err(|_| REFUSED.into())
}

fn retained_transport(
    config: &Config,
    context: Context,
) -> Result<(RelayNamespace, TlsRelay), String> {
    if config.context.room != hex(context.scope.room.as_bytes())
        || config.context.anchor != hex(context.scope.anchor.as_bytes())
        || config.context.account != hex(context.account.as_bytes())
        || config.context.device != hex(context.device.as_bytes())
        || !config.state.is_absolute()
        || !config.ca.is_absolute()
        || !config.token.is_absolute()
    {
        return Err(REFUSED.into());
    }
    let ns = RelayNamespace::from_bytes(unhex(&config.namespace)?).map_err(|_| REFUSED)?;
    let token = files::read(&config.token, 65, false)?;
    let token = std::str::from_utf8(&token)
        .map_err(|_| REFUSED)?
        .trim_end_matches('\n');
    let relay = TlsRelay::new(
        config.addr,
        &config.tls_name,
        files::read(&config.ca, 65536, false)?.to_vec(),
        RelayToken::from_bytes(unhex(token)?).map_err(|_| REFUSED)?,
        ns,
    )
    .map_err(|_| REFUSED)?;
    Ok((ns, relay))
}

fn check_fence(
    fence: &Fence,
    receipt: &ControllerPauseReceipt,
    old: &Config,
    next: &Config,
    ns: RelayNamespace,
) -> Result<(), String> {
    let ca = Sha256::digest(files::read(&old.ca, 65536, false)?.as_slice());
    if fence.version != 1
        || fence.transition != hex(&receipt.transition)
        || fence.predecessor != hex(&receipt.namespace)
        || fence.successor != hex(ns.as_bytes())
        || fence.head != receipt.terminal_head.to_string()
        || fence.items_commitment != hex(&receipt.items_commitment)
        || fence.predecessor_address != old.addr
        || fence.successor_address != next.addr
        || fence.tls_name != old.tls_name
        || fence.tls_name != next.tls_name
        || fence.ca_sha256 != hex(&ca)
        || Sha256::digest(files::read(&next.ca, 65536, false)?.as_slice()) != ca
        || fence.receipt_commitments.len() > 128
        || !fence
            .receipt_commitments
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || !fence
            .receipt_commitments
            .contains(&hex(&receipt.commitment().map_err(|_| REFUSED)?))
    {
        return Err(REFUSED.into());
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/private/relay-generation-fence/v1\0");
    hash.update(receipt.transition);
    hash.update(receipt.namespace);
    hash.update(ns.as_bytes());
    hash.update(receipt.terminal_head.to_be_bytes());
    hash.update(receipt.items_commitment);
    if hex(&hash.finalize()) != fence.fence_commitment {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn initialize_successor(
    next: &Config,
    context: Context,
    ns: RelayNamespace,
    relay: &TlsRelay,
    receipt: &ControllerPauseReceipt,
    selected: bool,
) -> Result<(), String> {
    let Accounting::NativeSplit {
        normal, controls, ..
    } = receipt.accounting
    else {
        return Err(REFUSED.into());
    };
    let path = &next.state;
    let present = path.symlink_metadata().is_ok();
    let (directory, owner) = if present {
        custody::open_private_directory(path)
    } else {
        custody::create_private_directory(path)
    }
    .map_err(|_| REFUSED)?;
    let lock_path = path.join("lock");
    let lock = if lock_path.symlink_metadata().is_ok() {
        custody::open_private_file(&lock_path, owner, 0)
    } else {
        custody::create_private_file(&lock_path)
    }
    .map_err(|_| REFUSED)?;
    custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
    let seed = receipt.commitment().map_err(|_| REFUSED)?;
    let claim = path.join("generation.predecessor");
    if selected {
        for name in [
            "jobs",
            "controls",
            "scan",
            "applied",
            "binding",
            "controls.enabled",
            "generation.predecessor",
            "generation.ready",
        ] {
            if path.join(name).symlink_metadata().is_err() {
                return Err(REFUSED.into());
            }
        }
    }
    if claim.symlink_metadata().is_err()
        && std::fs::read_dir(path)
            .map_err(|_| REFUSED)?
            .any(|entry| entry.map_or(true, |entry| entry.file_name() != "lock"))
    {
        return Err(REFUSED.into());
    }
    exact(&claim, &receipt.encode().map_err(|_| REFUSED)?)?;
    for (name, prior) in [("jobs", normal), ("controls", controls)] {
        let target = path.join(name);
        let store = DeliveryStore::create_successor(
            &target,
            context,
            ns,
            relay.endpoint_id(),
            next.limits(),
            next.retry(),
            vhalla_private_native::relay::delivery::SuccessorSeed {
                generation: receipt.generation + 1,
                prior,
                receipt: seed,
                now: now()?,
            },
        )
        .map_err(|_| REFUSED)?;
        if store.policy() != (next.limits(), next.retry()) {
            return Err(REFUSED.into());
        }
    }
    let _scan = ScanDirectory::open_from(&path.join("scan"), ns, 0).map_err(|_| REFUSED)?;
    if !path.join("applied").exists() {
        custody::create_private_directory(&path.join("applied")).map_err(|_| REFUSED)?;
    }
    exact(&path.join("binding"), &binding(context, ns, relay, next))?;
    exact(
        &path.join("controls.enabled"),
        &control_binding(next, context, ns, relay),
    )?;
    exact(&path.join("generation.ready"), &seed)?;
    directory.sync_all().map_err(|_| REFUSED)?;
    Ok(())
}

fn replace_selected(path: &Path, old: &[u8], next: &[u8]) -> Result<(), String> {
    let current = files::read(path, 16384, false)?;
    if current.as_slice() == next {
        File::open(path.parent().ok_or(REFUSED)?)
            .and_then(|f| f.sync_all())
            .map_err(|_| REFUSED)?;
        return Ok(());
    }
    if current.as_slice() != old {
        return Err(REFUSED.into());
    }
    let scratch = path.with_extension("generation-next");
    exact(&scratch, next)?;
    if files::read(path, 16384, false)?.as_slice() != old {
        return Err(REFUSED.into());
    }
    std::fs::rename(&scratch, path).map_err(|_| REFUSED)?;
    File::open(path.parent().ok_or(REFUSED)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| REFUSED)?;
    if files::read(path, 16384, false)?.as_slice() != next {
        return Err(REFUSED.into());
    }
    Ok(())
}
