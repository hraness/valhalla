//! Independently configured trusted host delivery; never an agent tool.
use super::{files, hex, now, unhex};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use vhalla_custody as custody;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, MemberAcceptance, OperationId, OutboxKind,
};
use vhalla_private_native::{
    client::agent_rpc::RpcSession,
    relay::{
        delivery::{DeliveryStore, Limits, RetryPolicy, TickBudget},
        net::{NetError, RelayToken, ScanDirectory, ScanFailure},
        tls::TlsRelay,
        RelayItem, RelayNamespace, MAX_RELAY_ITEMS,
    },
};

const REFUSED: &str = "host delivery refused; preserve the exact room, queue, scan and applied evidence; reconcile before another explicitly granted launch";
const PAGE: usize = 8;
const TICK: Duration = Duration::from_secs(2);

mod applied;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    context: ContextConfig,
    namespace: String,
    addr: SocketAddr,
    tls_name: String,
    ca: PathBuf,
    token: PathBuf,
    state: PathBuf,
    max_jobs: usize,
    max_bytes: usize,
    max_attempts: u32,
    initial_backoff_secs: u64,
    max_backoff_secs: u64,
    emit_acceptance: bool,
    #[serde(default)]
    initial_cursor: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextConfig {
    room: String,
    anchor: String,
    account: String,
    device: String,
}
impl Config {
    fn load(path: &Path, context: Context) -> Result<(Self, RelayNamespace, TlsRelay), String> {
        let bytes = files::read(path, 16384, false)?;
        let mut c: Self = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        if c.version != 1 {
            return Err(REFUSED.into());
        }
        let key = |s: &str| Key::from_bytes(unhex(s)?).map_err(|_| REFUSED.to_string());
        let selected = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(unhex(&c.context.room)?).map_err(|_| REFUSED)?,
                anchor: AnchorId::from_bytes(unhex(&c.context.anchor)?).map_err(|_| REFUSED)?,
            },
            account: key(&c.context.account)?,
            device: key(&c.context.device)?,
        };
        if selected != context
            || !c.state.is_absolute()
            || !c.ca.is_absolute()
            || !c.token.is_absolute()
        {
            return Err(REFUSED.into());
        }
        let parent = c
            .state
            .parent()
            .ok_or(REFUSED)?
            .canonicalize()
            .map_err(|_| REFUSED)?;
        custody::open_private_directory(&parent).map_err(|_| REFUSED)?;
        c.state = parent.join(c.state.file_name().ok_or(REFUSED)?);
        let namespace = RelayNamespace::from_bytes(unhex(&c.namespace)?).map_err(|_| REFUSED)?;
        let token = files::read(&c.token, 65, false)?;
        let token = std::str::from_utf8(&token).map_err(|_| REFUSED)?;
        let token = RelayToken::from_bytes(unhex(token.strip_suffix('\n').unwrap_or(token))?)
            .map_err(|_| REFUSED)?;
        let relay = TlsRelay::new(
            c.addr,
            &c.tls_name,
            files::read(&c.ca, 65536, false)?.to_vec(),
            token,
            namespace,
        )
        .map_err(|_| REFUSED)?;
        Ok((c, namespace, relay))
    }
    fn limits(&self) -> Limits {
        Limits {
            max_jobs: self.max_jobs,
            max_bytes: self.max_bytes,
        }
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy {
            max_attempts: self.max_attempts,
            initial_backoff_secs: self.initial_backoff_secs,
            max_backoff_secs: self.max_backoff_secs,
        }
    }
}

fn binding(context: Context, ns: RelayNamespace, relay: &TlsRelay, config: &Config) -> Vec<u8> {
    // Version 1 omitted limits and retry authority. Refuse it without altering
    // the old state; reinterpreting its queue would silently widen a new config.
    let mut bytes = if config.initial_cursor == 0 {
        b"VHDELHOST\x02".to_vec()
    } else {
        b"VHDELHOST\x03".to_vec()
    };
    for field in [
        context.scope.room.as_bytes(),
        context.scope.anchor.as_bytes(),
        context.account.as_bytes(),
        context.device.as_bytes(),
        ns.as_bytes(),
        relay.endpoint_id().as_bytes(),
    ] {
        bytes.extend_from_slice(field);
    }
    bytes.push(u8::from(config.emit_acceptance));
    for value in [
        config.max_jobs as u64,
        config.max_bytes as u64,
        u64::from(config.max_attempts),
        config.initial_backoff_secs,
        config.max_backoff_secs,
    ] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    if config.initial_cursor != 0 {
        bytes.extend_from_slice(&config.initial_cursor.to_be_bytes());
    }
    bytes
}

fn retained_scan(
    path: &Path,
    namespace: RelayNamespace,
    initial_cursor: u64,
) -> Result<ScanDirectory, String> {
    // ScanDirectory also supports explicit first-time initialization. This host
    // already has initialized custody: absent children must not reset its cursor.
    let (_, uid) = custody::open_private_directory(path).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("namespace"), uid, 1024).map_err(|_| REFUSED)?;
    custody::open_private_file(&path.join("lock"), uid, 0).map_err(|_| REFUSED)?;
    custody::open_private_directory(&path.join("items")).map_err(|_| REFUSED)?;
    ScanDirectory::open_from(path, namespace, initial_cursor).map_err(|_| REFUSED.into())
}
pub(super) fn initialize(path: &Path, context: Context) -> Result<(), String> {
    let (c, ns, relay) = Config::load(path, context)?;
    // Validate policy before creating any names. Actual queue creation performs
    // the authoritative validation; partial initialization is never auto-reset.
    if c.initial_cursor > MAX_RELAY_ITEMS as u64
        || c.max_jobs == 0
        || c.max_jobs > MAX_RELAY_ITEMS
        || c.max_bytes == 0
        || c.max_bytes > 1024 * 1024 * 1024
        || !(1..=100).contains(&c.max_attempts)
        || !(1..=3600).contains(&c.initial_backoff_secs)
        || c.max_backoff_secs < c.initial_backoff_secs
        || c.max_backoff_secs > 86400
    {
        return Err(REFUSED.into());
    }
    let (directory, _) = custody::create_private_directory(&c.state).map_err(|_| REFUSED)?;
    let lock = custody::create_private_file(&c.state.join("lock")).map_err(|_| REFUSED)?;
    custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
    let _queue = DeliveryStore::create_new(
        c.state.join("jobs"),
        context,
        ns,
        relay.endpoint_id(),
        c.limits(),
        c.retry(),
    )
    .map_err(|_| REFUSED)?;
    let _scan = ScanDirectory::open_from(&c.state.join("scan"), ns, c.initial_cursor)
        .map_err(|_| REFUSED)?;
    custody::create_private_directory(&c.state.join("applied")).map_err(|_| REFUSED)?;
    files::write(&c.state.join("binding"), &binding(context, ns, &relay, &c))?;
    directory.sync_all().map_err(|_| REFUSED)?;
    Ok(())
}

/// Lifetime queue custody is separate from a finite, one-use agent grant.
pub(super) struct Driver {
    config: Config,
    context: Context,
    namespace: RelayNamespace,
    relay: TlsRelay,
    queue: DeliveryStore,
    _directory: File,
    _lock: File,
    outgoing: u64,
    applied: u64,
    // Commitments only: never retain a lifetime in-memory ciphertext history.
    echoes: BTreeMap<[u8; 32], u64>,
    originals: BTreeMap<[u8; 32], u64>,
    poll_attempts: u32,
    next_poll: Instant,
}
impl Driver {
    pub(super) fn open(path: &Path, context: Context) -> Result<Self, String> {
        let (config, namespace, relay) = Config::load(path, context)?;
        let (directory, uid) =
            custody::open_private_directory(&config.state).map_err(|_| REFUSED)?;
        let lock =
            custody::open_private_file(&config.state.join("lock"), uid, 0).map_err(|_| REFUSED)?;
        custody::acquire_exclusive(&lock).map_err(|_| REFUSED)?;
        if *files::read(&config.state.join("binding"), 1024, false)?
            != binding(context, namespace, &relay, &config)
        {
            return Err(REFUSED.into());
        }
        custody::open_private_directory(&config.state.join("applied")).map_err(|_| REFUSED)?;
        // Missing child state is a refusal, never an implicit new cursor/queue.
        drop(retained_scan(
            &config.state.join("scan"),
            namespace,
            config.initial_cursor,
        )?);
        let queue = DeliveryStore::open(
            config.state.join("jobs"),
            context,
            namespace,
            relay.endpoint_id(),
        )
        .map_err(|_| REFUSED)?;
        Ok(Self {
            config,
            context,
            namespace,
            relay,
            queue,
            _directory: directory,
            _lock: lock,
            outgoing: 0,
            applied: 0,
            echoes: BTreeMap::new(),
            originals: BTreeMap::new(),
            poll_attempts: 0,
            next_poll: Instant::now(),
        })
    }
    /// One bounded host tick between RPCs. Kernel uncertainty ends the grant;
    /// no latch-clearing reopen, ratchet regeneration or budget renewal occurs.
    pub(super) async fn tick(&mut self, rpc: &mut RpcSession) -> Result<(), String> {
        rpc.check_release().map_err(|_| REFUSED)?;
        let deadline = (Instant::now() + TICK).min(rpc.deadline());
        let page = rpc
            .host()
            .outbox(self.outgoing, PAGE)
            .await
            .map_err(|_| REFUSED)?;
        if page.head > MAX_RELAY_ITEMS as u64 {
            return Err(REFUSED.into());
        }
        for entry in &page.records {
            if let Some(artifact) = entry.artifact().filter(|a| super::relay_kind(a.kind())) {
                let item =
                    RelayItem::from_artifact(self.namespace, artifact).map_err(|_| REFUSED)?;
                let status = self.queue.enqueue(&item, now()?).map_err(|_| REFUSED)?;
                rpc.update_delivery(self.namespace, &status)
                    .await
                    .map_err(|_| REFUSED)?;
                self.echoes.insert(item.digest(), artifact.sequence());
                if artifact.kind() == OutboxKind::Application {
                    self.originals.insert(
                        MemberAcceptance::ciphertext_commitment(artifact.bytes()),
                        artifact.sequence(),
                    );
                }
            }
            self.outgoing = entry.sequence();
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
        let tick = self
            .queue
            .tick(
                &mut self.relay,
                now()?,
                TickBudget {
                    max_jobs: 1,
                    max_bytes: 4 * 1024 * 1024,
                    deadline,
                },
            )
            .map_err(|_| REFUSED)?;
        for status in &tick.jobs {
            rpc.update_delivery(self.namespace, status)
                .await
                .map_err(|_| REFUSED)?;
        }
        // Complete the local commitment index before interpreting any own echo.
        if self.outgoing < page.head || Instant::now() >= deadline {
            return Ok(());
        }
        let mut scan = retained_scan(
            &self.config.state.join("scan"),
            self.namespace,
            self.config.initial_cursor,
        )?;
        // A disconnected relay does not discard already staged incoming work.
        if Instant::now() >= self.next_poll && self.poll_attempts < 4096 {
            self.poll_attempts += 1;
            self.next_poll = Instant::now() + Duration::from_secs(5);
            match scan.scan_page_until(&self.relay, PAGE, deadline) {
                Ok(_) => (),
                Err(ScanFailure::Net(
                    NetError::Connect
                    | NetError::Timeout
                    | NetError::Capacity
                    | NetError::Unavailable,
                )) => {
                    self.next_poll = Instant::now() + Duration::from_secs(30);
                }
                Err(ScanFailure::Timeout) => (),
                Err(_) => return Err(REFUSED.into()),
            }
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
        for position in scan
            .positions()
            .map_err(|_| REFUSED)?
            .into_iter()
            .filter(|p| *p > self.applied)
            .take(PAGE)
            .collect::<Vec<_>>()
        {
            if Instant::now() >= deadline {
                break;
            }
            let item = scan.read(position).map_err(|_| REFUSED)?;
            let path = self
                .config
                .state
                .join("applied")
                .join(format!("{position:016x}.json"));
            let existing = match path.symlink_metadata() {
                Ok(_) => Some(files::read(&path, 2048, false)?),
                Err(e) if e.kind() == ErrorKind::NotFound => None,
                Err(_) => return Err(REFUSED.into()),
            };
            if let Some(bytes) = &existing {
                let status = rpc.host().agent().status().map_err(|_| REFUSED)?.accepted;
                if !applied::validate(
                    bytes,
                    &item,
                    position,
                    status,
                    self.echoes.contains_key(&item.digest()),
                    self.config.emit_acceptance,
                )? {
                    self.applied = position;
                    continue;
                }
                // Restore claims after restart only by re-reading authenticated
                // kernel receive evidence and checking the signature below.
            }
            let mut result = json!({"digest":hex(&item.digest()),"position":position.to_string()});
            if self.echoes.contains_key(&item.digest()) {
                result["state"] = json!("exact-local-outbox-echo");
            } else {
                match item.kind() {
                    OutboxKind::Application => {
                        let received = rpc
                            .host()
                            .receive(item.payload())
                            .await
                            .map_err(|_| REFUSED)?;
                        result["state"] = json!("locally-received");
                        result["inbox_sequence"] = json!(received.sequence().to_string());
                        if MemberAcceptance::is_receipt(received.body()) {
                            result["state"] = json!("unmatched-receipt-content");
                            if let Some(sequence) =
                                MemberAcceptance::claimed_ciphertext(received.body())
                                    .and_then(|h| self.originals.get(&h).copied())
                            {
                                let original = rpc
                                    .host()
                                    .outbox(sequence - 1, 1)
                                    .await
                                    .map_err(|_| REFUSED)?;
                                let original = original
                                    .records
                                    .first()
                                    .and_then(|r| r.artifact())
                                    .ok_or(REFUSED)?;
                                if original.sequence() != sequence {
                                    return Err(REFUSED.into());
                                }
                                // An invalid inner claim remains inert received content;
                                // it cannot promote delivery or acknowledge another ACK.
                                if let Ok(Some(claim)) =
                                    MemberAcceptance::verify(self.context, original, &received)
                                {
                                    result["state"] = json!("recipient-device-claim");
                                    result["outbox_sequence"] = json!(sequence.to_string());
                                    result["recipient"] = json!(hex(claim.recipient().as_bytes()));
                                    result["recipient_inbox_sequence"] =
                                        json!(claim.received_sequence().to_string());
                                    rpc.record_member_acceptance(sequence, claim)
                                        .await
                                        .map_err(|_| REFUSED)?;
                                }
                            }
                        } else if self.config.emit_acceptance {
                            let mut hash = Sha256::new();
                            hash.update(b"vhalla/host/receipt-operation/v1\0");
                            hash.update(self.context.device.as_bytes());
                            hash.update(MemberAcceptance::ciphertext_commitment(item.payload()));
                            let digest: [u8; 32] = hash.finalize().into();
                            let operation = OperationId::from_bytes(
                                digest[..16].try_into().map_err(|_| REFUSED)?,
                            )
                            .map_err(|_| REFUSED)?;
                            let receipt = rpc
                                .host()
                                .issue_acceptance(operation, item.payload())
                                .await
                                .map_err(|_| REFUSED)?;
                            let relay = RelayItem::from_artifact(self.namespace, &receipt)
                                .map_err(|_| REFUSED)?;
                            let status = self.queue.enqueue(&relay, now()?).map_err(|_| REFUSED)?;
                            rpc.update_delivery(self.namespace, &status)
                                .await
                                .map_err(|_| REFUSED)?;
                            // Index immediately so our next scan cannot receive an
                            // ACK whose outbox page is still behind the live cursor.
                            self.echoes.insert(relay.digest(), receipt.sequence());
                            result["receipt_outbox_sequence"] =
                                json!(receipt.sequence().to_string());
                        }
                    }
                    OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession => {
                        rpc.host()
                            .apply_control(item.payload())
                            .await
                            .map_err(|_| REFUSED)?;
                        result["state"] = json!("locally-applied-control");
                    }
                    OutboxKind::ContactInvitation | OutboxKind::ContactRequest => {
                        result["state"] = json!("dedicated-bootstrap-command-required");
                    }
                    _ => return Err(REFUSED.into()),
                }
            }
            let bytes = serde_json::to_vec(&result).map_err(|_| REFUSED)?;
            if let Some(existing) = existing {
                if *existing != bytes {
                    return Err(REFUSED.into());
                }
            } else {
                applied::publish(&path, &bytes)?;
            }
            self.applied = position;
            rpc.check_release().map_err(|_| REFUSED)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_scan_never_initializes_missing_namespace_lock_or_items() {
        let root =
            std::env::temp_dir().join(format!("vhalla-retained-scan-{}", std::process::id()));
        custody::create_private_directory(&root).unwrap();
        let namespace = RelayNamespace::from_bytes([6; 32]).unwrap();
        for (index, missing) in ["namespace", "lock", "items"].iter().enumerate() {
            let path = root.join(index.to_string());
            drop(ScanDirectory::open(&path, namespace).unwrap());
            std::fs::rename(path.join(missing), root.join(format!("saved-{index}"))).unwrap();
            assert!(retained_scan(&path, namespace, 0).is_err());
            assert!(!path.join(missing).exists());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
