//! Explicit operator re-arm of stopped host delivery jobs. Offline only: the
//! queue's exclusive custody refuses while an agent driver owns it, so a live
//! session never observes a job leaving `Stopped`.
use super::{files, hex, now, unhex, Args};
use serde::Deserialize;
use serde_json::json;
use std::{net::SocketAddr, path::PathBuf};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context,
};
use vhalla_private_native::relay::{
    delivery::{DeliveryStore, JobState},
    net::RelayToken,
    tls::TlsRelay,
    RelayNamespace,
};

const REFUSED: &str = "delivery resume refused; preserve the exact queue, scan and applied evidence; stop any live agent-serve driver and retry with the same profile";

/// The same delivery profile shape the driver loads; only the fields needed to
/// reopen the exact queue binding are interpreted here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    version: u32,
    context: ProfileContext,
    namespace: String,
    addr: SocketAddr,
    tls_name: String,
    ca: PathBuf,
    token: PathBuf,
    state: PathBuf,
    #[allow(dead_code)]
    max_jobs: usize,
    #[allow(dead_code)]
    max_bytes: usize,
    #[allow(dead_code)]
    max_attempts: u32,
    #[allow(dead_code)]
    initial_backoff_secs: u64,
    #[allow(dead_code)]
    max_backoff_secs: u64,
    #[allow(dead_code)]
    emit_acceptance: bool,
    #[allow(dead_code)]
    #[serde(default)]
    initial_cursor: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileContext {
    room: String,
    anchor: String,
    account: String,
    device: String,
}

pub(super) fn execute(args: &Args, context: Context) -> Result<(), String> {
    let bytes = files::read(std::path::Path::new(args.value("config")?), 16384, false)?;
    let profile: Profile = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
    if profile.version != 1
        || !profile.state.is_absolute()
        || !profile.ca.is_absolute()
        || !profile.token.is_absolute()
    {
        return Err(REFUSED.into());
    }
    let key = |s: &str| Key::from_bytes(unhex(s)?).map_err(|_| REFUSED.to_string());
    let selected = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(unhex(&profile.context.room)?).map_err(|_| REFUSED)?,
            anchor: AnchorId::from_bytes(unhex(&profile.context.anchor)?).map_err(|_| REFUSED)?,
        },
        account: key(&profile.context.account)?,
        device: key(&profile.context.device)?,
    };
    if selected != context {
        return Err(REFUSED.into());
    }
    let namespace = RelayNamespace::from_bytes(unhex(&profile.namespace)?).map_err(|_| REFUSED)?;
    let token = files::read(&profile.token, 65, false)?;
    let token = std::str::from_utf8(&token).map_err(|_| REFUSED)?;
    let token = RelayToken::from_bytes(unhex(token.strip_suffix('\n').unwrap_or(token))?)
        .map_err(|_| REFUSED)?;
    // The endpoint commitment is derived exactly as the driver derives it, so
    // the queue's own binding check refuses a changed CA, name or address.
    let relay = TlsRelay::new(
        profile.addr,
        &profile.tls_name,
        files::read(&profile.ca, 65536, false)?.to_vec(),
        token,
        namespace,
    )
    .map_err(|_| REFUSED)?;
    let only = match args.flags.get("job") {
        Some(raw) => Some(unhex::<32>(raw.to_str().ok_or(REFUSED)?)?),
        None => None,
    };
    let mut queue = DeliveryStore::open(
        profile.state.join("jobs"),
        context,
        namespace,
        relay.endpoint_id(),
    )
    .map_err(|_| REFUSED)?;
    let resumed = queue.resume(only, now()?).map_err(|_| REFUSED)?;
    let mut jobs = Vec::with_capacity(resumed.len());
    for status in &resumed {
        let evidence = queue.evidence(status.id).map_err(|_| REFUSED)?;
        jobs.push(json!({
            "digest": hex(&status.id),
            "sequence": status.sequence.to_string(),
            "state": match status.state {
                JobState::Pending => "pending",
                JobState::Uncertain => "uncertain",
                JobState::Retained => "retained",
                JobState::Stopped => "stopped",
            },
            "uncertain": status.uncertain,
            "attempts": status.attempts,
            "outages": evidence.outages,
            "resumes": evidence.resumes,
            "spent_attempts": evidence.spent_attempts,
            "last_error": status.last_error.map(|e| e.to_string()),
        }));
    }
    println!(
        "{}",
        json!({"status":"resumed","resumed":resumed.len(),"jobs":jobs,"note":"exact bytes retry from a fresh budget; spent attempts remain evidence"})
    );
    Ok(())
}
