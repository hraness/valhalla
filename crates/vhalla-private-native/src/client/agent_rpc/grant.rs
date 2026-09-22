//! Trusted launch configuration. No RPC request reaches this parser or custody.

use super::{hex, unhex, Error};
use crate::{
    agent::{Budget, LocalGrant, Permissions, RevocationHandle},
    client::RoomSession,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_custody as custody;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, Status,
};

/// Maximum trusted configuration size; credentials never belong in this file.
pub const MAX_GRANT_BYTES: usize = 16 * 1024;

/// An explicitly reviewed, immutable launch authorization, consumed only once.
///
/// This is a cooperating-host contract. The declared provider is not remotely
/// authenticated, and an ambient CLI agent remains outside this API boundary.
pub struct LaunchGrant {
    pub(super) id: String,
    context: Context,
    epoch: u64,
    roster: [u8; 32],
    not_before: u64,
    pub(super) expires: u64,
    pub(super) permissions: Permissions,
    budget: Budget,
    pub(super) inbox_after: u64,
    pub(super) inbox_through: u64,
    follow: bool,
    receipt: PathBuf,
    pub(super) disclosure: Value,
    digest: [u8; 32],
}

impl LaunchGrant {
    /// Decode version 1 strictly. This does not consume or create authority.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if raw.is_empty() || raw.len() > MAX_GRANT_BYTES {
            return Err(Error::Grant);
        }
        let v: Value = serde_json::from_slice(raw).map_err(|_| Error::Grant)?;
        let o = object(
            &v,
            &[
                "version",
                "grant_id",
                "context",
                "epoch",
                "roster",
                "not_before",
                "expires_at",
                "permissions",
                "budget",
                "inbox",
                "receipt",
                "disclosure",
            ],
        )?;
        if o.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(Error::Grant);
        }
        let id = string(o, "grant_id", 32)?.to_owned();
        if unhex::<16>(&id).is_none_or(|id| id == [0; 16]) {
            return Err(Error::Grant);
        }
        let c = object(
            field(o, "context")?,
            &["room", "anchor", "account", "device"],
        )?;
        let key = |name| unhex::<32>(string(c, name, 64)?).ok_or(Error::Grant);
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes(key("room")?).map_err(|_| Error::Grant)?,
                anchor: AnchorId::from_bytes(key("anchor")?).map_err(|_| Error::Grant)?,
            },
            account: Key::from_bytes(key("account")?).map_err(|_| Error::Grant)?,
            device: Key::from_bytes(key("device")?).map_err(|_| Error::Grant)?,
        };
        let roster = unhex(string(o, "roster", 64)?).ok_or(Error::Grant)?;
        let p = object(
            field(o, "permissions")?,
            &["inbox", "queue", "outbox_status"],
        )?;
        let flag = |name| field(p, name)?.as_bool().ok_or(Error::Grant);
        let permissions = Permissions {
            inbox: flag("inbox")?,
            queue: flag("queue")?,
            outbox_status: flag("outbox_status")?,
        };
        let b = object(
            field(o, "budget")?,
            &[
                "preparations",
                "messages",
                "body_bytes",
                "read_records",
                "read_bytes",
            ],
        )?;
        let budget = Budget {
            preparations: integer(b, "preparations")?,
            messages: integer(b, "messages")?,
            body_bytes: integer(b, "body_bytes")?,
            read_records: integer(b, "read_records")?,
            read_bytes: integer(b, "read_bytes")?,
        };
        // Limits keep a single host-reviewed launch finite even when malformed
        // clients spend their whole allowance. These are not renewable quotas.
        if budget.preparations > 4096
            || budget.messages > 4096
            || budget.body_bytes > 16 * 1024 * 1024
            || budget.read_records > 4096
            || budget.read_bytes > 128 * 1024 * 1024
        {
            return Err(Error::Grant);
        }
        let i = object(field(o, "inbox")?, &["after", "through", "follow"])?;
        let inbox_after = integer(i, "after")?;
        let inbox_through = integer(i, "through")?;
        let follow = field(i, "follow")?.as_bool().ok_or(Error::Grant)?;
        if inbox_after > inbox_through || (!permissions.inbox && inbox_after != inbox_through) {
            return Err(Error::Grant);
        }
        let receipt = PathBuf::from(string(o, "receipt", 4096)?);
        if !receipt.is_absolute()
            || receipt.file_name().is_none()
            || receipt
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(Error::Grant);
        }
        let d = object(
            field(o, "disclosure")?,
            &[
                "host",
                "provider",
                "model",
                "processing_policy",
                "allow_cooperating_host",
            ],
        )?;
        for name in ["host", "provider", "model", "processing_policy"] {
            string(d, name, 1024)?;
        }
        if field(d, "allow_cooperating_host")?.as_bool() != Some(true) {
            return Err(Error::Grant);
        }
        let not_before = integer(o, "not_before")?;
        let expires = integer(o, "expires_at")?;
        if expires
            .checked_sub(not_before)
            .is_none_or(|duration| duration == 0 || duration > 86_400)
        {
            return Err(Error::Grant);
        }
        Ok(Self {
            id,
            context,
            epoch: integer(o, "epoch")?,
            roster,
            not_before,
            expires,
            permissions,
            budget,
            inbox_after,
            inbox_through,
            follow,
            receipt,
            disclosure: Value::Object(d.clone()),
            digest: Sha256::digest(raw).into(),
        })
    }

    /// Full selected context, compared before room custody is opened.
    pub const fn context(&self) -> Context {
        self.context
    }

    pub(super) fn consume(
        &self,
        room: &RoomSession,
    ) -> Result<(LocalGrant, RevocationHandle), Error> {
        let status = room.status().map_err(|_| Error::Authority)?;
        let now = wall()?;
        let ceiling = if self.follow {
            status
                .inbox_head
                .checked_add(4096)
                .ok_or(Error::Authority)?
        } else {
            status.inbox_head
        };
        if now < self.not_before
            || now >= self.expires
            || status.context != self.context
            || status.epoch != self.epoch
            || status.roster != self.roster
            || self.inbox_through > ceiling
        {
            return Err(Error::Authority);
        }
        let grant = LocalGrant::for_status(
            status,
            Duration::from_secs(self.expires - now),
            self.permissions,
            self.budget,
        )
        .map_err(|_| Error::Authority)?;
        // An entire allowance is reserved before the first RPC. Never remove,
        // replace, truncate or reinterpret this file after uncertainty. Exact
        // process restart refuses even if no request was completed.
        let parent = self.receipt.parent().ok_or(Error::Receipt)?;
        let canonical = parent.canonicalize().map_err(|_| Error::Receipt)?;
        let path = canonical.join(self.receipt.file_name().ok_or(Error::Receipt)?);
        let (directory, uid) =
            custody::open_private_directory(&canonical).map_err(|_| Error::Receipt)?;
        let bytes = serde_json::to_vec(&json!({"format":"vhalla-agent-launch-claim-v1", "grant_id":self.id, "grant_sha256":hex(&self.digest), "authority":"entire grant consumed; never restart or delete to renew", "expires_at":self.expires, "context":context_json(status), "epoch":status.epoch.to_string(), "roster":hex(&status.roster)})).map_err(|_| Error::Receipt)?;
        let mut file = custody::create_private_file(&path).map_err(|_| Error::Receipt)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .and_then(|_| directory.sync_all())
            .map_err(|_| Error::Receipt)?;
        if custody::read_private_file(&path, uid, MAX_GRANT_BYTES).map_err(|_| Error::Receipt)?
            != bytes
        {
            return Err(Error::Receipt);
        }
        Ok(grant)
    }
}

pub(super) fn context_json(status: Status) -> Value {
    let c = status.context;
    json!({"room":hex(c.scope.room.as_bytes()), "anchor":hex(c.scope.anchor.as_bytes()), "account":hex(c.account.as_bytes()), "device":hex(c.device.as_bytes())})
}
pub(super) fn wall() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Authority)
}
fn object<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, Error> {
    let o = v.as_object().ok_or(Error::Grant)?;
    if o.len() != keys.len() || keys.iter().any(|key| !o.contains_key(*key)) {
        return Err(Error::Grant);
    }
    Ok(o)
}
fn field<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a Value, Error> {
    o.get(key).ok_or(Error::Grant)
}
fn string<'a>(o: &'a Map<String, Value>, key: &str, max: usize) -> Result<&'a str, Error> {
    let s = field(o, key)?.as_str().ok_or(Error::Grant)?;
    if s.is_empty() || s.len() > max || s.chars().any(char::is_control) {
        return Err(Error::Grant);
    }
    Ok(s)
}
fn integer(o: &Map<String, Value>, key: &str) -> Result<u64, Error> {
    let n = field(o, key)?.as_u64().ok_or(Error::Grant)?;
    // Configuration JSON numbers must be exactly representable by common hosts.
    if n > 9_007_199_254_740_991 {
        return Err(Error::Grant);
    }
    Ok(n)
}
