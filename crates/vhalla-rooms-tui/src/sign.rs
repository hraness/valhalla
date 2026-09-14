//! Signing assembly for the modal forms. Runs in the CLI's trust domain:
//! the forms carry identity *paths*, keys load through `Identity::open`
//! (lock held, never exported), and only canonical signed bytes reach the
//! service. Mirrors `rooms create`/`describe`/`archive` — plus grant
//! synthesis when the owner has no room-control chain yet.

use std::path::Path;

use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_rooms::{
    CreateAction, CreationIntent, Description, DirectoryId, PolicyId, RoomControl, RoomRecordId,
    RoomUpdate, Slug, UpdateAction,
};
use vhalla_rooms_app::UpdateContext;
use vhalla_social::{AgentId, OwnerId, RecordId};

use crate::{hex32, Form, Source};

/// The empty room-settings commitment — the same well-known `PolicyId`
/// `rooms create` uses.
fn default_settings() -> PolicyId {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/rooms/default-settings/v1\0");
    PolicyId::from_bytes(hash.finalize().into())
}

fn nonce() -> Result<[u8; 32], String> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| "entropy source failed")?;
    Ok(nonce)
}

fn identity(path: &str) -> Result<Identity, String> {
    if path.is_empty() {
        return Err("identity directory is empty".into());
    }
    Identity::open(Path::new(path)).map_err(|e| format!("identity: {e:?}"))
}

fn expires(text: &str, now: u64) -> Result<u64, String> {
    text.parse::<u64>()
        .map_err(|_| "expires must be unix seconds".into())
        .and_then(|e| {
            if e > now {
                Ok(e)
            } else {
                Err("expires must be in the future".into())
            }
        })
}

/// Canonical body parts: evidence records plus room records.
pub type Body = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Assembles and signs the create body for the form: a grant record when
/// the owner has no committed chain (first room), then the owner permit
/// and agent proposal. Returns `(evidence, records)`.
pub fn create_body(f: &Form, now: u64, src: &mut dyn Source) -> Result<Body, String> {
    let owner_key = identity(f.get(5))?;
    let agent_key = identity(f.get(6))?;
    let owner = OwnerId::from_bytes(hex32(f.get(3).trim())?);
    let agent = AgentId::from_bytes(hex32(f.get(4).trim())?);
    let ctx = src
        .create_context(owner, owner_key.public_key(), now)
        .map_err(|e| format!("create context: {e}"))?;

    let directory = DirectoryId::from_bytes(hex32(&ctx.directory)?);
    let realm = RealmId(u128::from_str_radix(&ctx.realm, 16).map_err(|e| format!("realm: {e}"))?);
    let social_control = RecordId::from_bytes(hex32(&ctx.social_control)?);
    let expires_at = expires(f.get(2).trim(), now)?;

    let evidence_text = f.get(7).trim();
    if ctx.balance < ctx.charge && (evidence_text.is_empty() || evidence_text == "-") {
        return Err(format!(
            "unspent credit {} is below the quoted charge {}; attach evidence files or earn support first",
            ctx.balance, ctx.charge
        ));
    }

    let mut records = Vec::new();
    // The create's `room_control`/`grant` point at the chain head; when no
    // chain exists yet the same body carries the grant, exactly like the
    // `first_create` fixture.
    let head = match &ctx.room_head {
        Some(head) => RoomRecordId::from_bytes(hex32(head)?),
        None => {
            let grant = owner_key
                .sign_room_control(RoomControl {
                    directory,
                    realm,
                    owner,
                    social_control,
                    controller_key: owner_key.public_key(),
                    previous: None,
                    sequence: ctx.sequence,
                    action: CreateAction::GrantCreate {
                        agent,
                        agent_key: agent_key.public_key(),
                        expires_at,
                        maximum_charge: ctx.charge.max(1_000),
                        nonce: nonce()?,
                    },
                })
                .map_err(|e| format!("sign grant: {e:?}"))?;
            let verified = grant.verify().map_err(|e| format!("grant: {e:?}"))?;
            let id = verified.id();
            records.push(verified.encode());
            id
        }
    };

    let intent = CreationIntent {
        directory,
        realm,
        policy: PolicyId::from_bytes(hex32(&ctx.policy)?),
        initial_settings: default_settings(),
        owner,
        agent,
        owner_key: owner_key.public_key(),
        agent_key: agent_key.public_key(),
        social_control,
        room_control: head,
        grant: head,
        slug: Slug::new(f.get(0).trim()).map_err(|e| format!("slug: {e:?}"))?,
        description: Description::new(f.get(1).trim())
            .map_err(|e| format!("description: {e:?}"))?,
        slot: ctx.slot,
        charge: ctx.charge,
        expires_at,
        nonce: nonce()?,
    };
    let permit = owner_key
        .sign_room_permit(intent)
        .map_err(|e| format!("sign permit: {e:?}"))?;
    let record = agent_key
        .sign_room_proposal(permit)
        .map_err(|e| format!("sign proposal: {e:?}"))?;
    let verified = record.verify().map_err(|e| format!("proposal: {e:?}"))?;
    records.push(verified.encode());

    let evidence = evidence_files(f.get(7))?;
    Ok((evidence, records))
}

/// Signed describe update for `slug`.
pub fn describe_body(
    slug: &str,
    f: &Form,
    now: u64,
    src: &mut dyn Source,
) -> Result<Vec<u8>, String> {
    let owner_key = identity(f.get(2))?;
    let ctx = src
        .update_context(slug, owner_key.public_key(), now)
        .map_err(|e| format!("update context: {e}"))?;
    let description =
        Description::new(f.get(0).trim()).map_err(|e| format!("description: {e:?}"))?;
    update_record(
        &ctx,
        &owner_key,
        expires(f.get(1).trim(), now)?,
        UpdateAction::Describe(description),
    )
}

/// Signed archive update for `slug`; `key` is the owner identity path.
pub fn archive_body(
    slug: &str,
    key: &str,
    now: u64,
    src: &mut dyn Source,
) -> Result<Vec<u8>, String> {
    let owner_key = identity(key)?;
    let ctx = src
        .update_context(slug, owner_key.public_key(), now)
        .map_err(|e| format!("update context: {e}"))?;
    update_record(&ctx, &owner_key, now + 3600, UpdateAction::Archive)
}

fn update_record(
    ctx: &UpdateContext,
    owner_key: &Identity,
    expires_at: u64,
    action: UpdateAction,
) -> Result<Vec<u8>, String> {
    let record = owner_key
        .sign_room_update(RoomUpdate {
            directory: DirectoryId::from_bytes(hex32(&ctx.directory)?),
            realm: RealmId(
                u128::from_str_radix(&ctx.realm, 16).map_err(|e| format!("realm: {e}"))?,
            ),
            genesis: vhalla_rooms::RoomGenesisId::from_bytes(hex32(&ctx.genesis)?),
            previous: RoomRecordId::from_bytes(hex32(&ctx.previous)?),
            owner: OwnerId::from_bytes(hex32(&ctx.owner)?),
            social_control: RecordId::from_bytes(hex32(&ctx.social_control)?),
            controller_key: owner_key.public_key(),
            expires_at,
            nonce: nonce()?,
            action,
        })
        .map_err(|e| format!("sign update: {e:?}"))?;
    Ok(record
        .verify()
        .map_err(|e| format!("update: {e:?}"))?
        .encode())
}

/// Each comma-separated path holds either one canonical signed social
/// record or a whole `vhalla social export` snapshot — the snapshot's
/// records are expanded individually. Malformed or oversized drops are
/// refused here; the node still verifies every record strictly.
fn evidence_files(text: &str) -> Result<Vec<Vec<u8>>, String> {
    const SNAPSHOT_MAGIC: &[u8; 8] = b"VHSA\0\0\0\x01";
    let mut out = Vec::new();
    for part in text.split(',') {
        let path = part.trim();
        if path.is_empty() || path == "-" {
            continue;
        }
        let bytes = std::fs::read(Path::new(path)).map_err(|e| format!("evidence {path}: {e}"))?;
        if bytes.len() > vhalla_social::archive::MAX_SNAPSHOT_BYTES {
            return Err(format!("evidence {path}: over the snapshot bound"));
        }
        if bytes.starts_with(SNAPSHOT_MAGIC) {
            out.extend(split_snapshot(&bytes).map_err(|e| format!("evidence {path}: {e}"))?);
            continue;
        }
        verify_record(&bytes).map_err(|e| format!("evidence {path}: {e}"))?;
        out.push(bytes);
    }
    Ok(out)
}

/// Splits a `VHSA` snapshot into its canonical record frames — an 8-byte
/// magic, 16-byte realm and 4-byte count header, then length-prefixed
/// records. Each extracted record is verified before it is offered.
fn split_snapshot(raw: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if raw.len() < 28 {
        return Err("truncated snapshot header".into());
    }
    let count = u32::from_be_bytes(raw[24..28].try_into().unwrap()) as usize;
    let mut at = 28usize;
    let mut out = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let end = at.checked_add(4).ok_or("truncated record length")?;
        if end > raw.len() {
            return Err("truncated record length".into());
        }
        let len = u32::from_be_bytes(raw[at..end].try_into().unwrap()) as usize;
        at = end;
        let end = at.checked_add(len).ok_or("truncated record")?;
        if end > raw.len() || len > vhalla_social::MAX_RECORD_BYTES {
            return Err("truncated or oversized record".into());
        }
        let record = &raw[at..end];
        verify_record(record)?;
        out.push(record.to_vec());
        at = end;
    }
    if at != raw.len() {
        return Err("trailing bytes after snapshot records".into());
    }
    Ok(out)
}

/// Strict-decode and verify one canonical social record.
fn verify_record(raw: &[u8]) -> Result<(), String> {
    vhalla_social::SignedRecord::decode(raw)
        .and_then(|r| r.verify())
        .map(|_| ())
        .map_err(|e| format!("not a verified social record: {e:?}"))
}
