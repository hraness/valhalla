//! Signing assembly for `rooms submit` and the replica companions.
//! Runs in the CLI's trust domain: forms carry identity *paths*, keys
//! load through `Identity::open` (lock held, never exported), and only
//! canonical signed bytes reach the service. Mirrors `rooms
//! create`/`describe`/`archive` — plus grant synthesis when the owner
//! has no room-control chain yet.

use std::path::Path;

use sha2::{Digest, Sha256};
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_rooms::{
    CreateAction, CreationIntent, Description, DirectoryId, PolicyId, RoomControl, RoomRecordId,
    RoomUpdate, Slug, UpdateAction,
};
use vhalla_social::{AgentId, OwnerId, RecordId};

use crate::{CreateContext, Error, Service, UpdateContext};

/// The committed-context surface signing asks of the replica. `Service`
/// implements it; tests substitute canned contexts.
pub trait SigningSource {
    /// Committed context a create form needs.
    fn create_context(
        &self,
        owner: OwnerId,
        key: [u8; 32],
        now: u64,
    ) -> Result<CreateContext, Error>;
    /// Committed context an update form needs for `slug`.
    fn update_context(&self, slug: &str, key: [u8; 32], now: u64) -> Result<UpdateContext, Error>;
}

impl SigningSource for Service {
    fn create_context(
        &self,
        owner: OwnerId,
        key: [u8; 32],
        now: u64,
    ) -> Result<CreateContext, Error> {
        Service::create_context(self, owner, key, now)
    }

    fn update_context(&self, slug: &str, key: [u8; 32], now: u64) -> Result<UpdateContext, Error> {
        Service::update_context(self, slug, key, now)
    }
}

/// Parses 64 hex characters.
fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.is_ascii() {
        return Err(format!("expected 64 ASCII hex characters: {text:?}"));
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

/// A labelled single-line text field in a multi-field form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field's label.
    pub label: &'static str,
    /// The current text.
    pub value: String,
}

/// A focused multi-field form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// The form's title.
    pub title: &'static str,
    /// Ordered fields.
    pub fields: Vec<Field>,
    /// Focused field index.
    pub focus: usize,
}

impl Form {
    fn get(&self, index: usize) -> &str {
        self.fields
            .get(index)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }
}

/// Field order of the create form — shared with `rooms submit`.
pub const CREATE_LABELS: [&str; 8] = [
    "slug",
    "description",
    "expires (unix seconds)",
    "owner (hex64)",
    "agent (hex64)",
    "owner identity dir",
    "agent identity dir",
    "evidence record files (, separated, optional)",
];

/// Field order of the describe form — shared with `rooms submit`.
pub const DESCRIBE_LABELS: [&str; 3] = [
    "description",
    "expires (unix seconds)",
    "owner identity dir",
];

/// A form with `labels` fields, all empty.
pub fn form(title: &'static str, labels: &[&'static str]) -> Form {
    Form {
        title,
        fields: labels
            .iter()
            .map(|label| Field {
                label,
                value: String::new(),
            })
            .collect(),
        focus: 0,
    }
}

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
pub fn create_body(f: &Form, now: u64, src: &mut dyn SigningSource) -> Result<Body, String> {
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
    src: &mut dyn SigningSource,
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
    src: &mut dyn SigningSource,
) -> Result<Vec<u8>, String> {
    let owner_key = identity(key)?;
    let ctx = src
        .update_context(slug, owner_key.public_key(), now)
        .map_err(|e| format!("update context: {e}"))?;
    update_record(&ctx, &owner_key, now + 3600, UpdateAction::Archive)
}

/// Sign an explicit public posting policy against the committed room context.
/// The returned record remains a proposal until consensus commits it.
pub fn public_activity_body(
    slug: &str,
    key: &str,
    network: &str,
    enabled: bool,
    now: u64,
    src: &mut dyn SigningSource,
) -> Result<Vec<u8>, String> {
    let network = hex32(network)?;
    if network == [0; 32] {
        return Err("public network identifier must not be zero".into());
    }
    let expires_at = now.checked_add(3600).ok_or("policy expiry overflow")?;
    let owner_key = identity(key)?;
    let ctx = src
        .update_context(slug, owner_key.public_key(), now)
        .map_err(|e| format!("update context: {e}"))?;
    update_record(
        &ctx,
        &owner_key,
        expires_at,
        UpdateAction::SetPublicActivityPolicy { network, enabled },
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    use vhalla_identity::Identity;
    use vhalla_rooms::{Body as RecordBody, SignedRecord};

    struct CtxSource {
        ctx: CreateContext,
    }

    impl SigningSource for CtxSource {
        fn create_context(
            &self,
            _o: OwnerId,
            _k: [u8; 32],
            _n: u64,
        ) -> Result<CreateContext, Error> {
            Ok(self.ctx.clone())
        }
        fn update_context(&self, _s: &str, _k: [u8; 32], _n: u64) -> Result<UpdateContext, Error> {
            Err(Error::Bounds)
        }
    }

    fn field(form: &mut Form, i: usize, value: &str) {
        form.fields[i].value = value.into();
    }

    fn create_form(owner_id: &str, agent_id: &str, paths: (&str, &str)) -> Form {
        let mut f = form("create a room", &CREATE_LABELS);
        field(&mut f, 0, "salon");
        field(&mut f, 1, "a reading room");
        field(&mut f, 2, "9999999");
        field(&mut f, 3, owner_id);
        field(&mut f, 4, agent_id);
        field(&mut f, 5, paths.0);
        field(&mut f, 6, paths.1);
        f
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "sign-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn identity_pair(base: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let owner_dir = base.join("owner-id");
        let agent_dir = base.join("agent-id");
        Identity::create_new(&owner_dir).unwrap();
        Identity::create_new(&agent_dir).unwrap();
        (owner_dir, agent_dir)
    }

    #[test]
    fn create_body_signs_grant_and_proposal_with_real_identities() {
        let base = temp_dir("grant");
        let (owner_dir, agent_dir) = identity_pair(&base);
        let owner_id = Identity::open(&owner_dir).unwrap();
        let agent_id = Identity::open(&agent_dir).unwrap();
        let owner_pub = owner_id.public_key();
        let agent_pub = agent_id.public_key();
        drop(owner_id);
        drop(agent_id);

        let owner = OwnerId::from_bytes([7; 32]);
        let agent = AgentId::from_bytes([8; 32]);
        let ctx = CreateContext {
            directory: "aa".repeat(32),
            realm: format!("{:032x}", 0x47u128),
            policy: "bb".repeat(32),
            slot: 1,
            charge: 5,
            social_control: "cc".repeat(32),
            room_head: None,
            sequence: 0,
            balance: 10,
        };
        let mut src = CtxSource { ctx };
        let f = create_form(
            "07".repeat(32).as_str(),
            "08".repeat(32).as_str(),
            (owner_dir.to_str().unwrap(), agent_dir.to_str().unwrap()),
        );
        let (evidence, records) = create_body(&f, 1_000, &mut src).unwrap();
        assert!(evidence.is_empty());
        assert_eq!(records.len(), 2, "grant then create");

        let grant = SignedRecord::decode(&records[0]).unwrap().verify().unwrap();
        let RecordBody::Control(control) = grant.body() else {
            panic!("first record is the grant");
        };
        assert_eq!(control.owner, owner);
        assert_eq!(control.previous, None);
        assert_eq!(control.sequence, 0);
        let vhalla_rooms::CreateAction::GrantCreate {
            agent: a,
            agent_key,
            ..
        } = &control.action
        else {
            panic!("grant action");
        };
        assert_eq!(*a, agent);
        assert_eq!(*agent_key, agent_pub);
        assert_eq!(control.controller_key, owner_pub);

        let create = SignedRecord::decode(&records[1]).unwrap().verify().unwrap();
        let RecordBody::Create(intent) = create.body() else {
            panic!("second record is the create");
        };
        assert_eq!(intent.slug.as_str(), "salon");
        assert_eq!(intent.owner, owner);
        assert_eq!(intent.agent, agent);
        assert_eq!(intent.owner_key, owner_pub);
        assert_eq!(intent.agent_key, agent_pub);
        assert_eq!(intent.room_control, grant.id());
        assert_eq!(intent.grant, grant.id());
        assert_eq!(intent.slot, 1);
        assert_eq!(intent.charge, 5);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_body_uses_existing_chain_head() {
        let base = temp_dir("head");
        let (owner_dir, agent_dir) = identity_pair(&base);

        let head = "dd".repeat(32);
        let ctx = CreateContext {
            directory: "aa".repeat(32),
            realm: format!("{:032x}", 0x47u128),
            policy: "bb".repeat(32),
            slot: 2,
            charge: 3,
            social_control: "cc".repeat(32),
            room_head: Some(head.clone()),
            sequence: 1,
            balance: 10,
        };
        let mut src = CtxSource { ctx };
        let f = create_form(
            "07".repeat(32).as_str(),
            "08".repeat(32).as_str(),
            (owner_dir.to_str().unwrap(), agent_dir.to_str().unwrap()),
        );
        let (_evidence, records) = create_body(&f, 1_000, &mut src).unwrap();
        assert_eq!(records.len(), 1, "no grant when a chain exists");
        let create = SignedRecord::decode(&records[0]).unwrap().verify().unwrap();
        let RecordBody::Create(intent) = create.body() else {
            panic!("the single record is the create");
        };
        assert_eq!(
            intent
                .room_control
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            head
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_body_rejects_insufficient_credit_without_evidence() {
        let base = temp_dir("credit");
        let (owner_dir, agent_dir) = identity_pair(&base);

        let ctx = CreateContext {
            directory: "aa".repeat(32),
            realm: format!("{:032x}", 0x47u128),
            policy: "bb".repeat(32),
            slot: 1,
            charge: 5,
            social_control: "cc".repeat(32),
            room_head: None,
            sequence: 0,
            balance: 0,
        };
        let mut src = CtxSource { ctx };
        let f = create_form(
            "07".repeat(32).as_str(),
            "08".repeat(32).as_str(),
            (owner_dir.to_str().unwrap(), agent_dir.to_str().unwrap()),
        );
        let err = create_body(&f, 1_000, &mut src).unwrap_err();
        assert!(err.contains("unspent credit"), "{err}");

        let _ = std::fs::remove_dir_all(&base);
    }

    struct UpdateSource {
        ctx: UpdateContext,
    }

    impl SigningSource for UpdateSource {
        fn create_context(
            &self,
            _o: OwnerId,
            _k: [u8; 32],
            _n: u64,
        ) -> Result<CreateContext, Error> {
            Err(Error::Bounds)
        }
        fn update_context(
            &self,
            slug: &str,
            _k: [u8; 32],
            _n: u64,
        ) -> Result<UpdateContext, Error> {
            if slug == "salon" {
                Ok(self.ctx.clone())
            } else {
                Err(Error::Record("no committed room by that slug".into()))
            }
        }
    }

    fn update_ctx() -> UpdateContext {
        UpdateContext {
            directory: "aa".repeat(32),
            realm: format!("{:032x}", 0x47u128),
            genesis: "11".repeat(32),
            previous: "22".repeat(32),
            owner: "33".repeat(32),
            social_control: "44".repeat(32),
        }
    }

    #[test]
    fn describe_body_signs_an_owner_update() {
        let base = temp_dir("describe");
        let key_dir = base.join("owner-id");
        let id = Identity::create_new(&key_dir).unwrap();
        let key_pub = id.public_key();
        drop(id);

        let mut f = form("describe room", &DESCRIBE_LABELS);
        f.fields[0].value = "second edition".into();
        f.fields[1].value = "9999999".into();
        f.fields[2].value = key_dir.to_str().unwrap().into();

        let mut src = UpdateSource { ctx: update_ctx() };
        let raw = describe_body("salon", &f, 1_000, &mut src).unwrap();
        let record = SignedRecord::decode(&raw).unwrap().verify().unwrap();
        let RecordBody::Update(update) = record.body() else {
            panic!("the record is an update");
        };
        let vhalla_rooms::UpdateAction::Describe(d) = &update.action else {
            panic!("describe action");
        };
        assert_eq!(d.as_str(), "second edition");
        assert_eq!(update.controller_key, key_pub);
        assert_eq!(
            update
                .owner
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "33".repeat(32)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn archive_body_signs_and_denies_foreign_rooms() {
        let base = temp_dir("archive");
        let key_dir = base.join("owner-id");
        let id = Identity::create_new(&key_dir).unwrap();
        let key_pub = id.public_key();
        drop(id);

        let mut src = UpdateSource { ctx: update_ctx() };
        let raw = archive_body("salon", key_dir.to_str().unwrap(), 1_000, &mut src).unwrap();
        let record = SignedRecord::decode(&raw).unwrap().verify().unwrap();
        let RecordBody::Update(update) = record.body() else {
            panic!("the record is an update");
        };
        assert!(matches!(update.action, vhalla_rooms::UpdateAction::Archive));
        assert_eq!(update.controller_key, key_pub);

        // A slug the source does not know fails before any signing.
        assert!(archive_body("ghost", key_dir.to_str().unwrap(), 1_000, &mut src).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
