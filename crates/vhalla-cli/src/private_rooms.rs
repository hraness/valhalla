//! Explicit local private-room custody and inert file exchange. No network API.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{
        AnchorId, ControlFloor, ControlId, Key, PrivateRoomScope, RoomId, SignedDeviceEnrollment,
        Validity,
    },
    ContactBootstrap, Context, MembershipSnapshot, OperationId, OutboxKind, Status, MAX_BODY_BYTES,
    MAX_STORED_RECORD_BYTES,
};
use vhalla_private_native::{
    client::{RoomCreation, RoomSession},
    private_rooms::{Limits, NativePrivateStore},
};

mod archive;
mod files;

pub const HELP: &str = "vhalla private create ID NEW_STORE --not-before UNIX --expires UNIX [--max-records N --max-bytes N]
vhalla private inspect ID STORE --out PRIVATE_JSON
vhalla private offer-inspect ID --offer FILE|- --owner KEY64 --out PRIVATE_JSON
vhalla private offer ID STORE --recipient KEY64 --operation OP32 --not-before UNIX --expires UNIX --out SECRET_FILE
vhalla private import ID NEW_STORE --offer FILE|- --owner KEY64 --room ROOM64 --anchor ANCHOR64 --not-before UNIX --expires UNIX [--max-records N --max-bytes N]
vhalla private request ID STORE --offer FILE|- --operation OP32 --out ENCRYPTED_REQUEST
vhalla private accept ID STORE --request FILE --operation OP32 --not-before UNIX --expires UNIX --out ENCRYPTED_RESPONSE
vhalla private join ID STORE --response FILE
vhalla private send ID STORE --text FILE|- --operation OP32 --epoch N --roster HASH64 --out CIPHERTEXT
vhalla private receive ID STORE --message FILE --out PRIVATE_PLAINTEXT
vhalla private outbox ID STORE --after N --limit N --out PRIVATE_JSON
vhalla private inbox ID STORE --after N --limit N --out PRIVATE_JSON
vhalla private export ID STORE --sequence N --out CIPHERTEXT
vhalla private relay-export ID STORE --namespace NS64 --sequence N --out RELAY_ITEM
vhalla private relay-apply ID STORE --namespace NS64 --relay RELAY_ITEM --out PRIVATE_RESULT
vhalla private control-export ID STORE --after N --parent CONTROL64|none --out CIPHERTEXT
vhalla private remove ID STORE --device KEY64 --operation OP32 --out CIPHERTEXT
vhalla private apply ID STORE --control FILE
vhalla private renew ID STORE --operation OP32 --not-before UNIX --expires UNIX --out CIPHERTEXT
vhalla private archive-export ID STORE --out NEW_FILE.vharchive
vhalla private archive-import ID NEW_ARCHIVE_STORE --archive FILE.vharchive [--max-records N --max-bytes N]
vhalla private archive-resume ID ARCHIVE_STORE --archive FILE.vharchive [--max-records N --max-bytes N]
vhalla private archive-inspect ID ARCHIVE_STORE --archive FILE.vharchive --out PRIVATE_JSON [--max-records N --max-bytes N]
vhalla private archive-inbox|archive-outbox ID ARCHIVE_STORE --archive FILE.vharchive --after N --limit N --out PRIVATE_JSON [--max-records N --max-bytes N]
Archives are inert encrypted complete-state copies; they cannot restore or transfer a live device. Preserve the exact file for resume and finalization inspection. No account-key-only recovery.
Local files only. Existing identity; create/import always require a never-used store. Relay items are canonical opaque envelopes for an adapter or explicit local handoff; relay-apply dispatches only the authenticated item kind and never treats a relay receipt as member acceptance. There is no listener, relay service, agent registration, reset or automatic migration. Secret/plaintext input is a bounded pipe or 0600 file in a 0700 directory; all outputs are new 0600 files in a 0700 directory. No content is printed. Save exact operation, validity, epoch and roster for retries; output failure never authorizes regenerating or resetting a device.";

const REFUSED: &str = "private operation refused; preserve the existing store and reopen it; never reset or recreate a device";
const OFFER_LIMIT: usize = 1024;

struct Args {
    command: String,
    identity: PathBuf,
    store: Option<PathBuf>,
    flags: BTreeMap<String, OsString>,
}
impl Args {
    fn parse(raw: &[OsString]) -> Result<Self, String> {
        if raw.len() < 3 || raw.len() > 64 || raw[0] != "private" {
            return Err(HELP.into());
        }
        let command = raw[1].to_str().ok_or(HELP)?;
        let allowed: &[&str] = match command {
            "archive-export" => &["out"],
            "archive-import" | "archive-resume" => &["archive", "max-records", "max-bytes"],
            "archive-inspect" => &["archive", "out", "max-records", "max-bytes"],
            "archive-inbox" | "archive-outbox" => &[
                "archive",
                "after",
                "limit",
                "out",
                "max-records",
                "max-bytes",
            ],
            "create" => &["not-before", "expires", "max-records", "max-bytes"],
            "inspect" => &["out"],
            "offer-inspect" => &["offer", "owner", "out"],
            "offer" => &["recipient", "operation", "not-before", "expires", "out"],
            "import" => &[
                "offer",
                "owner",
                "room",
                "anchor",
                "not-before",
                "expires",
                "max-records",
                "max-bytes",
            ],
            "request" => &["offer", "operation", "out"],
            "accept" => &["request", "operation", "not-before", "expires", "out"],
            "join" => &["response"],
            "send" => &["text", "operation", "epoch", "roster", "out"],
            "receive" => &["message", "out"],
            "outbox" | "inbox" => &["after", "limit", "out"],
            "export" => &["sequence", "out"],
            "relay-export" => &["namespace", "sequence", "out"],
            "relay-apply" => &["namespace", "relay", "out"],
            "control-export" => &["after", "parent", "out"],
            "remove" => &["device", "operation", "out"],
            "apply" => &["control"],
            "renew" => &["operation", "not-before", "expires", "out"],
            _ => return Err(HELP.into()),
        };
        let start = if command == "offer-inspect" { 3 } else { 4 };
        if raw.len() < start || !(raw.len() - start).is_multiple_of(2) {
            return Err(HELP.into());
        }
        let mut flags = BTreeMap::new();
        for pair in raw[start..].as_chunks::<2>().0 {
            let name = pair[0]
                .to_str()
                .and_then(|s| s.strip_prefix("--"))
                .ok_or(HELP)?;
            if !allowed.contains(&name)
                || pair[1].is_empty()
                || flags.insert(name.to_owned(), pair[1].clone()).is_some()
            {
                return Err("unknown, duplicate, empty or incomplete private option".into());
            }
        }
        for required in allowed
            .iter()
            .filter(|name| !matches!(**name, "max-records" | "max-bytes"))
        {
            if !flags.contains_key(*required) {
                return Err("missing required private option; see private --help".into());
            }
        }
        if flags.get("out").is_some_and(|path| path == "-") {
            return Err("private output requires a new 0600 file; stdout is refused".into());
        }
        if raw[2].is_empty() || (start == 4 && raw[3].is_empty()) {
            return Err(HELP.into());
        }
        Ok(Self {
            command: command.to_owned(),
            identity: PathBuf::from(&raw[2]),
            store: (start == 4).then(|| PathBuf::from(&raw[3])),
            flags,
        })
    }
    fn value(&self, name: &str) -> Result<&std::ffi::OsStr, String> {
        self.flags
            .get(name)
            .map(OsString::as_os_str)
            .ok_or_else(|| "missing private option".into())
    }
    fn text(&self, name: &str) -> Result<&str, String> {
        self.value(name)?
            .to_str()
            .ok_or_else(|| "private numeric/key option must be canonical UTF-8".into())
    }
    fn number(&self, name: &str) -> Result<u64, String> {
        number(self.text(name)?)
    }
    fn key(&self, name: &str) -> Result<Key, String> {
        Key::from_bytes(unhex(self.text(name)?)?).map_err(|_| "invalid full public key".into())
    }
    fn operation(&self) -> Result<OperationId, String> {
        OperationId::from_bytes(unhex(self.text("operation")?)?)
            .map_err(|_| "operation must be a nonzero 32-digit lowercase hex ID".into())
    }
    fn namespace(&self) -> Result<vhalla_private_native::relay::RelayNamespace, String> {
        vhalla_private_native::relay::RelayNamespace::from_bytes(unhex(self.text("namespace")?)?)
            .map_err(|_| "namespace must be a nonzero full 64-digit lowercase hex token".into())
    }
    fn validity(&self) -> Result<Validity, String> {
        Validity::new(self.number("not-before")?, self.number("expires")?)
            .map_err(|_| "invalid validity interval".into())
    }
    fn input(
        &self,
        name: &str,
        bound: usize,
        stdin: bool,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        files::read(Path::new(self.value(name)?), bound, stdin)
    }
    fn output(&self, bytes: &[u8]) -> Result<(), String> {
        files::write(Path::new(self.value("out")?), bytes)
    }
    fn json(&self, value: Value) -> Result<(), String> {
        let bytes = zeroize::Zeroizing::new(
            serde_json::to_vec_pretty(&value).map_err(|_| "private output encoding refused")?,
        );
        self.output(&bytes)
    }
    fn limits(&self) -> Result<Limits, String> {
        Ok(Limits {
            max_records: if self.flags.contains_key("max-records") {
                self.number("max-records")?
            } else {
                100_000
            },
            max_record_bytes: if self.flags.contains_key("max-bytes") {
                self.number("max-bytes")?
            } else {
                256 * 1024 * 1024
            },
        })
    }
    fn store(&self) -> Result<&Path, String> {
        self.store
            .as_deref()
            .ok_or_else(|| "private store path required".into())
    }
}

pub fn run(raw: &[OsString]) -> Result<(), String> {
    if raw.len() == 2 && matches!(raw[1].to_str(), Some("--help" | "-h")) {
        println!("{HELP}");
        return Ok(());
    }
    let args = Args::parse(raw)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| "private runtime unavailable")?;
    runtime.block_on(execute(args))?;
    println!("private local operation completed; no network delivery performed");
    Ok(())
}

async fn execute(args: Args) -> Result<(), String> {
    let identity =
        Identity::open(&args.identity).map_err(|_| "existing identity custody unavailable")?;
    if args.command.starts_with("archive-") {
        return archive::execute(args, identity).await;
    }
    let account = Key::from_bytes(identity.public_key()).map_err(|_| REFUSED)?;
    if args.command == "offer-inspect" {
        let raw = args.input("offer", OFFER_LIMIT, true)?;
        let checked = ContactBootstrap::inspect(&raw, args.key("owner")?, account, now()?)
            .map_err(|_| REFUSED)?;
        return args.json(json!({"kind":"confidential-offer-metadata", "room":hex(checked.scope().room.as_bytes()),
            "anchor":hex(checked.scope().anchor.as_bytes()), "owner":enrollment(checked.owner()),
            "recipient":hex(checked.recipient().as_bytes()), "not_before":checked.validity().not_before(),
            "expires":checked.validity().expires_at(), "authority":"signed offer, not membership or global freshness"}));
    }
    if args.command == "create" {
        let creation = RoomCreation::owner(identity, args.validity()?).map_err(|_| REFUSED)?;
        creation
            .commit(args.store()?, args.limits()?)
            .await
            .map_err(|_| REFUSED)?;
        return Ok(());
    }
    if args.command == "import" {
        let raw = args.input("offer", OFFER_LIMIT, true)?;
        let owner = args.key("owner")?;
        let checked =
            ContactBootstrap::inspect(&raw, owner, account, now()?).map_err(|_| REFUSED)?;
        if checked.scope().room.as_bytes() != &unhex::<32>(args.text("room")?)?
            || checked.scope().anchor.as_bytes() != &unhex::<32>(args.text("anchor")?)?
        {
            return Err(
                "offer differs from the explicitly inspected room/anchor; no device created".into(),
            );
        }
        let creation = RoomCreation::from_contact(identity, &raw, owner, args.validity()?)
            .map_err(|_| REFUSED)?;
        creation
            .commit(args.store()?, args.limits()?)
            .await
            .map_err(|_| REFUSED)?;
        return Ok(());
    }
    let hint = NativePrivateStore::locate_context(args.store()?).map_err(|_| REFUSED)?;
    let context = context(hint.as_bytes())?;
    if context.account != account {
        return Err(
            "selected account does not match the private store; no recovery attempted".into(),
        );
    }
    let mut room = RoomSession::open(identity, args.store()?, context)
        .await
        .map_err(|_| REFUSED)?;
    match args.command.as_str() {
        "inspect" => {
            let snapshot = room.membership().await.map_err(|_| REFUSED)?;
            args.json(membership(&snapshot))?;
        }
        "offer" => {
            let secret = room
                .create_contact_offer(args.operation()?, args.key("recipient")?, args.validity()?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(secret.confidential_bytes())?;
        }
        "request" => {
            let raw = args.input("offer", OFFER_LIMIT, true)?;
            let result = room
                .contact_request(args.operation()?, &raw)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        "accept" => {
            let raw = args.input("request", MAX_STORED_RECORD_BYTES, false)?;
            let result = room
                .accept_contact(args.operation()?, &raw, args.validity()?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        "join" => {
            room.join_contact(&args.input("response", MAX_STORED_RECORD_BYTES, false)?)
                .await
                .map_err(|_| REFUSED)?;
        }
        "send" => {
            let snapshot = room.membership().await.map_err(|_| REFUSED)?;
            let time = now()?;
            if snapshot.status().quarantined
                || matches!(
                    snapshot.status().phase,
                    vhalla_private_kernel::Phase::AwaitingWelcome
                        | vhalla_private_kernel::Phase::Removed
                )
                || snapshot.local().claims().validity.check_at(time).is_err()
                || snapshot.owner().claims().validity.check_at(time).is_err()
            {
                return Err(
                    "local private membership is not currently authorized; no text prepared".into(),
                );
            }
            if snapshot.status().epoch != args.number("epoch")?
                || snapshot.status().roster != unhex::<32>(args.text("roster")?)?
            {
                return Err("selected epoch/recipients changed; inspect again and explicitly reconsider disclosure; no text prepared".into());
            }
            let text = args.input("text", MAX_BODY_BYTES, true)?;
            std::str::from_utf8(&text).map_err(|_| "text input must be UTF-8")?;
            let draft = room.prepare_message(&text).map_err(|_| REFUSED)?;
            let result = room
                .send(args.operation()?, &draft)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        "receive" => {
            let raw = args.input("message", MAX_STORED_RECORD_BYTES, false)?;
            let result = room.receive(&raw).await.map_err(|_| REFUSED)?;
            args.output(result.body())?;
        }
        "outbox" => {
            let page = room
                .outbox(args.number("after")?, page_limit(&args)?)
                .await
                .map_err(|_| REFUSED)?;
            let entries: Vec<_> = page
                .records
                .iter()
                .map(|entry| {
                    json!({"sequence":entry.sequence(),
                "operation":hex(entry.operation().as_bytes()), "kind":format!("{:?}", entry.kind()),
                "artifact_bytes":entry.artifact().map(|artifact| artifact.bytes().len())})
                })
                .collect();
            args.json(json!({"coverage":"local retained outbox only", "head":page.head,"next":page.next,"records":entries}))?;
        }
        "inbox" => {
            let page = room
                .inbox(args.number("after")?, page_limit(&args)?)
                .await
                .map_err(|_| REFUSED)?;
            let entries: Vec<_> = page
                .records
                .iter()
                .map(|entry| {
                    json!({"sequence":entry.sequence(),
                "sender":hex(entry.sender().as_bytes()),"body_hex":hex(entry.body()),
                "body_utf8":std::str::from_utf8(entry.body()).ok()})
                })
                .collect();
            args.json(json!({"coverage":"local accepted inbox only", "head":page.head,"next":page.next,"records":entries}))?;
        }
        "export" => {
            let sequence = args.number("sequence")?;
            let after = sequence.checked_sub(1).ok_or("sequence must be positive")?;
            let page = room.outbox(after, 1).await.map_err(|_| REFUSED)?;
            let artifact = page
                .records
                .first()
                .and_then(|entry| entry.artifact())
                .ok_or(
                    "no ordinary artifact; secret offers require exact dedicated offer recovery",
                )?;
            if artifact.sequence() != sequence || !relay_kind(artifact.kind()) {
                return Err(
                    "generic export refuses secret or legacy plaintext bootstrap artifacts".into(),
                );
            }
            args.output(artifact.bytes())?;
        }
        "relay-export" => {
            let sequence = args.number("sequence")?;
            let after = sequence.checked_sub(1).ok_or("sequence must be positive")?;
            let page = room.outbox(after, 1).await.map_err(|_| REFUSED)?;
            let artifact = page
                .records
                .first()
                .and_then(|entry| entry.artifact())
                .ok_or("no ordinary artifact; secret offers cannot be relayed")?;
            if artifact.sequence() != sequence {
                return Err("selected sequence is not retained in the local outbox".into());
            }
            let item =
                vhalla_private_native::relay::RelayItem::from_artifact(args.namespace()?, artifact)
                    .map_err(|_| "artifact kind is not eligible for opaque relay export")?;
            args.output(&item.encode().map_err(|_| REFUSED)?)?;
        }
        "relay-apply" => {
            let raw = args.input(
                "relay",
                vhalla_private_native::relay::MAX_RELAY_PAYLOAD + 256,
                false,
            )?;
            let item = vhalla_private_native::relay::RelayItem::decode(&raw)
                .map_err(|_| "relay item is malformed, oversized or fails its commitment")?;
            if item.namespace() != args.namespace()? {
                return Err("relay item belongs to another explicit namespace".into());
            }
            match item.kind() {
                OutboxKind::Application => {
                    let result = room.receive(item.payload()).await.map_err(|_| REFUSED)?;
                    args.output(result.body())?;
                }
                OutboxKind::Removal | OutboxKind::OwnerUpdate => {
                    let result = room
                        .apply_control(item.payload())
                        .await
                        .map_err(|_| REFUSED)?;
                    args.json(json!({"kind": format!("{:?}", item.kind()), "sequence": item.sequence(), "status": status(result), "coverage": "local authenticated control application; not relay acceptance"}))?;
                }
                OutboxKind::Invitation => {
                    let result = room.join(item.payload()).await.map_err(|_| REFUSED)?;
                    args.json(json!({"kind": "Invitation", "sequence": item.sequence(), "status": status(result), "coverage": "local authenticated invitation application; not relay acceptance"}))?;
                }
                OutboxKind::ContactInvitation => {
                    let result = room
                        .join_contact(item.payload())
                        .await
                        .map_err(|_| REFUSED)?;
                    args.json(json!({"kind": "ContactInvitation", "sequence": item.sequence(), "status": status(result), "coverage": "local authenticated contact application; not relay acceptance"}))?;
                }
                OutboxKind::KeyPackage | OutboxKind::ContactRequest => {
                    return Err("this relay kind requires its dedicated explicit owner/member command; no generic admission".into());
                }
                OutboxKind::ContactOffer => {
                    return Err("confidential contact offers cannot be relayed".into());
                }
            }
        }
        "control-export" => {
            let id = if args.text("parent")? == "none" {
                None
            } else {
                Some(ControlId::from_bytes(unhex(args.text("parent")?)?).map_err(|_| REFUSED)?)
            };
            let floor = ControlFloor::new(args.number("after")?, id)
                .map_err(|_| "invalid exact control cursor")?;
            let page = room
                .encrypted_controls(floor, 1)
                .await
                .map_err(|_| REFUSED)?;
            let artifact = page
                .records
                .first()
                .ok_or("no next encrypted control at this exact cursor")?;
            args.output(artifact.bytes())?;
        }
        "remove" => {
            let result = room
                .remove(args.operation()?, args.key("device")?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        "apply" => {
            room.apply_control(&args.input("control", MAX_STORED_RECORD_BYTES, false)?)
                .await
                .map_err(|_| REFUSED)?;
        }
        "renew" => {
            let result = room
                .renew_owner(args.operation()?, args.validity()?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        _ => return Err(HELP.into()),
    }
    room.lock();
    Ok(())
}

fn page_limit(args: &Args) -> Result<usize, String> {
    let limit = usize::try_from(args.number("limit")?).map_err(|_| "page limit out of range")?;
    if !(1..=16).contains(&limit) {
        return Err("page limit must be 1..16".into());
    }
    Ok(limit)
}
fn relay_kind(kind: OutboxKind) -> bool {
    matches!(
        kind,
        OutboxKind::Application
            | OutboxKind::Removal
            | OutboxKind::OwnerUpdate
            | OutboxKind::ContactRequest
            | OutboxKind::ContactInvitation
    )
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "system clock unavailable".into())
}
fn number(raw: &str) -> Result<u64, String> {
    let value = raw
        .parse::<u64>()
        .map_err(|_| "invalid canonical nonnegative integer")?;
    if value.to_string() != raw {
        return Err("noncanonical integer".into());
    }
    Ok(value)
}
fn unhex<const N: usize>(raw: &str) -> Result<[u8; N], String> {
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected full lowercase hexadecimal identifier".into());
    }
    let mut out = [0; N];
    for (pair, byte) in raw.as_bytes().as_chunks::<2>().0.iter().zip(&mut out) {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}
fn hex(raw: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
fn context(raw: &[u8; 128]) -> Result<Context, String> {
    let part = |n| raw[n..n + 32].try_into().map_err(|_| REFUSED);
    Ok(Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(part(0)?).map_err(|_| REFUSED)?,
            anchor: AnchorId::from_bytes(part(32)?).map_err(|_| REFUSED)?,
        },
        account: Key::from_bytes(part(64)?).map_err(|_| REFUSED)?,
        device: Key::from_bytes(part(96)?).map_err(|_| REFUSED)?,
    })
}
fn enrollment(value: &SignedDeviceEnrollment) -> Value {
    let claim = value.claims();
    json!({"account":hex(claim.account.as_bytes()),"device":hex(claim.device.as_bytes()),
        "not_before":claim.validity.not_before(),"expires":claim.validity.expires_at(),"signed_record":hex(&value.encode())})
}
fn status(status: Status) -> Value {
    json!({"room":hex(status.context.scope.room.as_bytes()),"anchor":hex(status.context.scope.anchor.as_bytes()),
        "account":hex(status.context.account.as_bytes()),"device":hex(status.context.device.as_bytes()),
        "phase":format!("{:?}",status.phase),"epoch":status.epoch,"roster":hex(&status.roster),
        "members":status.members,"quarantined":status.quarantined,"control_sequence":status.control_floor.sequence(),
        "control_id":status.control_floor.id().map(|id|hex(id.as_bytes())),"outbox_head":status.outbox_head,"inbox_head":status.inbox_head})
}
fn membership(snapshot: &MembershipSnapshot) -> Value {
    json!({"coverage":"last authenticated local membership; not global freshness", "status":status(snapshot.status()),
        "anchor_record":hex(&snapshot.anchor().encode()),"local":enrollment(snapshot.local()),"owner":enrollment(snapshot.owner()),
        "recipients":snapshot.members().iter().map(enrollment).collect::<Vec<_>>()})
}
