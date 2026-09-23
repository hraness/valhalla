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
        SignedOwnerControl, Validity,
    },
    ContactBootstrap, Context, MembershipSnapshot, OperationId, OutboxKind, Status, MAX_BODY_BYTES,
    MAX_STORED_RECORD_BYTES,
};
use vhalla_private_native::{
    client::{RoomCreation, RoomSession},
    private_rooms::{Limits, NativePrivateStore},
    relay::RelayKind,
};

mod agent;
mod agent_delivery;
mod agent_setup;
mod archive;
mod delivery_resume;
mod files;
mod relay_tls;

pub const HELP: &str = "vhalla private agent-serve ID STORE --grant PRIVATE_JSON [--delivery PRIVATE_JSON]
vhalla private agent-launch ID STORE --policy PRIVATE_JSON --session-dir PRIVATE_DIR [--delivery PRIVATE_JSON]
vhalla private delivery-init ID STORE --config PRIVATE_JSON
vhalla private delivery-upgrade ID STORE --config PRIVATE_JSON
vhalla private delivery-resume ID STORE --config PRIVATE_JSON [--stream outbox|control] [--job DIGEST64]
vhalla private delivery-status ID STORE --config PRIVATE_JSON [--stream outbox|control] [--after N] [--limit N] --out FILE
vhalla private agent-grant ID STORE --mode read-only|read-write --disclosure PRIVATE_JSON --receipt NEW_CLAIM --out NEW_GRANT [--lifetime SECONDS --inbox-after N --inbox-through N --follow-inbox true|false --max-messages N --max-body-bytes N --max-read-records N --max-read-bytes N --max-preparations N]
vhalla private create ID NEW_STORE --not-before UNIX --expires UNIX [--max-records N --max-bytes N]
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
vhalla private relay-mailbox NEW_DIR --namespace NS64 [--max-items N --max-bytes N]
vhalla private relay-put MAILBOX --namespace NS64 --relay RELAY_ITEM --out RECEIPT_JSON
vhalla private relay-get MAILBOX --namespace NS64 --position N --out RELAY_ITEM
vhalla private relay-unwrap RELAY_ITEM --out PAYLOAD
vhalla private relay-page MAILBOX --namespace NS64 --after N --limit N --out PAGE_JSON
vhalla private relay-serve MAILBOX --namespace NS64 --token FILE|- --listen IP:PORT
vhalla private relay-tls-init MAILBOX --namespace NS64
vhalla private relay-tls-serve MAILBOX --namespace NS64 --config PRIVATE_JSON --cert DER --key PKCS8_DER --listen IP:PORT
vhalla private relay-submit RELAY_ITEM [--namespace NS64] (--addr IP:PORT --token FILE|- | --mailbox MAILBOX_DIR) --out RECEIPT_JSON
vhalla private relay-scan CURSOR_DIR --namespace NS64 (--addr IP:PORT --token FILE|- | --mailbox MAILBOX_DIR) [--limit N] --out SCAN_JSON
vhalla private relay-push ID STORE --namespace NS64 (--addr IP:PORT --token FILE|- | --mailbox MAILBOX_DIR) [--after N] [--limit N] --out PUSH_JSON
vhalla private relay-pull ID STORE --namespace NS64 --dir CURSOR_DIR (--addr IP:PORT --token FILE|- | --mailbox MAILBOX_DIR) [--limit N] --out PULL_JSON
vhalla private control-export ID STORE --after N --parent CONTROL64|none --out CIPHERTEXT
vhalla private control-proof ID STORE --after N --parent CONTROL64|none --out SIGNED
vhalla private observe ID STORE --control SIGNED --out JSON
vhalla private fork-evidence ID STORE --out PRIVATE_JSON
vhalla private remove ID STORE --device KEY64 --operation OP32 --out CIPHERTEXT
vhalla private apply ID STORE --control FILE
vhalla private renew ID STORE --operation OP32 --not-before UNIX --expires UNIX --out CIPHERTEXT
vhalla private succeed ID STORE --device KEY64 --operation OP32 --not-before UNIX --expires UNIX --out CIPHERTEXT
vhalla private archive-export ID STORE --out NEW_FILE.vharchive
vhalla private archive-import ID NEW_ARCHIVE_STORE --archive FILE.vharchive [--max-records N --max-bytes N]
vhalla private archive-resume ID ARCHIVE_STORE --archive FILE.vharchive [--max-records N --max-bytes N]
vhalla private archive-inspect ID ARCHIVE_STORE --archive FILE.vharchive --out PRIVATE_JSON [--max-records N --max-bytes N]
vhalla private archive-inbox|archive-outbox ID ARCHIVE_STORE --archive FILE.vharchive --after N --limit N --out PRIVATE_JSON [--max-records N --max-bytes N]
Archives are inert encrypted complete-state copies; they cannot restore or transfer a live device. Preserve the exact file for resume and finalization inspection. No account-key-only recovery.
control-proof exports signed owner controls for inspection; observe compares one signed control against retained history only and writes durable quarantine on a proven conflict; fork-evidence reports the retained proof. None claim global freshness or grant succession.
Existing identity; create/import always require a never-used store. Relay items are canonical opaque envelopes for an adapter or explicit local handoff; relay-apply dispatches only the authenticated item kind and never treats a relay receipt as member acceptance. The relay-mailbox/put/get/page commands operate a durable opaque mailbox and never open identity or room custody. relay-serve exposes one mailbox over a token-authenticated loopback-only TCP socket while relay-submit retains one item and relay-scan stages a bounded prefix after a durable cursor into an explicitly namespace-bound private directory. Both scan transports require --namespace; preserve older nonempty unbound directories and select a new empty directory. Legacy plaintext bootstrap artifacts are never relay eligible. relay-submit/relay-scan/relay-push/relay-pull accept either the socket transport (--addr with --token) or --mailbox DIR, which opens the durable mailbox directly under filesystem custody — one process at a time, suitable for a synced or explicitly copied directory. relay-push submits a bounded local outbox prefix and relay-pull scans then applies each applicable item, reopening custody after each deterministic refusal and retrying refused items within one pull so out-of-order delivery heals without an extra pass; neither emits plaintext or claims acceptance by another member. relay-unwrap verifies one retained item and writes only its inner payload, feeding skipped encrypted contact requests to the dedicated commands which authenticate the envelope themselves. A mailbox assigns each retained item its own increasing position shared by every sender in the namespace, so pages, cursors and relay-get use positions while each item still carries its sender-local outbox sequence. Remote transports require --addr IP:PORT --token FILE --tls-ca DER --tls-name DNS together. TLS verifies the selected certificate authority, server name and opaque namespace before sending credentials; there is no plaintext fallback. relay-tls-init explicitly enrolls an empty mailbox in durable credential quotas before relay-tls-serve can start. Agent grants explicitly authorize one cooperating-host MCP session with finite quotas and a retained one-use claim; they do not sandbox external CLI tools or authenticate the declared inference provider. There is no reset or automatic migration. Secret/plaintext input is a bounded pipe or 0600 file in a 0700 directory; all outputs are new 0600 files in a 0700 directory. No content is printed. Save exact operation, validity, epoch and roster for retries; output failure never authorizes regenerating or resetting a device.";

const REFUSED: &str = "private operation refused; preserve the existing store and reopen it; never reset or recreate a device";
const OFFER_LIMIT: usize = 1024;

struct Args {
    command: String,
    /// Identity directory for custody commands; the relay mailbox directory for
    /// `relay-mailbox`/`relay-put`/`relay-get`/`relay-page`/`relay-serve`, the
    /// canonical item file for `relay-submit`/`relay-unwrap`, and the catch-up
    /// directory for `relay-scan` — none of which open identity or room custody.
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
            "delivery-init" | "delivery-upgrade" => &["config"],
            "delivery-resume" => &["config", "stream", "job"],
            "delivery-status" => &["config", "stream", "after", "limit", "out"],
            "agent-grant" => &[
                "mode",
                "disclosure",
                "receipt",
                "out",
                "lifetime",
                "inbox-after",
                "inbox-through",
                "follow-inbox",
                "max-messages",
                "max-body-bytes",
                "max-read-records",
                "max-read-bytes",
                "max-preparations",
            ],
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
            "relay-mailbox" => &["namespace", "max-items", "max-bytes"],
            "relay-put" => &["namespace", "relay", "out"],
            "relay-get" => &["namespace", "position", "out"],
            "relay-unwrap" => &["out"],
            "relay-page" => &["namespace", "after", "limit", "out"],
            "relay-serve" => &["namespace", "token", "listen"],
            "relay-tls-init" => &["namespace"],
            "relay-tls-serve" => &["namespace", "config", "cert", "key", "listen"],
            "relay-submit" => &[
                "addr",
                "token",
                "mailbox",
                "namespace",
                "out",
                "tls-ca",
                "tls-name",
            ],
            "relay-scan" => &[
                "addr",
                "token",
                "mailbox",
                "namespace",
                "limit",
                "out",
                "tls-ca",
                "tls-name",
            ],
            "relay-push" => &[
                "namespace",
                "addr",
                "token",
                "tls-ca",
                "tls-name",
                "mailbox",
                "after",
                "limit",
                "out",
            ],
            "relay-pull" => &[
                "namespace",
                "dir",
                "addr",
                "token",
                "tls-ca",
                "tls-name",
                "mailbox",
                "limit",
                "out",
            ],
            "control-export" => &["after", "parent", "out"],
            "control-proof" => &["after", "parent", "out"],
            "observe" => &["control", "out"],
            "fork-evidence" => &["out"],
            "remove" => &["device", "operation", "out"],
            "apply" => &["control"],
            "renew" => &["operation", "not-before", "expires", "out"],
            "succeed" => &["device", "operation", "not-before", "expires", "out"],
            _ => return Err(HELP.into()),
        };
        let start = if matches!(
            command,
            "offer-inspect"
                | "relay-mailbox"
                | "relay-put"
                | "relay-get"
                | "relay-page"
                | "relay-serve"
                | "relay-tls-init"
                | "relay-tls-serve"
                | "relay-submit"
                | "relay-unwrap"
                | "relay-scan"
        ) {
            3
        } else {
            4
        };
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
        for required in allowed.iter().filter(|name| {
            !matches!(**name, "max-records" | "max-items" | "max-bytes")
                && !matches!(**name, "tls-ca" | "tls-name")
                && !(command == "agent-grant"
                    && !matches!(**name, "mode" | "disclosure" | "receipt" | "out"))
                && !(command == "delivery-status" && matches!(**name, "after" | "limit" | "stream"))
                && !(command == "relay-submit"
                    && matches!(**name, "addr" | "token" | "mailbox" | "namespace"))
                && !(command == "relay-scan"
                    && matches!(**name, "addr" | "token" | "mailbox" | "limit"))
                && !(command == "relay-push"
                    && matches!(**name, "after" | "limit" | "addr" | "token" | "mailbox"))
                && !(command == "relay-pull"
                    && matches!(**name, "limit" | "addr" | "token" | "mailbox"))
                && !(command == "delivery-resume" && matches!(**name, "job" | "stream"))
        }) {
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
    if raw.get(1).is_some_and(|value| value == "agent-serve") {
        return agent::run(raw);
    }
    if raw.get(1).is_some_and(|value| value == "agent-launch") {
        return agent_setup::launch(raw);
    }
    if raw.len() == 2 && matches!(raw[1].to_str(), Some("--help" | "-h")) {
        println!("{HELP}");
        return Ok(());
    }
    let args = Args::parse(raw)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| "private runtime unavailable")?;
    runtime.block_on(execute(args))?;
    println!("private operation completed; consult the retained result for delivery status");
    Ok(())
}

async fn execute(args: Args) -> Result<(), String> {
    if matches!(args.command.as_str(), "relay-tls-init" | "relay-tls-serve") {
        return relay_tls::execute(&args);
    }
    if matches!(
        args.command.as_str(),
        "relay-mailbox"
            | "relay-put"
            | "relay-get"
            | "relay-unwrap"
            | "relay-page"
            | "relay-serve"
            | "relay-submit"
            | "relay-scan"
    ) {
        return relay_mailbox(&args);
    }
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
        "delivery-init" => agent_delivery::initialize(
            Path::new(args.value("config")?),
            room.status().map_err(|_| REFUSED)?.context,
        )?,
        "delivery-upgrade" => agent_delivery::upgrade(
            Path::new(args.value("config")?),
            room.status().map_err(|_| REFUSED)?.context,
        )?,
        "delivery-resume" => {
            delivery_resume::execute(&args, room.status().map_err(|_| REFUSED)?.context)?
        }
        "delivery-status" => {
            agent_delivery::status(&args, room.status().map_err(|_| REFUSED)?.context)?
        }
        "agent-grant" => agent_setup::execute(&args, &room)?,
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
                RelayKind::Outbox(OutboxKind::Application) => {
                    let result = room.receive(item.payload()).await.map_err(|_| REFUSED)?;
                    args.output(result.body())?;
                }
                RelayKind::Control
                | RelayKind::Outbox(
                    OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession,
                ) => {
                    let result = room
                        .apply_control(item.payload())
                        .await
                        .map_err(|_| REFUSED)?;
                    args.json(json!({"kind": format!("{:?}", item.kind()), "sequence": item.sequence(), "status": status(result), "coverage": "local authenticated control application; not relay acceptance"}))?;
                }
                RelayKind::Outbox(OutboxKind::ContactInvitation) => {
                    let result = room
                        .join_contact(item.payload())
                        .await
                        .map_err(|_| REFUSED)?;
                    args.json(json!({"kind": "ContactInvitation", "sequence": item.sequence(), "status": status(result), "coverage": "local authenticated contact application; not relay acceptance"}))?;
                }
                RelayKind::Outbox(OutboxKind::ContactRequest) => {
                    return Err("this relay kind requires its dedicated explicit owner/member command; no generic admission".into());
                }
                RelayKind::Outbox(
                    OutboxKind::ContactOffer | OutboxKind::KeyPackage | OutboxKind::Invitation,
                ) => {
                    return Err("confidential bootstrap artifacts cannot be relayed".into());
                }
            }
        }
        "relay-push" => {
            let namespace = args.namespace()?;
            let mut transport = relay_transport(&args, Some(namespace))?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            let after = if args.flags.contains_key("after") {
                args.number("after")?
            } else {
                0
            };
            let limit = if args.flags.contains_key("limit") {
                usize::try_from(args.number("limit")?)
                    .map_err(|_| "outbox page limit out of range")?
                    .clamp(1, vhalla_private_kernel::MAX_PAGE_RECORDS)
            } else {
                vhalla_private_kernel::MAX_PAGE_RECORDS
            };
            let page = room.outbox(after, limit).await.map_err(|_| REFUSED)?;
            let mut submitted = 0u64;
            let mut duplicates = 0u64;
            let mut skipped = 0u64;
            let mut skipped_bootstrap = 0u64;
            let mut records = Vec::new();
            for entry in &page.records {
                let Some(artifact) = entry.artifact() else {
                    skipped += 1;
                    continue;
                };
                if !relay_kind(artifact.kind()) {
                    skipped_bootstrap += 1;
                    continue;
                }
                let item =
                    vhalla_private_native::relay::RelayItem::from_artifact(namespace, artifact)
                        .map_err(relay_error)?;
                let receipt = transport.submit_until(&item, deadline)?;
                if receipt.duplicate {
                    duplicates += 1;
                } else {
                    submitted += 1;
                }
                records.push(
                    json!({"sequence":entry.sequence(),"position":receipt.position,
                    "digest":hex(&receipt.digest),"duplicate":receipt.duplicate}),
                );
            }
            args.json(json!({"coverage":"local outbox prefix retained on an opaque relay; not delivery or member acceptance",
                "head":page.head,"next":page.next,"submitted":submitted,"duplicates":duplicates,
                "skipped_secret":skipped,"skipped_bootstrap":skipped_bootstrap,"records":records}))?;
        }
        "relay-pull" => {
            let namespace = args.namespace()?;
            let directory = PathBuf::from(args.text("dir")?);
            let transport = relay_transport(&args, Some(namespace))?;
            let limit = if args.flags.contains_key("limit") {
                usize::try_from(args.number("limit")?)
                    .map_err(|_| "scan page limit out of range")?
                    .clamp(1, vhalla_private_native::relay::MAX_RELAY_PAGE)
            } else {
                vhalla_private_native::relay::MAX_RELAY_PAGE
            };
            let mut catchup =
                vhalla_private_native::relay::net::ScanDirectory::open(&directory, namespace)
                    .map_err(scan_error)?;
            let report = catchup
                .scan(transport.source(), limit)
                .map_err(scan_error)?;
            // A mailbox-directory transport holds its exclusive lock while
            // open; the apply pass below needs only the staged item files, so
            // release the mailbox before touching room custody.
            drop(transport);
            // Retain catch-up custody through every bounded read and apply.
            let positions = catchup.positions().map_err(scan_error)?;
            // Apply in position order, then retry refused items until a pass
            // accepts nothing new: an item delivered before its predecessor
            // heals once the parent lands at a later position. Accepted and
            // dedicated-command items are terminal for this pull.
            const MAX_PULL_PASSES: usize = 8;
            let mut accepted = Vec::new();
            let mut skipped = Vec::new();
            let mut done = std::collections::BTreeSet::new();
            let mut refused: Vec<u64> = positions.clone();
            for _ in 0..MAX_PULL_PASSES {
                let mut progressed = false;
                refused = Vec::new();
                for &position in &positions {
                    if done.contains(&position) {
                        continue;
                    }
                    let item = catchup.read(position).map_err(scan_error)?;
                    // Encrypted contact requests need their dedicated command;
                    // legacy plaintext bootstrap kinds never pass relay decoding.
                    let outcome = match item.kind() {
                        RelayKind::Outbox(OutboxKind::Application) => {
                            room.receive(item.payload()).await.map(|_| ())
                        }
                        RelayKind::Control
                        | RelayKind::Outbox(
                            OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession,
                        ) => room.apply_control(item.payload()).await.map(|_| ()),
                        RelayKind::Outbox(OutboxKind::ContactInvitation) => {
                            room.join_contact(item.payload()).await.map(|_| ())
                        }
                        RelayKind::Outbox(OutboxKind::ContactRequest) => {
                            skipped.push(position);
                            done.insert(position);
                            continue;
                        }
                        RelayKind::Outbox(
                            OutboxKind::KeyPackage
                            | OutboxKind::Invitation
                            | OutboxKind::ContactOffer,
                        ) => {
                            return Err("confidential bootstrap artifacts cannot be relayed".into());
                        }
                    };
                    match outcome {
                        Ok(()) => {
                            accepted.push(position);
                            done.insert(position);
                            progressed = true;
                        }
                        // A deterministic refusal is recoverable once missing
                        // predecessors arrive; reopen clears the uncertainty
                        // latch before the next item.
                        Err(_) => {
                            refused.push(position);
                            // The live session still holds the identity custody
                            // lock; drop it before reopening.
                            room.lock();
                            room = RoomSession::open(
                                Identity::open(&args.identity)
                                    .map_err(|_| "existing identity custody unavailable")?,
                                args.store()?,
                                context,
                            )
                            .await
                            .map_err(|_| REFUSED)?;
                        }
                    }
                }
                if !progressed {
                    break;
                }
            }
            catchup.check_deadline().map_err(scan_error)?;
            args.json(json!({"coverage":"opaque relay catch-up applied locally; a refused item may succeed after its predecessors arrive",
                "scanned":report.scanned,"head":report.head,"cursor":report.cursor,
                "accepted":accepted,"refused":refused,"skipped":skipped}))?;
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
        "control-proof" => {
            let id = if args.text("parent")? == "none" {
                None
            } else {
                Some(ControlId::from_bytes(unhex(args.text("parent")?)?).map_err(|_| REFUSED)?)
            };
            let floor = ControlFloor::new(args.number("after")?, id)
                .map_err(|_| "invalid exact control cursor")?;
            let page = room.controls(floor, 1).await.map_err(|_| REFUSED)?;
            let artifact = page
                .records
                .first()
                .ok_or("no next signed control at this exact cursor")?;
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
        "observe" => {
            let raw = args.input("control", MAX_STORED_RECORD_BYTES, false)?;
            // Read the retained base before observing: a missing verdict still
            // latches the session's reopen requirement even though nothing was
            // committed.
            let base = room.status().map_err(|_| REFUSED)?.history_base.sequence();
            let verdict = match room.observe_owner_control(&raw).await {
                Ok(_) => "retained",
                Err(vhalla_private_native::client::Error::Kernel(
                    vhalla_private_kernel::Error::Quarantined,
                )) => "conflicting-fork-quarantined",
                Err(vhalla_private_native::client::Error::Kernel(
                    vhalla_private_kernel::Error::Missing,
                )) => {
                    // Below-base and future floors both report missing; only a
                    // future floor can ever be caught up by applying controls.
                    let below = SignedOwnerControl::decode(&raw)
                        .ok()
                        .and_then(|c| c.claims().sequence().ok())
                        .is_some_and(|sequence| sequence < base);
                    if below {
                        "below-retained-base"
                    } else {
                        "unknown-history"
                    }
                }
                Err(_) => return Err(REFUSED.into()),
            };
            args.json(json!({"verdict":verdict,
                "coverage":"compared against retained history only; no global freshness or fork-freedom claim"}))?;
        }
        "fork-evidence" => {
            let proof = room
                .fork_evidence()
                .await
                .map_err(|_| REFUSED)?
                .ok_or("no retained fork evidence")?;
            let conflicting = proof
                .conflicting
                .verify()
                .map_err(|_| "retained fork evidence fails verification")?;
            args.json(json!({"accepted_sequence":proof.accepted.sequence(),
                "accepted_control":proof.accepted.id().map(|id| hex(id.as_bytes())),
                "conflicting_control":hex(conflicting.id().as_bytes()),
                "conflicting_claims":hex(&proof.conflicting.encode()),
                "accepted_proof":hex(&proof.accepted_proof),
                "accepted_from_checkpoint":proof.accepted_from_checkpoint,
                "coverage":"first locally proven conflict under the fixed owner key; not global freshness"}))?;
        }
        "renew" => {
            let result = room
                .renew_owner(args.operation()?, args.validity()?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        "succeed" => {
            let result = room
                .succeed(args.operation()?, args.key("device")?, args.validity()?)
                .await
                .map_err(|_| REFUSED)?;
            args.output(result.bytes())?;
        }
        _ => return Err(HELP.into()),
    }
    room.lock();
    Ok(())
}

/// Durable local relay mailbox commands. The mailbox is untrusted opaque
/// storage: these commands never open identity custody or a private room
/// store, and a retention receipt is never recipient acceptance.
fn relay_mailbox(args: &Args) -> Result<(), String> {
    use vhalla_private_native::relay::{net, FileStore, RelayItem, MAX_RELAY_PAYLOAD};
    let mailbox = args.identity.as_path();
    match args.command.as_str() {
        "relay-mailbox" => {
            FileStore::create_new(mailbox, args.namespace()?, relay_limits(args)?)
                .map_err(relay_error)?;
        }
        "relay-put" => {
            let raw = args.input("relay", MAX_RELAY_PAYLOAD + 256, false)?;
            let item = RelayItem::decode(&raw)
                .map_err(|_| "relay item is malformed, oversized or fails its commitment")?;
            let mut store = FileStore::open(mailbox, args.namespace()?).map_err(relay_error)?;
            let receipt = store.put(item).map_err(relay_error)?;
            args.json(json!({"coverage":"local mailbox retention only; not delivery or member acceptance",
                "position":receipt.position,"digest":hex(&receipt.digest),"duplicate":receipt.duplicate}))?;
        }
        "relay-get" => {
            let position = args.number("position")?;
            let after = position.checked_sub(1).ok_or("position must be positive")?;
            let store = FileStore::open(mailbox, args.namespace()?).map_err(relay_error)?;
            let page = store.page(after, 1).map_err(relay_error)?;
            let item = &page
                .records
                .first()
                .filter(|record| record.position == position)
                .ok_or("no retained relay item at this exact position")?
                .item;
            args.output(&item.encode().map_err(|_| "relay item encoding failed")?)?;
        }
        "relay-page" => {
            let limit = relay_page_limit(args)?;
            let store = FileStore::open(mailbox, args.namespace()?).map_err(relay_error)?;
            let page = store
                .page(args.number("after")?, limit)
                .map_err(relay_error)?;
            let records: Vec<Value> = page
                .records
                .iter()
                .map(|record| {
                    let item = &record.item;
                    json!({"position":record.position,"sequence":item.sequence(),
                        "operation":hex(item.operation().as_bytes()),
                        "kind":format!("{:?}",item.kind()),"digest":hex(&item.digest()),
                        "bytes":item.payload().len()})
                })
                .collect();
            args.json(json!({"coverage":"local retained mailbox manifest only; not delivery or member acceptance",
                "head":page.head,"next":page.next,"records":records}))?;
        }
        "relay-serve" => {
            use std::net::TcpListener;
            let listen = relay_addr(args, "listen")?;
            if !listen.ip().is_loopback() {
                return Err("plaintext relay-serve is loopback-only; use relay-tls-serve for a remote listener".into());
            }
            let token = relay_token(args)?;
            let store = FileStore::open(mailbox, args.namespace()?).map_err(relay_error)?;
            let listener = TcpListener::bind(listen)
                .map_err(|_| "relay listener bind failed; choose an explicit IP:port")?;
            // One line is the ready signal; no room, account or item content.
            println!(
                "relay-serve {}",
                listener
                    .local_addr()
                    .map_err(|_| "relay listener unavailable")?
            );
            net::serve(listener, store, token, None).map_err(relay_error)?;
        }
        "relay-submit" => {
            let raw = files::read(&args.identity, MAX_RELAY_PAYLOAD + 256, false)?;
            let item = RelayItem::decode(&raw)
                .map_err(|_| "relay item is malformed, oversized or fails its commitment")?;
            if args.flags.contains_key("namespace") && args.namespace()? != item.namespace() {
                return Err(
                    "relay item differs from the explicit namespace; no transport opened".into(),
                );
            }
            let mut transport = relay_transport(args, Some(item.namespace()))?;
            let receipt = transport.submit(&item)?;
            args.json(json!({"coverage":"relay retention only; not delivery or member acceptance",
                "position":receipt.position,"digest":hex(&receipt.digest),"duplicate":receipt.duplicate}))?;
        }
        "relay-unwrap" => {
            // Emit only the verified payload: the destination file feeds a
            // dedicated command (request, join, accept, key-package) which
            // authenticates the envelope itself.
            let raw = files::read(&args.identity, MAX_RELAY_PAYLOAD + 256, false)?;
            let item = RelayItem::decode(&raw)
                .map_err(|_| "relay item is malformed, oversized or fails its commitment")?;
            args.output(item.payload())?;
        }
        "relay-scan" => {
            let namespace = args.namespace()?;
            let transport = relay_transport(args, Some(namespace))?;
            let limit = if args.flags.contains_key("limit") {
                usize::try_from(args.number("limit")?)
                    .map_err(|_| "scan page limit out of range")?
                    .clamp(1, vhalla_private_native::relay::MAX_RELAY_PAGE)
            } else {
                vhalla_private_native::relay::MAX_RELAY_PAGE
            };
            let report = net::scan(&args.identity, namespace, transport.source(), limit)
                .map_err(scan_error)?;
            args.json(
                json!({"coverage":"opaque relay catch-up only; not room acceptance",
                "head":report.head,"cursor":report.cursor,"scanned":report.scanned}),
            )?;
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}

fn relay_limits(args: &Args) -> Result<vhalla_private_native::relay::Limits, String> {
    let limits = vhalla_private_native::relay::Limits {
        max_items: if args.flags.contains_key("max-items") {
            usize::try_from(args.number("max-items")?).map_err(|_| "max-items out of range")?
        } else {
            4096
        },
        max_bytes: if args.flags.contains_key("max-bytes") {
            usize::try_from(args.number("max-bytes")?).map_err(|_| "max-bytes out of range")?
        } else {
            256 * 1024 * 1024
        },
    };
    Ok(limits)
}

fn relay_page_limit(args: &Args) -> Result<usize, String> {
    let limit = usize::try_from(args.number("limit")?).map_err(|_| "page limit out of range")?;
    if !(1..=vhalla_private_native::relay::MAX_RELAY_PAGE).contains(&limit) {
        return Err("relay page limit must be 1..64".into());
    }
    Ok(limit)
}

/// The mailbox admission secret is secret input: a bounded pipe or 0600 file
/// holding one nonzero 64-digit lowercase hex token, never an argv value.
fn relay_token(args: &Args) -> Result<vhalla_private_native::relay::net::RelayToken, String> {
    let raw = args.input("token", 65, true)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| "relay token must be a 64-digit lowercase hex secret")?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    vhalla_private_native::relay::net::RelayToken::from_bytes(unhex(text)?)
        .map_err(|_| "relay token must be a nonzero 64-digit lowercase hex secret".into())
}

/// Relay addresses are explicit numeric IP:port pairs; no DNS or ambient host.
fn relay_addr(args: &Args, name: &str) -> Result<std::net::SocketAddr, String> {
    args.text(name)?
        .parse()
        .map_err(|_| "relay address must be an explicit IP:port".into())
}

/// One interchangeable relay transport: the token-authenticated socket
/// (`--addr`/`--token`) or a durable local mailbox directory (`--mailbox`),
/// which puts shared-folder or explicitly copied custody under filesystem
/// permissions instead of the mailbox token. Exactly one transport is allowed.
enum RelayTransport {
    Socket(vhalla_private_native::relay::net::SocketRelay),
    Tls(vhalla_private_native::relay::tls::TlsRelay),
    Mailbox(vhalla_private_native::relay::FileStore),
}
impl RelayTransport {
    fn submit(
        &mut self,
        item: &vhalla_private_native::relay::RelayItem,
    ) -> Result<vhalla_private_native::relay::RelayReceipt, String> {
        match self {
            Self::Socket(relay) => relay.submit(item).map_err(net_error),
            Self::Tls(relay) => relay.submit(item).map_err(net_error),
            Self::Mailbox(store) => store.put(item.clone()).map_err(relay_error),
        }
    }
    fn submit_until(
        &mut self,
        item: &vhalla_private_native::relay::RelayItem,
        deadline: std::time::Instant,
    ) -> Result<vhalla_private_native::relay::RelayReceipt, String> {
        if std::time::Instant::now() >= deadline {
            return Err(
                "relay push exceeded its absolute time budget; retry the exact prefix".into(),
            );
        }
        let receipt = match self {
            Self::Socket(relay) => relay.submit_until(item, deadline).map_err(net_error),
            Self::Tls(relay) => relay.submit_until(item, deadline).map_err(net_error),
            Self::Mailbox(store) => store.put(item.clone()).map_err(relay_error),
        }?;
        if std::time::Instant::now() >= deadline {
            return Err(
                "relay push exceeded its absolute time budget; retry the exact prefix".into(),
            );
        }
        Ok(receipt)
    }
    fn source(&self) -> &dyn vhalla_private_native::relay::net::PageSource {
        match self {
            Self::Socket(relay) => relay,
            Self::Tls(relay) => relay,
            Self::Mailbox(store) => store,
        }
    }
}

fn relay_transport(
    args: &Args,
    namespace: Option<vhalla_private_native::relay::RelayNamespace>,
) -> Result<RelayTransport, String> {
    let tls_ca = args.flags.contains_key("tls-ca");
    let tls_name = args.flags.contains_key("tls-name");
    if tls_ca || tls_name {
        if !tls_ca
            || !tls_name
            || args.flags.contains_key("mailbox")
            || !args.flags.contains_key("addr")
            || !args.flags.contains_key("token")
        {
            return Err(
                "TLS requires --addr, --token, --tls-ca and --tls-name together, without --mailbox"
                    .into(),
            );
        }
        return relay_tls::client(args, namespace.ok_or("TLS requires an explicit namespace")?)
            .map(RelayTransport::Tls);
    }
    let socket = args.flags.contains_key("addr") || args.flags.contains_key("token");
    let mailbox = args.flags.contains_key("mailbox");
    match (socket, mailbox) {
        (true, false) if args.flags.contains_key("addr") && args.flags.contains_key("token") => {
            let addr = relay_addr(args, "addr")?;
            if !addr.ip().is_loopback() {
                return Err("remote relay addresses require --tls-ca and --tls-name; plaintext is loopback-only".into());
            }
            Ok(RelayTransport::Socket(
                vhalla_private_native::relay::net::SocketRelay::new(addr, relay_token(args)?),
            ))
        }
        (false, true) => Ok(RelayTransport::Mailbox(
            vhalla_private_native::relay::FileStore::open(
                args.text("mailbox")?,
                namespace.ok_or("a mailbox transport needs an explicit --namespace")?,
            )
            .map_err(relay_error)?,
        )),
        _ => Err("choose exactly one relay transport: --addr with --token, or --mailbox".into()),
    }
}

fn net_error(error: vhalla_private_native::relay::net::NetError) -> String {
    use vhalla_private_native::relay::net::NetError;
    match error {
        NetError::Connect => "relay listener unreachable or connection refused",
        NetError::Timeout => "relay connection exceeded its bounded deadline",
        NetError::Denied => "relay mailbox refused the presented token",
        NetError::Conflict => {
            "the same relay sequence or operation was presented with different bytes"
        }
        NetError::Capacity => "relay storage or work budget exhausted; retained items are preserved; retry only under the configured backoff",
        NetError::Bounds => "relay input is malformed, noncanonical or exceeds a fixed bound",
        NetError::Scope => "relay item or mailbox belongs to another explicit namespace",
        NetError::Malformed => "relay answered with a noncanonical frame or status",
        NetError::Unavailable => "relay storage or socket operation failed",
    }
    .into()
}

fn scan_error(error: vhalla_private_native::relay::net::ScanFailure) -> String {
    use vhalla_private_native::relay::net::ScanFailure;
    match error {
        ScanFailure::Net(error) => net_error(error),
        ScanFailure::Corrupt => {
            "a retained item file disagrees with the relay's canonical bytes; preserve it and reconcile manually".into()
        }
        ScanFailure::Storage => {
            "cursor directory storage is unavailable or not owner-private; preserve it and reopen the exact directory to reconcile".into()
        }
        ScanFailure::Scope => "catchup directory or item belongs to another namespace; preserve it and choose the correct namespace or a new output directory".into(),
        ScanFailure::Legacy => "nonempty catchup directory lacks a namespace binding; preserve it and select a new empty output directory".into(),
        ScanFailure::Busy => "catchup directory is in use by another scan or pull; retry after its custody ends".into(),
        ScanFailure::Capacity => "catchup item or byte budget exceeded; preserve the directory".into(),
        ScanFailure::Timeout => "catchup operation exceeded its absolute time budget; reopen the same directory to resume".into(),
        ScanFailure::Source => {
            "the mailbox source failed; verify the mailbox directory or relay listener and rerun".into()
        }
    }
}

fn relay_error(error: vhalla_private_native::relay::Error) -> String {
    use vhalla_private_native::relay::Error;
    match error {
        Error::Bounds => "relay input is malformed, noncanonical or exceeds a fixed bound",
        Error::Scope => "relay item or mailbox belongs to another explicit namespace",
        Error::Conflict => {
            "the same relay sequence or operation was presented with different bytes"
        }
        Error::Confidential => "confidential offer metadata cannot be relayed",
        Error::Capacity => "relay mailbox quota is full; retained items are never pruned",
        Error::Storage => "relay mailbox storage is unavailable, locked or failed verification",
    }
    .into()
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
            | OutboxKind::Succession
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
    let anchor_owner = snapshot.anchor().claims().owner_device;
    let successions: Vec<Value> = snapshot
        .successions()
        .iter()
        .map(|grant| {
            let claims = grant.claims();
            json!({"sequence":claims.sequence,"predecessor":hex(claims.predecessor.as_bytes()),
                "successor":hex(claims.successor.claims().device.as_bytes()),
                "signed_record":hex(&grant.encode())})
        })
        .collect();
    json!({"coverage":"last authenticated local membership; not global freshness", "status":status(snapshot.status()),
        "anchor_record":hex(&snapshot.anchor().encode()),"anchor_owner_device":hex(anchor_owner.as_bytes()),
        "local":enrollment(snapshot.local()),"owner":enrollment(snapshot.owner()),"successions":successions,
        "recipients":snapshot.members().iter().map(enrollment).collect::<Vec<_>>()})
}
