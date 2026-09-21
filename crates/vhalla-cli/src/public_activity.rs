//! Native local-first authoring, using the same reserved drafts as the browser.
//! No key restoration, server head, or missing directory authorizes a fresh floor.
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use vhalla_browser_storage::{
    history::{HistoryFrontier, HistoryHead, HistoryScope},
    native::{replay::NativeReplay, Limits, NativeOutbox},
    outbox::{AuthorHead, AuthorScope, ReservedDraft},
};
use vhalla_identity::Identity;
use vhalla_journal::{FsStore, Journal, PublishedRange, MAX_PUBLISHED_PAGE_BYTES};
use vhalla_public_client::{
    checkpoint::CheckpointHead, Bootstrap, CertifiedClient, MAX_BOOTSTRAP_BYTES,
};
use vhalla_room_activity::{Content, EventClaims, RoomScope, Text, UnsignedEvent};
use vhalla_rooms::RoomGenesisId;

#[path = "public_activity/network.rs"]
mod network;

pub const HELP: &str = "vhalla public activity init BOOTSTRAP PIN64 JOURNAL NEW_KEY_DIR NEW_OUTBOX ROOM64\nvhalla public activity reserve|queue BOOTSTRAP PIN64 JOURNAL KEY_DIR OUTBOX ROOM64 TEXT_FILE\nvhalla public activity resume|catch-up BOOTSTRAP PIN64 JOURNAL KEY_DIR OUTBOX ROOM64\nvhalla public activity outbox BOOTSTRAP PIN64 JOURNAL KEY_DIR OUTBOX ROOM64 AFTER_SEQUENCE NEW_EXPORT_DIR\ninit couples a genuinely new identity with one new room-scoped outbox. reserve saves exact unsigned bytes; queue also signs; resume signs only the retained draft. All are local operations. Keep the key and complete outbox together; restored keys and absent author state cannot reset sequences. outbox exports at most 16 signed frames without publishing them. JOURNAL supplies certified policy, replayed with a 4096-bundle/30-second per-call budget; incomplete replay refuses authoring. Append --replay-profile PROFILE to local author commands for authenticated restart continuation. Create that profile at verified genesis with public activity replay-init BOOTSTRAP PIN64 JOURNAL NEW_PROFILE. Then use replay-step BOOTSTRAP PIN64 JOURNAL PROFILE for pre-author progress, or catch-up with the exact existing outbox before any replay. replay-init reports replay-profile-created; replay-step reports more or caught-up-local-journal. Profile commands never create an author or authorize a post. Use one profile per author workflow. Bare replay-step refuses once an author anchor is retained; activity catch-up with the exact outbox continues without signing. Keep journal and outbox evidence. No network delivery or global freshness is implied.";

const MAX_REPLAY_BUNDLES: usize = 4096;
const REPLAY_TIMEOUT: Duration = Duration::from_secs(30);

struct Context {
    client: Replica,
    head: HistoryHead,
    journal: Journal<FsStore>,
    room: RoomScope,
    started: Instant,
}

fn history_head(client: &CertifiedClient, bundle: [u8; 32]) -> Result<HistoryHead, String> {
    let frontier = client.frontier();
    HistoryHead::new(
        HistoryScope::new(client.network_id(), client.bootstrap_pin()),
        HistoryFrontier {
            height: frontier.height,
            value: frontier.value,
            registry: frontier.registry,
            social: frontier.social,
            control: frontier.control,
            time: frontier.time,
        },
        bundle,
    )
    .map_err(|e| format!("certified history metadata: {e:?}"))
}

enum Replica {
    Memory(CertifiedClient),
    Durable(NativeReplay),
}
impl std::ops::Deref for Replica {
    type Target = CertifiedClient;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Memory(client) => client,
            Self::Durable(profile) => profile.client(),
        }
    }
}
impl Replica {
    fn require_anchor(&mut self, head: CheckpointHead) -> Result<(), String> {
        match self {
            Self::Memory(client) => client
                .require_anchor(head)
                .map_err(|e| format!("retained policy ancestry: {e:?}")),
            Self::Durable(profile) => profile.require_anchor(head).map_err(preserved),
        }
    }
    fn apply(&mut self, raw: &[u8]) -> Result<(), String> {
        match self {
            Self::Memory(client) => {
                let candidate = client
                    .prepare(client.network_id(), raw)
                    .map_err(|e| format!("certificate/application replay: {e:?}"))?;
                client
                    .commit_after_persist(candidate)
                    .map_err(|e| format!("certified replay commit: {e:?}"))?;
                Ok(())
            }
            Self::Durable(profile) => profile.apply_published_bundle(raw).map_err(preserved),
        }
    }
    fn persist(&mut self) -> Result<bool, String> {
        match self {
            Self::Memory(_) => Ok(false),
            Self::Durable(profile) => {
                profile.checkpoint().map_err(preserved)?;
                Ok(true)
            }
        }
    }
    fn ready(&self) -> Result<(), String> {
        if matches!(self, Self::Durable(profile) if profile.needs_reopen()) {
            Err("replay publication uncertain; reopen the retained profile".into())
        } else {
            Ok(())
        }
    }
}

impl Context {
    fn load(args: &[OsString], profile: Option<&Path>) -> Result<Self, String> {
        let pin = super::hex32(args[4].to_str().ok_or("invalid bootstrap pin")?)?;
        let room =
            RoomGenesisId::from_bytes(super::hex32(args[8].to_str().ok_or("invalid room ID")?)?);
        Self::load_paths(
            Path::new(&args[3]),
            pin,
            Path::new(&args[5]),
            room,
            profile.map(|path| (path, false)),
        )
    }
    fn load_paths(
        bootstrap_path: &Path,
        pin: [u8; 32],
        journal_path: &Path,
        room_id: RoomGenesisId,
        profile: Option<(&Path, bool)>,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let raw = super::bytes(bootstrap_path, MAX_BOOTSTRAP_BYTES)?;
        let bootstrap = Bootstrap::decode(&raw, pin)
            .map_err(|e| format!("independently pinned bootstrap: {e:?}"))?;
        let genesis = CertifiedClient::new(bootstrap.clone(), pin)
            .map_err(|e| format!("certified genesis: {e:?}"))?;
        let commitment = genesis.frontier().commitment();
        let room = RoomScope {
            network: genesis.network_id(),
            realm: genesis.registry().realm(),
            directory: genesis.registry().directory(),
            room: room_id,
        };
        let client = if let Some((path, create)) = profile {
            let profile = if create {
                NativeReplay::create_new(path, bootstrap, pin)
            } else {
                NativeReplay::open(path, bootstrap, pin)
            }
            .map_err(preserved)?;
            Replica::Durable(profile)
        } else {
            Replica::Memory(genesis)
        };
        let head = history_head(&client, client.checkpoint_head().bundle_id())?;
        let journal = Journal::with_genesis(journal_path, FsStore, commitment);
        let out = Self {
            client,
            head,
            journal,
            room,
            started,
        };
        out.check_checkpoint()?;
        Ok(out)
    }
    fn check_checkpoint(&self) -> Result<(), String> {
        let frontier = self.client.frontier();
        if frontier.height == 0 {
            return Ok(());
        }
        let page = self
            .journal
            .read_published_range(PublishedRange {
                after_height: frontier.height - 1,
                expected_predecessor: None,
                max_bundles: 1,
                max_bytes: MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(|e| format!("checkpoint journal evidence: {e}"))?;
        let bundle = page
            .bundles()
            .first()
            .ok_or("checkpoint journal bundle is missing")?;
        if bundle.height() != frontier.height
            || bundle.id() != self.head.bundle_id()
            || bundle.next() != frontier.commitment()
        {
            return Err(
                "checkpoint differs from exact retained published journal evidence; preserve both"
                    .into(),
            );
        }
        Ok(())
    }
    fn replay(&mut self, retained: Option<HistoryHead>) -> Result<(), String> {
        if self.replay_step(retained)? {
            Ok(())
        } else {
            Err("bounded replay progress saved; repeat with the same replay profile; no authoring authorized yet".into())
        }
    }
    // Each call verifies only a bounded prefix. A successful More outcome means
    // the prefix is durable, never that the final policy frontier is current.
    fn replay_step(&mut self, retained: Option<HistoryHead>) -> Result<bool, String> {
        let deadline = self.started + REPLAY_TIMEOUT;
        if let Some(head) = retained {
            if head.scope() != self.head.scope() {
                return Err("retained author bootstrap differs from replay profile".into());
            }
            let frontier = head.frontier();
            self.client.require_anchor(
                CheckpointHead::new(
                    vhalla_rooms_consensus::Frontier {
                        height: frontier.height,
                        value: frontier.value,
                        registry: frontier.registry,
                        social: frontier.social,
                        control: frontier.control,
                        time: frontier.time,
                    },
                    head.bundle_id(),
                )
                .map_err(|e| format!("retained anchor: {e:?}"))?,
            )?;
        }
        let mut target = None;
        let mut replayed = 0usize;
        loop {
            if Instant::now() >= deadline || replayed >= MAX_REPLAY_BUNDLES {
                if !self.client.persist()? {
                    return Err("certified replay budget exhausted; use an explicitly created replay profile for durable continuation; no authoring authorized".into());
                }
                // Snapshot work is included in the cooperative budget. Crossing
                // it still yields only More, after successful durable publication.
                let _snapshot_exhausted_budget = Instant::now() >= deadline;
                return Ok(false);
            }
            let frontier = self.client.frontier();
            let remaining = target.map_or(32, |pin: vhalla_journal::Pin| {
                pin.height.saturating_sub(frontier.height).min(32) as usize
            });
            let page = self
                .journal
                .read_published_range(PublishedRange {
                    after_height: frontier.height,
                    expected_predecessor: Some(frontier.commitment()),
                    max_bundles: remaining.max(1).min(MAX_REPLAY_BUNDLES - replayed),
                    max_bytes: MAX_PUBLISHED_PAGE_BYTES,
                })
                .map_err(|e| format!("read-only published journal: {e}"))?;
            let observed = *target.get_or_insert(page.observed_head());
            if page.observed_head().height < observed.height {
                return Err("published journal moved backward; preserve state".into());
            }
            for bundle in page.bundles() {
                if bundle.height() > observed.height || Instant::now() >= deadline {
                    break;
                }
                self.client.apply(bundle.bytes())?;
                self.head = history_head(&self.client, bundle.id())?;
                replayed += 1;
            }
            if self.client.frontier().height == observed.height {
                if self.client.frontier().commitment() != observed.next
                    || self.head.bundle_id() != observed.bundle
                    || !self.client.anchor_matched()
                {
                    return Err("journal does not establish the retained policy history and observed frontier".into());
                }
                // Check before and after potentially expensive snapshot work;
                // final authoring still requires a fresh exact local HEAD check.
                let expired_before_save = Instant::now() >= deadline;
                let durable = self.client.persist()?;
                if expired_before_save || Instant::now() >= deadline {
                    if durable {
                        return Ok(false);
                    }
                    return Err(
                        "certified replay deadline exhausted; no authoring authorized".into(),
                    );
                }
                self.check_current()?;
                return Ok(true);
            }
            if page.bundles().is_empty() {
                return Err("certified replay made no progress; no authoring authorized".into());
            }
        }
    }

    fn check_current(&self) -> Result<(), String> {
        self.client.ready()?;
        let frontier = self.client.frontier();
        let page = self
            .journal
            .read_published_range(PublishedRange {
                after_height: frontier.height,
                expected_predecessor: Some(frontier.commitment()),
                max_bundles: 1,
                max_bytes: MAX_PUBLISHED_PAGE_BYTES,
            })
            .map_err(|e| format!("final published policy check: {e}"))?;
        if page.observed_head().height != frontier.height
            || page.observed_head().next != frontier.commitment()
            || page.observed_head().bundle != self.head.bundle_id()
            || !page.bundles().is_empty()
        {
            return Err(
                "published policy advanced during this operation; retry with retained state".into(),
            );
        }
        Ok(())
    }

    fn policy(&self) -> Result<vhalla_rooms::RoomRecordId, String> {
        let room = self
            .client
            .registry()
            .room_by_genesis(self.room.room)
            .ok_or("room is absent from the certified directory")?;
        room.public_activity_policy()
            .filter(|p| room.allows_public_activity(&self.room.network, p.record))
            .map(|p| p.record)
            .ok_or("this room's current certified policy does not allow public activity".into())
    }

    fn permit(&self, request: &UnsignedEvent) -> Result<(), String> {
        if request.claims().scope != self.room || request.claims().policy != self.policy()? {
            return Err(
                "pending draft is not permitted by this exact current room policy; preserve it"
                    .into(),
            );
        }
        self.check_current()
    }
}

fn preserved(error: impl std::fmt::Debug) -> String {
    format!("author storage: {error:?}; preserve the key and complete outbox; reopen to reconcile before retrying")
}

fn sign_reserved(
    context: &Context,
    identity: &Identity,
    store: &mut NativeOutbox,
    draft: &ReservedDraft,
) -> Result<(), String> {
    context.permit(draft.request())?;
    let mut draft = draft.clone();
    if draft.policy_head() != context.head {
        let next = ReservedDraft::new(draft.base(), context.head, draft.request().clone())
            .map_err(preserved)?;
        store.rebase_reservation(&draft, &next).map_err(preserved)?;
        draft = next;
    }
    store.reserve(&draft).map_err(preserved)?;
    // The exact durable reservation precedes any use of the custody signer.
    context.permit(draft.request())?;
    let event = identity
        .sign_activity(draft.request().clone())
        .and_then(|signed| signed.verify())
        .map_err(|e| format!("typed author signing: {e:?}; exact reservation retained"))?;
    store.finalize(&draft, &event).map_err(preserved)?;
    println!("author-sequence {}", event.claims().sequence);
    println!("event-id {}", super::hex(event.id().as_bytes()));
    println!("status signed-and-retained-locally");
    println!("delivery unconfirmed");
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| format!("create new export file: {e}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("export publication uncertain: {e}; retain partial export"))
}

fn export(store: &NativeOutbox, scope: RoomScope, after: u64, path: &Path) -> Result<(), String> {
    let page = store.read_page(after, 16).map_err(preserved)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("create new export directory (never overwrites): {e}"))?;
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .and_then(|f| f.sync_all())
    .map_err(|e| format!("export directory publication: {e}"))?;
    let mut records = Vec::new();
    for event in &page.events {
        let filename = format!(
            "{:020}-{}.vhactivity",
            event.claims().sequence,
            super::hex(event.id().as_bytes())
        );
        write_new(&path.join(&filename), &event.encode())?;
        records.push(serde_json::json!({"file":filename,"sequence":event.claims().sequence.to_string(),"eventId":super::hex(event.id().as_bytes())}));
    }
    let manifest = serde_json::json!({
        "format":"vhalla-author-export/1", "author":super::hex(&page.head.scope().author()),
        "network":super::hex(&page.head.scope().network()), "realm":format!("{:032x}", scope.realm.0),
        "directory":super::hex(scope.directory.as_bytes()), "room":super::hex(scope.room.as_bytes()), "after":after.to_string(),
        "headSequence":page.head.sequence().to_string(), "headEvent":super::hex(page.head.event_id().as_bytes()),
        "records":records, "coverage":"bounded-local-author-page", "delivery":"not-established"
    });
    write_new(
        &path.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )?;
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("export directory sync: {e}"))?;
    println!("exported-events {}", page.events.len());
    println!("author-head {}", page.head.sequence());
    println!(
        "next-after {}",
        page.events
            .last()
            .map_or(after, |event| event.claims().sequence)
    );
    println!("coverage bounded-local-author-page");
    Ok(())
}

fn run_replay_profile(args: &[OsString]) -> Result<(), String> {
    if args.len() != 7 {
        return Err(HELP.into());
    }
    let create = args[2] == "replay-init";
    let pin = super::hex32(args[4].to_str().ok_or("invalid bootstrap pin")?)?;
    let mut context = Context::load_paths(
        Path::new(&args[3]),
        pin,
        Path::new(&args[5]),
        RoomGenesisId::from_bytes([0; 32]),
        Some((Path::new(&args[6]), create)),
    )?;
    if context.client.retained_anchor().is_some() {
        return Err("this profile has a retained author anchor; use activity catch-up with its exact outbox and --replay-profile; bare replay-step cannot advance it".into());
    }
    let from = context.client.frontier().height;
    let status = if create {
        // Leave genesis unadvanced so an existing outbox can supply its exact
        // required ancestry before the first journal bundle is consumed.
        "replay-profile-created"
    } else if context.replay_step(None)? {
        "caught-up-local-journal"
    } else {
        "more"
    };
    println!("status {status}");
    println!("replayed-from {from}");
    println!("durable-height {}", context.head.frontier().height);
    println!("bundle-id {}", super::hex(&context.head.bundle_id()));
    println!("elapsed-ms {}", context.started.elapsed().as_millis());
    println!("authoring not-authorized-by-profile-command");
    Ok(())
}

pub fn run(args: &[OsString]) -> Result<(), String> {
    let (args, profile) = if args.len() >= 2 && args[args.len() - 2] == "--replay-profile" {
        (
            &args[..args.len() - 2],
            Some(Path::new(&args[args.len() - 1])),
        )
    } else {
        (args, None)
    };
    let command = args
        .get(2)
        .and_then(|arg| arg.to_str())
        .ok_or_else(|| format!("{HELP}\n{}\n{}", network::HELP, network::continuity::HELP))?;
    if network::continuity::recognizes(command) {
        return network::continuity::run(args, profile);
    }
    if matches!(command, "replay-init" | "replay-step") {
        if profile.is_some() {
            return Err(HELP.into());
        }
        return run_replay_profile(args);
    }
    if matches!(command, "peer-add" | "send" | "read") {
        if profile.is_some() {
            return Err("replay profiles apply to local authoring; send/read operate only on existing signed evidence".into());
        }
        return network::run(args);
    }
    let count = match command {
        "init" | "resume" | "catch-up" => 9,
        "reserve" | "queue" => 10,
        "outbox" => 11,
        _ => {
            return Err(format!(
                "{HELP}\n{}\n{}",
                network::HELP,
                network::continuity::HELP
            ))
        }
    };
    if args.len() != count {
        return Err(HELP.into());
    }
    if command == "catch-up" && profile.is_none() {
        return Err("catch-up requires --replay-profile PROFILE".into());
    }
    let mut context = Context::load(args, profile)?;
    if command == "init" {
        if let Some((anchor, matched)) = context.client.retained_anchor() {
            if !matched || anchor != context.client.checkpoint_head() {
                return Err("anchored replay profile belongs to an existing author workflow; init cannot replace its anchor; use catch-up with the exact outbox".into());
            }
            context.check_current().map_err(|_| "anchored replay profile cannot advance during init; use catch-up with the exact existing outbox, or a separately created profile for a new author")?;
        } else {
            context.replay(None)?;
        }
        context.policy()?;
        let anchor = context.client.checkpoint_head();
        context.client.require_anchor(anchor)?;
        context.client.persist()?;
        if context.started.elapsed() >= REPLAY_TIMEOUT {
            return Err("policy checkpoint saved after the replay budget; retry init before creating an author".into());
        }
        context.check_current()?;
        // Identity::create_new refuses every existing key directory. If creation
        // or outbox publication is interrupted, retain both paths; never reuse
        // the surviving key to assert an absent author state means sequence zero.
        let identity = Identity::create_new(Path::new(&args[6])).map_err(|e| {
            format!("create genuinely new author identity: {e:?}; preserve partial paths")
        })?;
        let author = AuthorScope::new(context.room, identity.public_key());
        let _store = NativeOutbox::create_new(
            Path::new(&args[7]),
            AuthorHead::fresh_scope_authorized(author),
            context.head,
            Limits::default(),
        )
        .map_err(preserved)?;
        println!("author-key {}", super::hex(&identity.public_key()));
        println!("network-id {}", super::hex(&context.room.network));
        println!("room-id {}", super::hex(context.room.room.as_bytes()));
        println!("policy-height {}", context.head.frontier().height);
        println!("status new-local-author-ready");
        return Ok(());
    }
    let identity = Identity::open(Path::new(&args[6]))
        .map_err(|e| format!("open retained author identity: {e:?}"))?;
    let author = AuthorScope::new(context.room, identity.public_key());
    let mut store =
        NativeOutbox::open(Path::new(&args[7]), author, context.head.scope()).map_err(preserved)?;
    if command == "outbox" {
        let after = args[9]
            .to_str()
            .ok_or("invalid sequence")?
            .parse::<u64>()
            .map_err(|_| "invalid sequence")?;
        return export(&store, context.room, after, Path::new(&args[10]));
    }
    let retained = store.history_head().map_err(preserved)?;
    context.replay(Some(retained))?;
    if context.head != retained {
        store
            .advance_history(retained, context.head)
            .map_err(preserved)?;
    }
    if command == "catch-up" {
        println!("status caught-up-local-journal");
        println!("policy-height {}", context.head.frontier().height);
        println!("authoring not-signed-by-catch-up");
        return Ok(());
    }
    let pending = store.load_pending().map_err(preserved)?;
    if command == "resume" {
        return sign_reserved(
            &context,
            &identity,
            &mut store,
            &pending.ok_or("no saved draft to resume")?,
        );
    }
    if pending.is_some() {
        return Err("an exact draft is already reserved; use resume, never replace it".into());
    }
    let raw = super::bytes(Path::new(&args[9]), 4096)?;
    let text = Text::new(std::str::from_utf8(&raw).map_err(|_| "text file must be UTF-8")?)
        .map_err(|e| format!("room text: {e:?}"))?;
    let base = store.head().map_err(preserved)?;
    let request = UnsignedEvent::new(EventClaims {
        scope: context.room,
        policy: context.policy()?,
        author: identity.public_key(),
        sequence: base
            .sequence()
            .checked_add(1)
            .ok_or("author sequence exhausted")?,
        previous: base.event_id(),
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock before Unix epoch")?
            .as_secs(),
        content: Content::Text(text),
    })
    .map_err(|e| format!("unsigned activity: {e:?}"))?;
    context.permit(&request)?;
    let draft = ReservedDraft::new(base, context.head, request).map_err(preserved)?;
    store.reserve(&draft).map_err(preserved)?;
    if command == "reserve" {
        println!("reserved-sequence {}", draft.request().claims().sequence);
        println!(
            "reserved-event {}",
            super::hex(draft.request().id().as_bytes())
        );
        println!("status exact-unsigned-draft-retained");
        Ok(())
    } else {
        sign_reserved(&context, &identity, &mut store, &draft)
    }
}
