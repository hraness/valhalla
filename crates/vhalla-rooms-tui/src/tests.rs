//! Model and render tests — no terminal required.

use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;

use vhalla_rooms::registry::Account;
use vhalla_rooms_app::{
    CreateContext, Error, Pending, PendingState, Projection, RoomRow, Screen, UpdateContext,
};
use vhalla_social::OwnerId;

use crate::{App, Modal, Source, View};

/// A scripted replica: directory rows, an account, and a pending list
/// the test controls. `submit` records the body and enqueues a marker so
/// the submission journey is observable. The generative traces also draw
/// `fail_*` wedges and the reported `height`/`revision`.
struct Fixture {
    rooms: Vec<RoomRow>,
    account: Option<Account>,
    pending: Vec<Pending>,
    submissions: Vec<crate::sign::Body>,
    syncs: usize,
    height: u64,
    revision: u64,
    fail_sync: bool,
    fail_project: bool,
}

impl Fixture {
    fn new() -> Self {
        Self {
            rooms: vec![
                row("papers", "aaaa", "peer reviewed preprints", false),
                row("ops", "bbbb", "incident channel", false),
                row("archive", "cccc", "cold storage", true),
            ],
            account: Some(Account {
                earned: 10,
                spent: 2,
                lifetime_slots: 1,
            }),
            pending: Vec::new(),
            submissions: Vec::new(),
            syncs: 0,
            height: 3,
            revision: 3,
            fail_sync: false,
            fail_project: false,
        }
    }
}

fn row(slug: &str, owner: &str, description: &str, archived: bool) -> RoomRow {
    RoomRow {
        slug: slug.into(),
        owner: owner.repeat(16),
        agent: "dddd".repeat(16),
        description: description.into(),
        slot: 1,
        charge: 2,
        archived,
        record: "ee".repeat(32),
        head: "ff".repeat(32),
        revisions: 1,
        created_at: 1_000,
    }
}

impl Source for Fixture {
    fn sync(&mut self) -> Result<u64, Error> {
        self.syncs += 1;
        if self.fail_sync {
            return Err(Error::Io("drawn sync wedge".into()));
        }
        Ok(self.height)
    }

    fn project(&self, screen: &Screen) -> Result<Projection, Error> {
        if self.fail_project {
            return Err(Error::Bounds);
        }
        let mut rooms = Vec::new();
        let mut account = None;
        let mut quote = None;
        match screen {
            Screen::Directory { query } => {
                for r in &self.rooms {
                    if r.archived {
                        continue;
                    }
                    if !query.is_empty() && !r.slug.contains(query.as_str()) {
                        continue;
                    }
                    rooms.push(r.clone());
                }
            }
            Screen::Room { slug } => {
                if let Some(r) = self.rooms.iter().find(|r| &r.slug == slug && !r.archived) {
                    rooms.push(r.clone());
                }
            }
            Screen::Account { owner } => {
                let owner_hex: String = owner
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                if self.rooms.iter().any(|r| r.owner == owner_hex) {
                    account = self.account;
                    quote = Some((2, 3));
                    for r in &self.rooms {
                        if r.owner == owner_hex && !r.archived {
                            rooms.push(r.clone());
                        }
                    }
                }
            }
        }
        Ok(Projection {
            rooms,
            account,
            quote,
            partial: false,
            revision: self.revision,
            height: self.height,
            pending: self.pending.clone(),
        })
    }

    fn pending(&self) -> Result<Vec<Pending>, Error> {
        Ok(self.pending.clone())
    }

    fn submit(
        &mut self,
        _time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error> {
        self.submissions.push((evidence, records));
        let name = format!("{:064x}", self.submissions.len());
        self.pending.push(Pending {
            name: name.clone(),
            slug: Some("ops".into()),
            state: PendingState::Queued,
        });
        Ok(name)
    }

    fn create_context(
        &self,
        _owner: OwnerId,
        _key: [u8; 32],
        _now: u64,
    ) -> Result<CreateContext, Error> {
        Err(Error::Record("fixture holds no keys".into()))
    }

    fn update_context(
        &self,
        _slug: &str,
        _key: [u8; 32],
        _now: u64,
    ) -> Result<UpdateContext, Error> {
        Err(Error::Record("fixture holds no keys".into()))
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn render(app: &App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut term = Terminal::new(backend).unwrap();
    term.draw(|f| crate::view::draw(app, f)).unwrap();
    let buffer = term.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = buffer.cell((x, y)) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

#[test]
fn directory_renders_rows_and_help() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    let text = render(&app, 100, 20);
    assert!(text.contains("papers"), "{text}");
    assert!(text.contains("ops"), "{text}");
    assert!(!text.contains("cold storage"), "{text}"); // archived rows stay out
    assert!(text.contains("height 3"), "{text}");
    assert!(text.contains("n new room"), "{text}");
}

#[test]
fn empty_directory_shows_hint() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    src.rooms.clear();
    app.refresh(&mut src);
    let text = render(&app, 100, 20);
    assert!(text.contains("Press n to create"), "{text}");
}

#[test]
fn filter_narrows_and_resets_selection() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Down), &mut src);
    assert_eq!(app.selected, 1);
    app.key(key(KeyCode::Char('/')), &mut src);
    for c in "pap".chars() {
        app.key(key(KeyCode::Char(c)), &mut src);
        app.refresh(&mut src);
    }
    assert_eq!(app.filter, "pap");
    assert_eq!(app.rows().len(), 1);
    assert_eq!(app.rows()[0].slug, "papers");
    app.key(key(KeyCode::Enter), &mut src);
    assert!(!app.filter_active);
}

#[test]
fn navigation_opens_room_and_back() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Down), &mut src);
    app.key(key(KeyCode::Enter), &mut src);
    assert_eq!(app.view, View::Room { slug: "ops".into() });
    let text = render(&app, 100, 24);
    assert!(text.contains("incident channel"), "{text}");
    assert!(text.contains("charge"), "{text}");
    app.key(key(KeyCode::Esc), &mut src);
    assert_eq!(app.view, View::Directory);
    app.key(key(KeyCode::Char('q')), &mut src);
    assert!(app.quit);
}

#[test]
fn not_found_room_is_explicit() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.view = View::Room {
        slug: "ghost".into(),
    };
    app.refresh(&mut src);
    let text = render(&app, 100, 20);
    assert!(text.contains("No committed room is named"), "{text}");
}

#[test]
fn account_screen_shows_ledger_and_quote() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Char('a')), &mut src);
    assert!(matches!(app.view, View::Account { .. }));
    let text = render(&app, 100, 20);
    assert!(text.contains("earned"), "{text}");
    assert!(text.contains("10"), "{text}");
    assert!(text.contains("next slot"), "{text}");
    assert!(text.contains("papers"), "{text}");
}

#[test]
fn create_modal_fields_and_cancel() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Char('n')), &mut src);
    let Modal::Create(f) = app.modal.as_ref().unwrap() else {
        panic!("expected create modal");
    };
    assert_eq!(f.fields.len(), 8);
    for c in "salon".chars() {
        app.key(key(KeyCode::Char(c)), &mut src);
    }
    app.key(key(KeyCode::Tab), &mut src);
    for c in "a reading room".chars() {
        app.key(key(KeyCode::Char(c)), &mut src);
    }
    let text = render(&app, 100, 20);
    assert!(text.contains("salon"), "{text}");
    assert!(text.contains("a reading room"), "{text}");
    app.key(key(KeyCode::Esc), &mut src);
    assert!(app.modal.is_none());
}

#[test]
fn archive_modal_confirms() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Down), &mut src);
    app.key(key(KeyCode::Enter), &mut src);
    app.key(key(KeyCode::Char('x')), &mut src);
    assert!(matches!(app.modal, Some(Modal::Archive { .. })));
    let text = render(&app, 100, 20);
    assert!(text.contains("Archive \"ops\""), "{text}");
    app.key(key(KeyCode::Esc), &mut src);
    assert!(app.modal.is_none());
}

#[test]
fn pending_strip_renders_states() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    src.pending = vec![
        Pending {
            name: "01".repeat(32),
            slug: Some("queued-room".into()),
            state: PendingState::Queued,
        },
        Pending {
            name: "02".repeat(32),
            slug: Some("flight".into()),
            state: PendingState::Submitted,
        },
        Pending {
            name: "03".repeat(32),
            slug: Some("landed".into()),
            state: PendingState::Committed,
        },
        Pending {
            name: "04".repeat(32),
            slug: Some("clash".into()),
            state: PendingState::Collision,
        },
        Pending {
            name: "05".repeat(32),
            slug: Some("denied".into()),
            state: PendingState::Rejected,
        },
    ];
    app.refresh(&mut src);
    let text = render(&app, 100, 24);
    for needle in ["queued", "in flight", "committed", "collision", "rejected"] {
        assert!(text.contains(needle), "{needle} missing: {text}");
    }
}

#[test]
fn describe_modal_prefills_description() {
    let mut app = App::new(1_000);
    let mut src = Fixture::new();
    app.refresh(&mut src);
    app.key(key(KeyCode::Enter), &mut src); // open "papers"
    app.key(key(KeyCode::Char('d')), &mut src);
    let Modal::Describe { slug, form } = app.modal.as_ref().unwrap() else {
        panic!("expected describe modal");
    };
    assert_eq!(slug, "papers");
    assert_eq!(form.fields[0].value, "peer reviewed preprints");
}

/// The signing path with real on-disk identities: the context is served
/// by a stub source, the emitted bytes are canonical signed records that
/// verify under the identities' own public keys.
#[cfg(unix)]
mod signing {
    use super::*;
    use crate::sign;
    use crate::Form;
    use vhalla_identity::Identity;
    use vhalla_rooms::{Body, SignedRecord};

    struct CtxSource {
        ctx: CreateContext,
    }

    impl Source for CtxSource {
        fn sync(&mut self) -> Result<u64, Error> {
            Ok(0)
        }
        fn project(&self, _screen: &Screen) -> Result<Projection, Error> {
            Err(Error::Bounds)
        }
        fn pending(&self) -> Result<Vec<Pending>, Error> {
            Ok(Vec::new())
        }
        fn submit(&mut self, _t: u64, _e: Vec<Vec<u8>>, _r: Vec<Vec<u8>>) -> Result<String, Error> {
            Err(Error::Bounds)
        }
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
        let mut f = crate::form("create a room", &crate::CREATE_LABELS);
        field(&mut f, 0, "salon");
        field(&mut f, 1, "a reading room");
        field(&mut f, 2, "9999999");
        field(&mut f, 3, owner_id);
        field(&mut f, 4, agent_id);
        field(&mut f, 5, paths.0);
        field(&mut f, 6, paths.1);
        f
    }

    #[test]
    fn create_body_signs_grant_and_proposal_with_real_identities() {
        let base = std::env::temp_dir().join(format!(
            "tui-sign-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let owner_dir = base.join("owner-id");
        let agent_dir = base.join("agent-id");
        let owner_id = Identity::create_new(&owner_dir).unwrap();
        let agent_id = Identity::create_new(&agent_dir).unwrap();
        let owner_pub = owner_id.public_key();
        let agent_pub = agent_id.public_key();
        drop(owner_id);
        drop(agent_id);

        let owner = OwnerId::from_bytes([7; 32]);
        let agent = vhalla_social::AgentId::from_bytes([8; 32]);
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
        let (evidence, records) = sign::create_body(&f, 1_000, &mut src).unwrap();
        assert!(evidence.is_empty());
        assert_eq!(records.len(), 2, "grant then create");

        let grant = SignedRecord::decode(&records[0]).unwrap().verify().unwrap();
        let Body::Control(control) = grant.body() else {
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
        let Body::Create(intent) = create.body() else {
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
        let base = std::env::temp_dir().join(format!(
            "tui-sign2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let owner_dir = base.join("owner-id");
        let agent_dir = base.join("agent-id");
        Identity::create_new(&owner_dir).unwrap();
        Identity::create_new(&agent_dir).unwrap();

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
        let (_evidence, records) = sign::create_body(&f, 1_000, &mut src).unwrap();
        assert_eq!(records.len(), 1, "no grant when a chain exists");
        let create = SignedRecord::decode(&records[0]).unwrap().verify().unwrap();
        let Body::Create(intent) = create.body() else {
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
        let base = std::env::temp_dir().join(format!(
            "tui-sign3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let owner_dir = base.join("owner-id");
        let agent_dir = base.join("agent-id");
        Identity::create_new(&owner_dir).unwrap();
        Identity::create_new(&agent_dir).unwrap();

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
        let err = sign::create_body(&f, 1_000, &mut src).unwrap_err();
        assert!(err.contains("unspent credit"), "{err}");

        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(unix)]
mod update_signing {
    use super::*;
    use crate::sign;
    use vhalla_identity::Identity;
    use vhalla_rooms::{Body, SignedRecord};

    struct UpdateSource {
        ctx: UpdateContext,
    }

    impl Source for UpdateSource {
        fn sync(&mut self) -> Result<u64, Error> {
            Ok(0)
        }
        fn project(&self, _s: &Screen) -> Result<Projection, Error> {
            Err(Error::Bounds)
        }
        fn pending(&self) -> Result<Vec<Pending>, Error> {
            Ok(Vec::new())
        }
        fn submit(&mut self, _t: u64, _e: Vec<Vec<u8>>, _r: Vec<Vec<u8>>) -> Result<String, Error> {
            Err(Error::Bounds)
        }
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

    fn dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tui-upd-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn ctx() -> UpdateContext {
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
        let base = dir("describe");
        let key_dir = base.join("owner-id");
        let id = Identity::create_new(&key_dir).unwrap();
        let key_pub = id.public_key();
        drop(id);

        let mut f = crate::form("describe room", &crate::DESCRIBE_LABELS);
        f.fields[0].value = "second edition".into();
        f.fields[1].value = "9999999".into();
        f.fields[2].value = key_dir.to_str().unwrap().into();

        let mut src = UpdateSource { ctx: ctx() };
        let raw = sign::describe_body("salon", &f, 1_000, &mut src).unwrap();
        let record = SignedRecord::decode(&raw).unwrap().verify().unwrap();
        let Body::Update(update) = record.body() else {
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
        let base = dir("archive");
        let key_dir = base.join("owner-id");
        let id = Identity::create_new(&key_dir).unwrap();
        let key_pub = id.public_key();
        drop(id);

        let mut src = UpdateSource { ctx: ctx() };
        let raw = sign::archive_body("salon", key_dir.to_str().unwrap(), 1_000, &mut src).unwrap();
        let record = SignedRecord::decode(&raw).unwrap().verify().unwrap();
        let Body::Update(update) = record.body() else {
            panic!("the record is an update");
        };
        assert!(matches!(update.action, vhalla_rooms::UpdateAction::Archive));
        assert_eq!(update.controller_key, key_pub);

        // A slug the source does not know fails before any signing.
        assert!(sign::archive_body("ghost", key_dir.to_str().unwrap(), 1_000, &mut src).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}

// ---------------------------------------------------------------------------
// Generative Hegel properties over the interaction state machine — a
// different shape from the store spikes: the model under test is the UI
// state, not durable data. Each case draws an interleaved trace — key
// events folded through `App::key`, replica ticks that land new committed
// rows, pending resolutions, and drawn sync/project wedges — while a
// step-parallel model of the screen machine tracks what the app must hold.
// After EVERY drawn step the app is checked against it: the active view, at
// most one modal bound to the screen that opened it, the live filter text,
// a selection inside the retained projection's row bounds, and a frame that
// renders the model without panic. `recovery_hegel.rs` in vhalla-ledger is
// the reference for the draw-inside-the-loop style.
// ---------------------------------------------------------------------------

mod generative {
    use super::*;

    use hegel::{generators as gs, TestCase};

    /// The screen the model believes is on top — the shape of [`View`]
    /// without the app attached.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MScreen {
        Directory,
        Room(String),
        Account(String),
    }

    /// The open modal, if any — its kind and the slug it is bound to.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MModal {
        Create,
        Describe(String),
        Archive(String),
    }

    /// Slug pool for drawn rooms: short shared stems so drawn filter text
    /// both hits and misses.
    const SLUGS: [&str; 8] = ["aa", "abe", "lob", "ops", "pap", "papers", "pod", "salon"];
    /// Owner pool — `row` repeats each stem into a 64-hex id.
    const OWNERS: [&str; 3] = ["aaaa", "bbbb", "cccc"];
    /// Description pool for drawn and rewritten rooms.
    const DESCS: [&str; 8] = [
        "preprints",
        "incidents",
        "cold store",
        "reading room",
        "idle",
        "zephyr",
        "lobby",
        "notes",
    ];
    /// Text bytes the filter line and form fields can receive — mostly slug
    /// stems plus a few that match nothing.
    const TEXT: [char; 10] = ['a', 'b', 'e', 'l', 'p', 's', 'z', '5', '?', ' '];
    /// Modal openers; each is gated on the view that admits it.
    const OPENERS: [char; 3] = ['n', 'd', 'x'];
    /// Editing keys that carry no text.
    const EDITS: [KeyCode; 4] = [
        KeyCode::Backspace,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Home,
    ];
    /// Movement keys — one binding at the top level, focus moves or literal
    /// text inside a modal or the filter line.
    const MOVES: [KeyCode; 4] = [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
    ];
    /// Keys with no top-level binding — they exercise the `_` arm (or land
    /// as text where text is live).
    const QUIET: [KeyCode; 5] = [
        KeyCode::Left,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::Char('Z'),
        KeyCode::Char('!'),
    ];

    /// A step-parallel model of [`App`]: the same folds, minus ratatui. The
    /// `projected_*` fields are the projection the last successful
    /// `project` retained — exactly what `App::rows` serves — so a wedged
    /// replica leaves the previous screen's rows on the table, selection
    /// included.
    struct Model {
        screen: MScreen,
        modal: Option<MModal>,
        filter: String,
        filter_active: bool,
        selected: usize,
        quit: bool,
        /// Whether the error line should be set — refresh failures wedge
        /// it and only the next key clears it.
        error: bool,
        has_projection: bool,
        projected_rows: Vec<RoomRow>,
        projected_pending: Vec<Pending>,
        projected_meta: (u64, u64),
        projected_account: bool,
        projected_quote: Option<(u32, u64)>,
    }

    impl Model {
        fn new() -> Self {
            Self {
                screen: MScreen::Directory,
                modal: None,
                filter: String::new(),
                filter_active: false,
                selected: 0,
                quit: false,
                error: false,
                has_projection: false,
                projected_rows: Vec::new(),
                projected_pending: Vec::new(),
                projected_meta: (0, 0),
                projected_account: false,
                projected_quote: None,
            }
        }

        /// The rows `Fixture::project` would commit for the model's current
        /// screen and filter — mirrors its per-screen filtering exactly.
        fn world_rows(&self, w: &Fixture) -> Vec<RoomRow> {
            match &self.screen {
                MScreen::Directory => w
                    .rooms
                    .iter()
                    .filter(|r| {
                        !r.archived
                            && (self.filter.is_empty() || r.slug.contains(self.filter.as_str()))
                    })
                    .cloned()
                    .collect(),
                MScreen::Room(slug) => w
                    .rooms
                    .iter()
                    .filter(|r| &r.slug == slug && !r.archived)
                    .cloned()
                    .collect(),
                MScreen::Account(owner) => {
                    if w.rooms.iter().any(|r| &r.owner == owner) {
                        w.rooms
                            .iter()
                            .filter(|r| &r.owner == owner && !r.archived)
                            .cloned()
                            .collect()
                    } else {
                        Vec::new()
                    }
                }
            }
        }

        /// `App::refresh`: a sync wedge sets the error line but the project
        /// still runs; a project wedge keeps the previous projection —
        /// selection un-clamped against it — and only a successful project
        /// replaces the retained rows and re-clamps. Nothing here clears a
        /// standing error; `key` does that.
        fn refresh(&mut self, w: &Fixture) {
            if w.fail_sync {
                self.error = true;
            }
            if w.fail_project {
                self.error = true;
                return;
            }
            self.projected_rows = self.world_rows(w);
            self.projected_pending = w.pending.clone();
            self.projected_meta = (w.revision, w.height);
            match &self.screen {
                MScreen::Account(owner) => {
                    let known = w.rooms.iter().any(|r| &r.owner == owner);
                    self.projected_account = known && w.account.is_some();
                    self.projected_quote = known.then_some((2, 3));
                }
                _ => {
                    self.projected_account = false;
                    self.projected_quote = None;
                }
            }
            self.has_projection = true;
            let rows = self.projected_rows.len();
            if rows == 0 {
                self.selected = 0;
            } else if self.selected >= rows {
                self.selected = rows - 1;
            }
        }

        /// `App::key`: modal first, then the filter line, then the
        /// top-level bindings — the same dispatch order.
        fn key(&mut self, k: &KeyEvent, w: &Fixture) {
            if k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char('c') {
                self.quit = true;
                return;
            }
            self.error = false;
            if self.modal.is_some() {
                match k.code {
                    // Esc cancels; Enter signs — which always fails against
                    // the keyless fixture — and the modal is gone either way.
                    KeyCode::Esc => self.modal = None,
                    KeyCode::Enter => {
                        self.modal = None;
                        self.error = true;
                    }
                    _ => {}
                }
                return;
            }
            if self.filter_active {
                match k.code {
                    KeyCode::Esc | KeyCode::Enter => self.filter_active = false,
                    KeyCode::Char(c) => {
                        self.filter.push(c);
                        self.selected = 0;
                        self.refresh(w);
                    }
                    KeyCode::Backspace => {
                        self.filter.pop();
                        self.selected = 0;
                        self.refresh(w);
                    }
                    _ => {}
                }
                return;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    if matches!(self.screen, MScreen::Directory) {
                        self.quit = true;
                    } else {
                        self.screen = MScreen::Directory;
                        self.refresh(w);
                    }
                }
                KeyCode::Char('/') => {
                    if matches!(self.screen, MScreen::Directory) {
                        self.filter_active = true;
                    }
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if self.selected + 1 < self.projected_rows.len() {
                        self.selected += 1;
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.selected = self.selected.saturating_sub(1);
                }
                KeyCode::Enter => {
                    if matches!(self.screen, MScreen::Directory) {
                        if let Some(row) = self.projected_rows.get(self.selected) {
                            self.screen = MScreen::Room(row.slug.clone());
                            self.refresh(w);
                        }
                    }
                }
                KeyCode::Char('n') => {
                    if matches!(self.screen, MScreen::Directory) {
                        self.modal = Some(MModal::Create);
                    }
                }
                KeyCode::Char('d') => {
                    if let MScreen::Room(slug) = &self.screen {
                        self.modal = Some(MModal::Describe(slug.clone()));
                    }
                }
                KeyCode::Char('x') => {
                    if let MScreen::Room(slug) = &self.screen {
                        self.modal = Some(MModal::Archive(slug.clone()));
                    }
                }
                KeyCode::Char('o') => {
                    if let MScreen::Room(slug) = &self.screen {
                        if let Some(row) = self.projected_rows.iter().find(|r| &r.slug == slug) {
                            self.screen = MScreen::Account(row.owner.clone());
                            self.refresh(w);
                        }
                    }
                }
                KeyCode::Char('a') => {
                    if let Some(row) = self.projected_rows.get(self.selected) {
                        self.screen = MScreen::Account(row.owner.clone());
                        self.refresh(w);
                    }
                }
                KeyCode::Char('r') => self.refresh(w),
                _ => {}
            }
        }
    }

    /// One drawn replica tick: committed rooms arrive, get re-described or
    /// archived; pending markers resolve; the reported height and revision
    /// drift; sync or project may wedge until a later tick clears it.
    fn tick(tc: &TestCase, w: &mut Fixture) {
        match tc.draw(gs::integers::<u8>().max_value(5)) {
            0 | 1 => {
                let slug = SLUGS[tc.draw(gs::integers::<usize>().max_value(SLUGS.len() - 1))];
                if let Some(r) = w.rooms.iter_mut().find(|r| r.slug == slug) {
                    if tc.draw(gs::booleans()) {
                        r.archived = !r.archived;
                    } else {
                        r.description = DESCS
                            [tc.draw(gs::integers::<usize>().max_value(DESCS.len() - 1))]
                        .into();
                        r.revisions += 1;
                    }
                } else if w.rooms.len() < 8 {
                    let owner =
                        OWNERS[tc.draw(gs::integers::<usize>().max_value(OWNERS.len() - 1))];
                    let desc = DESCS[tc.draw(gs::integers::<usize>().max_value(DESCS.len() - 1))];
                    let archived = tc.draw(gs::integers::<u8>().max_value(3)) == 0;
                    w.rooms.push(row(slug, owner, desc, archived));
                }
            }
            2 => {
                let n = tc.draw(gs::integers::<usize>().max_value(4));
                let mut pending = Vec::with_capacity(n);
                for _ in 0..n {
                    pending.push(Pending {
                        name: format!("{:064x}", tc.draw(gs::integers::<u64>())),
                        slug: tc.draw(gs::booleans()).then(|| {
                            SLUGS[tc.draw(gs::integers::<usize>().max_value(SLUGS.len() - 1))]
                                .to_string()
                        }),
                        state: match tc.draw(gs::integers::<u8>().max_value(4)) {
                            0 => PendingState::Queued,
                            1 => PendingState::Submitted,
                            2 => PendingState::Committed,
                            3 => PendingState::Collision,
                            _ => PendingState::Rejected,
                        },
                    });
                }
                w.pending = pending;
            }
            3 => {
                w.account = if tc.draw(gs::integers::<u8>().max_value(4)) == 0 {
                    None
                } else {
                    Some(Account {
                        earned: tc.draw(gs::integers::<u64>().max_value(50)),
                        spent: tc.draw(gs::integers::<u64>().max_value(50)),
                        lifetime_slots: tc.draw(gs::integers::<u32>().max_value(5)),
                    })
                };
            }
            4 => {
                w.height += tc.draw(gs::integers::<u64>().max_value(3));
                w.revision += tc.draw(gs::integers::<u64>().max_value(2));
            }
            _ => {
                w.fail_sync = tc.draw(gs::integers::<u8>().max_value(5)) == 0;
                w.fail_project = tc.draw(gs::integers::<u8>().max_value(5)) == 0;
            }
        }
    }

    /// A drawn key event; `class` picks the weight band so navigation,
    /// modal work, text, and quitting all stay reachable.
    fn draw_key(tc: &TestCase, class: u8) -> KeyEvent {
        match class {
            0..=2 => key(MOVES[tc.draw(gs::integers::<usize>().max_value(MOVES.len() - 1))]),
            3 | 4 => key(if tc.draw(gs::booleans()) {
                KeyCode::Enter
            } else {
                KeyCode::Esc
            }),
            5 => key(KeyCode::Char(if tc.draw(gs::booleans()) {
                'o'
            } else {
                'a'
            })),
            6 => key(KeyCode::Char(if tc.draw(gs::booleans()) {
                '/'
            } else {
                'r'
            })),
            7 | 8 => key(KeyCode::Char(
                OPENERS[tc.draw(gs::integers::<usize>().max_value(OPENERS.len() - 1))],
            )),
            9..=12 => key(KeyCode::Char(
                TEXT[tc.draw(gs::integers::<usize>().max_value(TEXT.len() - 1))],
            )),
            13 => key(EDITS[tc.draw(gs::integers::<usize>().max_value(EDITS.len() - 1))]),
            16 => key(KeyCode::Char('q')),
            17 => KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            _ => key(QUIET[tc.draw(gs::integers::<usize>().max_value(QUIET.len() - 1))]),
        }
    }

    /// The frame must reflect the model — the modal's own title when one is
    /// open, else the active screen's body — and the pending strip and the
    /// error line whenever they exist.
    fn assert_render(text: &str, app: &App, m: &Model) {
        match &app.modal {
            Some(Modal::Create(_)) => assert!(text.contains("create a room"), "{text}"),
            Some(Modal::Describe { .. }) => {
                assert!(text.contains("describe room"), "{text}")
            }
            Some(Modal::Archive { slug, .. }) => {
                assert!(text.contains(&format!("Archive \"{slug}\"")), "{text}")
            }
            None => {}
        }
        if app.modal.is_none() {
            match &m.screen {
                MScreen::Directory => {
                    assert!(text.contains("rooms /"), "{text}");
                    if !m.filter.is_empty() {
                        assert!(text.contains(&format!("/{}", m.filter)), "{text}");
                    }
                    if m.projected_rows.is_empty() {
                        assert!(text.contains("No committed rooms"), "{text}");
                    } else {
                        let selected = &m.projected_rows[app.selected];
                        assert!(
                            text.contains(&selected.slug) || text.contains(&selected.description),
                            "selected row missing: {text}"
                        );
                    }
                    if m.filter_active {
                        assert!(text.contains("type to filter"), "{text}");
                    } else {
                        assert!(text.contains("enter open"), "{text}");
                    }
                }
                MScreen::Room(slug) => {
                    if let Some(row) = m.projected_rows.iter().find(|r| &r.slug == slug) {
                        // An early field — late ones clip under a tall
                        // pending strip.
                        assert!(text.contains(&row.description), "{text}");
                    } else {
                        assert!(text.contains("No committed room is named"), "{text}");
                    }
                }
                MScreen::Account(_) => {
                    if !m.has_projection {
                        assert!(text.contains("loading"), "{text}");
                    } else if m.projected_account {
                        assert!(text.contains("earned"), "{text}");
                    } else {
                        assert!(text.contains("Owner missing"), "{text}");
                    }
                }
            }
            for p in &m.projected_pending {
                let label = match p.state {
                    PendingState::Queued => "queued",
                    PendingState::Submitted => "in flight",
                    PendingState::Committed => "committed",
                    PendingState::Collision => "collision",
                    PendingState::Rejected => "rejected",
                };
                assert!(text.contains(label), "pending {label} missing: {text}");
            }
        }
        if m.error {
            assert!(text.contains("error:"), "{text}");
        }
    }

    /// The whole invariant bundle, run after EVERY drawn step: the app
    /// agrees with the model on screen, modal, filter, selection, retained
    /// projection, error line, and quit — and renders it without panic.
    fn check(app: &App, m: &Model, src: &Fixture) {
        match (&app.view, &m.screen) {
            (View::Directory, MScreen::Directory) => {}
            (View::Room { slug }, MScreen::Room(s)) => assert_eq!(slug, s),
            (View::Account { owner }, MScreen::Account(o)) => assert_eq!(owner, o),
            (view, screen) => panic!("view {view:?} diverged from model {screen:?}"),
        }
        assert_eq!(app.filter, m.filter, "filter text diverged");
        assert_eq!(app.filter_active, m.filter_active, "filter focus diverged");
        if app.filter_active {
            assert!(
                matches!(app.view, View::Directory),
                "filter focus off the directory"
            );
        }
        match (&app.modal, &m.modal) {
            (None, None) => {}
            (Some(Modal::Create(_)), Some(MModal::Create)) => {}
            (Some(Modal::Describe { slug, .. }), Some(MModal::Describe(s))) => {
                assert_eq!(slug, s)
            }
            (Some(Modal::Archive { slug, .. }), Some(MModal::Archive(s))) => {
                assert_eq!(slug, s)
            }
            (modal, wanted) => panic!("modal {modal:?} diverged from model {wanted:?}"),
        }
        match &app.modal {
            Some(Modal::Create(_)) => assert!(
                matches!(app.view, View::Directory),
                "create modal open off the directory"
            ),
            Some(Modal::Describe { slug, .. } | Modal::Archive { slug, .. }) => assert!(
                matches!(&app.view, View::Room { slug: s } if s == slug),
                "edit modal open off its room"
            ),
            None => {}
        }
        if app.rows().is_empty() {
            assert_eq!(app.selected, 0, "phantom selection on empty rows");
        } else {
            assert!(
                app.selected < app.rows().len(),
                "selection {} out of {} projected rows",
                app.selected,
                app.rows().len()
            );
        }
        assert_eq!(app.projection.is_some(), m.has_projection);
        if let Some(p) = &app.projection {
            assert_eq!(p.rooms, m.projected_rows, "retained rows diverged");
            assert_eq!(p.pending, m.projected_pending, "pending strip diverged");
            assert_eq!(
                (p.revision, p.height),
                m.projected_meta,
                "height/revision diverged"
            );
            assert!(!p.partial);
            assert_eq!(p.account.is_some(), m.projected_account);
            assert_eq!(p.quote, m.projected_quote);
        }
        assert_eq!(app.error.is_some(), m.error, "error line diverged");
        assert!(
            app.status.is_none(),
            "the keyless fixture can never report a queued body"
        );
        assert!(
            src.submissions.is_empty(),
            "a body reached intake without signing"
        );
        assert_eq!(app.quit, m.quit);
        let text = render(app, 100, 20);
        assert_render(&text, app, m);
    }

    /// Property (a): drawn interleavings of keys, ticks, and wedges — every
    /// step leaves the screen, the modal, the filter, the selection bounds,
    /// and the retained projection exactly where the model puts them, and
    /// the frame renders that state without panic.
    #[hegel::test(test_cases = 64)]
    fn drawn_traces_never_break_the_screen_model(tc: TestCase) {
        let mut app = App::new(1_000);
        let mut src = Fixture::new();
        app.refresh(&mut src);
        let mut model = Model::new();
        model.refresh(&src);
        let steps = tc.draw(gs::integers::<usize>().max_value(39));
        for _ in 0..steps {
            match tc.draw(gs::integers::<u8>().max_value(19)) {
                // A replica tick: the world moves and the loop refreshes,
                // modal or no modal — exactly what `run` does every tick.
                14 | 15 => {
                    tick(&tc, &mut src);
                    app.refresh(&mut src);
                    model.refresh(&src);
                }
                class => {
                    let k = draw_key(&tc, class);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
            }
            check(&app, &model, &src);
            // Odd-shaped frames must not panic either — drawn small and
            // wide terminals squeeze the modal math hardest.
            if tc.draw(gs::integers::<u8>().max_value(7)) == 0 {
                let w = 16 + tc.draw(gs::integers::<u16>().max_value(120));
                let h = 4 + tc.draw(gs::integers::<u16>().max_value(28));
                let _ = render(&app, w, h);
            }
            if model.quit {
                break;
            }
        }
    }

    /// Property (b): a churn-weighted distribution — most steps are ticks
    /// that grow, shrink, archive, and re-describe the committed set while
    /// the operator moves and navigates — so the selection is hammered
    /// against the retained rows' bounds across every screen change.
    #[hegel::test(test_cases = 64)]
    fn replica_churn_never_strands_the_selection(tc: TestCase) {
        let mut app = App::new(1_000);
        let mut src = Fixture::new();
        app.refresh(&mut src);
        let mut model = Model::new();
        model.refresh(&src);
        let steps = tc.draw(gs::integers::<usize>().max_value(31));
        for _ in 0..steps {
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=4 => {
                    tick(&tc, &mut src);
                    app.refresh(&mut src);
                    model.refresh(&src);
                }
                5 | 6 => {
                    let k = key(MOVES[tc.draw(gs::integers::<usize>().max_value(MOVES.len() - 1))]);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                7 => {
                    let k = key(match tc.draw(gs::integers::<u8>().max_value(3)) {
                        0 => KeyCode::Enter,
                        1 => KeyCode::Esc,
                        _ => KeyCode::Char('a'),
                    });
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                _ => {
                    let k = key(KeyCode::Char(if tc.draw(gs::booleans()) {
                        '/'
                    } else {
                        'r'
                    }));
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
            }
            check(&app, &model, &src);
            if model.quit {
                break;
            }
        }
    }

    /// Property (c): a modal-weighted distribution — openers, form text,
    /// Tab/BackTab focus walks, Enter submits and Esc cancels — so the
    /// create/describe/archive gates open, resolve, and close under churn
    /// without ever stacking or outliving the screen that opened them.
    #[hegel::test(test_cases = 64)]
    fn modal_journeys_never_stack_or_phantom(tc: TestCase) {
        let mut app = App::new(1_000);
        let mut src = Fixture::new();
        app.refresh(&mut src);
        let mut model = Model::new();
        model.refresh(&src);
        let steps = tc.draw(gs::integers::<usize>().max_value(31));
        for _ in 0..steps {
            match tc.draw(gs::integers::<u8>().max_value(11)) {
                0 | 1 => {
                    tick(&tc, &mut src);
                    app.refresh(&mut src);
                    model.refresh(&src);
                }
                2 | 3 => {
                    let k = key(KeyCode::Char(
                        OPENERS[tc.draw(gs::integers::<usize>().max_value(OPENERS.len() - 1))],
                    ));
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                4..=6 => {
                    let k = key(KeyCode::Char(
                        TEXT[tc.draw(gs::integers::<usize>().max_value(TEXT.len() - 1))],
                    ));
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                7 => {
                    let k = key(EDITS[tc.draw(gs::integers::<usize>().max_value(EDITS.len() - 1))]);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                8 => {
                    let k = key(KeyCode::Enter);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                9 => {
                    let k = key(KeyCode::Esc);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
                _ => {
                    let k = key(MOVES[tc.draw(gs::integers::<usize>().max_value(MOVES.len() - 1))]);
                    app.key(k, &mut src);
                    model.key(&k, &src);
                }
            }
            check(&app, &model, &src);
            if model.quit {
                break;
            }
        }
    }
}
