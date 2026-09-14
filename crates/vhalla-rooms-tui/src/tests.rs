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
/// the submission journey is observable.
struct Fixture {
    rooms: Vec<RoomRow>,
    account: Option<Account>,
    pending: Vec<Pending>,
    submissions: Vec<crate::sign::Body>,
    syncs: usize,
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
        Ok(3)
    }

    fn project(&self, screen: &Screen) -> Result<Projection, Error> {
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
            revision: 3,
            height: 3,
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
