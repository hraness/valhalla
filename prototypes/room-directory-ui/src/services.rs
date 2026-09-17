//! The UI↔service boundary. Screens only ever see `vhalla_rooms_app`
//! projections — no registry, journal, key or consensus type crosses.
use vhalla_rooms_app::{Error, Pending, Projection, RoomRow, Screen};

/// The renderer-facing service contract: project a screen, list local
/// submission markers, and drop a signed body into the node's intake.
/// Signing stays outside — `submit` takes canonical signed record bytes.
pub trait RoomServices {
    /// The projection for one screen against committed replica state.
    fn project(&self, screen: &Screen) -> Result<Projection, Error>;
    /// Local submission markers with their committed-state resolutions.
    fn pending(&self) -> Result<Vec<Pending>, Error>;
    /// Drops a `BatchBody` into the node's intake; returns the marker
    /// name (the effect record's hex id). `records` are canonical
    /// signed record bytes produced by the caller's signing path.
    fn submit(
        &self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error>;
}

/// The real service adapter: a `vhalla_rooms_app::Service` replica over
/// a running node. `sync` runs inside `project` so every screen reflects
/// the newest committed bundles.
#[cfg(unix)]
pub struct NodeServices(std::cell::RefCell<vhalla_rooms_app::Service>);

#[cfg(unix)]
impl NodeServices {
    /// Wraps an open replica service.
    pub fn new(service: vhalla_rooms_app::Service) -> Self {
        Self(std::cell::RefCell::new(service))
    }
}

#[cfg(unix)]
impl RoomServices for NodeServices {
    fn project(&self, screen: &Screen) -> Result<Projection, Error> {
        let mut service = self.0.try_borrow_mut().map_err(|_| Error::Bounds)?;
        let _ = service.sync()?;
        service.project(screen)
    }
    fn pending(&self) -> Result<Vec<Pending>, Error> {
        self.0.try_borrow().map_err(|_| Error::Bounds)?.pending()
    }
    fn submit(
        &self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Bounds)?
            .submit_body(time, evidence, records)
    }
}

/// A fabricated in-session fixture — the demonstration corpus plus
/// pending markers covering every resolution state. Deliberately
/// ephemeral: nothing crosses a process or signing boundary.
pub struct FixtureServices(std::cell::RefCell<FixtureState>);

/// Mutable fixture state: projected rooms and local submission markers.
pub struct FixtureState {
    /// The committed rooms the fixture projects.
    pub rooms: Vec<RoomRow>,
    /// Pending markers in each resolution state.
    pub pending: Vec<Pending>,
    /// Next fabricated marker counter.
    pub counter: u64,
}

impl Default for FixtureServices {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureServices {
    /// The demonstration corpus.
    pub fn new() -> Self {
        Self(std::cell::RefCell::new(FixtureState {
            rooms: vec![
                RoomRow {
                    slug: "parlor".into(),
                    owner: hex(&[1; 32]),
                    agent: hex(&[2; 32]),
                    description: "The standing room for open design review.".into(),
                    slot: 1,
                    charge: 4,
                    archived: false,
                    record: hex(&[0xA1; 32]),
                    head: hex(&[0xA1; 32]),
                    revisions: 0,
                    created_at: 1_755_000_000,
                },
                RoomRow {
                    slug: "signal-desk".into(),
                    owner: hex(&[3; 32]),
                    agent: hex(&[4; 32]),
                    description: "Weekly sync notes and decision log.".into(),
                    slot: 2,
                    charge: 16,
                    archived: false,
                    record: hex(&[0xB2; 32]),
                    head: hex(&[0xB2; 32]),
                    revisions: 2,
                    created_at: 1_755_100_000,
                },
                RoomRow {
                    slug: "cold-store".into(),
                    owner: hex(&[5; 32]),
                    agent: hex(&[6; 32]),
                    description: "Archived project records, kept for reference.".into(),
                    slot: 1,
                    charge: 4,
                    archived: true,
                    record: hex(&[0xC3; 32]),
                    head: hex(&[0xC3; 32]),
                    revisions: 1,
                    created_at: 1_754_000_000,
                },
            ],
            pending: vec![
                Pending {
                    name: hex(&[0xD4; 32]),
                    slug: Some("reading-room".into()),
                    state: vhalla_rooms_app::PendingState::Queued,
                    reason: None,
                },
                Pending {
                    name: hex(&[0xE5; 32]),
                    slug: Some("ledger-nook".into()),
                    state: vhalla_rooms_app::PendingState::Submitted,
                    reason: None,
                },
                Pending {
                    name: hex(&[0xF6; 32]),
                    slug: Some("parlor".into()),
                    state: vhalla_rooms_app::PendingState::Collision,
                    reason: None,
                },
            ],
            counter: 1,
        }))
    }
}

impl RoomServices for FixtureServices {
    fn project(&self, screen: &Screen) -> Result<Projection, Error> {
        let state = self.0.try_borrow().map_err(|_| Error::Bounds)?;
        let mut projection = Projection {
            rooms: Vec::new(),
            account: None,
            quote: Some((3, 36)),
            partial: false,
            revision: 4,
            height: 12,
            pending: state.pending.clone(),
        };
        match screen {
            Screen::Directory { query } => {
                let terms: Vec<String> = query
                    .split_ascii_whitespace()
                    .map(|t| t.to_ascii_lowercase())
                    .collect();
                projection.rooms = state
                    .rooms
                    .iter()
                    .filter(|r| !r.archived)
                    .filter(|r| {
                        terms.iter().all(|t| {
                            r.slug.to_ascii_lowercase().contains(t.as_str())
                                || r.description.to_ascii_lowercase().contains(t.as_str())
                        })
                    })
                    .cloned()
                    .collect();
            }
            Screen::Room { slug } => {
                if let Some(room) = state.rooms.iter().find(|r| r.slug == *slug) {
                    projection.rooms.push(room.clone());
                }
            }
            Screen::Account { owner } => {
                projection.account = Some(vhalla_rooms::registry::Account {
                    earned: 60,
                    spent: 20,
                    lifetime_slots: 3,
                });
                let _ = owner;
            }
        }
        Ok(projection)
    }
    fn pending(&self) -> Result<Vec<Pending>, Error> {
        Ok(self
            .0
            .try_borrow()
            .map_err(|_| Error::Bounds)?
            .pending
            .clone())
    }
    fn submit(
        &self,
        _time: u64,
        _evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error> {
        let mut state = self.0.try_borrow_mut().map_err(|_| Error::Bounds)?;
        let name = format!("{:064x}", state.counter);
        state.counter += 1;
        // A real body carries signed record bytes; the fixture fabricates
        // `b"room-create:<slug>"` and reads the slug back for the marker.
        let slug = records
            .first()
            .and_then(|r| r.strip_prefix(b"room-create:"))
            .and_then(|s| String::from_utf8(s.to_vec()).ok())
            .filter(|s| !s.is_empty());
        state.pending.push(Pending {
            name: name.clone(),
            slug,
            state: vhalla_rooms_app::PendingState::Queued,
            reason: None,
        });
        Ok(name)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
