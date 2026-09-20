//! Terminal companion for the room directory.
//!
//! The crate follows an Elm-style split: [`App`] is a pure model, key
//! events fold through [`App::key`], and [`view`] renders the model. The
//! [`Source`] trait mirrors the `vhalla-rooms-app` service boundary —
//! committed projections plus a keyless canonical-byte submission drop —
//! so the model is fully testable without a terminal. Terminal setup and
//! identity custody are unix-only ([`run`], [`sign`]); signing happens in
//! the CLI's own trust domain, never inside the service.

mod view;

#[cfg(unix)]
mod run;
/// In-process signing assembly for the operator trust domain — shared by
/// the interactive forms and the `rooms submit` command.
#[cfg(unix)]
pub mod sign;

#[cfg(unix)]
pub use run::run;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use vhalla_rooms_app::{CreateContext, Error, Pending, Projection, RoomRow, Screen, UpdateContext};
use vhalla_social::OwnerId;

/// The replica boundary the model drives — the same contract the
/// Dioxus spike defined, so renderers stay interchangeable.
pub trait Source {
    /// Absorbs newly committed journal bundles; returns the height reached.
    fn sync(&mut self) -> Result<u64, Error>;
    /// Renders the committed projection for `screen`.
    fn project(&self, screen: &Screen) -> Result<Projection, Error>;
    /// Local submission markers with their current resolutions.
    fn pending(&self) -> Result<Vec<Pending>, Error>;
    /// Drops canonical signed evidence and record bytes into the node's
    /// intake. The service never sees keys; the caller signs.
    fn submit(
        &mut self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error>;
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

#[cfg(unix)]
impl Source for vhalla_rooms_app::Service {
    fn sync(&mut self) -> Result<u64, Error> {
        self.sync()
    }

    fn project(&self, screen: &Screen) -> Result<Projection, Error> {
        self.project(screen)
    }

    fn pending(&self) -> Result<Vec<Pending>, Error> {
        self.pending()
    }

    fn submit(
        &mut self,
        time: u64,
        evidence: Vec<Vec<u8>>,
        records: Vec<Vec<u8>>,
    ) -> Result<String, Error> {
        self.submit_body(time, evidence, records)
    }

    fn create_context(
        &self,
        owner: OwnerId,
        key: [u8; 32],
        now: u64,
    ) -> Result<CreateContext, Error> {
        self.create_context(owner, key, now)
    }

    fn update_context(&self, slug: &str, key: [u8; 32], now: u64) -> Result<UpdateContext, Error> {
        self.update_context(slug, key, now)
    }
}

/// The live view — a single screen at a time with `b`/`Esc` walking back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum View {
    /// The directory list, filtered by `App::filter`.
    Directory,
    /// One room's committed fields.
    Room {
        /// The slug being inspected.
        slug: String,
    },
    /// One owner's account.
    Account {
        /// The owner under inspection, hex.
        owner: String,
    },
}

/// A labelled single-line text field in a modal form.
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
    /// Ordered fields; `Tab`/`Shift-Tab` walk them.
    pub fields: Vec<Field>,
    /// Focused field index.
    pub focus: usize,
}

impl Form {
    fn focused(&mut self) -> Option<&mut Field> {
        self.fields.get_mut(self.focus)
    }

    fn get(&self, index: usize) -> &str {
        self.fields
            .get(index)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }
}

/// A modal layered over the current view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modal {
    /// Room-creation form; signs in-process at submit.
    Create(Form),
    /// Re-describe form for one committed room.
    Describe {
        /// The room being edited.
        slug: String,
        /// The form fields.
        form: Form,
    },
    /// Confirmation gate before an archive update is signed.
    Archive {
        /// The room being archived.
        slug: String,
        /// Owner identity path field.
        key: String,
    },
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

/// The complete UI model — one replica cursor plus interaction state.
#[derive(Clone, Debug)]
pub struct App {
    /// The screen on top.
    pub view: View,
    /// The open modal, when one is open.
    pub modal: Option<Modal>,
    /// The live filter text for the directory.
    pub filter: String,
    /// Whether the filter line holds key focus.
    pub filter_active: bool,
    /// Selected row in the directory list.
    pub selected: usize,
    /// The committed projection for `view` at the last refresh.
    pub projection: Option<Projection>,
    /// The agreed clock, refreshed by the run loop each tick.
    pub now: u64,
    /// One-line status (submission results, hints).
    pub status: Option<String>,
    /// One-line error (last operation's failure).
    pub error: Option<String>,
    /// Whether the run loop should exit.
    pub quit: bool,
}

impl App {
    /// A directory view at genesis.
    pub fn new(now: u64) -> Self {
        Self {
            view: View::Directory,
            modal: None,
            filter: String::new(),
            filter_active: false,
            selected: 0,
            projection: None,
            now,
            status: None,
            error: None,
            quit: false,
        }
    }

    /// The `Screen` the current view projects.
    fn screen(&self) -> Screen {
        match &self.view {
            View::Directory => Screen::Directory {
                query: self.filter.clone(),
            },
            View::Room { slug } => Screen::Room { slug: slug.clone() },
            View::Account { owner } => Screen::Account {
                owner: OwnerId::from_bytes(hex32(owner).unwrap_or([0; 32])),
            },
        }
    }

    /// Pulls committed state into the model: sync, project, clamp the
    /// selection. Called on every tick and after every submission.
    pub fn refresh(&mut self, src: &mut dyn Source) {
        if let Err(e) = src.sync() {
            self.error = Some(format!("sync: {e}"));
        }
        match src.project(&self.screen()) {
            Ok(p) => {
                self.projection = Some(p);
                let rows = self.projection.as_ref().map(|p| p.rooms.len()).unwrap_or(0);
                if rows == 0 {
                    self.selected = 0;
                } else if self.selected >= rows {
                    self.selected = rows - 1;
                }
            }
            Err(e) => self.error = Some(format!("project: {e}")),
        }
    }

    /// The directory rows the current projection carries (empty
    /// elsewhere).
    pub fn rows(&self) -> &[RoomRow] {
        self.projection
            .as_ref()
            .map(|p| p.rooms.as_slice())
            .unwrap_or(&[])
    }

    /// The pending strip's entries.
    pub fn pending(&self) -> &[Pending] {
        self.projection
            .as_ref()
            .map(|p| p.pending.as_slice())
            .unwrap_or(&[])
    }

    /// Folds one key event into the model. Returns immediately when a
    /// modal or the filter line consumed the key.
    pub fn key(&mut self, key: KeyEvent, src: &mut dyn Source) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        self.status = None;
        self.error = None;
        if self.modal.is_some() {
            self.modal_key(key, src);
            return;
        }
        if self.filter_active {
            self.filter_key(key, src);
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if matches!(self.view, View::Directory) {
                    self.quit = true;
                } else {
                    self.view = View::Directory;
                    self.refresh(src);
                }
            }
            KeyCode::Char('/') => {
                if matches!(self.view, View::Directory) {
                    self.filter_active = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                let rows = self.rows().len();
                if rows > 0 && self.selected + 1 < rows {
                    self.selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if matches!(self.view, View::Directory) {
                    if let Some(row) = self.rows().get(self.selected) {
                        let slug = row.slug.clone();
                        self.view = View::Room { slug };
                        self.refresh(src);
                    }
                }
            }
            KeyCode::Char('n') => {
                if matches!(self.view, View::Directory) {
                    self.modal = Some(Modal::Create(form("create a room", &CREATE_LABELS)));
                }
            }
            KeyCode::Char('d') => {
                if let View::Room { slug } = &self.view {
                    let mut f = form("describe room", &DESCRIBE_LABELS);
                    if let Some(row) = self.rows().iter().find(|r| &r.slug == slug) {
                        f.fields[0].value = row.description.clone();
                    }
                    self.modal = Some(Modal::Describe {
                        slug: slug.clone(),
                        form: f,
                    });
                }
            }
            KeyCode::Char('x') => {
                if let View::Room { slug } = &self.view {
                    self.modal = Some(Modal::Archive {
                        slug: slug.clone(),
                        key: String::new(),
                    });
                }
            }
            KeyCode::Char('o') => {
                if let View::Room { slug } = &self.view {
                    if let Some(row) = self.rows().iter().find(|r| &r.slug == slug) {
                        let owner = row.owner.clone();
                        self.view = View::Account { owner };
                        self.refresh(src);
                    }
                }
            }
            KeyCode::Char('a') => {
                if let Some(row) = self.rows().get(self.selected) {
                    let owner = row.owner.clone();
                    self.view = View::Account { owner };
                    self.refresh(src);
                }
            }
            KeyCode::Char('r') => self.refresh(src),
            _ => {}
        }
    }

    /// Keys while a modal holds focus. The modal is taken out first so
    /// submission paths can re-borrow `self`; keys that keep editing put
    /// it back.
    fn modal_key(&mut self, key: KeyEvent, src: &mut dyn Source) {
        let Some(modal) = self.modal.take() else {
            return;
        };
        if key.code == KeyCode::Esc {
            return;
        }
        match modal {
            Modal::Create(mut f) => {
                if Self::form_keys(&mut f, &key) {
                    self.submit_create(&f, src);
                } else {
                    self.modal = Some(Modal::Create(f));
                }
            }
            Modal::Describe { slug, mut form } => {
                if Self::form_keys(&mut form, &key) {
                    self.submit_describe(&slug, &form, src);
                } else {
                    self.modal = Some(Modal::Describe { slug, form });
                }
            }
            Modal::Archive {
                slug,
                key: mut field,
            } => match key.code {
                KeyCode::Enter => self.submit_archive(&slug, &field, src),
                KeyCode::Char(c) => {
                    field.push(c);
                    self.modal = Some(Modal::Archive { slug, key: field });
                }
                KeyCode::Backspace => {
                    field.pop();
                    self.modal = Some(Modal::Archive { slug, key: field });
                }
                _ => self.modal = Some(Modal::Archive { slug, key: field }),
            },
        }
    }

    /// Shared form editing — returns true when Enter submits.
    fn form_keys(f: &mut Form, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Tab | KeyCode::Down => f.focus = (f.focus + 1) % f.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                f.focus = (f.focus + f.fields.len() - 1) % f.fields.len();
            }
            KeyCode::Char(c) => {
                if let Some(field) = f.focused() {
                    field.value.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(field) = f.focused() {
                    field.value.pop();
                }
            }
            KeyCode::Enter => return true,
            _ => {}
        }
        false
    }

    /// Keys while the filter line holds focus. Each edit re-projects so
    /// the list narrows as the operator types.
    fn filter_key(&mut self, key: KeyEvent, src: &mut dyn Source) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => self.filter_active = false,
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.selected = 0;
                self.refresh(src);
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.selected = 0;
                self.refresh(src);
            }
            _ => {}
        }
    }

    /// Signs and submits the create form. Unix-only: key custody never
    /// crosses into the portable model.
    #[cfg(unix)]
    fn submit_create(&mut self, f: &Form, src: &mut dyn Source) {
        match sign::create_body(f, self.now, src) {
            Ok((evidence, records)) => self.submit(src, evidence, records),
            Err(e) => self.error = Some(e),
        }
    }

    /// Signs and submits a describe update.
    #[cfg(unix)]
    fn submit_describe(&mut self, slug: &str, f: &Form, src: &mut dyn Source) {
        match sign::describe_body(slug, f, self.now, src) {
            Ok(record) => self.submit(src, Vec::new(), vec![record]),
            Err(e) => self.error = Some(e),
        }
    }

    /// Signs and submits an archive update.
    #[cfg(unix)]
    fn submit_archive(&mut self, slug: &str, key_path: &str, src: &mut dyn Source) {
        match sign::archive_body(slug, key_path, self.now, src) {
            Ok(record) => self.submit(src, Vec::new(), vec![record]),
            Err(e) => self.error = Some(e),
        }
    }

    #[cfg(not(unix))]
    fn submit_create(&mut self, _f: &Form, _src: &mut dyn Source) {
        self.error = Some("signing requires a unix host".into());
    }

    #[cfg(not(unix))]
    fn submit_describe(&mut self, _slug: &str, _f: &Form, _src: &mut dyn Source) {
        self.error = Some("signing requires a unix host".into());
    }

    #[cfg(not(unix))]
    fn submit_archive(&mut self, _slug: &str, _key: &str, _src: &mut dyn Source) {
        self.error = Some("signing requires a unix host".into());
    }

    /// The shared intake drop: submit, then refresh so the new marker
    /// shows immediately.
    fn submit(&mut self, src: &mut dyn Source, evidence: Vec<Vec<u8>>, records: Vec<Vec<u8>>) {
        match src.submit(self.now, evidence, records) {
            Ok(name) => {
                let short = name.chars().take(12).collect::<String>();
                self.status = Some(format!("queued {short}"));
                self.refresh(src);
            }
            Err(e) => self.error = Some(format!("submit: {e}")),
        }
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

#[cfg(test)]
mod tests;
