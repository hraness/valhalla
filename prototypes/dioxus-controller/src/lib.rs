#![forbid(unsafe_code)]
//! Disposable UI/controller seam. A launcher owns and serially drives each backend.
//! No filesystem, browser, key, socket, spawning, or renderer API is used here.
use std::{cell::RefCell, rc::Rc};
use vhalla_dioxus_services_spike::{
    Error, Intent, OwnerId, Persistence, PostRef, Projection, ReaderScope, Screen, Service,
    MAX_ROWS,
};

pub const MAX_READERS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reject {
    Bounds,
    Busy,
    NeedsReopen,
    StalePage,
    NotObserved,
    WrongRecoveryState,
    ReaderMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Ready,
    Busy,
    NeedsReopen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Projected,
    AppliedEphemeral,
    /// This classification relies on the trusted backend's publication contract.
    Published(Persistence),
    QueryFailed(Error),
    CanceledBeforeStart,
    /// U1's unphased error does not establish whether publication happened.
    Uncertain(Error),
    CanceledUncertain,
    InvalidProjection,
    RejectedBeforeStart(Reject),
}

/// Host-owned service binding. U1 lacks a reader accessor, so binding performs one
/// read projection and privately retains the verified service. No mutable service
/// getter is exposed. A future maintained interface should report immutable scope.
pub struct BoundBackend<S> {
    scope: ReaderScope,
    inner: S,
}
impl<S: Service> BoundBackend<S> {
    pub fn new(scope: ReaderScope, mut inner: S) -> Result<Self, Error> {
        let page = inner.project(Screen::Inbox)?;
        if !valid_projection(&page, scope, &Screen::Inbox) {
            return Err(Error::Evidence);
        }
        Ok(Self { scope, inner })
    }
}

/// Process-local exact issued-page identity, not a credential or owner approval.
#[derive(Clone, Debug)]
pub struct PageLease(Rc<()>);
impl PartialEq for PageLease {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for PageLease {}

#[derive(Clone, Debug)]
pub struct CachedPage {
    pub lease: PageLease,
    pub projection: Rc<Projection>,
}

#[derive(Clone, Debug)]
pub struct Display {
    pub reader: usize,
    pub epoch: u64,
    pub page: Option<CachedPage>,
    /// False means the old page may be displayed as stale but cannot issue writes.
    pub fresh: bool,
    pub status: Status,
    pub outcome: Option<Outcome>,
}

#[derive(Clone, Debug)]
pub enum Mutation {
    Acknowledge {
        page: PageLease,
        ids: Vec<[u8; 32]>,
    },
    Seen {
        page: PageLease,
        post: PostRef,
    },
    Bookmark {
        page: PageLease,
        post: PostRef,
        enabled: bool,
    },
    MuteOwner {
        page: PageLease,
        owner: OwnerId,
        enabled: bool,
    },
}
impl Mutation {
    fn page(&self) -> PageLease {
        match self {
            Self::Acknowledge { page, .. }
            | Self::Seen { page, .. }
            | Self::Bookmark { page, .. }
            | Self::MuteOwner { page, .. } => page.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ticket {
    reader: usize,
    serial: u64,
    view_epoch: u64,
}

struct Reader {
    scope: ReaderScope,
    page: Option<CachedPage>,
    fresh: bool,
    pending: Option<Ticket>,
    needs_reopen: bool,
    outcome: Option<Outcome>,
}
impl Reader {
    fn status(&self) -> Status {
        if self.needs_reopen {
            Status::NeedsReopen
        } else if self.pending.is_some() {
            Status::Busy
        } else {
            Status::Ready
        }
    }
}

struct State {
    readers: Vec<Reader>,
    selected: usize,
    epoch: u64,
    next_serial: u64,
}
impl State {
    fn serial(&mut self) -> Result<u64, Reject> {
        let serial = self.next_serial;
        self.next_serial = serial.checked_add(1).ok_or(Reject::Bounds)?;
        Ok(serial)
    }
    fn is_visible(&self, ticket: Ticket) -> bool {
        self.selected == ticket.reader && self.epoch == ticket.view_epoch
    }
}

/// UI-facing state handle. It stores bounded DTOs, not backend handles.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<State>>);
impl Controller {
    pub fn new(scopes: Vec<ReaderScope>) -> Result<Self, Reject> {
        if scopes.is_empty()
            || scopes.len() > MAX_READERS
            || scopes
                .iter()
                .enumerate()
                .any(|(i, s)| scopes[..i].contains(s))
        {
            return Err(Reject::Bounds);
        }
        Ok(Self(Rc::new(RefCell::new(State {
            readers: scopes
                .into_iter()
                .map(|scope| Reader {
                    scope,
                    page: None,
                    fresh: false,
                    pending: None,
                    needs_reopen: false,
                    outcome: None,
                })
                .collect(),
            selected: 0,
            epoch: 0,
            next_serial: 1,
        }))))
    }

    /// Pure cached read: rendering never invokes Service::project or issues a page.
    pub fn display(&self) -> Display {
        let state = self.0.borrow();
        let reader = &state.readers[state.selected];
        Display {
            reader: state.selected,
            epoch: state.epoch,
            page: reader.page.clone(),
            fresh: reader.fresh,
            status: reader.status(),
            outcome: reader.outcome,
        }
    }

    pub fn select(&self, reader: usize) -> Result<(), Reject> {
        let mut state = self.0.borrow_mut();
        if reader >= state.readers.len() {
            return Err(Reject::Bounds);
        }
        let epoch = state.epoch.checked_add(1).ok_or(Reject::Bounds)?;
        state.selected = reader;
        state.epoch = epoch;
        state.readers[reader].fresh = false;
        Ok(())
    }

    pub fn project(&self, screen: Screen) -> Result<Operation, Reject> {
        // A route/refresh request invalidates the presentation epoch even when
        // backpressure refuses the query. A pending old-screen mutation still
        // finishes, but its completion must not replace this requested view.
        {
            let mut state = self.0.borrow_mut();
            state.epoch = state.epoch.checked_add(1).ok_or(Reject::Bounds)?;
            let selected = state.selected;
            state.readers[selected].fresh = false;
        }
        self.reserve(screen, None)
    }

    /// Checks exact displayed membership before calling any backend. A refusal is
    /// definitely rejected locally; it does not assert anything about other writers.
    pub fn mutate(&self, mutation: Mutation) -> Result<Operation, Reject> {
        let (screen, intent) = {
            let state = self.0.borrow();
            let reader = &state.readers[state.selected];
            check_ready(reader)?;
            let cached = reader.page.as_ref().ok_or(Reject::StalePage)?;
            if !reader.fresh || cached.lease != mutation.page() {
                return Err(Reject::StalePage);
            }
            let page = &cached.projection;
            let intent = match mutation {
                Mutation::Acknowledge { ids, .. } => {
                    if ids.is_empty() || ids.len() > MAX_ROWS {
                        return Err(Reject::Bounds);
                    }
                    if ids
                        .iter()
                        .any(|id| !page.notifications.iter().any(|n| n.id == *id))
                    {
                        return Err(Reject::NotObserved);
                    }
                    Intent::acknowledge(page.receipt, ids).map_err(|_| Reject::Bounds)?
                }
                Mutation::Seen { post, .. } => {
                    observed(page, post)?;
                    Intent::seen(page.receipt, post)
                }
                Mutation::Bookmark { post, enabled, .. } => {
                    observed(page, post)?;
                    Intent::bookmark(page.receipt, post, enabled)
                }
                Mutation::MuteOwner { owner, enabled, .. } => Intent::mute_owner(owner, enabled),
            };
            (page.screen.clone(), intent)
        };
        self.reserve(screen, Some(intent))
    }

    fn reserve(&self, screen: Screen, intent: Option<Intent>) -> Result<Operation, Reject> {
        let mut state = self.0.borrow_mut();
        let reader = state.selected;
        check_ready(&state.readers[reader])?;
        let ticket = Ticket {
            reader,
            serial: state.serial()?,
            view_epoch: state.epoch,
        };
        state.readers[reader].pending = Some(ticket);
        Ok(Operation {
            state: self.0.clone(),
            ticket,
            screen,
            mutation: intent.is_some(),
            intent,
            started: false,
            finished: false,
        })
    }

    /// Host-only seam: the launcher must reconcile storage and supply its reopened
    /// backend. Merely producing a DTO or clearing a flag cannot establish recovery.
    /// U1 has no recovery API; this call only verifies its reopened query succeeds.
    pub fn attach_reopened<S: Service>(
        &self,
        reader: usize,
        backend: &mut BoundBackend<S>,
        screen: Screen,
    ) -> Result<(), Reject> {
        {
            let state = self.0.borrow();
            let slot = state.readers.get(reader).ok_or(Reject::Bounds)?;
            if !slot.needs_reopen || slot.pending.is_some() {
                return Err(Reject::WrongRecoveryState);
            }
            if backend.scope != slot.scope {
                return Err(Reject::ReaderMismatch);
            }
        }
        let result = backend.inner.project(screen.clone());
        let mut state = self.0.borrow_mut();
        let slot = &state.readers[reader];
        let page = result.map_err(|_| Reject::NeedsReopen)?;
        if !valid_projection(&page, slot.scope, &screen) {
            return Err(Reject::NeedsReopen);
        }
        let slot = &mut state.readers[reader];
        slot.page = Some(CachedPage {
            lease: PageLease(Rc::new(())),
            projection: Rc::new(page),
        });
        slot.fresh = true;
        slot.needs_reopen = false;
        slot.outcome = Some(Outcome::Projected);
        Ok(())
    }
}

fn observed(page: &Projection, post: PostRef) -> Result<(), Reject> {
    if page.posts.iter().any(|p| p.reference == post) {
        Ok(())
    } else {
        Err(Reject::NotObserved)
    }
}
fn check_ready(reader: &Reader) -> Result<(), Reject> {
    match reader.status() {
        Status::Ready => Ok(()),
        Status::Busy => Err(Reject::Busy),
        Status::NeedsReopen => Err(Reject::NeedsReopen),
    }
}
fn valid_projection(page: &Projection, scope: ReaderScope, screen: &Screen) -> bool {
    page.reader == scope
        && page.screen == *screen
        && page.posts.len() <= MAX_ROWS
        && page.notifications.len() <= MAX_ROWS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub reader: usize,
    pub current_view: bool,
    pub outcome: Outcome,
}

/// One bounded operation, driven by the launcher with that reader's owned backend.
/// There is no implicit queue and no automatic retry. Dropping this guard records
/// whether the backend could already have published a private change.
pub struct Operation {
    state: Rc<RefCell<State>>,
    ticket: Ticket,
    screen: Screen,
    intent: Option<Intent>,
    mutation: bool,
    started: bool,
    finished: bool,
}
impl Operation {
    pub fn reader(&self) -> usize {
        self.ticket.reader
    }

    pub async fn run<S: Service>(mut self, backend: &mut BoundBackend<S>) -> Completion {
        {
            let mut state = self.state.borrow_mut();
            if backend.scope != state.readers[self.ticket.reader].scope {
                let visible = state.is_visible(self.ticket);
                let slot = &mut state.readers[self.ticket.reader];
                slot.pending = None;
                let outcome = Outcome::RejectedBeforeStart(Reject::ReaderMismatch);
                if visible {
                    slot.outcome = Some(outcome);
                }
                self.finished = true;
                return Completion {
                    reader: self.ticket.reader,
                    current_view: visible,
                    outcome,
                };
            }
        }
        self.started = true;
        let mutation = self.mutation;
        let result = if let Some(intent) = self.intent.take() {
            backend.inner.submit(intent).await
        } else {
            backend.inner.project(self.screen.clone())
        };
        let mut state = self.state.borrow_mut();
        let visible = state.is_visible(self.ticket);
        let slot = &mut state.readers[self.ticket.reader];
        // One guard owns this ticket; reopening cannot occur while it is pending.
        assert_eq!(slot.pending, Some(self.ticket));
        let outcome = match result {
            Ok(page) if valid_projection(&page, slot.scope, &self.screen) => {
                let outcome = if !mutation {
                    Outcome::Projected
                } else if page.persistence == Persistence::Ephemeral {
                    Outcome::AppliedEphemeral
                } else {
                    Outcome::Published(page.persistence)
                };
                if visible {
                    slot.page = Some(CachedPage {
                        lease: PageLease(Rc::new(())),
                        projection: Rc::new(page),
                    });
                    slot.fresh = true;
                } else {
                    // Hidden completions update operation state but never replace
                    // a visible page after A→B or A→B→A. Requery before new writes.
                    slot.fresh = false;
                }
                outcome
            }
            Ok(_) => {
                slot.fresh = false;
                slot.needs_reopen = mutation;
                Outcome::InvalidProjection
            }
            Err(error) if mutation => {
                slot.fresh = false;
                slot.needs_reopen = true;
                Outcome::Uncertain(error)
            }
            Err(error) => Outcome::QueryFailed(error),
        };
        slot.pending = None;
        // A stale operation never replaces the newly selected view's status text.
        if visible {
            slot.outcome = Some(outcome);
        }
        self.finished = true;
        Completion {
            reader: self.ticket.reader,
            current_view: visible,
            outcome,
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut state = self.state.borrow_mut();
        let visible = state.is_visible(self.ticket);
        let slot = &mut state.readers[self.ticket.reader];
        if slot.pending != Some(self.ticket) {
            return;
        }
        slot.pending = None;
        if self.started && self.mutation {
            slot.needs_reopen = true;
            slot.fresh = false;
            if visible {
                slot.outcome = Some(Outcome::CanceledUncertain);
            }
        } else if visible {
            slot.outcome = Some(Outcome::CanceledBeforeStart);
        }
    }
}

#[cfg(test)]
mod tests;
