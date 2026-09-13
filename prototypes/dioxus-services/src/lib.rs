#![forbid(unsafe_code)]
//! U1 disposable typed client boundary. Projections are inert data, never effects.
use std::{future::Future, pin::Pin};
pub use vhalla_attention::{Notification, ReadState, ReaderScope, Reason};
pub use vhalla_discovery::Filters;
pub use vhalla_discovery::{Coverage, FeedMode, Query};
pub use vhalla_social::{
    view::{Attribution, EvaluationBasis, RecordState},
    AgentId, Facet, OwnerId, Placement, PostRef, RecordId, ReplyRef,
};

mod engine;
pub use engine::{Engine, Image, MemoryStorage};
#[cfg(target_arch = "wasm32")]
pub mod browser;
#[cfg(unix)]
pub mod native;

/// Prototype operating bounds, deliberately below canonical archive maxima.
pub const MAX_SOURCE_RECORDS: usize = 128;
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ROWS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Bounds,
    Evidence,
    Stale,
    Corrupt,
    MissingSource,
    Storage,
    Clock,
}
impl From<vhalla_attention::Error> for Error {
    fn from(_: vhalla_attention::Error) -> Self {
        Self::Evidence
    }
}
impl From<vhalla_discovery::Error> for Error {
    fn from(_: vhalla_discovery::Error) -> Self {
        Self::Evidence
    }
}
impl From<vhalla_social::Error> for Error {
    fn from(_: vhalla_social::Error) -> Self {
        Self::Evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Feed(FeedMode),
    Search(Query),
    FilteredSearch { query: Query, filters: Filters },
    Thread(RecordId),
    Profile(OwnerId),
    Inbox,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Persistence {
    Ephemeral,
    Native,
    Browser,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bio {
    Empty,
    Text(String),
    Conflict(Vec<String>),
    Incomplete,
}
#[derive(Clone, Debug)]
pub struct AgentBio {
    pub owner: OwnerId,
    pub agent: AgentId,
    pub bio: Bio,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionPosition {
    Current,
    Historical,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentRevisions {
    Resolved(RecordId),
    Conflict(Vec<RecordId>),
}
/// Full evidence context for a displayed revision. Text remains in `PostRow`;
/// this context prevents authorship, repost and conflict history being flattened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostEvidence {
    pub original: Attribution,
    pub revision_signer: Attribution,
    pub revision_key: [u8; 32],
    pub position: RevisionPosition,
    pub current: CurrentRevisions,
    pub original_state: RecordState,
    pub revision_state: RecordState,
    pub placement: Placement,
    pub profile_owner: Option<OwnerId>,
    pub reply: Option<ReplyRef>,
    pub quote: Option<PostRef>,
    pub quote_attribution: Option<Attribution>,
    pub reposted_by: Vec<OwnerId>,
    pub first_observed: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct ProfileRow {
    pub owner: OwnerId,
    pub bio: Bio,
    pub agents: Vec<AgentBio>,
    pub incomplete: bool,
    pub frozen: bool,
    pub capacity_blocked: bool,
    pub roster_total: usize,
    pub next_offset: Option<usize>,
}
#[derive(Clone, Debug)]
pub struct PostRow {
    pub reference: PostRef,
    pub owner: OwnerId,
    pub agent: Option<AgentId>,
    pub root: RecordId,
    pub text: String,
    pub facets: Vec<Facet>,
    pub state: RecordState,
    pub why: [i16; 6],
    pub evidence: PostEvidence,
}
#[derive(Clone, Debug)]
pub struct InboxRow {
    pub id: [u8; 32],
    pub reason: Reason,
    pub source_owner: OwnerId,
    pub source_agent: Option<AgentId>,
    pub read: ReadState,
    pub priority: Option<ReadState>,
    pub detail: Notification,
}
/// Opaque issued local page identity. Cannot be constructed from remote bytes or a route.
/// ```compile_fail
/// use vhalla_dioxus_services_spike::Receipt;
/// let forged = Receipt { namespace: [0;32], serial: 1, image: [0;32] };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    namespace: [u8; 32],
    serial: u64,
    image: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct Projection {
    pub screen: Screen,
    pub reader: ReaderScope,
    pub posts: Vec<PostRow>,
    pub profile: Option<ProfileRow>,
    pub notifications: Vec<InboxRow>,
    /// Inbox's own capacity/history coverage, distinct from post-query coverage.
    pub inbox_coverage: Option<vhalla_attention::Coverage>,
    pub notifications_total: usize,
    pub coverage: Coverage,
    pub basis: EvaluationBasis,
    pub post_matches: usize,
    pub receipt: Receipt,
    pub persistence: Persistence,
}

/// Bounded explicit component intent, with no path, key, URL or command variant.
/// ```compile_fail
/// use vhalla_dioxus_services_spike::Intent;
/// let remote_command = Intent::execute("sign arbitrary bytes");
/// ```
#[derive(Clone, Debug)]
pub struct Intent {
    action: Action,
}
#[derive(Clone, Debug)]
enum Action {
    Ack(Receipt, Vec<[u8; 32]>),
    Seen(Receipt, PostRef),
    Mute(OwnerId, bool),
    Bookmark(Receipt, PostRef, bool),
}
impl Intent {
    pub fn acknowledge(receipt: Receipt, ids: Vec<[u8; 32]>) -> Result<Self, Error> {
        if ids.is_empty()
            || ids.len() > MAX_ROWS
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        {
            return Err(Error::Bounds);
        }
        Ok(Self {
            action: Action::Ack(receipt, ids),
        })
    }
    pub fn seen(receipt: Receipt, reference: PostRef) -> Self {
        Self {
            action: Action::Seen(receipt, reference),
        }
    }
    pub fn bookmark(receipt: Receipt, reference: PostRef, enabled: bool) -> Self {
        Self {
            action: Action::Bookmark(receipt, reference, enabled),
        }
    }
    pub fn mute_owner(owner: OwnerId, enabled: bool) -> Self {
        Self {
            action: Action::Mute(owner, enabled),
        }
    }
}

/// Launcher supplies this object to components; storage and the evaluation clock
/// are platform-owned. No generic effect execution/IPC method is exposed.
pub trait Service {
    fn project(&mut self, screen: Screen) -> Result<Projection, Error>;
    fn submit(
        &mut self,
        intent: Intent,
    ) -> Pin<Box<dyn Future<Output = Result<Projection, Error>> + '_>>;
}

/// Host-selected clock. Browser/native adapters must supply a trusted local source.
pub trait Clock {
    fn now(&self) -> Result<u64, Error>;
}

#[cfg(test)]
mod tests;
