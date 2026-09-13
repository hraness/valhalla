//! Explicit local discovery controls. Foreign content never invokes these commands.
use super::*;
use vhalla_attention::{AttentionPolicy, ReaderScope};
use vhalla_core::RoomId;
use vhalla_discovery::{Change, DiscoveryState, Subscription};
use vhalla_discovery_store::{PrivateState, Store as PrivateStore};

pub const HELP: &str = "Private discovery (same social STORE REALM prefix):
  reader-init | reader-show | reader-observe | reader-recover
  reader-set subscribe|unsubscribe owner:ID|agent:ID|channel:ROOM32|tag:TAG|thread:ID
  reader-set mute|unmute|block|unblock OWNER64
  reader-set watch|unwatch|mute-thread|unmute-thread ROOT64
  reader-set bookmark|unbookmark POST64 REV64
  reader-set more|less TAG | reader-set clear-interests
  reader-set save-search NAME QUERY | reader-set remove-search NAME
  reader-set wider on|off | reader-seen POST64 REV64
  reader-feedback POST64 REV64 up|down|clear
  feed following|discover | search QUERY | search-saved NAME | boards | directory
  notifications | notifications-ack EXACT_UPDATE_CSV
All require --private PATH --reader owner:OWNER64|agent:AGENT64.
Optional --profile-id ID64 --device-id ID64 default to this local default namespace.
Queries: --live on|off --owner ID64 --agent ID64 --channel ROOM32 --root ID64
--tag TAG --mentions owner:ID64|agent:ID64 --kind post|reply|repost
--state committed|provisional (provisional also requires --live on)
--unread on|off (notifications). Paging keeps --offset/--limit.
Querying never marks read. Acknowledge only exact IDs returned by notifications.
Private state is excluded from social export. Search coverage is local and bounded.";

#[derive(Default)]
pub(super) struct Options {
    used: bool,
    private: Option<String>,
    reader: Option<String>,
    profile: Option<[u8; 32]>,
    device: Option<[u8; 32]>,
    live: Option<bool>,
    owner: Option<OwnerId>,
    agent: Option<AgentId>,
    channel: Option<RoomId>,
    root: Option<RecordId>,
    pub(super) tag: Option<String>,
    mention: Option<MentionTarget>,
    kind: Option<String>,
    state: Option<RecordState>,
    unread: Option<bool>,
}
impl Options {
    pub(super) fn flag(&mut self, name: &str, value: &str) -> Result<bool, String> {
        match name {
            "--private" => set(&mut self.private, value.to_owned())?,
            "--reader" => set(&mut self.reader, value.to_owned())?,
            "--profile-id" => set(&mut self.profile, hex32(value)?)?,
            "--device-id" => set(&mut self.device, hex32(value)?)?,
            "--live" => set(&mut self.live, on_off(value)?)?,
            "--owner" => set(&mut self.owner, oid(value)?)?,
            "--agent" => set(&mut self.agent, aid(value)?)?,
            "--channel" => set(&mut self.channel, RoomId(hex128(value)?))?,
            "--root" => set(&mut self.root, rid(value)?)?,
            "--mentions" => set(&mut self.mention, target(value)?)?,
            "--kind" => {
                if !matches!(value, "post" | "reply" | "repost") {
                    return Err("kind must be post, reply or repost".into());
                }
                set(&mut self.kind, value.to_owned())?;
            }
            "--unread" => set(&mut self.unread, on_off(value)?)?,
            "--state" => set(
                &mut self.state,
                match value {
                    "committed" => RecordState::Committed,
                    "provisional" => RecordState::Provisional,
                    _ => return Err("search state must be committed or provisional".into()),
                },
            )?,
            _ => return Ok(false),
        }
        self.used = true;
        Ok(true)
    }
    pub(super) fn validate(&self, command: &str) -> Result<(), String> {
        if !handles(command) && (self.used || self.tag.is_some()) {
            return Err("discovery options require a discovery command".into());
        }
        let filter = self.owner.is_some()
            || self.agent.is_some()
            || self.channel.is_some()
            || self.root.is_some()
            || self.tag.is_some()
            || self.mention.is_some()
            || self.kind.is_some()
            || self.state.is_some();
        if filter && !matches!(command, "feed" | "search" | "search-saved") {
            return Err("search filters require feed or search".into());
        }
        if self.unread.is_some() && command != "notifications" {
            return Err("--unread applies to notifications only".into());
        }
        if self.live.is_some()
            && !matches!(
                command,
                "feed"
                    | "search"
                    | "search-saved"
                    | "boards"
                    | "directory"
                    | "notifications"
                    | "notifications-ack"
            )
        {
            return Err(
                "--live applies to discovery queries and exact notification acknowledgements"
                    .into(),
            );
        }
        Ok(())
    }
    fn scope(&self, args: &Args, archive: &Archive) -> Result<ReaderScope, String> {
        let (owner, agent) = match target(self.reader.as_deref().ok_or("--reader is required")?)? {
            MentionTarget::Owner(owner) => (owner, None),
            MentionTarget::Agent(agent) => (
                args.view(archive)
                    .agent_owner(agent)
                    .ok_or("reader agent has no verified historical owner")?,
                Some(agent),
            ),
        };
        ReaderScope::new(
            archive,
            args.now,
            owner,
            agent,
            self.profile.unwrap_or([0; 32]),
            self.device.unwrap_or([0; 32]),
        )
        .map_err(|e| format!("reader scope: {e:?}"))
    }
    fn path(&self) -> Result<&str, String> {
        self.private
            .as_deref()
            .ok_or_else(|| "--private is required".into())
    }
}
fn on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err("value must be on or off".into()),
    }
}
fn target(value: &str) -> Result<MentionTarget, String> {
    let (kind, id) = value
        .split_once(':')
        .ok_or("expected owner:ID or agent:ID")?;
    match kind {
        "owner" => Ok(MentionTarget::Owner(oid(id)?)),
        "agent" => Ok(MentionTarget::Agent(aid(id)?)),
        _ => Err("expected owner:ID or agent:ID".into()),
    }
}
pub(super) fn handles(command: &str) -> bool {
    matches!(
        command,
        "reader-init"
            | "reader-show"
            | "reader-observe"
            | "reader-recover"
            | "reader-set"
            | "reader-seen"
            | "reader-feedback"
            | "feed"
            | "search"
            | "search-saved"
            | "boards"
            | "directory"
            | "notifications"
            | "notifications-ack"
    )
}

fn subscription(value: &str) -> Result<Subscription, String> {
    let (kind, id) = value
        .split_once(':')
        .ok_or("subscription needs a typed ID")?;
    match kind {
        "owner" => Ok(Subscription::Owner(oid(id)?)),
        "agent" => Ok(Subscription::Agent(aid(id)?)),
        "channel" => Ok(Subscription::Channel(RoomId(hex128(id)?))),
        "thread" => Ok(Subscription::Thread(rid(id)?)),
        "tag" => Ok(Subscription::Tag(
            CanonicalTag::new(id)
                .map_err(social_error)?
                .as_str()
                .to_owned(),
        )),
        _ => Err("unknown subscription kind".into()),
    }
}
fn preference_change(args: &Args) -> Result<Change, String> {
    let action = args.get(0)?;
    let change = match action {
        "subscribe" | "unsubscribe" => {
            args.count(2)?;
            Change::Subscribe(subscription(args.get(1)?)?, action == "subscribe")
        }
        "mute" | "unmute" => {
            args.count(2)?;
            Change::MuteOwner(oid(args.get(1)?)?, action == "mute")
        }
        "block" | "unblock" => {
            args.count(2)?;
            Change::BlockOwner(oid(args.get(1)?)?, action == "block")
        }
        "watch" | "unwatch" => {
            args.count(2)?;
            Change::Subscribe(Subscription::Thread(rid(args.get(1)?)?), action == "watch")
        }
        "mute-thread" | "unmute-thread" => {
            args.count(2)?;
            Change::MuteThread(rid(args.get(1)?)?, action == "mute-thread")
        }
        "bookmark" | "unbookmark" => {
            args.count(3)?;
            Change::Bookmark(
                PostRef {
                    post: rid(args.get(1)?)?,
                    revision: rid(args.get(2)?)?,
                },
                action == "bookmark",
            )
        }
        "more" | "less" => {
            args.count(2)?;
            Change::Interest {
                tag: CanonicalTag::new(args.get(1)?)
                    .map_err(social_error)?
                    .as_str()
                    .to_owned(),
                delta: if action == "more" { 1 } else { -1 },
            }
        }
        "clear-interests" => {
            args.count(1)?;
            Change::ClearInterests
        }
        "save-search" => {
            args.count(3)?;
            Change::SaveSearch {
                name: args.get(1)?.to_owned(),
                query: args.get(2)?.to_owned(),
            }
        }
        "remove-search" => {
            args.count(2)?;
            Change::RemoveSearch(args.get(1)?.to_owned())
        }
        "wider" => {
            args.count(2)?;
            Change::Wider(on_off(args.get(1)?)?)
        }
        _ => return Err("unknown reader preference action".into()),
    };
    Ok(change)
}

fn preferences(state: &DiscoveryState) -> String {
    let p = state.preferences();
    json::object(vec![
        ("reader", json::id(state.reader())),
        ("generation", state.generation().to_string()),
        ("observation_cutoff", state.cutoff().to_string()),
        (
            "subscriptions",
            json::array(p.subscriptions().iter().map(|value| {
                json::string(&match value {
                    Subscription::Owner(id) => format!("owner:{}", json::hex(id.as_bytes())),
                    Subscription::Agent(id) => format!("agent:{}", json::hex(id.as_bytes())),
                    Subscription::Channel(id) => format!("channel:{:032x}", id.0),
                    Subscription::Thread(id) => format!("thread:{}", json::hex(id.as_bytes())),
                    Subscription::Tag(tag) => format!("tag:{tag}"),
                })
            })),
        ),
        (
            "muted_owners",
            json::array(p.muted_owners().iter().map(|id| json::id(id.as_bytes()))),
        ),
        (
            "blocked_owners",
            json::array(p.blocked_owners().iter().map(|id| json::id(id.as_bytes()))),
        ),
        (
            "muted_threads",
            json::array(p.muted_threads().iter().map(|id| json::id(id.as_bytes()))),
        ),
        (
            "bookmarks",
            json::array(p.bookmarks().iter().map(|r| {
                json::object(vec![
                    ("post", json::id(r.post.as_bytes())),
                    ("revision", json::id(r.revision.as_bytes())),
                ])
            })),
        ),
        (
            "interests",
            json::array(p.interests().iter().map(|(tag, value)| {
                json::object(vec![
                    ("tag", json::string(tag)),
                    ("affinity", value.to_string()),
                ])
            })),
        ),
        (
            "saved_searches",
            json::array(p.saved_searches().iter().map(|(name, query)| {
                json::object(vec![
                    ("name", json::string(name)),
                    ("query", json::string(query)),
                ])
            })),
        ),
        ("wider", p.wider().to_string()),
    ])
}

fn policy(args: &Args, state: &DiscoveryState) -> Result<AttentionPolicy, String> {
    let p = state.preferences();
    let selected = p
        .subscriptions()
        .iter()
        .filter_map(|s| match s {
            Subscription::Owner(owner) => Some(*owner),
            _ => None,
        })
        .collect();
    let muted: BTreeSet<_> = p
        .muted_owners()
        .union(p.blocked_owners())
        .copied()
        .collect();
    let watched = p
        .subscriptions()
        .iter()
        .filter_map(|s| match s {
            Subscription::Thread(root) => Some(*root),
            _ => None,
        })
        .collect();
    AttentionPolicy::new(
        selected,
        muted.into_iter().collect(),
        watched,
        args.discovery.live.unwrap_or(false),
    )
    .and_then(|policy| policy.with_muted_threads(p.muted_threads().iter().copied().collect()))
    .map_err(|e| format!("attention policy: {e:?}"))
}
fn private_summary(store: &PrivateStore) -> String {
    json::object(vec![
        ("durable", "true".into()),
        ("private_generation", store.pin().generation().to_string()),
        ("reader", json::id(&store.state().scope().digest())),
        ("discovery", preferences(store.state().discovery())),
        (
            "attention_generation",
            store.state().attention().generation().to_string(),
        ),
    ])
}
fn save(
    store: &mut PrivateStore,
    candidate: PrivateState,
    source: &Store,
) -> Result<String, String> {
    store
        .commit(candidate, store.pin(), source)
        .map_err(|e| format!("private publication: {e:?}"))?;
    Ok(private_summary(store))
}
pub(super) fn run(args: &Args, source: &Store) -> Result<String, String> {
    let scope = args.discovery.scope(args, source.archive())?;
    let path = args.discovery.path()?;
    if args.command == "reader-init" {
        args.count(0)?;
        let private = PrivateStore::create(path, scope, source)
            .map_err(|e| format!("private reader creation: {e:?}"))?;
        return Ok(private_summary(&private));
    }
    let mut private =
        PrivateStore::open(path, scope, None).map_err(|e| format!("private reader open: {e:?}"))?;
    if args.command == "reader-recover" {
        args.count(0)?;
        private
            .recover(source)
            .map_err(|e| format!("private recovery: {e:?}"))?;
        return Ok(private_summary(&private));
    }
    if private
        .recovery_required()
        .map_err(|e| format!("private recovery check: {e:?}"))?
    {
        return Err("private publication requires reader-recover before use".into());
    }
    match args.command.as_str() {
        "reader-show" => {
            args.count(0)?;
            Ok(private_summary(&private))
        }
        "reader-set" | "reader-observe" | "reader-seen" | "reader-feedback" => {
            let mut discovery = private.state().discovery().clone();
            let view = args.view(source.archive());
            match args.command.as_str() {
                "reader-set" => discovery.apply(preference_change(args)?),
                "reader-observe" => {
                    args.count(0)?;
                    discovery.observe(&view)
                }
                "reader-seen" => {
                    args.count(2)?;
                    discovery.mark_seen(
                        &view,
                        PostRef {
                            post: rid(args.get(0)?)?,
                            revision: rid(args.get(1)?)?,
                        },
                    )
                }
                _ => {
                    args.count(3)?;
                    discovery.feedback(
                        &view,
                        PostRef {
                            post: rid(args.get(0)?)?,
                            revision: rid(args.get(1)?)?,
                        },
                        match args.get(2)? {
                            "up" => 1,
                            "down" => -1,
                            "clear" => 0,
                            _ => return Err("feedback must be up, down or clear".into()),
                        },
                    )
                }
            }
            .map_err(|e| format!("private discovery edit: {e:?}"))?;
            let candidate = private
                .state()
                .clone()
                .with_discovery(discovery)
                .map_err(|e| format!("private state: {e:?}"))?;
            save(&mut private, candidate, source)
        }
        "notifications-ack" => {
            args.count(1)?;
            let ids = parse_list(args.get(0)?)?;
            if ids.is_empty() || ids.len() > 64 {
                return Err("acknowledge 1..64 exact update IDs".into());
            }
            let mut remaining: BTreeSet<_> = ids.iter().copied().collect();
            if remaining.len() != ids.len() {
                return Err("duplicate update ID".into());
            }
            let policy = policy(args, private.state().discovery())?;
            let mut attention = private.state().attention().clone();
            let mut offset = 0;
            loop {
                let page = private
                    .state()
                    .attention()
                    .notifications(source.archive(), args.now, &policy, offset, 64)
                    .map_err(|e| format!("notification snapshot: {e:?}"))?;
                let matches: Vec<_> = page
                    .entries()
                    .iter()
                    .map(|entry| entry.id())
                    .filter(|id| remaining.contains(id))
                    .collect();
                if !matches.is_empty() {
                    let selected = page
                        .select(&matches)
                        .map_err(|e| format!("exact notification selection: {e:?}"))?;
                    attention = attention
                        .acknowledge(&selected, source.archive())
                        .map_err(|e| format!("acknowledgement: {e:?}"))?;
                    for id in matches {
                        remaining.remove(&id);
                    }
                }
                offset += page.entries().len();
                if remaining.is_empty() || offset >= page.total() || page.entries().is_empty() {
                    break;
                }
                if offset > 2 * vhalla_attention::MAX_CANDIDATES {
                    return Err("notification scan budget exhausted".into());
                }
            }
            if !remaining.is_empty() {
                return Err("an exact requested notification is no longer in the current bounded inbox; nothing acknowledged".into());
            }
            let candidate = private
                .state()
                .clone()
                .with_attention(attention)
                .map_err(|e| format!("private state: {e:?}"))?;
            save(&mut private, candidate, source)
        }
        _ => query(args, source, &private),
    }
}

fn read_state(state: vhalla_attention::ReadState) -> String {
    json::string(match state {
        vhalla_attention::ReadState::Read => "read",
        vhalla_attention::ReadState::Unread => "unread",
        vhalla_attention::ReadState::Unknown => "unknown",
    })
}
fn notification(entry: &vhalla_attention::Notification) -> String {
    use vhalla_attention::{Lane, Reason};
    json::object(vec![
        ("id", json::id(&entry.id())),
        (
            "recipient",
            json::id(entry.update.group.recipient.as_bytes()),
        ),
        ("source", json::actor(entry.source.actor)),
        ("event", json::id(entry.update.event.as_bytes())),
        (
            "reason",
            json::string(match entry.update.group.reason {
                Reason::Mention => "mention",
                Reason::Reply => "reply",
                Reason::Follow => "follow",
                Reason::Reaction => "reaction",
                Reason::Repost => "repost",
                Reason::Quote => "quote",
                Reason::WatchedThread => "watched-thread",
            }),
        ),
        (
            "recipient_agents",
            json::array(
                entry
                    .recipient_agents
                    .iter()
                    .map(|id| json::id(id.as_bytes())),
            ),
        ),
        (
            "post",
            json::optional(entry.source_post, |id| json::id(id.as_bytes())),
        ),
        (
            "root",
            json::optional(entry.root, |id| json::id(id.as_bytes())),
        ),
        (
            "target",
            json::optional(entry.target, |r| {
                json::object(vec![
                    ("post", json::id(r.post.as_bytes())),
                    ("revision", json::id(r.revision.as_bytes())),
                ])
            }),
        ),
        ("state", json::state(entry.state)),
        (
            "lane",
            json::string(match entry.lane {
                Lane::Selected => "selected",
                Lane::Requests => "requests",
            }),
        ),
        ("positive", entry.positive.to_string()),
        ("conflict", entry.conflict.to_string()),
        ("read", read_state(entry.read)),
        ("priority", json::optional(entry.priority, read_state)),
    ])
}

fn coverage(value: vhalla_discovery::Coverage) -> String {
    json::object(vec![
        ("scope", json::string("local-retained")),
        ("retained_records", value.retained_records.to_string()),
        ("documents", value.documents.to_string()),
        ("corpus_complete", value.corpus_complete.to_string()),
        ("history_complete", value.history_complete.to_string()),
        ("query_complete", value.query_complete.to_string()),
        ("examined", value.examined.to_string()),
        ("bytes", value.bytes.to_string()),
        ("steps", value.steps.to_string()),
        ("network_complete", "false".into()),
    ])
}
fn hit(value: &vhalla_discovery::Hit<'_>) -> String {
    let why = value.why;
    json::object(vec![
        ("post", json::id(value.reference.post.as_bytes())),
        ("revision", json::id(value.reference.revision.as_bytes())),
        ("owner", json::id(value.owner.as_bytes())),
        (
            "agent",
            json::optional(value.agent, |id| json::id(id.as_bytes())),
        ),
        ("root", json::id(value.root.as_bytes())),
        ("placement", json::placement(value.placement)),
        ("text", json::string(value.text)),
        ("facets", json::facets(value.facets)),
        ("state", json::state(value.state)),
        ("reply", value.reply.to_string()),
        (
            "reposted_by",
            json::array(value.reposted_by.iter().map(|id| json::id(id.as_bytes()))),
        ),
        (
            "first_observed",
            json::optional(value.first_observed, |n| n.to_string()),
        ),
        (
            "why",
            json::object(vec![
                ("followed", why[0].to_string()),
                ("subscription", why[1].to_string()),
                ("topic", why[2].to_string()),
                ("selected_endorsements", why[3].to_string()),
                ("freshness", why[4].to_string()),
                ("unseen", why[5].to_string()),
            ]),
        ),
    ])
}
fn query(args: &Args, source: &Store, private: &PrivateStore) -> Result<String, String> {
    if args.command == "notifications" {
        args.count(0)?;
        let policy = policy(args, private.state().discovery())?;
        let page = private
            .state()
            .attention()
            .notifications_filtered(
                source.archive(),
                args.now,
                &policy,
                args.discovery.unread.unwrap_or(false),
                args.offset,
                args.limit,
            )
            .map_err(|e| format!("notification query: {e:?}"))?;
        let counts = page.counts();
        let c = page.coverage();
        return Ok(json::object(vec![
            (
                "notifications",
                json::array(page.entries().iter().map(notification)),
            ),
            ("basis", json::basis(page.basis())),
            ("known_total", page.total().to_string()),
            ("offset", args.offset.to_string()),
            (
                "counts",
                json::object(vec![
                    ("unread_updates", counts.unread_updates.to_string()),
                    ("unknown_updates", counts.unknown_updates.to_string()),
                    ("unread_groups", counts.unread_groups.to_string()),
                    ("unknown_groups", counts.unknown_groups.to_string()),
                    ("scope", json::string("returned-page")),
                ]),
            ),
            (
                "coverage",
                json::object(vec![
                    ("incomplete", c.incomplete.to_string()),
                    ("selected_limited", c.selected_limited.to_string()),
                    ("requests_limited", c.requests_limited.to_string()),
                    ("owner_limited", c.owner_limited.to_string()),
                    ("unresolved_mentions", c.unresolved_mentions.to_string()),
                    (
                        "unresolved_ack_sources",
                        private
                            .state()
                            .attention()
                            .unresolved_sources(source.archive())
                            .map_err(|e| format!("read-state resolution: {e:?}"))?
                            .to_string(),
                    ),
                ]),
            ),
        ]));
    }
    let view = args.view(source.archive());
    let visibility = if args.discovery.live.unwrap_or(false) {
        vhalla_discovery::Visibility::Live
    } else {
        vhalla_discovery::Visibility::Committed
    };
    if args.discovery.state == Some(RecordState::Provisional)
        && visibility != vhalla_discovery::Visibility::Live
    {
        return Err("provisional search requires explicit --live on".into());
    }
    let snapshot = vhalla_discovery::DiscoverySnapshot::new(
        source.archive(),
        &view,
        private.state().scope().owner(),
        private.state().discovery(),
        visibility,
    )
    .map_err(|e| format!("discovery snapshot: {e:?}"))?;
    if args.command == "boards" {
        args.count(0)?;
        let boards = snapshot
            .boards_page(args.offset, args.limit)
            .map_err(|e| format!("boards: {e:?}"))?;
        return Ok(json::object(vec![
            (
                "boards",
                json::array(boards.iter().map(|board| {
                    json::object(vec![
                        (
                            "channel",
                            json::string(&format!("{:032x}", board.channel.0)),
                        ),
                        ("roots", board.roots.to_string()),
                        ("replies", board.replies.to_string()),
                        (
                            "last_observed",
                            json::optional(board.last_observed, |n| n.to_string()),
                        ),
                    ])
                })),
            ),
            ("offset", args.offset.to_string()),
            ("coverage", coverage(snapshot.coverage())),
        ]));
    }
    if args.command == "directory" {
        args.count(0)?;
        let owners = snapshot
            .directory_page(args.offset, args.limit)
            .map_err(|e| format!("directory: {e:?}"))?;
        return Ok(json::object(vec![
            (
                "owners",
                json::array(owners.iter().map(|id| json::id(id.as_bytes()))),
            ),
            ("offset", args.offset.to_string()),
            ("coverage", coverage(snapshot.coverage())),
        ]));
    }
    let mode = if args.command == "feed" {
        args.count(1)?;
        Some(match args.get(0)? {
            "following" => vhalla_discovery::FeedMode::Following,
            "discover" => vhalla_discovery::FeedMode::Discover,
            _ => return Err("feed mode must be following or discover".into()),
        })
    } else {
        None
    };
    let query = if mode.is_some() {
        ""
    } else {
        args.count(1)?;
        if args.command == "search-saved" {
            private
                .state()
                .discovery()
                .preferences()
                .saved_searches()
                .get(args.get(0)?)
                .map(String::as_str)
                .ok_or("saved query does not exist")?
        } else {
            args.get(0)?
        }
    };
    let query = vhalla_discovery::Query::parse(query).map_err(|e| format!("query: {e:?}"))?;
    let filters = vhalla_discovery::Filters {
        owner: args.discovery.owner,
        agent: args.discovery.agent,
        channel: args.discovery.channel,
        root: args.discovery.root,
        tag: args.discovery.tag.clone(),
        mention: args.discovery.mention,
        kind: args.discovery.kind.as_deref().map(|kind| match kind {
            "post" => vhalla_discovery::Kind::Post,
            "reply" => vhalla_discovery::Kind::Reply,
            _ => vhalla_discovery::Kind::Repost,
        }),
        state: args.discovery.state,
        ..Default::default()
    };
    let mut cursor = snapshot
        .cursor(query, filters, mode, vhalla_discovery::Budget::default())
        .map_err(|e| format!("bounded query: {e:?}"))?;
    cursor.skip(args.offset);
    let page = cursor
        .page(
            source.archive(),
            &view,
            private.state().discovery(),
            args.limit,
        )
        .map_err(|e| format!("query page: {e:?}"))?;
    Ok(json::object(vec![
        ("items", json::array(page.hits.iter().map(hit))),
        ("matches", page.matches.to_string()),
        ("offset", args.offset.to_string()),
        ("remaining", cursor.remaining().to_string()),
        (
            "policy_version",
            vhalla_discovery::POLICY_VERSION.to_string(),
        ),
        ("coverage", coverage(page.coverage)),
    ]))
}
