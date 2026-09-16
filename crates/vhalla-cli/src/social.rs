//! Explicit local experimental social commands; no network or host activation.
#[path = "discovery.rs"]
mod discovery;
#[path = "social_json.rs"]
mod json;
#[cfg(feature = "experimental-sync")]
#[path = "social_sync.rs"]
mod sync;

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_core::{RealmId, RoomId};
use vhalla_identity::Identity;
use vhalla_social::{
    archive::{Archive, Budget, Limits, MAX_SNAPSHOT_BYTES},
    control::{ControlView, SocialStatus},
    view::*,
    *,
};
use vhalla_social_store::Store;

pub const HELP: &str = "Experimental local social commands (build: --features experimental-social):
vhalla social COMMAND STORE REALM32HEX [arguments] [--now SECONDS]
  init NEW_OWNER_KEYDIR
  enroll OWNER_KEYDIR OWNER64 NEW_AGENT_KEYDIR RIGHTS EXPIRY
  grant OWNER_KEYDIR OWNER64 AGENT64 RIGHTS EXPIRY
  post KEYDIR ACTOR profile|channel:ROOM32 TEXT
  reply KEYDIR ACTOR PARENT_POST64 PARENT_REV64 TEXT
  quote KEYDIR ACTOR PLACEMENT SOURCE_POST64 SOURCE_REV64 TEXT
  revise KEYDIR ACTOR POST64 TEXT | retract KEYDIR ACTOR POST64
  react KEYDIR ACTOR POST64 up|down|clear REV64|-
  follow KEYDIR ACTOR OWNER64 on|off | repost KEYDIR ACTOR POST64 REV64|-
  bio KEYDIR ACTOR TEXT | profile-set KEYDIR ACTOR TEXT
  seal|ratify OWNER_KEYDIR OWNER64 HEAD_CSV|-
  revoke OWNER_KEYDIR OWNER64 GRANT64 ACCEPTED_CSV|-
  retire OWNER_KEYDIR OWNER64 AGENT64 ACCEPTED_CSV|-
  rotate OWNER_KEYDIR OWNER64 NEW_KEYDIR
  profile OWNER64 | active-bios OWNER64 | post-show POST64
  posts [PLACEMENT] | timeline OWNER64 | thread ROOT64 | stats OWNER64 | records
  sync serve KEYDIR REQUESTER64 [LISTEN_IP] | sync pull KEYDIR PROVIDER64 ROUTE EXPIRY [QUERY]
  reaction OWNER64 POST64 | following OWNER64 TARGET64 | repost-show OWNER64 POST64
  votes POST64 REV64 | export NEWFILE | import FILE | recover
ACTOR is owner:OWNER64 or agent:AGENT64:GRANT64; IDs are full hex.
RIGHTS is all or a comma-list of post,bio,react,follow,repost,revise.
Read paging: --offset N --limit N (1..64); stats policy: --eligible OWNER_CSV.
Signed facets on post/reply/quote/revise: --mention START:END:owner:OWNER64
or --mention START:END:agent:AGENT64; --tag START:END:TAG. Offsets are UTF-8 bytes.
Repeat up to 16 facets. --format legacy|faceted selects encoding; facets imply
faceted, otherwise legacy is the default. Legacy revisions have no facets.
Register updates default to all visible heads; --heads ID_CSV explicitly resolves
up to 16 predecessors, including partial resolution discovered through records.
Use -- before positional text beginning with --. Output is ASCII JSON.
Owner writes are atomically sealed; agent writes remain provisional until sealed.
sync needs --features experimental-sync; serve prints a 60s route the peer
copies into pull. Both sides pin exact application keys; nothing is open.";

pub fn help() -> String {
    format!("{HELP}\n\n{}", discovery::HELP)
}

struct Args {
    command: String,
    store: String,
    realm: RealmId,
    values: Vec<String>,
    now: u64,
    heads: Option<References>,
    eligibility: Eligibility,
    offset: usize,
    limit: usize,
    facets: Vec<Facet>,
    faceted: bool,
    discovery: discovery::Options,
}
impl Args {
    fn parse(args: Vec<OsString>) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut now = None;
        let mut heads = None;
        let mut eligible = None;
        let mut offset = None;
        let mut limit = None;
        let mut facets = Vec::new();
        let mut tags = Vec::new();
        let mut faceted = None;
        let mut discovery = discovery::Options::default();
        let mut literal = false;
        let mut args = args.into_iter().skip(1);
        while let Some(raw) = args.next() {
            if raw.len() > MAX_RECORD_BYTES {
                return Err("argument exceeds 8192 bytes".into());
            }
            let value = raw
                .into_string()
                .map_err(|_| "social arguments must be UTF-8")?;
            if !literal && value == "--" {
                literal = true;
                continue;
            }
            if !literal && value.starts_with("--") {
                let raw = args.next().ok_or("option needs a value")?;
                if raw.len() > MAX_RECORD_BYTES {
                    return Err("option exceeds 8192 bytes".into());
                }
                let option = raw.into_string().map_err(|_| "option must be UTF-8")?;
                match value.as_str() {
                    "--mention" => {
                        if facets.len() == 16 {
                            return Err("at most 16 signed facets".into());
                        }
                        facets.push(parse_facet(&option, true)?);
                    }
                    "--tag" => {
                        if tags.len() == 16 {
                            return Err("at most 16 tag arguments".into());
                        }
                        tags.push(option);
                    }
                    "--format" => set(
                        &mut faceted,
                        match option.as_str() {
                            "legacy" => false,
                            "faceted" => true,
                            _ => return Err("format must be legacy or faceted".into()),
                        },
                    )?,
                    "--now" => set(
                        &mut now,
                        option.parse::<u64>().map_err(|_| "invalid --now")?,
                    )?,
                    "--heads" => set(&mut heads, references(&option)?)?,
                    "--eligible" => {
                        let mut ids = parse_list(&option)?
                            .into_iter()
                            .map(OwnerId::from_bytes)
                            .collect::<Vec<_>>();
                        ids.sort();
                        set(&mut eligible, Eligibility::new(ids).map_err(social_error)?)?;
                    }
                    "--offset" => set(
                        &mut offset,
                        option.parse::<usize>().map_err(|_| "invalid --offset")?,
                    )?,
                    "--limit" => set(
                        &mut limit,
                        option.parse::<usize>().map_err(|_| "invalid --limit")?,
                    )?,
                    _ => {
                        if !discovery.flag(&value, &option)? {
                            return Err("unknown social option".into());
                        }
                    }
                }
            } else {
                values.push(value);
            }
        }
        if values.len() < 3 {
            return Err(HELP.into());
        }
        let command = values.remove(0);
        if matches!(command.as_str(), "post" | "reply" | "quote" | "revise") {
            if facets.len() + tags.len() > 16 {
                return Err("at most 16 signed facets".into());
            }
            for tag in tags {
                facets.push(parse_facet(&tag, false)?);
            }
        } else {
            for tag in tags {
                set(
                    &mut discovery.tag,
                    CanonicalTag::new(&tag)
                        .map_err(social_error)?
                        .as_str()
                        .to_owned(),
                )?;
            }
        }
        if (faceted.is_some() || !facets.is_empty())
            && !matches!(command.as_str(), "post" | "reply" | "quote" | "revise")
        {
            return Err("facet options require post/reply/quote/revise".into());
        }
        let faceted = faceted.unwrap_or(!facets.is_empty());
        if !faceted && !facets.is_empty() {
            return Err("legacy format cannot contain signed facets".into());
        }
        facets.sort_by_key(|facet| (facet.start, facet.end));
        discovery.validate(&command)?;
        let store = values.remove(0);
        let realm = RealmId(hex128(&values.remove(0))?);
        let limit = limit.unwrap_or(32);
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err("limit must be 1..64".into());
        }
        Ok(Self {
            command,
            store,
            realm,
            values,
            now: match now {
                Some(now) => now,
                None => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "clock before Unix epoch")?
                    .as_secs(),
            },
            heads,
            eligibility: eligible.unwrap_or_default(),
            offset: offset.unwrap_or(0),
            limit,
            facets,
            faceted,
            discovery,
        })
    }
    fn count(&self, n: usize) -> Result<(), String> {
        if self.values.len() == n {
            Ok(())
        } else {
            Err(format!(
                "wrong argument count for {}; see vhalla --help",
                self.command
            ))
        }
    }
    fn get(&self, n: usize) -> Result<&str, String> {
        self.values
            .get(n)
            .map(String::as_str)
            .ok_or_else(|| "missing argument".into())
    }
    fn view<'a>(&'a self, archive: &'a Archive) -> View<'a> {
        View::new(archive, self.now, &self.eligibility)
    }
}
fn parse_facet(input: &str, mention: bool) -> Result<Facet, String> {
    let mut parts = input.splitn(3, ':');
    let start = parts
        .next()
        .ok_or("facet start missing")?
        .parse::<u16>()
        .map_err(|_| "facet start must be a UTF-8 byte offset")?;
    let end = parts
        .next()
        .ok_or("facet end missing")?
        .parse::<u16>()
        .map_err(|_| "facet end must be a UTF-8 byte offset")?;
    let target = parts.next().ok_or("facet target missing")?;
    let kind = if mention {
        let (kind, id) = target
            .split_once(':')
            .ok_or("mention needs owner:ID or agent:ID")?;
        FacetKind::Mention(match kind {
            "owner" => MentionTarget::Owner(oid(id)?),
            "agent" => MentionTarget::Agent(aid(id)?),
            _ => return Err("mention needs owner:ID or agent:ID".into()),
        })
    } else {
        FacetKind::Tag(CanonicalTag::new(target).map_err(social_error)?)
    };
    Ok(Facet { start, end, kind })
}
fn set<T>(value: &mut Option<T>, next: T) -> Result<(), String> {
    if value.is_some() {
        Err("duplicate option".into())
    } else {
        *value = Some(next);
        Ok(())
    }
}
fn social_error(error: vhalla_social::Error) -> String {
    format!("social operation rejected: {error:?}")
}
fn identity(path: &str) -> Result<Identity, String> {
    Identity::open(path).map_err(|e| format!("identity: {e:?}"))
}
fn nonce() -> Result<[u8; 32], String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| "OS entropy unavailable")?;
    Ok(bytes)
}
fn hex32(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 || !text.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err("expected full 64-hex ID".into());
    }
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| "invalid hex ID")?;
    }
    Ok(bytes)
}
fn hex128(text: &str) -> Result<u128, String> {
    if text.len() != 32 || !text.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err("expected full 32-hex realm/channel ID".into());
    }
    u128::from_str_radix(text, 16).map_err(|_| "invalid realm/channel ID".into())
}
fn rid(text: &str) -> Result<RecordId, String> {
    Ok(RecordId::from_bytes(hex32(text)?))
}
fn oid(text: &str) -> Result<OwnerId, String> {
    Ok(OwnerId::from_bytes(hex32(text)?))
}
fn aid(text: &str) -> Result<AgentId, String> {
    Ok(AgentId::from_bytes(hex32(text)?))
}
fn parse_list(text: &str) -> Result<Vec<[u8; 32]>, String> {
    if text == "-" {
        Ok(Vec::new())
    } else {
        let list = text.split(',').map(hex32).collect::<Result<Vec<_>, _>>()?;
        if list.len() > MAX_RECORDS {
            Err("ID list too long".into())
        } else {
            Ok(list)
        }
    }
}
fn references(text: &str) -> Result<References, String> {
    References::sorted(
        parse_list(text)?
            .into_iter()
            .map(RecordId::from_bytes)
            .collect(),
    )
    .map_err(social_error)
}
fn placement(text: &str) -> Result<Placement, String> {
    if text == "profile" {
        Ok(Placement::Profile)
    } else {
        Ok(Placement::Channel(RoomId(hex128(
            text.strip_prefix("channel:")
                .ok_or("expected profile or channel:ROOM32")?,
        )?)))
    }
}
fn rights(text: &str) -> Result<Rights, String> {
    if text == "all" {
        return Ok(Rights::ALL);
    }
    let mut parts = text.split(',');
    let first = parts.next().ok_or("missing rights")?;
    let one = |v| match v {
        "post" => Ok(Rights::POST),
        "bio" => Ok(Rights::BIO),
        "react" => Ok(Rights::REACT),
        "follow" => Ok(Rights::FOLLOW),
        "repost" => Ok(Rights::REPOST),
        "revise" => Ok(Rights::REVISE),
        _ => Err("unknown right"),
    };
    let mut value = one(first)?;
    for part in parts {
        value = value.union(one(part)?);
    }
    Ok(value)
}
fn sign(identity: &Identity, body: Body) -> Result<SignedRecord, String> {
    identity
        .sign_social(UnsignedRecord::new(identity.public_key(), body).map_err(social_error)?)
        .map_err(social_error)?
        .finish()
        .map_err(social_error)
}
fn joint(primary: &Identity, ack: &Identity, body: Body) -> Result<SignedRecord, String> {
    ack.countersign_social(
        primary
            .sign_social(UnsignedRecord::new(primary.public_key(), body).map_err(social_error)?)
            .map_err(social_error)?,
    )
    .map_err(social_error)
}
fn insert(archive: &mut Archive, record: &SignedRecord) -> Result<RecordId, String> {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).map_err(social_error)?,
        )
        .map_err(social_error)?;
    Ok(record.id())
}
fn owner_head(
    archive: &Archive,
    now: u64,
    owner: OwnerId,
    key: &Identity,
) -> Result<RecordId, String> {
    let controls = ControlView::new(archive, now);
    let status = controls
        .owner(owner)
        .ok_or("owner missing; import its authenticated history")?;
    if status.frozen() || status.incomplete() || status.key() != Some(key.public_key()) {
        return Err("owner controller is mismatched, conflicted or incomplete".into());
    }
    status
        .head()
        .ok_or_else(|| "owner control head unavailable".into())
}
fn actor(archive: &Archive, now: u64, text: &str, key: &Identity) -> Result<Actor, String> {
    let pieces = text.split(':').collect::<Vec<_>>();
    match pieces.as_slice() {
        ["owner", owner] => {
            let owner = oid(owner)?;
            Ok(Actor::Owner {
                owner,
                control: owner_head(archive, now, owner, key)?,
            })
        }
        ["agent", agent, grant] => {
            let agent = aid(agent)?;
            let grant = rid(grant)?;
            let controls = ControlView::new(archive, now);
            let status = controls.agent(agent).ok_or("agent binding missing")?;
            if status.key() != key.public_key()
                || !status.active()
                || !status.grant_ids().contains(&grant)
            {
                return Err("agent key/grant mismatched or current eligibility closed".into());
            }
            Ok(Actor::Agent {
                owner: status.owner(),
                agent,
                grant,
            })
        }
        _ => Err("actor must be owner:OWNER64 or agent:AGENT64:GRANT64".into()),
    }
}
fn next_sequence(
    archive: &Archive,
    now: u64,
    actor: Actor,
    key: &Identity,
) -> Result<(u64, Option<RecordId>), String> {
    let records = archive
        .records()
        .filter(|record| {
            record.primary_key() == &key.public_key()
                && matches!(record.body(),Body::Social{actor:a,..}if *a==actor)
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return Ok((0, None));
    }
    let ancestors = records
        .iter()
        .filter_map(|record| match record.body() {
            Body::Social { previous, .. } => *previous,
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let heads = records
        .iter()
        .filter(|record| !ancestors.contains(&record.id()))
        .collect::<Vec<_>>();
    if heads.len() != 1 {
        return Err(
            "writer history has conflicting heads; use a fresh explicitly granted writer".into(),
        );
    }
    let head = heads[0];
    let controls = ControlView::new(archive, now);
    if !matches!(
        controls.social_status(head.id()),
        SocialStatus::Committed | SocialStatus::Provisional
    ) {
        return Err("writer history is incomplete or rejected".into());
    }
    let Body::Social { sequence, .. } = head.body() else {
        return Err("invalid writer head".into());
    };
    Ok((
        sequence.checked_add(1).ok_or("writer sequence exhausted")?,
        Some(head.id()),
    ))
}
fn heads<T>(args: &Args, register: Register<T>) -> Result<References, String> {
    if let Some(explicit) = &args.heads {
        return Ok(explicit.clone());
    }
    let ids =
        match register {
            Register::Empty => Vec::new(),
            Register::Resolved { heads, .. } | Register::Conflict { heads, .. } => heads,
            Register::Incomplete => return Err(
                "register incomplete: inspect records and provide --heads with up to 16 exact IDs"
                    .into(),
            ),
        };
    References::new(ids).map_err(social_error)
}
fn operation(args: &Args, archive: &Archive, actor: Actor) -> Result<Operation, String> {
    let view = args.view(archive);
    let owner = actor.owner();
    let text = |i| Text::new(args.get(i)?).map_err(social_error);
    let operation: Result<Operation, String> = match args.command.as_str() {
        "post" => {
            args.count(4)?;
            Ok(Operation::Post {
                placement: placement(args.get(2)?)?,
                text: text(3)?,
                reply: None,
                quote: None,
            })
        }
        "reply" => {
            args.count(5)?;
            let parent = PostRef {
                post: rid(args.get(2)?)?,
                revision: rid(args.get(3)?)?,
            };
            let original = view.post(parent.post).map_err(social_error)?;
            Ok(Operation::Post {
                placement: original.placement,
                text: text(4)?,
                reply: Some(ReplyRef {
                    root: original.root,
                    parent,
                }),
                quote: None,
            })
        }
        "quote" => {
            args.count(6)?;
            Ok(Operation::Post {
                placement: placement(args.get(2)?)?,
                text: text(5)?,
                reply: None,
                quote: Some(PostRef {
                    post: rid(args.get(3)?)?,
                    revision: rid(args.get(4)?)?,
                }),
            })
        }
        "revise" => {
            args.count(4)?;
            let post = rid(args.get(2)?)?;
            let content = view.post(post).map_err(social_error)?.observed;
            let predecessors = match content {
                Content::Present(value) => heads(args, value)?,
                Content::Incomplete if args.heads.is_some() => {
                    args.heads.clone().expect("explicit")
                }
                _ => return Err(
                    "cannot automatically revise unavailable or retracted content; inspect records"
                        .into(),
                ),
            };
            Ok(Operation::Revise {
                post,
                text: text(3)?,
                supersedes: predecessors,
            })
        }
        "retract" => {
            args.count(3)?;
            Ok(Operation::Retract {
                post: rid(args.get(2)?)?,
            })
        }
        "react" => {
            args.count(5)?;
            let post = rid(args.get(2)?)?;
            let reaction = match (args.get(3)?, args.get(4)?) {
                ("clear", "-") => Reaction::Clear,
                ("up", v) => Reaction::Up(rid(v)?),
                ("down", v) => Reaction::Down(rid(v)?),
                _ => return Err("reaction must be up/down with exact revision, or clear -".into()),
            };
            Ok(Operation::React {
                post,
                reaction,
                supersedes: heads(
                    args,
                    view.reaction(owner, post).map_err(social_error)?.observed,
                )?,
            })
        }
        "follow" => {
            args.count(4)?;
            let target = oid(args.get(2)?)?;
            let following = match args.get(3)? {
                "on" => true,
                "off" => false,
                _ => return Err("follow value must be on or off".into()),
            };
            Ok(Operation::Follow {
                target,
                following,
                supersedes: heads(
                    args,
                    view.follow(owner, target).map_err(social_error)?.observed,
                )?,
            })
        }
        "repost" => {
            args.count(4)?;
            let post = rid(args.get(2)?)?;
            let revision = if args.get(3)? == "-" {
                None
            } else {
                Some(rid(args.get(3)?)?)
            };
            Ok(Operation::Repost {
                post,
                revision,
                supersedes: heads(
                    args,
                    view.repost(owner, post).map_err(social_error)?.observed,
                )?,
            })
        }
        "bio" => {
            args.count(3)?;
            let Actor::Agent { agent, .. } = actor else {
                return Err("bio requires an exact agent actor".into());
            };
            let roster = view
                .active_bios(owner, 0, MAX_PAGE_SIZE)
                .map_err(social_error)?;
            let mut selected = roster.items.into_iter().find(|v| v.agent == agent);
            let mut offset = roster.next_offset;
            while selected.is_none() {
                let Some(next) = offset else { break };
                let page = view
                    .active_bios(owner, next, MAX_PAGE_SIZE)
                    .map_err(social_error)?;
                selected = page.items.into_iter().find(|v| v.agent == agent);
                offset = page.next_offset;
            }
            let register = selected
                .ok_or("agent absent from current roster")?
                .bio
                .observed;
            Ok(Operation::AgentBio {
                text: text(2)?,
                supersedes: heads(args, register)?,
            })
        }
        "profile-set" => {
            args.count(3)?;
            if !matches!(actor, Actor::Owner { .. }) {
                return Err("profile-set requires the owner controller".into());
            }
            Ok(Operation::OwnerProfile {
                text: text(2)?,
                supersedes: heads(
                    args,
                    view.profile(owner).map_err(social_error)?.profile.observed,
                )?,
            })
        }
        _ => Err("unknown social write command".into()),
    };
    let operation = operation?;
    if !args.faceted {
        return Ok(operation);
    }
    Ok(match operation {
        Operation::Post {
            placement,
            text,
            reply,
            quote,
        } => Operation::PostFaceted {
            placement,
            content: FacetedText::new(text, args.facets.clone()).map_err(social_error)?,
            reply,
            quote,
        },
        Operation::Revise {
            post,
            text,
            supersedes,
        } => Operation::ReviseFaceted {
            post,
            content: FacetedText::new(text, args.facets.clone()).map_err(social_error)?,
            supersedes,
        },
        _ => return Err("facets require an exact text revision".into()),
    })
}
fn commit(store: &mut Store, candidate: Archive) -> Result<Vec<(&'static str, String)>, String> {
    let published = store
        .commit(candidate, store.pin())
        .map_err(|e| e.to_string())?;
    Ok(vec![
        ("durable", "true".into()),
        ("generation", published.pin().generation().to_string()),
        ("root", json::id(published.pin().logical().as_bytes())),
        ("reconciled", published.reconciled().to_string()),
    ])
}
fn social_write(args: &Args, store: &mut Store) -> Result<String, String> {
    let key = identity(args.get(0)?)?;
    let actor = actor(store.archive(), args.now, args.get(1)?, &key)?;
    let op = operation(args, store.archive(), actor)?;
    let (sequence, previous) = next_sequence(store.archive(), args.now, actor, &key)?;
    let record = sign(
        &key,
        Body::Social {
            actor,
            realm: args.realm,
            sequence,
            previous,
            operation: op,
        },
    )?;
    let mut candidate = store.archive().clone();
    let event = insert(&mut candidate, &record)?;
    if args.view(&candidate).state(event) != Some(RecordState::Provisional) {
        return Err(
            "new social record is not currently admissible; no publication occurred".into(),
        );
    }
    if let Actor::Owner { owner, control } = actor {
        insert(
            &mut candidate,
            &sign(
                &key,
                Body::Control {
                    owner,
                    previous: control,
                    action: ControlAction::Seal {
                        realm: args.realm,
                        heads: References::new(vec![event]).map_err(social_error)?,
                    },
                },
            )?,
        )?;
        if args.view(&candidate).state(event) != Some(RecordState::Committed) {
            return Err("owner post could not be committed atomically".into());
        }
    }
    let mut fields = commit(store, candidate)?;
    let view = args.view(store.archive());
    fields.extend([
        ("event", json::id(event.as_bytes())),
        ("state", json::optional(view.state(event), json::state)),
        ("basis", json::basis(view.basis())),
        (
            "capacity_blocked",
            view.profile(actor.owner())
                .map_err(social_error)?
                .capacity_blocked
                .to_string(),
        ),
    ]);
    Ok(json::object(fields))
}
fn control_write(args: &Args, store: &mut Store) -> Result<String, String> {
    let key = identity(args.get(0)?)?;
    let owner = oid(args.get(1)?)?;
    let previous = owner_head(store.archive(), args.now, owner, &key)?;
    let mut candidate = store.archive().clone();
    let mut fields = vec![("owner", json::id(owner.as_bytes()))];
    let (action, ack) = match args.command.as_str() {
        "enroll" => {
            args.count(5)?;
            let rights = rights(args.get(3)?)?;
            let expires_at = expiry(args.get(4)?, args.now)?;
            let genesis_nonce = nonce()?;
            let grant_nonce = nonce()?;
            let agent_key = Identity::create_new(args.get(2)?).map_err(|e| {
                format!("new agent identity: {e:?}; existing/partial paths are preserved")
            })?;
            let genesis = joint(
                &key,
                &agent_key,
                Body::AgentGenesis {
                    owner,
                    control: previous,
                    key: agent_key.public_key(),
                    nonce: genesis_nonce,
                },
            )?;
            let agent = AgentId::from_bytes(*insert(&mut candidate, &genesis)?.as_bytes());
            fields.push(("agent", json::id(agent.as_bytes())));
            (
                ControlAction::Grant {
                    agent,
                    realm: args.realm,
                    rights,
                    expires_at,
                    nonce: grant_nonce,
                },
                None,
            )
        }
        "grant" => {
            args.count(5)?;
            (
                ControlAction::Grant {
                    agent: aid(args.get(2)?)?,
                    realm: args.realm,
                    rights: rights(args.get(3)?)?,
                    expires_at: expiry(args.get(4)?, args.now)?,
                    nonce: nonce()?,
                },
                None,
            )
        }
        "seal" | "ratify" => {
            args.count(3)?;
            let heads = references(args.get(2)?)?;
            (
                if args.command == "seal" {
                    ControlAction::Seal {
                        realm: args.realm,
                        heads,
                    }
                } else {
                    ControlAction::Ratify {
                        realm: args.realm,
                        heads,
                    }
                },
                None,
            )
        }
        "revoke" => {
            args.count(4)?;
            (
                ControlAction::Revoke {
                    grant: rid(args.get(2)?)?,
                    accepted: references(args.get(3)?)?,
                },
                None,
            )
        }
        "retire" => {
            args.count(4)?;
            (
                ControlAction::Retire {
                    agent: aid(args.get(2)?)?,
                    realm: args.realm,
                    accepted: references(args.get(3)?)?,
                },
                None,
            )
        }
        "rotate" => {
            args.count(3)?;
            let next = Identity::create_new(args.get(2)?).map_err(|e| {
                format!("new controller identity: {e:?}; existing/partial paths are preserved")
            })?;
            fields.push(("controller", json::id(&next.public_key())));
            (
                ControlAction::Rotate {
                    new_key: next.public_key(),
                },
                Some(next),
            )
        }
        _ => return Err("unknown owner control command".into()),
    };
    let record = if let Some(ack) = ack {
        joint(
            &key,
            &ack,
            Body::Control {
                owner,
                previous,
                action,
            },
        )?
    } else {
        sign(
            &key,
            Body::Control {
                owner,
                previous,
                action,
            },
        )?
    };
    let event = insert(&mut candidate, &record)?;
    let controls = ControlView::new(&candidate, args.now);
    let status = controls.owner(owner).ok_or("owner authority unavailable")?;
    if status.frozen() || status.incomplete() || status.head() != Some(event) {
        return Err("control transition was not admitted; inspect its exact dependencies".into());
    }
    let is_grant = matches!(
        record.body(),
        Body::Control {
            action: ControlAction::Grant { .. },
            ..
        }
    );
    let capacity_blocked = status.capacity_blocked();
    let committed = commit(store, candidate)?;
    fields.extend(committed);
    fields.push(("event", json::id(event.as_bytes())));
    fields.push(("capacity_blocked", capacity_blocked.to_string()));
    if is_grant {
        fields.push(("grant", json::id(event.as_bytes())));
    }
    fields.push(("basis", json::basis(args.view(store.archive()).basis())));
    Ok(json::object(fields))
}
fn expiry(value: &str, now: u64) -> Result<u64, String> {
    let value = value.parse::<u64>().map_err(|_| "invalid expiry")?;
    if value <= now {
        Err("grant expiry must be after evaluation time".into())
    } else {
        Ok(value)
    }
}
fn slice<T>(
    values: &[T],
    offset: usize,
    limit: usize,
    f: impl Fn(&T) -> String,
) -> Result<String, String> {
    if offset > values.len() {
        return Err("offset exceeds known result count".into());
    }
    let end = offset.saturating_add(limit).min(values.len());
    Ok(json::object(vec![
        ("items", json::array(values[offset..end].iter().map(f))),
        ("known_total", values.len().to_string()),
        (
            "next_offset",
            json::optional((end < values.len()).then_some(end), |v| v.to_string()),
        ),
    ]))
}
fn query(args: &Args, store: &Store) -> Result<String, String> {
    let view = args.view(store.archive());
    let mut fields = vec![
        ("basis", json::basis(view.basis())),
        ("generation", store.pin().generation().to_string()),
    ];
    let (name, value) = match args.command.as_str() {
        "profile" => {
            args.count(1)?;
            (
                "profile",
                json::profile(&view.profile(oid(args.get(0)?)?).map_err(social_error)?),
            )
        }
        "timeline" => {
            args.count(1)?;
            (
                "timeline",
                json::page(
                    &view
                        .timeline(oid(args.get(0)?)?, args.offset, args.limit)
                        .map_err(social_error)?,
                    json::timeline,
                ),
            )
        }
        "active-bios" => {
            args.count(1)?;
            (
                "active_bios",
                json::page(
                    &view
                        .active_bios(oid(args.get(0)?)?, args.offset, args.limit)
                        .map_err(social_error)?,
                    json::bio,
                ),
            )
        }
        "post-show" => {
            args.count(1)?;
            (
                "post",
                json::post(&view.post(rid(args.get(0)?)?).map_err(social_error)?),
            )
        }
        "posts" => {
            if args.values.len() > 1 {
                return Err("posts accepts at most one placement".into());
            }
            let placement = args.values.first().map(|v| placement(v)).transpose()?;
            (
                "posts",
                slice(&view.posts(placement), args.offset, args.limit, json::post)?,
            )
        }
        "thread" => {
            args.count(1)?;
            (
                "thread",
                slice(
                    &view.thread(rid(args.get(0)?)?).map_err(social_error)?,
                    args.offset,
                    args.limit,
                    json::post,
                )?,
            )
        }
        "stats" => {
            args.count(1)?;
            (
                "stats",
                json::stats(&view.stats(oid(args.get(0)?)?).map_err(social_error)?),
            )
        }
        "records" => {
            args.count(0)?;
            let records = store.archive().records().collect::<Vec<_>>();
            (
                "records",
                slice(&records, args.offset, args.limit, |r| {
                    json::record(r, &view)
                })?,
            )
        }
        "reaction" => {
            args.count(2)?;
            (
                "reaction",
                json::preference(
                    &view
                        .reaction(oid(args.get(0)?)?, rid(args.get(1)?)?)
                        .map_err(social_error)?,
                    json::reaction,
                ),
            )
        }
        "following" => {
            args.count(2)?;
            (
                "following",
                json::preference(
                    &view
                        .follow(oid(args.get(0)?)?, oid(args.get(1)?)?)
                        .map_err(social_error)?,
                    |v| v.to_string(),
                ),
            )
        }
        "repost-show" => {
            args.count(2)?;
            (
                "repost",
                json::preference(
                    &view
                        .repost(oid(args.get(0)?)?, rid(args.get(1)?)?)
                        .map_err(social_error)?,
                    |v| json::optional(*v, |v| json::id(v.as_bytes())),
                ),
            )
        }
        "votes" => {
            args.count(2)?;
            let votes = view
                .votes(PostRef {
                    post: rid(args.get(0)?)?,
                    revision: rid(args.get(1)?)?,
                })
                .map_err(social_error)?;
            let tally = |v: &Tally| {
                json::object(vec![("up", v.up.to_string()), ("down", v.down.to_string())])
            };
            (
                "votes",
                json::object(vec![
                    ("committed", json::measured(&votes.committed, tally)),
                    ("observed", json::measured(&votes.observed, tally)),
                ]),
            )
        }
        _ => return Err("unknown social command; see vhalla --help".into()),
    };
    fields.push((name, value));
    Ok(json::object(fields))
}
fn read_snapshot(path: &str) -> Result<Vec<u8>, String> {
    // Validate the descriptor, not an earlier pathname observation. Nonblocking
    // open rejects FIFO substitution without waiting while holding a store lock.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| format!("input file: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES as u64 {
        return Err("input must be a bounded regular snapshot file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SNAPSHOT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("snapshot too large".into());
    }
    Ok(bytes)
}
fn export(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("new export file: {e}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("export sync failed; partial output preserved: {e}"))?;
    let absolute = if Path::new(path).is_absolute() {
        Path::new(path).to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(absolute.parent().ok_or("export parent missing")?)
        .map_err(|e| format!("export directory open failed: {e}"))?;
    if !directory.metadata().map_err(|e| e.to_string())?.is_dir() {
        return Err("export parent is not a directory".into());
    }
    directory
        .sync_all()
        .map_err(|e| format!("export directory sync failed: {e}"))
}
pub fn run(raw: Vec<OsString>) -> Result<(), String> {
    if raw.len() == 2 && (raw[1] == "--help" || raw[1] == "-h") {
        println!("{}", help());
        return Ok(());
    }
    let args = Args::parse(raw)?;
    let output = if args.command == "init" {
        args.count(1)?;
        for path in [&args.store, args.get(0)?] {
            match fs::symlink_metadata(path){Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},_=>return Err("init requires nonexistent store and identity paths; partial state is never reset".into())}
        }
        let genesis_nonce = nonce()?;
        let key =
            Identity::create_new(args.get(0)?).map_err(|e| format!("new owner identity: {e:?}"))?;
        let mut store = Store::create(&args.store, args.realm, Limits::default())
            .map_err(|e| format!("{e}; owner key directory is preserved"))?;
        let record = sign(
            &key,
            Body::OwnerGenesis {
                controller: key.public_key(),
                recovery: None,
                nonce: genesis_nonce,
            },
        )?;
        let mut candidate = store.archive().clone();
        let owner = OwnerId::from_bytes(*insert(&mut candidate, &record)?.as_bytes());
        let mut fields = commit(&mut store, candidate)?;
        fields.extend([
            ("owner", json::id(owner.as_bytes())),
            ("controller", json::id(&key.public_key())),
        ]);
        json::object(fields)
    } else {
        let mut store = Store::open(&args.store, args.realm, Limits::default(), None)
            .map_err(|e| e.to_string())?;
        if args.command != "recover" && store.recovery_required().map_err(|e| e.to_string())? {
            return Err("retained publication requires explicit social recover before deriving or exporting state".into());
        }
        match args.command.as_str() {
            command if discovery::handles(command) => discovery::run(&args, &store)?,
            "post" | "reply" | "quote" | "revise" | "retract" | "react" | "follow" | "repost"
            | "bio" | "profile-set" => social_write(&args, &mut store)?,
            "enroll" | "grant" | "seal" | "ratify" | "revoke" | "retire" | "rotate" => {
                control_write(&args, &mut store)?
            }
            "import" => {
                args.count(1)?;
                let raw = read_snapshot(args.get(0)?)?;
                let candidate = store
                    .archive()
                    .merged_snapshot(&raw)
                    .map_err(social_error)?;
                json::object(commit(&mut store, candidate)?)
            }
            "export" => {
                args.count(1)?;
                export(args.get(0)?, &store.archive().snapshot())?;
                json::object(vec![
                    ("durable", "true".into()),
                    ("generation", store.pin().generation().to_string()),
                    ("root", json::id(store.pin().logical().as_bytes())),
                ])
            }
            "recover" => {
                args.count(0)?;
                let publication = store.recover().map_err(|e| e.to_string())?;
                json::object(vec![
                    ("durable", "true".into()),
                    ("generation", publication.pin().generation().to_string()),
                    ("root", json::id(publication.pin().logical().as_bytes())),
                    ("reconciled", publication.reconciled().to_string()),
                ])
            }
            "sync" => sync_dispatch(&args, &mut store)?,
            _ => query(&args, &store)?,
        }
    };
    // The escaped presentation has its own ceiling, separate from signed text
    // and query budgets. Never emit a partial JSON object on overflow.
    if output.len() > 2 * 1024 * 1024 {
        return Err("presentation exceeds 2 MiB; reduce --limit and inspect durable state before retrying a write".into());
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{output}")
        .and_then(|()| stdout.flush())
        .map_err(|e| {
            format!("output failed after operation; inspect durable store before retry: {e}")
        })
}

#[cfg(feature = "experimental-sync")]
fn sync_dispatch(args: &Args, store: &mut Store) -> Result<String, String> {
    sync::run(args, store)
}
#[cfg(not(feature = "experimental-sync"))]
fn sync_dispatch(_: &Args, _: &mut Store) -> Result<String, String> {
    Err("social sync requires an explicit build with --features experimental-sync".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Result<Args, String> {
        let mut raw = vec![
            "social".into(),
            "records".into(),
            "unused".into(),
            "00000000000000000000000000000001".into(),
        ];
        raw.extend(extra.iter().map(OsString::from));
        Args::parse(raw)
    }
    #[test]
    fn input_bounds_and_exact_ids_are_enforced_before_opening_any_store() {
        assert!(args(&["--limit", "0"]).is_err());
        assert!(args(&["--limit", "65"]).is_err());
        assert!(args(&["--now", "10", "--now", "11"]).is_err());
        assert!(args(&["--eligible", "abc"]).is_err());
        assert!(args(&[
            "--heads",
            &std::iter::repeat_n("ab".repeat(32), 17)
                .collect::<Vec<_>>()
                .join(",")
        ])
        .is_err());
        assert!(args(&[&"x".repeat(MAX_RECORD_BYTES + 1)]).is_err());
        assert!(hex32(&"é".repeat(32)).is_err());
        let parsed = args(&["--now", "10", "--", "--literal"]).unwrap();
        assert_eq!(parsed.now, 10);
        assert_eq!(parsed.values, vec!["--literal"]);
    }
    #[test]
    fn head_overflow_never_selects_an_implicit_winner() {
        let parsed = args(&["--now", "10"]).unwrap();
        assert!(heads::<bool>(&parsed, Register::Incomplete).is_err());
        let explicit = "ab".repeat(32);
        let parsed = args(&["--now", "10", "--heads", &explicit]).unwrap();
        assert_eq!(
            heads::<bool>(&parsed, Register::Incomplete)
                .unwrap()
                .as_slice(),
            &[rid(&explicit).unwrap()]
        );
        let resolved = Register::Resolved {
            heads: vec![RecordId::from_bytes([1; 32]), RecordId::from_bytes([2; 32])],
            value: true,
        };
        assert_eq!(
            heads(&args(&["--now", "10"]).unwrap(), resolved)
                .unwrap()
                .as_slice()
                .len(),
            2
        );
    }
}
