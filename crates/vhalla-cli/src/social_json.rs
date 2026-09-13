//! Structured terminal presentation: every string is escaped to ASCII JSON.
use vhalla_social::{view::*, *};

pub fn string(value: &str) -> String {
    let mut out = String::from("\"");
    for unit in value.encode_utf16() {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from_u32(u32::from(unit)).expect("ASCII")),
            _ => out.push_str(&format!("\\u{unit:04x}")),
        }
    }
    out.push('"');
    out
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn id(bytes: &[u8]) -> String {
    string(&hex(bytes))
}
pub fn object(fields: Vec<(&str, String)>) -> String {
    format!(
        "{{{}}}",
        fields
            .into_iter()
            .map(|(key, value)| format!("{}:{value}", string(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
pub fn ids(values: &[RecordId]) -> String {
    array(values.iter().map(|v| id(v.as_bytes())))
}
pub fn optional<T>(value: Option<T>, f: impl FnOnce(T) -> String) -> String {
    value.map(f).unwrap_or_else(|| "null".into())
}
pub fn basis(value: EvaluationBasis) -> String {
    object(vec![
        ("root", id(value.archive_root.as_bytes())),
        ("digest", id(&value.digest)),
        ("eligibility_digest", id(&value.eligibility_digest)),
        ("limits_digest", id(&value.limits_digest)),
        ("now", value.now.to_string()),
        ("policy_version", value.policy_version.to_string()),
        (
            "known_history_complete",
            value.known_history_complete.to_string(),
        ),
    ])
}
pub fn state(value: RecordState) -> String {
    string(match value {
        RecordState::Committed => "committed",
        RecordState::Provisional => "provisional",
        RecordState::Pending => "pending",
        RecordState::Rejected => "rejected",
        RecordState::Conflicted => "conflicted",
    })
}
pub fn register<T>(value: &Register<T>, f: impl Fn(&T) -> String) -> String {
    match value {
        Register::Empty => object(vec![("state", string("empty"))]),
        Register::Incomplete => object(vec![("state", string("incomplete"))]),
        Register::Resolved { heads, value } => object(vec![
            ("state", string("resolved")),
            ("heads", ids(heads)),
            ("value", f(value)),
        ]),
        Register::Conflict {
            heads,
            alternatives,
        } => object(vec![
            ("state", string("conflict")),
            ("heads", ids(heads)),
            ("alternatives", array(alternatives.iter().map(f))),
        ]),
    }
}
pub fn preference<T>(value: &Preference<T>, f: impl Fn(&T) -> String) -> String {
    object(vec![
        ("committed", register(&value.committed, &f)),
        ("observed", register(&value.observed, f)),
    ])
}
fn revision(value: &RevisionText<'_>) -> String {
    object(vec![
        ("revision", id(value.revision.as_bytes())),
        ("text", string(value.text)),
    ])
}
fn content(value: &Content<'_>) -> String {
    match value {
        Content::Present(value) => register(value, revision),
        Content::Retracted { records } => object(vec![
            ("state", string("retracted")),
            ("records", ids(records)),
        ]),
        Content::Incomplete => object(vec![("state", string("incomplete"))]),
    }
}
pub fn actor(value: Actor) -> String {
    match value {
        Actor::Owner { owner, control } => object(vec![
            ("kind", string("owner")),
            ("owner", id(owner.as_bytes())),
            ("control", id(control.as_bytes())),
        ]),
        Actor::Agent {
            owner,
            agent,
            grant,
        } => object(vec![
            ("kind", string("agent")),
            ("owner", id(owner.as_bytes())),
            ("agent", id(agent.as_bytes())),
            ("grant", id(grant.as_bytes())),
        ]),
    }
}
pub fn placement(value: Placement) -> String {
    string(&match value {
        Placement::Profile => "profile".into(),
        Placement::Channel(room) => format!("channel:{:032x}", room.0),
    })
}
fn reference(value: PostRef) -> String {
    object(vec![
        ("post", id(value.post.as_bytes())),
        ("revision", id(value.revision.as_bytes())),
    ])
}
pub fn post(value: &PostView<'_>) -> String {
    object(vec![
        ("id", id(value.id.as_bytes())),
        ("owner", id(value.attribution.owner.as_bytes())),
        ("actor", actor(value.attribution.actor)),
        ("placement", placement(value.placement)),
        (
            "profile_owner",
            optional(value.profile_owner, |v| id(v.as_bytes())),
        ),
        ("root", id(value.root.as_bytes())),
        (
            "reply",
            optional(value.reply, |v| {
                object(vec![
                    ("root", id(v.root.as_bytes())),
                    ("parent", reference(v.parent)),
                ])
            }),
        ),
        ("quote", optional(value.quote, reference)),
        (
            "quote_attribution",
            optional(value.quote_attribution, |v| {
                object(vec![
                    ("owner", id(v.owner.as_bytes())),
                    ("actor", actor(v.actor)),
                ])
            }),
        ),
        ("state", state(value.state)),
        ("committed", content(&value.committed)),
        ("observed", content(&value.observed)),
    ])
}
pub fn timeline(value: &TimelineEntry<'_>) -> String {
    match value {
        TimelineEntry::Post(value) => object(vec![("kind", string("post")), ("post", post(value))]),
        TimelineEntry::Repost(value) => object(vec![
            ("kind", string("repost")),
            ("owner", id(value.owner.as_bytes())),
            ("post", id(value.post.as_bytes())),
            (
                "preference",
                preference(&value.preference, |revision| {
                    optional(*revision, |v| id(v.as_bytes()))
                }),
            ),
            (
                "attribution",
                optional(value.attribution, |v| {
                    object(vec![
                        ("owner", id(v.owner.as_bytes())),
                        ("actor", actor(v.actor)),
                    ])
                }),
            ),
            ("source_incomplete", value.source_incomplete.to_string()),
            ("source_retracted", value.source_retracted.to_string()),
            ("source_state", optional(value.source_state, state)),
        ]),
    }
}
pub fn page<T>(value: &Page<T>, f: impl Fn(&T) -> String) -> String {
    object(vec![
        ("items", array(value.items.iter().map(f))),
        (
            "next_offset",
            optional(value.next_offset, |v| v.to_string()),
        ),
        ("known_total", value.known_total.to_string()),
    ])
}
pub fn bio(value: &AgentBioView<'_>) -> String {
    object(vec![
        ("agent", id(value.agent.as_bytes())),
        ("owner", id(value.owner.as_bytes())),
        ("key", id(&value.key)),
        ("bio", preference(&value.bio, |v| string(v))),
    ])
}
pub fn profile(value: &Profile<'_>) -> String {
    object(vec![
        ("owner", id(value.owner.as_bytes())),
        ("controller", optional(value.controller, |v| id(&v))),
        ("frozen", value.frozen.to_string()),
        ("incomplete", value.incomplete.to_string()),
        ("capacity_blocked", value.capacity_blocked.to_string()),
        ("profile", preference(&value.profile, |v| string(v))),
        ("active_bios", page(&value.active_bios, bio)),
    ])
}
pub fn measured<T>(value: &Measured<T>, f: impl Fn(&T) -> String) -> String {
    match value {
        Measured::Known(v) => object(vec![("state", string("known")), ("value", f(v))]),
        Measured::Incomplete => object(vec![("state", string("incomplete"))]),
    }
}
pub fn stats(value: &Stats) -> String {
    object(vec![
        (
            "committed_followers",
            measured(&value.committed_followers, |v| v.to_string()),
        ),
        (
            "observed_followers",
            measured(&value.observed_followers, |v| v.to_string()),
        ),
        (
            "observed_appreciation",
            measured(&value.observed_appreciation, |v| v.to_string()),
        ),
        (
            "eligible_appreciation",
            measured(&value.eligible_appreciation, |v| v.to_string()),
        ),
        ("committed_posts", value.committed_posts.to_string()),
        (
            "disputed_committed_posts",
            value.disputed_committed_posts.to_string(),
        ),
        (
            "committed_history_complete",
            value.committed_history_complete.to_string(),
        ),
        ("provisional_posts", value.provisional_posts.to_string()),
    ])
}
pub fn reaction(value: &Reaction) -> String {
    match value {
        Reaction::Clear => object(vec![("kind", string("clear"))]),
        Reaction::Up(v) => object(vec![("kind", string("up")), ("revision", id(v.as_bytes()))]),
        Reaction::Down(v) => object(vec![
            ("kind", string("down")),
            ("revision", id(v.as_bytes())),
        ]),
    }
}
pub fn operation(value: &Operation) -> String {
    let mut fields = vec![("supersedes", ids(value.supersedes()))];
    match value {
        Operation::Post {
            placement: p,
            text,
            reply,
            quote,
        } => fields.extend([
            ("kind", string("post")),
            ("placement", placement(*p)),
            ("text", string(text.as_str())),
            (
                "reply",
                optional(*reply, |v| {
                    object(vec![
                        ("root", id(v.root.as_bytes())),
                        ("parent", reference(v.parent)),
                    ])
                }),
            ),
            ("quote", optional(*quote, reference)),
        ]),
        Operation::Revise { post, text, .. } => fields.extend([
            ("kind", string("revise")),
            ("post", id(post.as_bytes())),
            ("text", string(text.as_str())),
        ]),
        Operation::Retract { post } => {
            fields.extend([("kind", string("retract")), ("post", id(post.as_bytes()))])
        }
        Operation::Repost { post, revision, .. } => fields.extend([
            ("kind", string("repost")),
            ("post", id(post.as_bytes())),
            ("revision", optional(*revision, |v| id(v.as_bytes()))),
        ]),
        Operation::React {
            post, reaction: r, ..
        } => fields.extend([
            ("kind", string("react")),
            ("post", id(post.as_bytes())),
            ("reaction", reaction(r)),
        ]),
        Operation::Follow {
            target, following, ..
        } => fields.extend([
            ("kind", string("follow")),
            ("target", id(target.as_bytes())),
            ("following", following.to_string()),
        ]),
        Operation::AgentBio { text, .. } => {
            fields.extend([("kind", string("bio")), ("text", string(text.as_str()))])
        }
        Operation::OwnerProfile { text, .. } => {
            fields.extend([("kind", string("profile")), ("text", string(text.as_str()))])
        }
    }
    object(fields)
}
pub fn record(value: &vhalla_social::VerifiedRecord, view: &View<'_>) -> String {
    let mut fields = vec![
        ("id", id(value.id().as_bytes())),
        ("primary_key", id(value.primary_key())),
    ];
    match value.body() {
        Body::Social {
            actor: a,
            sequence,
            previous,
            operation: op,
            ..
        } => fields.extend([
            ("kind", string("social")),
            ("actor", actor(*a)),
            ("sequence", sequence.to_string()),
            ("previous", optional(*previous, |v| id(v.as_bytes()))),
            ("operation", operation(op)),
            ("state", optional(view.state(value.id()), state)),
        ]),
        Body::OwnerGenesis { controller, .. } => fields.extend([
            ("kind", string("owner-genesis")),
            ("controller", id(controller)),
        ]),
        Body::AgentGenesis {
            owner,
            key,
            control,
            ..
        } => fields.extend([
            ("kind", string("agent-genesis")),
            ("owner", id(owner.as_bytes())),
            ("key", id(key)),
            ("control", id(control.as_bytes())),
        ]),
        Body::Control {
            owner,
            previous,
            action,
        } => fields.extend([
            ("kind", string("control")),
            ("owner", id(owner.as_bytes())),
            ("previous", id(previous.as_bytes())),
            ("action", string(&format!("{action:?}"))),
        ]),
    }
    object(fields)
}

#[cfg(test)]
mod tests {
    #[test]
    fn escaping_roundtrips_controls_and_supplementary_unicode_through_independent_parser() {
        let ascii = (0..=127u8).map(char::from).collect::<String>();
        for original in [
            ascii.as_str(),
            "\u{2028}\u{202e}\u{2066} 🦀 𐐀 \u{10ffff}",
            "<script>\"quoted\"\\end",
        ] {
            let encoded = super::string(original);
            assert!(encoded.bytes().all(|v| (0x20..=0x7e).contains(&v)));
            assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), original);
        }
    }
}
