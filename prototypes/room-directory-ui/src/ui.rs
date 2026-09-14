//! The shared component tree for the room-directory companion. Screens
//! only ever render `vhalla_rooms_app` projections — the same surface
//! the desktop, browser and any future native renderer consume.
use crate::services::{FixtureServices, RoomServices};
use dioxus::prelude::*;
use std::{fmt, rc::Rc, str::FromStr};
use vhalla_rooms_app::{PendingState, RoomRow, Screen};

pub const STYLE: Asset = asset!("/assets/screen.css");
pub const STYLE_BYTES: &[u8] = include_bytes!("../assets/screen.css");
/// Fixed host-selected URI for the exact embedded CSS bytes, never a caller URL.
pub const CLOSED_STYLE_URI: &str = "dioxus://index.html/assets/vhalla-screen.css";

/// Public route identifier, parsed canonically without granting source admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Id(pub [u8; 32]);
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl FromStr for Id {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err("expected a canonical public ID");
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid ID")?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Routable, Debug, PartialEq)]
pub enum Route {
    #[layout(Shell)]
    #[route("/")]
    Directory {},
    #[route("/room/:slug")]
    Room { slug: String },
    #[route("/account/:id")]
    Account { id: Id },
    #[route("/new")]
    Create {},
    #[route("/:..segments")]
    NotFound { segments: Vec<String> },
}

#[derive(Clone)]
struct Context {
    services: Rc<dyn RoomServices>,
    status: Signal<Option<String>>,
    error: Signal<Option<String>>,
    /// Bumped whenever a local action lands so projections re-run.
    revision: Signal<u64>,
}

/// Explicit demonstration launcher wrapper; no production storage or account.
pub fn fixture_app() -> Element {
    rsx! {App{}}
}

/// Shared component tree. The mounted App's services are fixed; remount
/// to switch service sources.
#[component]
pub fn App() -> Element {
    let status = use_signal(|| None);
    let error = use_signal(|| None);
    let revision = use_signal(|| 0);
    use_context_provider(|| Context {
        services: Rc::new(FixtureServices::new()),
        status,
        error,
        revision,
    });
    rsx! { document::Stylesheet { href:STYLE } Router::<Route> {} }
}

#[component]
fn Shell() -> Element {
    let context = use_context::<Context>();
    rsx! {
        div { class:"app-shell",
            aside { class:"sidebar",
                Link { to:Route::Directory {}, class:"wordmark", "vhalla ", span { "(valhalla)" } }
                nav { aria_label:"Main navigation",
                    Link { to:Route::Directory {}, active_class:"active", "Rooms" }
                    Link { to:Route::Create {}, active_class:"active", "New room" }
                }
                p { class:"demo-note", "Read replica of a hosted room node. Submissions drop as signed bodies into the node intake; nothing here holds keys or consensus authority." }
            }
            main { class:"main", id:"main-content",
                if let Some(error)=context.error.read().as_ref() { p { role:"alert", "{error}" } }
                if let Some(status)=context.status.read().as_ref() {p{class:"action-status",role:"status","{status}"}}
                Outlet::<Route> {}
            }
        }
    }
}

fn pending_label(state: &PendingState) -> &'static str {
    match state {
        PendingState::Queued => "queued",
        PendingState::Submitted => "in flight",
        PendingState::Committed => "committed",
        PendingState::Collision => "name taken",
        PendingState::Rejected => "not admitted",
    }
}

#[component]
fn PendingStrip() -> Element {
    let context = use_context::<Context>();
    let _ = *context.revision.read();
    let pending = context.services.pending().unwrap_or_default();
    if pending.is_empty() {
        return rsx! {};
    }
    rsx! {
        section { class:"pending-strip", aria_label:"Your submissions",
            for item in pending.iter() {
                p { class:"pending-item",
                    span { class:match item.state { PendingState::Collision | PendingState::Rejected => "pending-badge problem", _ => "pending-badge" }, "{pending_label(&item.state)}" }
                    if let Some(slug) = &item.slug {
                        " ", strong { "{slug}" }
                    }
                    match item.state {
                        PendingState::Collision => rsx!{ span { class:"muted", " — another room claimed this slug" } },
                        PendingState::Rejected => rsx!{ span { class:"muted", " — the node could not apply it" } },
                        _ => rsx!{ span { class:"muted mono", " {short_id(&item.name)}" } },
                    }
                }
            }
        }
    }
}

fn short_id(name: &str) -> String {
    name.chars().take(12).collect()
}

#[component]
fn RoomTable(rooms: Vec<RoomRow>) -> Element {
    if rooms.is_empty() {
        return rsx! { p { class:"muted", "No rooms match." } };
    }
    rsx! {
        ul { class:"room-list",
            for room in rooms {
                li { key:"{room.record}",
                    Link { to:Route::Room { slug: room.slug.clone() },
                        strong { "{room.slug}" }
                    }
                    " ", span { class:"muted", "{room.description}" }
                    div { class:"room-meta",
                        span { "slot {room.slot}" }
                        span { "{room.charge} credits" }
                        span { "{room.revisions} revisions" }
                        if room.archived { span { class:"pending-badge problem", "archived" } }
                    }
                }
            }
        }
    }
}

#[component]
fn Directory() -> Element {
    let context = use_context::<Context>();
    let mut query = use_signal(String::new);
    let _ = *context.revision.read();
    let projection = context
        .services
        .project(&Screen::Directory {
            query: query.read().clone(),
        })
        .ok();
    rsx! {
        h1 { "Rooms" }
        PendingStrip {}
        input {
            r#type:"search",
            class:"directory-search",
            placeholder:"Filter rooms",
            aria_label:"Filter rooms",
            value:"{query}",
            oninput:move |event| query.set(event.value()),
        }
        match projection {
            Some(p) => rsx! {
                RoomTable { rooms: p.rooms }
                if p.partial { p { class:"muted", "Directory scan stopped at its bound — narrow the filter." } }
            },
            None => rsx! { p { class:"muted", "The replica has no committed state yet." } },
        }
    }
}

#[component]
fn Room(slug: String) -> Element {
    let context = use_context::<Context>();
    let _ = *context.revision.read();
    let projection = context
        .services
        .project(&Screen::Room { slug: slug.clone() })
        .ok();
    rsx! {
        PendingStrip {}
        match projection.and_then(|p| p.rooms.into_iter().next()) {
            Some(room) => rsx! {
                h1 { "{room.slug}" }
                p { "{room.description}" }
                dl { class:"room-detail",
                    dt { "Owner" } dd { class:"mono", "{short_id(&room.owner)}…" }
                    dt { "Agent" } dd { class:"mono", "{short_id(&room.agent)}…" }
                    dt { "Slot" } dd { "{room.slot}" }
                    dt { "Charge" } dd { "{room.charge} credits" }
                    dt { "Created" } dd { "{room.created_at}" }
                    dt { "Record" } dd { class:"mono", "{short_id(&room.record)}…" }
                    dt { "Head" } dd { class:"mono", "{short_id(&room.head)}…" }
                    dt { "Revisions" } dd { "{room.revisions}" }
                    if room.archived { dt { "State" } dd { "archived — slug retained" } }
                }
            },
            None => rsx! {
                h1 { "Not found" }
                p { class:"muted", "No committed room is named \"{slug}\"." }
            },
        }
    }
}

#[component]
fn Account(id: Id) -> Element {
    let context = use_context::<Context>();
    let _ = *context.revision.read();
    let owner = vhalla_social::OwnerId::from_bytes(id.0);
    let projection = context.services.project(&Screen::Account { owner }).ok();
    rsx! {
        h1 { "Account" }
        p { class:"mono muted", "{id}" }
        match projection.and_then(|p| p.account) {
            Some(account) => rsx! {
                dl { class:"room-detail",
                    dt { "Earned" } dd { "{account.earned} credits" }
                    dt { "Spent" } dd { "{account.spent} credits" }
                    dt { "Lifetime rooms" } dd { "{account.lifetime_slots}" }
                }
            },
            None => rsx! { p { class:"muted", "No account on the committed registry." } },
        }
    }
}

#[component]
fn Create() -> Element {
    let mut context = use_context::<Context>();
    let mut slug = use_signal(String::new);
    let mut description = use_signal(String::new);
    let slug_ok = {
        let s = slug.read();
        !s.is_empty()
            && s.len() <= 24
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    rsx! {
        h1 { "New room" }
        PendingStrip {}
        p { class:"muted", "A room claim is a signed creation record plus its funding evidence, dropped into the node intake as a body. The node assembles and proposes it; this screen never signs." }
        form { class:"create-form",
            onsubmit:move |event| {
                event.prevent_default();
                if !slug_ok { context.error.set(Some("slug must be 1-24 lowercase letters, digits or '-'".into())); return; }
                // The fixture fabricates the signed record bytes; a real
                // deployment's signer adapter produces them instead.
                match context.services.submit(0, Vec::new(), Vec::new()) {
                    Ok(name) => {
                        let short = short_id(&name);
                        context.status.set(Some(format!("queued {short}")));
                        context.error.set(None);
                        *context.revision.write() += 1;
                        slug.set(String::new());
                        description.set(String::new());
                    }
                    Err(e) => context.error.set(Some(format!("{e:?}"))),
                }
            },
            label { "Slug"
                input { r#type:"text", value:"{slug}", maxlength:"24",
                    oninput:move |event| slug.set(event.value()) }
            }
            label { "Description"
                input { r#type:"text", value:"{description}", maxlength:"160",
                    oninput:move |event| description.set(event.value()) }
            }
            button { r#type:"submit", disabled:!slug_ok, "Queue creation" }
        }
    }
}

#[component]
fn NotFound(segments: Vec<String>) -> Element {
    rsx! {
        h1 { "Not found" }
        p { class:"muted", "No directory screen matches /{segments.join(\"/\")}." }
    }
}
