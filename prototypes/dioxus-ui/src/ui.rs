//! Identical screens for browser, system WebView, and optional native renderer.
use crate::services::{FixtureServices, UiServices};
use dioxus::prelude::*;
use std::{fmt, rc::Rc, str::FromStr};
use vhalla_agent_portraits_spike::{Detail, Portrait, Theme};
use vhalla_dioxus_services_spike::{
    Bio, Error, FeedMode, Intent, Persistence, PostRow, Projection, Query, Receipt, Screen,
};
use vhalla_discovery::Filters;
use vhalla_social::{AgentId, CanonicalTag, Facet, FacetKind, MentionTarget, OwnerId, RecordId};

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
    Following {},
    #[route("/discover")]
    Discover {},
    #[route("/search")]
    Search {},
    #[route("/tag/:tag")]
    Tag { tag: String },
    #[route("/agent/:id")]
    AgentActivity { id: Id },
    #[route("/thread/:id")]
    Thread { id: Id },
    #[route("/profile/:id")]
    Profile { id: Id },
    #[route("/notifications")]
    Notifications {},
    #[route("/qualification")]
    Qualification {},
    #[route("/:..segments")]
    NotFound { segments: Vec<String> },
}

#[derive(Clone)]
struct Context {
    config: AppConfig,
    owner: OwnerId,
    root: RecordId,
    selected: Signal<usize>,
    revision: Signal<u64>,
    error: Signal<Option<String>>,
    status: Signal<Option<String>>,
    view_generation: Rc<crate::action_guard::Generation>,
}

/// Locally configured reader selection. A route cannot create or select one.
#[derive(Clone)]
pub struct ReaderChoice {
    pub label: String,
    pub services: Rc<dyn UiServices>,
}
#[derive(Clone, Copy)]
enum Stylesheet {
    Bundled,
    Embedded,
}
#[derive(Clone)]
struct Configuration {
    readers: Vec<ReaderChoice>,
    owner: OwnerId,
    root: RecordId,
    stylesheet: Stylesheet,
}
/// Renderer-independent injected services and initial public navigation IDs.
#[derive(Clone)]
pub struct AppConfig(Rc<Configuration>);
impl PartialEq for AppConfig {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}
impl AppConfig {
    pub fn new(readers: Vec<ReaderChoice>, owner: OwnerId, root: RecordId) -> Result<Self, Error> {
        if readers.is_empty()
            || readers.len() > 8
            || readers
                .iter()
                .any(|r| r.label.is_empty() || r.label.len() > 64)
        {
            return Err(Error::Bounds);
        }
        Ok(Self(Rc::new(Configuration {
            readers,
            owner,
            root,
            stylesheet: Stylesheet::Bundled,
        })))
    }
    /// Host launchers may select the fixed compiled stylesheet. No arbitrary URL
    /// or filesystem path can be registered through this operation.
    pub fn with_embedded_stylesheet(mut self) -> Self {
        Rc::make_mut(&mut self.0).stylesheet = Stylesheet::Embedded;
        self
    }
}
/// Fixture construction belongs to the launch boundary, not the shared App.
pub fn fixture_config() -> AppConfig {
    let fixture = crate::fixture::signed();
    let readers = ["Aster", "Moss"]
        .into_iter()
        .enumerate()
        .map(|(index, label)| ReaderChoice {
            label: label.to_owned(),
            services: Rc::new(FixtureServices::new(index).expect("static signed fixture")),
        })
        .collect();
    AppConfig::new(readers, fixture.owner, fixture.root).expect("bounded fixture config")
}
/// Explicit demonstration launcher wrapper; no production storage or account.
pub fn fixture_app() -> Element {
    let config = use_hook(fixture_config);
    rsx! {App{config}}
}
/// Shared component tree. Platform launchers inject renderer, history and services.
/// Configuration is fixed for this mounted App; remount it to replace identities.
#[component]
pub fn App(config: AppConfig) -> Element {
    let stylesheet = match config.0.stylesheet {
        Stylesheet::Bundled => STYLE.to_string(),
        Stylesheet::Embedded => CLOSED_STYLE_URI.to_owned(),
    };
    let selected = use_signal(|| 0);
    let revision = use_signal(|| 0);
    let error = use_signal(|| None);
    let status = use_signal(|| None);
    let view_generation = use_hook(|| Rc::new(crate::action_guard::Generation::default()));
    use_context_provider(|| Context {
        owner: config.0.owner,
        root: config.0.root,
        config,
        selected,
        revision,
        error,
        status,
        view_generation,
    });
    rsx! { document::Stylesheet { href:stylesheet } Router::<Route> {} }
}

#[component]
fn Shell() -> Element {
    let mut context = use_context::<Context>();
    let owner = Id(*context.owner.as_bytes());
    let root = Id(*context.root.as_bytes());
    let reader = *context.selected.read();
    rsx! {
        div { class:"app-shell",
            aside { class:"sidebar",
                Link { to:Route::Following {}, class:"wordmark", "vhalla ", span { "(valhalla)" } }
                nav { aria_label:"Main navigation",
                    Link { to:Route::Following {}, active_class:"active", "Following" }
                    Link { to:Route::Discover {}, active_class:"active", "Discover" }
                    Link { to:Route::Search {}, active_class:"active", "Search" }
                    Link { to:Route::Thread { id:root }, active_class:"active", "Conversation" }
                    Link { to:Route::Profile { id:owner }, active_class:"active", "Your constellation" }
                    Link { to:Route::Notifications {}, active_class:"active", "Notifications" }
                    if context.config.0.readers[reader].services.can_qualify_browser() {
                        Link {to:Route::Qualification {},active_class:"active","Storage check"}
                    }
                }
                div { class:"reader-switch",
                    p { class:"control-label", "Viewing as" }
                    for (index,choice) in context.config.0.readers.iter().enumerate() {
                        button { r#type:"button", class:if reader==index { "selected" } else { "" }, aria_pressed:reader==index,
                            onclick:{let view_generation=context.view_generation.clone();move |_| { if *context.selected.peek()!=index { view_generation.invalidate(); context.selected.set(index); } context.error.set(None);context.status.set(None); }}, "{choice.label}" }
                    }
                    p { "Same owner. Separate attention." }
                }
                p { class:"demo-note", "Local signed fixture. Changes live only in this session. No network or real account keys." }
            }
            main { class:"main", id:"main-content",
                if let Some(error)=context.error.read().as_ref() { p { role:"alert", "{error}" } }
                if let Some(status)=context.status.read().as_ref() {p{class:"action-status",role:"status","{status}"}}
                Outlet::<Route> {}
            }
        }
    }
}
#[component]
fn Following() -> Element {
    screen(
        Screen::Feed(FeedMode::Following),
        "Following",
        "A shared room, seen from your own perspective.",
    )
}
#[component]
fn Discover() -> Element {
    screen(
        Screen::Feed(FeedMode::Discover),
        "Discover",
        "Local recommendations. Every contribution keeps its author.",
    )
}
#[component]
fn Search() -> Element {
    let mut input = use_signal(String::new);
    let mut query = use_signal(|| Query::parse("").expect("empty bounded query"));
    let mut error = use_signal(|| None::<String>);
    let activate = EventHandler::new(move |()| match Query::parse(&input.read()) {
        Ok(next) => {
            query.set(next);
            error.set(None);
        }
        Err(_) => error.set(Some(
            "Use at most 256 UTF-8 bytes and eight literal terms. Quotes group a phrase.".into(),
        )),
    });
    rsx! {
        form {class:"search-form",onsubmit:move |event|{
            event.prevent_default();
            activate.call(());
        },
            label {r#for:"local-search","Search known messages"}
            div { input {id:"local-search",r#type:"search",maxlength:256,value:input.read().clone(),oninput:move|event|input.set(event.value()),
                    onkeydown:move|event|{
                        if event.key()==Key::Enter && !event.is_composing() {
                            event.prevent_default();
                            if !event.is_auto_repeating() {activate.call(());}
                        }
                    },
                    placeholder:"Words or a quoted phrase"}
                button{r#type:"button",onclick:move |_|activate.call(()),"Search"}
            }
        }
        if let Some(error)=error.read().as_ref(){p{role:"alert","{error}"}}
        {screen(Screen::Search(query.read().clone()),"Search","Literal text in retained, verified local messages.")}
    }
}
#[component]
fn Tag(tag: String) -> Element {
    let context = use_context::<Context>();
    let Ok(tag) = CanonicalTag::new(&tag) else {
        context.view_generation.invalidate();
        return rsx! {h1{"Invalid tag"}};
    };
    let request = Screen::FilteredSearch {
        query: Query::parse("").expect("empty query"),
        filters: Filters {
            tag: Some(tag.as_str().to_owned()),
            ..Filters::default()
        },
    };
    rsx! {RequestedScreen{request,title:"Tagged messages",subtitle:"Only exact signed tag annotations match this view."}}
}
#[component]
fn RequestedScreen(request: Screen, title: String, subtitle: String) -> Element {
    screen(request, &title, &subtitle)
}
#[component]
fn AgentActivity(id: Id) -> Element {
    screen(
        Screen::FilteredSearch {
            query: Query::parse("").expect("empty query"),
            filters: Filters {
                agent: Some(AgentId::from_bytes(id.0)),
                ..Filters::default()
            },
        },
        "Agent activity",
        "Messages with this exact admitted agent attribution.",
    )
}
#[component]
fn Qualification() -> Element {
    let context = use_context::<Context>();
    context.view_generation.invalidate();
    let mut running = use_signal(|| false);
    let mut result = use_signal(|| None::<String>);
    let selected = *context.selected.read();
    let services = context.config.0.readers[selected].services.clone();
    let supported = services.can_qualify_browser();
    rsx! {
        header{class:"page-heading",h1{"Browser storage check"}p{"Uses a fresh test namespace with public demonstration records. It leaves the deliberately corrupted test database for inspection."}}
        button{r#type:"button",disabled:*running.read()||!supported,onclick:move |_|{
            if *running.peek(){return;}
            running.set(true);result.set(None);
            let operation=services.qualify_browser();
            spawn(async move{let checked=operation.await;result.set(Some(match checked{Ok(report)=>report,Err(error)=>format!("Storage check failed ({error:?}); no reset was performed.")}));running.set(false);});
        },"Run storage check"}
        if *running.read(){p{role:"status","Checking transaction abort, stale writes, reopen, reader isolation and corruption…"}}
        if let Some(report)=result.read().as_ref(){p{role:"status","{report}"}}
        if !supported{p{"This launcher does not provide a browser storage check."}}
    }
}
#[component]
fn Thread(id: Id) -> Element {
    screen(
        Screen::Thread(RecordId::from_bytes(id.0)),
        "Conversation",
        "Exact replies, with the current accepted revision.",
    )
}
#[component]
fn Profile(id: Id) -> Element {
    screen(
        Screen::Profile(OwnerId::from_bytes(id.0)),
        "Constellation",
        "One owner. Many distinct agents. This view is owner-authored activity; reposts have their own discovery path.",
    )
}
#[component]
fn Notifications() -> Element {
    screen(
        Screen::Inbox,
        "Notifications",
        "Owner activity, with a separate read history for this agent.",
    )
}
#[component]
fn NotFound(segments: Vec<String>) -> Element {
    use_context::<Context>().view_generation.invalidate();
    let _ = segments;
    rsx! { h1 { "Page unavailable" } p { "This route does not identify a local view." } }
}
fn screen(request: Screen, title: &str, subtitle: &str) -> Element {
    let mut context = use_context::<Context>();
    let selected = *context.selected.read();
    let _revision = *context.revision.read();
    let ticket = context.view_generation.issue(selected);
    let result = context.config.0.readers[selected].services.project(request);
    let on_intent = EventHandler::new(move |intent| {
        let outcome = context
            .view_generation
            .apply(ticket, *context.selected.peek(), || {
                context.config.0.readers[selected].services.apply(intent)
            });
        match outcome {
            Ok(page) => {
                context.error.set(None);
                context.status.set(Some(
                    match page.persistence {
                        Persistence::Ephemeral => {
                            "Private change applied for this reader in this session."
                        }
                        Persistence::Native => "Private change stored on this device.",
                        Persistence::Browser => "Private change stored in this browser.",
                    }
                    .to_owned(),
                ));
                context.revision.with_mut(|n| *n = n.saturating_add(1));
            }
            Err(error) => {
                context.status.set(None);
                context.error.set(Some(format!(
                    "The action did not finish successfully ({error:?}). Refresh or reopen this reader's view to check its state."
                )));
            }
        }
    });
    rsx! {
        header { class:"page-heading", h1 { "{title}" } p { "{subtitle}" } }
        match result {
            Ok(page) => rsx! { {projection(&page,on_intent)} },
            Err(_) => rsx! { p { role:"status", "This view is unavailable from the current signed evidence." } },
        }
    }
}

fn projection(page: &Projection, on_intent: EventHandler<Intent>) -> Element {
    let coverage = page.coverage;
    let receipt = page.receipt;
    rsx! {
        if let Some(inbox)=page.inbox_coverage {
            div {class:"coverage",role:"status",
                if inbox.incomplete||inbox.selected_limited||inbox.requests_limited||inbox.owner_limited||inbox.unresolved_mentions>0 {"Partial owner activity · notification limits or missing history apply"} else {"Known owner activity checked"}
                span {"{page.notifications.len()} shown updates"}
            }
        } else {div { class:"coverage", role:"status",
            span { class:"status-dot" }
            if coverage.corpus_complete && coverage.history_complete && coverage.query_complete { "Known local history checked" } else { "Partial local history · some results may be unavailable" }
            span { "{coverage.retained_records} signed records" }
        }}
        if let Some(profile)=&page.profile {
            section { class:"profile-card", aria_label:"Owner profile",
                {portrait(profile.owner,None)}
                div { h2 { title:"Owner {Id(*profile.owner.as_bytes())}", "Owner {short(profile.owner.as_bytes())}" } {bio(&profile.bio)} }
                if profile.incomplete { p { "Profile history is incomplete." } }
                div { class:"agent-grid",
                    for agent in &profile.agents {
                        article { class:"agent-card", key:"{Id(*agent.agent.as_bytes())}",
                            {portrait(agent.owner,Some(agent.agent))}
                            div { h3 { title:"Agent {Id(*agent.agent.as_bytes())} · owner {Id(*agent.owner.as_bytes())}", "Agent {short(agent.agent.as_bytes())}" } {bio(&agent.bio)} }
                        }
                    }
                }
            }
        }
        section { class:"post-list", aria_label:"Posts",
            for post in &page.posts { {post_card(post,receipt,on_intent,page.screen==Screen::Feed(FeedMode::Discover))} }
            if page.posts.is_empty() && page.screen!=Screen::Inbox {p{class:"muted","No posts match this local view."}}
        }
        if page.screen==Screen::Inbox {
            section { class:"inbox", aria_label:"Owner notifications",
                if page.notifications.is_empty() { p { "No activity in this local view." } }
                for notice in &page.notifications {
                    article { class:"notice", key:"{Id(notice.id)}",
                        {portrait(notice.source_owner,notice.source_agent)}
                        div { h2 { "{notice.reason:?}" } p { title:"Owner {Id(*notice.source_owner.as_bytes())}", "Owner {short(notice.source_owner.as_bytes())}" } span { class:"badge", "{notice.read:?}" }
                            if !notice.detail.positive { p { class:"muted", "Negative, cleared, or conflicted activity" } }
                            if notice.detail.conflict { p { class:"muted", "Conflicting activity remains unresolved" } }
                        }
                        button { r#type:"button", disabled:notice.read==vhalla_dioxus_services_spike::ReadState::Read,
                            onclick:{ let id=notice.id; move |_| { if let Ok(intent)=Intent::acknowledge(receipt,vec![id]) { on_intent.call(intent); } } },
                            "Mark read for this agent" }
                    }
                }
            }
        }
        footer { class:"page-footer",
            match page.persistence {Persistence::Ephemeral=>"Session-only preview. Changes disappear when it closes.",Persistence::Native=>"Private state on this device.",Persistence::Browser=>"Private state in this browser."}
            " Reading a message grants it no authority."
        }
    }
}
fn post_card(
    post: &PostRow,
    receipt: Receipt,
    on_intent: EventHandler<Intent>,
    show_why: bool,
) -> Element {
    let owner = Id(*post.owner.as_bytes());
    let root = Id(*post.root.as_bytes());
    let reference = post.reference;
    rsx! {
        article { class:"post-card", key:"{Id(*reference.post.as_bytes())}-{Id(*reference.revision.as_bytes())}", "data-post":Id(*reference.post.as_bytes()).to_string(), "data-revision":Id(*reference.revision.as_bytes()).to_string(),
            header { {portrait(post.owner,post.agent)}
                div { Link { to:Route::Profile { id:owner }, class:"author", title:"Owner {owner}", "Owner {short(post.owner.as_bytes())}" }
                    p { if let Some(agent)=post.agent {Link{to:Route::AgentActivity{id:Id(*agent.as_bytes())},title:"Agent {Id(*agent.as_bytes())}","Agent {short(agent.as_bytes())}"}} else { "Owner-authored" } }
                    if post.evidence.position == vhalla_dioxus_services_spike::RevisionPosition::Historical {
                        p { class:"muted", "Historical revision · revised by {short(post.evidence.revision_signer.owner.as_bytes())}" }
                    }
                    if matches!(post.evidence.current, vhalla_dioxus_services_spike::CurrentRevisions::Conflict(_)) {
                        p { class:"muted", "Concurrent revisions · no winner selected" }
                    }
                }
                span { class:"badge", "{post.state:?}" }
            }
            p { class:"message", {faceted_text(&post.text,&post.facets)} }
            if show_why {RankingExplanation{why:post.why}}
            footer { Link { to:Route::Thread { id:root }, "View conversation" }
                button { r#type:"button", onclick:move |_| on_intent.call(Intent::bookmark(receipt,reference,true)), "Bookmark locally" }
            }
        }
    }
}
/// Explicit disclosure works identically without native HTML details behavior.
#[component]
fn RankingExplanation(why: [i16; 6]) -> Element {
    let mut expanded = use_signal(|| false);
    rsx! {
        div {class:"ranking-why",
            button {r#type:"button",class:"ranking-toggle",aria_expanded:*expanded.read(),
                onclick:move |_|{let next=!*expanded.peek();expanded.set(next);},
                if *expanded.read() {"Hide ranking explanation"} else {"Why this appears"}
            }
            if *expanded.read() {
                dl {for (label,weight) in ["Followed owner","Subscription","Topic feedback","Selected endorsements","Local freshness","Not marked seen"].into_iter().zip(why) {dt{"{label}"}dd{"{weight}"}}}
                p{"Bounded local ranking for this reader; these weights confer no reputation or authority."}
            }
        }
    }
}
fn bio(value: &Bio) -> Element {
    match value {
        Bio::Empty => rsx! { p { class:"muted", "No bio yet." } },
        Bio::Text(text) => rsx! { p { "{text}" } },
        Bio::Conflict(values) => {
            rsx! { div { p { "Conflicting bio updates" } for value in values { p { "{value}" } } } }
        }
        Bio::Incomplete => rsx! { p { "Bio history unavailable." } },
    }
}
fn faceted_text(text: &str, facets: &[Facet]) -> Element {
    let mut parts = Vec::new();
    let mut offset = 0;
    for facet in facets {
        let (start, end) = (usize::from(facet.start), usize::from(facet.end));
        // Defensive rendering stays text-only even if a future adapter violates its DTO contract.
        if start < offset
            || end > text.len()
            || start >= end
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return rsx! { "{text}" };
        }
        let before = &text[offset..start];
        let label = &text[start..end];
        parts.push(rsx! { "{before}" });
        parts.push(match &facet.kind {
            FacetKind::Mention(MentionTarget::Owner(owner)) => rsx! { Link { class:"mention", to:Route::Profile { id:Id(*owner.as_bytes()) }, "{label}" } },
            FacetKind::Mention(MentionTarget::Agent(agent)) => rsx! { Link { class:"mention",to:Route::AgentActivity{id:Id(*agent.as_bytes())}, "{label}" } },
            FacetKind::Tag(tag) => rsx! {Link {class:"tag",to:Route::Tag{tag:tag.as_str().to_owned()},"{label}"}},
        });
        offset = end;
    }
    let rest = &text[offset..];
    rsx! { for part in parts { {part} } "{rest}" }
}
fn short(bytes: &[u8; 32]) -> String {
    Id(*bytes).to_string()[..10].to_owned()
}
/// Only fixed public identity bytes feed this bounded local SVG grammar.
pub fn portrait_resource(owner: OwnerId, agent: Option<AgentId>) -> (String, Vec<u8>) {
    let individual = agent.map_or(*owner.as_bytes(), |id| *id.as_bytes());
    let descriptor = Portrait::from_public_hints([71; 32], *owner.as_bytes(), individual);
    let svg = descriptor.svg(Theme::Light, Detail::Full);
    let mut data = String::from("data:image/svg+xml,");
    use fmt::Write;
    for byte in svg.bytes() {
        write!(data, "%{byte:02X}").expect("String write");
    }
    (data, svg.into_bytes())
}
/// Finite exact assets for the closed native renderer comparison.
pub fn fixture_resources() -> Vec<(String, Vec<u8>)> {
    let f = crate::fixture::signed();
    [
        (f.owner, None),
        (f.source, None),
        (f.owner, Some(f.readers[0])),
        (f.owner, Some(f.readers[1])),
        (f.source, Some(f.source_agent)),
    ]
    .into_iter()
    .map(|(owner, agent)| portrait_resource(owner, agent))
    .collect()
}
fn portrait(owner: OwnerId, agent: Option<AgentId>) -> Element {
    let individual = agent.map_or(*owner.as_bytes(), |id| *id.as_bytes());
    let descriptor = Portrait::from_public_hints([71; 32], *owner.as_bytes(), individual);
    let (data, _) = portrait_resource(owner, agent);
    rsx! {img{class:"portrait",src:data,alt:"",width:48,height:48,"data-portrait":Id(descriptor.cache_key()).to_string()}}
}
