//! Meaningful pure/SSR evidence. These tests do not launch or qualify a GUI.
use dioxus::prelude::*;
use std::rc::Rc;
use vhalla_dioxus_services_spike::{
    Bio, Error, FeedMode, Intent, Persistence, Query, ReadState, Screen,
};
use vhalla_dioxus_ui_spike::{
    fixture,
    services::{FixtureServices, UiServices},
    ui::{Id, Route},
};
use vhalla_discovery::Filters;
use vhalla_social::view::{Eligibility, RecordState, View};

#[derive(Clone, PartialEq, Props)]
struct RootProps {
    route: Route,
}
fn root(props: RootProps) -> Element {
    use_context_provider(|| {
        Rc::new(dioxus::history::MemoryHistory::with_initial_path(
            props.route,
        )) as Rc<dyn dioxus::history::History>
    });
    vhalla_dioxus_ui_spike::fixture_app()
}
fn render(route: Route) -> String {
    let mut dom = VirtualDom::new_with_props(root, RootProps { route });
    dom.rebuild_in_place();
    dioxus_ssr::render(&dom)
}

#[test]
fn signed_fixture_keeps_exact_revision_and_admitted_agent_bios() {
    let f = fixture::signed();
    let eligibility = Eligibility::default();
    let view = View::new(&f.archive, fixture::NOW, &eligibility);
    assert_eq!(view.state(f.root), Some(RecordState::Committed));
    assert_eq!(view.state(f.revision), Some(RecordState::Committed));
    assert_eq!(view.state(f.reply), Some(RecordState::Committed));
    let service = FixtureServices::new(0).unwrap();
    let page = service.project(Screen::Feed(FeedMode::Following)).unwrap();
    assert_eq!(page.posts.len(), 2);
    let current = page
        .posts
        .iter()
        .find(|p| p.reference.post == f.root)
        .unwrap();
    assert_eq!(current.reference.revision, f.revision);
    assert_eq!(current.text, fixture::HOSTILE);
    assert_eq!(current.facets.len(), 2);
    assert_eq!(current.owner, f.owner);
    assert_eq!(current.agent, Some(f.readers[0]));
    assert!(
        page.coverage.corpus_complete
            && page.coverage.history_complete
            && page.coverage.query_complete
    );
    assert_eq!(page.persistence, Persistence::Ephemeral);
    let profile = service
        .project(Screen::Profile(f.owner))
        .unwrap()
        .profile
        .unwrap();
    assert_eq!(profile.agents.len(), 2);
    assert!(profile
        .agents
        .iter()
        .all(|a| a.owner == f.owner && matches!(a.bio, Bio::Text(_))));
}

#[test]
fn exact_ack_is_private_to_reader_and_stale_receipts_cannot_apply() {
    let first = FixtureServices::new(0).unwrap();
    let sibling = FixtureServices::new(1).unwrap();
    let shown = first.project(Screen::Inbox).unwrap();
    assert!(!shown.notifications.is_empty());
    let entry = shown.notifications[0].id;
    assert!(shown
        .notifications
        .iter()
        .all(|n| n.read == ReadState::Unread));
    let next = first
        .apply(Intent::acknowledge(shown.receipt, vec![entry]).unwrap())
        .unwrap();
    assert_eq!(
        next.notifications
            .iter()
            .find(|n| n.id == entry)
            .unwrap()
            .read,
        ReadState::Read
    );
    let other = sibling.project(Screen::Inbox).unwrap();
    assert_ne!(shown.reader.digest(), other.reader.digest());
    assert!(other
        .notifications
        .iter()
        .all(|n| n.read == ReadState::Unread));
    assert_eq!(
        sibling
            .apply(Intent::acknowledge(shown.receipt, vec![entry]).unwrap())
            .unwrap_err(),
        Error::Stale
    );
    let old = first.project(Screen::Inbox).unwrap();
    first.project(Screen::Feed(FeedMode::Following)).unwrap();
    assert_eq!(
        first
            .apply(Intent::acknowledge(old.receipt, vec![entry]).unwrap())
            .unwrap_err(),
        Error::Stale
    );
}

#[test]
fn shared_component_escapes_hostile_text_and_uses_exact_typed_local_links() {
    let f = fixture::signed();
    let html = render(Route::Following {});
    assert!(
        html.contains("&lt;script&gt;alert(") || html.contains("&#60;script&#62;alert("),
        "{html}"
    );
    assert!(!html.contains("<script>"));
    assert!(!html.contains("An older draft"));
    assert!(html.contains(&format!("data-revision=\"{}\"", Id(*f.revision.as_bytes()))));
    assert!(html.contains(&format!("href=\"/profile/{}\"", Id(*f.source.as_bytes()))));
    assert!(html.contains(&format!("title=\"Owner {}\"", Id(*f.owner.as_bytes()))));
    assert!(html.contains(&format!("title=\"Agent {}\"", Id(*f.readers[0].as_bytes()))));
    assert!(html.contains("href=\"/tag/rust\""));
    assert!(html.contains("data:image/svg+xml,%3C%73%76%67"));
    assert!(!html.contains("<svg"));
    assert!(!html.contains("javascript:"));
    assert!(html.contains("No network or real account keys"));
}

#[test]
fn same_component_routes_show_thread_profile_and_inbox_from_signed_sources() {
    let f = fixture::signed();
    let thread = render(Route::Thread {
        id: Id(*f.root.as_bytes()),
    });
    assert!(thread.contains("build resilient agent games"));
    assert!(thread.contains(&format!("data-post=\"{}\"", Id(*f.reply.as_bytes()))));
    let profile = render(Route::Profile {
        id: Id(*f.owner.as_bytes()),
    });
    assert!(profile.contains("Aster · follows protocols and proofs"));
    assert!(profile.contains("Moss · explores games and living systems"));
    assert!(profile.contains(&format!("title=\"Owner {}\"", Id(*f.owner.as_bytes()))));
    assert!(profile.contains(&format!("title=\"Agent {}", Id(*f.readers[1].as_bytes()))));
    let inbox = render(Route::Notifications {});
    assert!(inbox.contains("Mention"));
    assert!(inbox.contains("Reply"));
    assert!(inbox.contains("Unread"));
    assert!(inbox.contains("Mark read for this agent"));
    assert!(inbox.contains("Known owner activity checked"));
    assert!(!inbox.contains("Known local history checked"));
}

#[test]
fn literal_queries_typed_tags_and_agent_routes_use_the_same_verified_projection() {
    let f = fixture::signed();
    let service = FixtureServices::new(0).unwrap();
    let searched = service
        .project(Screen::Search(
            Query::parse("\"resilient agent games\"").unwrap(),
        ))
        .unwrap();
    assert_eq!(searched.posts.len(), 1);
    assert_eq!(searched.posts[0].reference.post, f.reply);
    assert!(service
        .project(Screen::Search(Query::parse("missing-unicorn").unwrap()))
        .unwrap()
        .posts
        .is_empty());
    let tagged = service
        .project(Screen::FilteredSearch {
            query: Query::parse("").unwrap(),
            filters: Filters {
                tag: Some("rust".into()),
                ..Filters::default()
            },
        })
        .unwrap();
    assert_eq!(tagged.posts.len(), 2);
    let agent = service
        .project(Screen::FilteredSearch {
            query: Query::parse("").unwrap(),
            filters: Filters {
                agent: Some(f.readers[0]),
                ..Filters::default()
            },
        })
        .unwrap();
    assert_eq!(agent.posts.len(), 1);
    assert_eq!(agent.posts[0].reference.revision, f.revision);
    let html = render(Route::Tag { tag: "rust".into() });
    assert!(html.contains("Tagged messages"));
    assert!(html.contains(&format!("data-post=\"{}\"", Id(*f.reply.as_bytes()))));
    let ranked = render(Route::Discover {});
    assert!(ranked.contains("Why this appears"));
    assert!(ranked.contains("aria-expanded=\"false\"") || ranked.contains("aria-expanded=false"));
    assert!(!ranked.contains("Topic feedback"));
}

#[test]
fn fixed_portrait_resources_are_bounded_distinct_and_share_the_rendered_asset_bytes() {
    let first = vhalla_dioxus_ui_spike::fixture_resources();
    assert_eq!(first, vhalla_dioxus_ui_spike::fixture_resources());
    assert_eq!(first.len(), 5);
    assert_eq!(
        first
            .iter()
            .map(|(url, _)| url)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        5
    );
    for (url, bytes) in first {
        assert!(bytes.len() <= vhalla_agent_portraits_spike::MAX_SVG_BYTES);
        assert!(url.starts_with("data:image/svg+xml,%3C%73%76%67"));
        let svg = String::from_utf8(bytes).unwrap();
        assert!(!svg.contains("<script"));
        assert!(!svg.contains("foreignObject"));
        assert!(!svg.contains("href="));
    }
}

#[test]
fn public_route_parser_is_canonical_and_unknown_ids_grant_no_admission() {
    assert!("../keys".parse::<Id>().is_err());
    assert!("A".repeat(64).parse::<Id>().is_err());
    assert!("é".repeat(32).parse::<Id>().is_err());
    let missing = Id([0xff; 32]);
    assert_eq!(missing.to_string().parse::<Id>().unwrap(), missing);
    let html = render(Route::Profile { id: missing });
    assert!(html.contains("view is unavailable"));
    assert!(!html.contains("Agent "));
}
