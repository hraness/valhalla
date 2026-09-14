//! SSR evidence for the room-directory screens: real projections
//! through the service boundary, pending-state badges, and the
//! collision and rejection surface a genuine journey needs.
use dioxus::prelude::*;
use std::rc::Rc;
use vhalla_room_directory_ui::ui::Route;

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
    vhalla_room_directory_ui::fixture_app()
}
fn render(route: Route) -> String {
    let mut dom = VirtualDom::new_with_props(root, RootProps { route });
    dom.rebuild_in_place();
    dioxus_ssr::render(&dom)
}

#[test]
fn directory_lists_committed_rooms_and_pending_states() {
    let html = render(Route::Directory {});
    assert!(html.contains("parlor"), "{html}");
    assert!(html.contains("signal-desk"), "{html}");
    assert!(
        html.contains("standing room for open design review"),
        "{html}"
    );
    // The pending strip surfaces every local submission state.
    assert!(html.contains("queued"), "{html}");
    assert!(html.contains("in flight"), "{html}");
    assert!(html.contains("name taken"), "{html}");
    assert!(html.contains("reading-room"), "{html}");
}

#[test]
fn room_detail_renders_committed_fields() {
    let html = render(Route::Room {
        slug: "signal-desk".into(),
    });
    assert!(html.contains("signal-desk"), "{html}");
    assert!(
        html.contains("Weekly sync notes and decision log"),
        "{html}"
    );
    assert!(html.contains("16 credits"), "{html}");
    assert!(html.contains("<dt>Revisions</dt><dd>2</dd>"), "{html}");
}

#[test]
fn unknown_room_reports_missing_not_empty() {
    let html = render(Route::Room {
        slug: "no-such-room".into(),
    });
    assert!(html.contains("Not found"), "{html}");
    assert!(html.contains("committed room"), "{html}");
}

#[test]
fn account_screen_renders_credit_fields() {
    let id = vhalla_room_directory_ui::ui::Id([7; 32]);
    let html = render(Route::Account { id });
    assert!(html.contains("Earned"), "{html}");
    assert!(html.contains("60 credits"), "{html}");
    assert!(html.contains("Lifetime rooms"), "{html}");
}

#[test]
fn create_form_anchors_the_submission_journey() {
    let html = render(Route::Create {});
    assert!(html.contains("New room"), "{html}");
    assert!(html.contains("Queue creation"), "{html}");
    assert!(html.contains("never signs"), "{html}");
}

#[test]
fn not_found_route_is_explicit() {
    let html = render(Route::NotFound {
        segments: vec!["deep".into(), "nowhere".into()],
    });
    assert!(html.contains("Not found"), "{html}");
}

#[test]
fn submission_journey_names_the_slug_in_pending() {
    use vhalla_room_directory_ui::services::RoomServices;
    let services = vhalla_room_directory_ui::FixtureServices::new();
    let before = services.pending().unwrap().len();
    let name = services
        .submit(0, Vec::new(), vec![b"room-create:quiet-hall".to_vec()])
        .unwrap();
    let pending = services.pending().unwrap();
    assert_eq!(pending.len(), before + 1);
    let marker = pending.iter().find(|p| p.name == name).unwrap();
    assert_eq!(marker.slug.as_deref(), Some("quiet-hall"));
    assert_eq!(marker.state, vhalla_rooms_app::PendingState::Queued);
    // And the strip projects it on the next render.
    let html = render(Route::Directory {});
    assert!(html.contains("queued"), "{html}");
}
