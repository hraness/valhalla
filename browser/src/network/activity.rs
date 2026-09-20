//! Local-first room composition. A durable reservation always precedes signing.
use super::*;
use crate::ui;
use vhalla_browser_storage::{
    browser::outbox::IndexedOutbox,
    outbox::{AuthorHead, AuthorScope, ReservedDraft},
};
use vhalla_room_activity::{Content, EventClaims, RoomScope, UnsignedEvent};
use web_sys::{HtmlSelectElement, HtmlTextAreaElement};
#[path = "../composer_model.rs"]
mod composer_model;
#[path = "../recovery_room.rs"]
mod recovery_room;
use composer_model::{Context as ComposerContext, Draft as ComposerDraft};
thread_local! {
    static COMPOSER: RefCell<ComposerDraft> = RefCell::new(ComposerDraft::default());
    static COMPOSER_NAME: RefCell<Option<String>> = const { RefCell::new(None) };
}
fn current_composer_context(app: &App) -> Option<ComposerContext> {
    let state = app.borrow();
    let session = state.session.as_ref()?;
    if state.busy || state.failed || session.head != session.recovery_target {
        return None;
    }
    Some(ComposerContext {
        room: scope(app, session).ok()?,
        bootstrap_pin: session.head.scope().bootstrap_pin(),
        author: ui::activity_author().ok()?,
    })
}
fn remember_composer_name(app: &App, context: Option<ComposerContext>) {
    let name = context.and_then(|context| {
        let state = app.borrow();
        let session = state.session.as_ref()?;
        if session.client.network_id() != context.room.network
            || session.head.scope().bootstrap_pin() != context.bootstrap_pin
        {
            return None;
        }
        session
            .client
            .registry()
            .room_by_genesis(context.room.room)
            .map(|room| room.slug().as_str().to_owned())
    });
    COMPOSER_NAME.with(|saved| *saved.borrow_mut() = name);
}
fn render_composer_scope(app: &App) {
    let current = current_composer_context(app);
    let (label, details) = COMPOSER.with(|draft| {
        let draft = draft.borrow();
        match draft.context() {
            Some(context) => {
                let room = COMPOSER_NAME.with(|name| name.borrow().clone())
                    .unwrap_or_else(|| "original room".into());
                let author = hex(&context.author);
                let summary = format!("Public draft for {room} · author {}…{}. {}",
                    &author[..8], &author[56..],
                    if current == Some(context) { "Review before signing." }
                    else { "Return to this room and author to sign, or explicitly move the text." });
                let details = format!("Network: {}\nBootstrap: {}\nRealm: {}\nDirectory: {}\nRoom: {}\nAuthor: {}",
                    hex(&context.room.network), hex(&context.bootstrap_pin), context.room.realm.0,
                    hex(context.room.directory.as_bytes()), hex(context.room.room.as_bytes()), author);
                (summary, details)
            }
            None if draft.started() => ("This text has no destination yet. Unlock the intended author, select a room, then choose Use text in selected room.".into(), String::new()),
            None => ("New text stays with the selected room and unlocked author. Changing rooms will not move it.".into(), String::new()),
        }
    });
    let state = app.borrow();
    state
        .document
        .get_element_by_id("composer-scope")
        .unwrap()
        .set_text_content(Some(&label));
    state
        .document
        .get_element_by_id("composer-scope-details")
        .unwrap()
        .set_text_content(Some(&details));
}

fn message(app: &App, text: &str) {
    app.borrow()
        .document
        .get_element_by_id("activity-status")
        .unwrap()
        .set_text_content(Some(text));
}
fn selection(app: &App) -> HtmlSelectElement {
    app.borrow()
        .document
        .get_element_by_id("activity-room")
        .unwrap()
        .unchecked_into()
}
fn composer(app: &App) -> HtmlTextAreaElement {
    app.borrow()
        .document
        .get_element_by_id("activity-text")
        .unwrap()
        .unchecked_into()
}
fn scope(app: &App, session: &Session) -> Result<RoomScope, String> {
    let selected = selection(app).value();
    let registry = session.client.registry();
    let found = registry
        .search("", 32, 4096)
        .map_err(|_| "Could not read verified rooms.")?;
    let room = found
        .rooms
        .into_iter()
        .find(|r| hex(r.genesis().as_bytes()) == selected)
        .ok_or("Choose a verified room first.")?;
    Ok(RoomScope {
        network: session.client.network_id(),
        realm: registry.realm(),
        directory: registry.directory(),
        room: room.genesis(),
    })
}
// Recovery may inspect retained state for an archived room. This separate lookup
// never feeds composition or weakens the current posting-policy check below.
fn recovery_scope(app: &App, session: &Session) -> Result<RoomScope, String> {
    let explicit = field(app, "recovery-room-genesis").value();
    if explicit.is_empty() {
        return scope(app, session).map_err(|_| {
            "Choose a listed verified room or enter its full recovery room ID.".into()
        });
    }
    let registry = session.client.registry();
    let room = recovery_room::lookup(registry, &explicit)?;
    Ok(RoomScope {
        network: session.client.network_id(),
        realm: registry.realm(),
        directory: registry.directory(),
        room,
    })
}
fn reset_recovery_status(app: &App) {
    let status = app
        .borrow()
        .document
        .get_element_by_id("author-state-status")
        .unwrap();
    let _ = status.set_attribute("data-complete", "false");
    status.set_text_content(Some("Recovery target changed. Choose a verified room or enter its full recovery room ID, then unlock the matching identity. Saved author state and backup progress are preserved."));
}
fn permit(session: &Session, request: &UnsignedEvent) -> Result<(), String> {
    let claims = request.claims();
    let registry = session.client.registry();
    if claims.scope.network != session.client.network_id()
        || claims.scope.realm != registry.realm()
        || claims.scope.directory != registry.directory()
        || !registry
            .room_by_genesis(claims.scope.room)
            .is_some_and(|r| r.allows_public_activity(&claims.scope.network, claims.policy))
    {
        return Err("This room's current verified policy does not permit this post. The exact pending draft is preserved.".into());
    }
    Ok(())
}
async fn outbox() -> Result<IndexedOutbox, String> {
    IndexedOutbox::open(Namespace::new(PROFILE))
        .await
        .map_err(|_| "Could not open the local activity outbox.".into())
}
async fn head(
    app: &App,
    storage: &mut IndexedOutbox,
    scope: AuthorScope,
) -> Result<AuthorHead, String> {
    match storage.load_head(scope).await {
        Ok(Some(head)) => {
            if head.sequence() > 0 {
                // Tie the floor to its actual immutable signed bytes before authoring.
                let page = storage
                    .read_page(scope, head.sequence(), 1, 8192)
                    .await
                    .map_err(|_| {
                        app.borrow_mut().failed = true;
                        "Saved author history is incomplete. Preserve storage and reload before recovery."
                    })?;
                if page.head != head
                    || page.events.len() != 1
                    || page.events[0].id() != head.event_id()
                {
                    app.borrow_mut().failed = true;
                    return Err(
                        "Saved author history changed or is corrupt. Reload before continuing."
                            .into(),
                    );
                }
            }
            Ok(head)
        }
        Ok(None) => ui::authorize_fresh_activity_scope(scope).await,
        Err(_) => {
            app.borrow_mut().failed = true;
            Err("Could not read the saved author sequence. Reload before continuing.".into())
        }
    }
}
async fn sign_reserved(
    app: &App,
    session: &Session,
    storage: &mut IndexedOutbox,
    draft: &ReservedDraft,
    clear_composer: bool,
) -> Result<(), String> {
    // A later certified directory may leave the room's exact policy unchanged.
    // Rebind only the reservation metadata, never the signed draft or sequence.
    permit(session, draft.request())?;
    let mut retained = draft.clone();
    if draft.policy_head() != session.head {
        let next = ReservedDraft::new(draft.base(), session.head, draft.request().clone())
            .map_err(|_| "The pending draft cannot be rebound to this directory state.")?;
        storage.rebase_reservation(draft, &next).await.map_err(|_| {
            app.borrow_mut().failed = true;
            "Could not confirm the exact saved draft at the newer directory state. Reload to reconcile; the draft must not be replaced."
        })?;
        retained = next;
    }
    let draft = &retained;
    storage.reserve(draft).await.map_err(|_| {
        app.borrow_mut().failed = true;
        "The author or directory state changed, or storage failed. Reload to reconcile the exact pending draft."
    })?;
    message(app, "Draft saved. Signing with your unlocked identity…");
    let signed = ui::sign_activity(draft.request().clone()).await?;
    let verified = signed
        .verify()
        .map_err(|_| "The signing worker returned invalid evidence.")?;
    storage.finalize(draft, &verified).await.map_err(|_| {
        app.borrow_mut().failed = true;
        "Could not confirm local publication. Reload to reconcile; do not replace or discard the pending draft."
    })?;
    if clear_composer {
        composer(app).set_value("");
        COMPOSER.with(|draft| draft.borrow_mut().clear_saved());
        COMPOSER_NAME.with(|name| *name.borrow_mut() = None);
    }
    super::puzzles::observe(app, &verified);
    message(
        app,
        &format!(
            "Post {} saved in your local outbox. No peer delivery has been confirmed.",
            verified.claims().sequence
        ),
    );
    Ok(())
}
pub(super) fn selected_room_name(app: &App) -> String {
    let selected = selection(app).value();
    let document = app.borrow().document.clone();
    let element = document.get_element_by_id("activity-room").unwrap();
    let mut child = element.first_element_child();
    while let Some(option) = child {
        if option.get_attribute("value").as_deref() == Some(&selected) {
            return option.text_content().unwrap_or(selected);
        }
        child = option.next_element_sibling();
    }
    selected
}

async fn queue(
    app: &App,
    session: &Session,
    resume: bool,
    puzzle: Option<super::puzzles::PreparedPart>,
) -> Result<(), String> {
    let author = ui::activity_author()?;
    let scope = scope(app, session)?;
    let author_scope = AuthorScope::new(scope, author);
    // Check exact text and destination before any await or author-state write.
    // Resume uses its immutable reservation; puzzle preview remains separate.
    let typed = if !resume && puzzle.is_none() {
        let context = ComposerContext {
            room: scope,
            bootstrap_pin: session.head.scope().bootstrap_pin(),
            author,
        };
        Some(COMPOSER.with(|draft| draft.borrow().queue_text(&composer(app).value(), context))?)
    } else {
        None
    };
    if let Some(preview) = &puzzle {
        super::puzzles::validate_prepared(
            app,
            preview,
            scope,
            session.head.scope().bootstrap_pin(),
            author,
            false,
        )?;
    }
    let mut storage = outbox().await?;
    let retained = head(app, &mut storage, author_scope).await?;
    let pending = storage.load_pending(author_scope).await.map_err(|_| {
        app.borrow_mut().failed = true;
        "Could not read the pending draft. Reload before continuing."
    })?;
    let puzzle_content = puzzle
        .as_ref()
        .map(|preview| {
            super::puzzles::validate_prepared(
                app,
                preview,
                scope,
                session.head.scope().bootstrap_pin(),
                author,
                pending.is_some(),
            )
        })
        .transpose()?;
    let clear_composer = puzzle.is_none();
    if let Some(draft) = pending {
        if !resume {
            return Err("An exact draft is already reserved for this room. Use Resume saved draft; it cannot be replaced safely.".into());
        }
        if draft.base() != retained {
            app.borrow_mut().failed = true;
            return Err(
                "Pending draft and author floor disagree. Preserve storage and reload before recovery.".into(),
            );
        }
        // Resume must not discard unrelated unsaved composer text.
        return sign_reserved(app, session, &mut storage, &draft, false).await;
    }
    if resume {
        return Err("There is no pending draft in this room.".into());
    }
    let room = session
        .client
        .registry()
        .room_by_genesis(scope.room)
        .ok_or("The room no longer exists.")?;
    let policy = room
        .public_activity_policy()
        .filter(|p| room.allows_public_activity(&scope.network, p.record))
        .ok_or("Public activity is closed in this room.")?;
    let content = match puzzle_content {
        Some(content) => content,
        None => typed.ok_or("No scope-bound public text was prepared.")?,
    };
    let request = UnsignedEvent::new(EventClaims {
        scope,
        policy: policy.record,
        author,
        sequence: retained
            .sequence()
            .checked_add(1)
            .ok_or("This author's sequence is exhausted.")?,
        previous: retained.event_id(),
        created_at: now(app.borrow().clock_floor)?,
        content: Content::Text(content),
    })
    .map_err(|_| "The draft could not be encoded safely.")?;
    permit(session, &request)?;
    let draft = ReservedDraft::new(retained, session.head, request)
        .map_err(|_| "The draft does not extend the saved author sequence.")?;
    sign_reserved(app, session, &mut storage, &draft, clear_composer).await
}
async fn show(app: &App, session: &Session) -> Result<(), String> {
    let author = ui::activity_author()?;
    let scope = AuthorScope::new(scope(app, session)?, author);
    let mut storage = outbox().await?;
    let Some(head) = storage
        .load_head(scope)
        .await
        .map_err(|_| "Could not read the outbox.")?
    else {
        message(
            app,
            "There are no locally authored posts for this identity in this room.",
        );
        return Ok(());
    };
    let page = storage
        .read_page(
            scope,
            head.sequence().saturating_sub(15).max(1),
            16,
            128 * 1024,
        )
        .await
        .map_err(|_| "Saved activity could not be verified. Preserve storage before recovery.")?;
    let document = app.borrow().document.clone();
    let list = document.get_element_by_id("activity-list").unwrap();
    list.set_text_content(None);
    for event in page.events {
        super::puzzles::observe(app, &event);
        let item = document.create_element("article").unwrap();
        item.set_class_name("room-card");
        let label = document.create_element("small").unwrap();
        label.set_text_content(Some(&format!(
            "Your local post {} · {}",
            event.claims().sequence,
            hex(event.id().as_bytes())
        )));
        let text = document.create_element("p").unwrap();
        let Content::Text(content) = &event.claims().content;
        text.set_text_content(Some(content.as_str()));
        let _ = item.append_child(&label);
        let _ = item.append_child(&text);
        let _ = list.append_child(&item);
    }
    message(
        app,
        &format!(
            "Showing up to 16 recent local posts through sequence {}. These signatures identify your key; this view does not establish peer delivery.",
            head.sequence()
        ),
    );
    Ok(())
}
pub(super) fn render(app: &App, session: Option<&Session>, available: bool) {
    let select = selection(app);
    let previous = select.value();
    select.set_text_content(None);
    let ready = session.is_some_and(|s| s.head == s.recovery_target);
    if ready {
        let session = session.unwrap();
        if let Ok(found) = session.client.registry().search("", 32, 4096) {
            for room in found.rooms {
                let option = app.borrow().document.create_element("option").unwrap();
                let _ = option.set_attribute("value", &hex(room.genesis().as_bytes()));
                option.set_text_content(Some(room.slug().as_str()));
                let _ = select.append_child(&option);
            }
        }
    }
    if !previous.is_empty() {
        select.set_value(&previous);
    }
    if select.value() != previous {
        reset_recovery_status(app);
    }
    let room_selected = ready && !select.value().is_empty();
    let puzzle_room = session.filter(|_| ready).and_then(|s| scope(app, s).ok());
    super::puzzles::render(app, session, puzzle_room, available);
    select.set_disabled(!available || !ready || select.length() == 0);
    composer(app).set_disabled(!available || !room_selected);
    app.borrow()
        .document
        .get_element_by_id("use-composer-here")
        .unwrap()
        .unchecked_into::<HtmlButtonElement>()
        .set_disabled(!available || !room_selected);
    render_composer_scope(app);
    for id in ["import-author-file", "recovery-room-genesis"] {
        field(app, id).set_disabled(!available || !ready);
    }
    for id in [
        "queue-activity",
        "resume-activity",
        "show-outbox",
        "send-activity",
        "read-activity",
        "more-activity",
    ] {
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!available || !room_selected);
    }
    for id in ["export-author-state", "import-author-state"] {
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!available || !ready);
    }
}
pub(super) fn bind_actions(app: &App) {
    let draft_app = app.clone();
    let edited = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        if draft_app.borrow().busy || draft_app.borrow().failed {
            return;
        }
        let context = current_composer_context(&draft_app);
        let text = composer(&draft_app).value();
        let starting = COMPOSER.with(|draft| !draft.borrow().started());
        let result = COMPOSER.with(|draft| draft.borrow_mut().edit(&text, context));
        if starting || text.is_empty() {
            remember_composer_name(&draft_app, if text.is_empty() { None } else { context });
        }
        if let Err(error) = result {
            message(&draft_app, error);
        }
        render_composer_scope(&draft_app);
    });
    composer(app)
        .add_event_listener_with_callback("input", edited.as_ref().unchecked_ref())
        .unwrap();
    edited.forget();
    let move_app = app.clone();
    let use_here = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        if move_app.borrow().busy || move_app.borrow().failed {
            return;
        }
        let context = current_composer_context(&move_app);
        let result = context
            .ok_or("Unlock the intended identity and select a verified room first.")
            .and_then(|context| {
                COMPOSER.with(|draft| {
                    draft
                        .borrow_mut()
                        .use_here(&composer(&move_app).value(), context)
                })
            });
        match result {
            Ok(()) => {
                remember_composer_name(&move_app, context);
                message(&move_app, "Text now targets the selected public room and author. Review before signing; nothing was signed or sent.");
            }
            Err(error) => message(&move_app, error),
        }
        render_composer_scope(&move_app);
    });
    app.borrow()
        .document
        .get_element_by_id("use-composer-here")
        .unwrap()
        .add_event_listener_with_callback("click", use_here.as_ref().unchecked_ref())
        .unwrap();
    use_here.forget();
    let selected = selection(app);
    let changed_app = app.clone();
    let changed = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        let mut state = changed_app.borrow_mut();
        if state.busy || state.failed {
            return;
        }
        state.feed = None;
        state
            .document
            .get_element_by_id("activity-list")
            .unwrap()
            .set_text_content(None);
        state
            .document
            .get_element_by_id("activity-status")
            .unwrap()
            .set_text_content(Some(
                "Room selected. Read public posts or view your local outbox.",
            ));
        drop(state);
        reset_recovery_status(&changed_app);
        super::render(&changed_app);
    });
    selected
        .add_event_listener_with_callback("change", changed.as_ref().unchecked_ref())
        .unwrap();
    changed.forget();
    let recovery_input = field(app, "recovery-room-genesis");
    let recovery_app = app.clone();
    let recovery_changed = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
        let unavailable = {
            let state = recovery_app.borrow();
            state.busy || state.failed
        };
        if unavailable {
            return;
        }
        reset_recovery_status(&recovery_app);
        super::render(&recovery_app);
    });
    recovery_input
        .add_event_listener_with_callback("input", recovery_changed.as_ref().unchecked_ref())
        .unwrap();
    recovery_changed.forget();
    for (id, operation) in [
        ("queue-activity", 0),
        ("resume-activity", 1),
        ("show-outbox", 2),
        ("send-activity", 3),
        ("read-activity", 4),
        ("more-activity", 5),
        ("export-author-state", 6),
        ("import-author-state", 7),
        ("queue-puzzle", 8),
    ] {
        let app = app.clone();
        let document = app.borrow().document.clone();
        let callback = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            {
                let mut state = app.borrow_mut();
                if state.busy
                    || state.failed
                    || !state
                        .session
                        .as_ref()
                        .is_some_and(|s| s.head == s.recovery_target)
                {
                    return;
                }
                state.busy = true;
            }
            super::render(&app);
            let app = app.clone();
            launch(app.clone(), async move {
                let session = app.borrow_mut().session.take().unwrap();
                let result = match operation {
                    2 => show(&app, &session).await,
                    3 => deliver(&app, &session).await,
                    4 | 5 => read_public(&app, &session, operation == 5).await,
                    6 | 7 => recover_author(&app, &session, operation == 7).await,
                    8 => match super::puzzles::prepared(&app) {
                        Ok(preview) => queue(&app, &session, false, Some(preview)).await,
                        Err(error) => Err(error),
                    },
                    _ => queue(&app, &session, operation == 1, None).await,
                };
                app.borrow_mut().session = Some(session);
                if operation == 8 {
                    super::puzzles::queued(&app, &result);
                }
                if let Err(error) = result {
                    if matches!(operation, 6 | 7) {
                        let status = app
                            .borrow()
                            .document
                            .get_element_by_id("author-state-status")
                            .unwrap();
                        let _ = status.set_attribute("data-complete", "false");
                        status.set_text_content(Some(&error));
                    } else {
                        message(&app, &error);
                    }
                }
                finish(&app, Ok(()));
            });
        });
        document
            .get_element_by_id(id)
            .unwrap()
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .unwrap();
        callback.forget();
    }
}

async fn recover_author(app: &App, session: &Session, import: bool) -> Result<(), String> {
    let selected = AuthorScope::new(recovery_scope(app, session)?, ui::activity_author()?);
    let history = session.head.scope();
    let status = app
        .borrow()
        .document
        .get_element_by_id("author-state-status")
        .unwrap();
    let _ = status.set_attribute("data-complete", "false");
    status.set_text_content(Some(if import {
        "Verifying the selected encrypted author-state part…"
    } else {
        "Preparing the next encrypted author-state part…"
    }));
    let notice = if import {
        let file = field(app, "import-author-file")
            .files()
            .and_then(|files| files.get(0))
            .ok_or("Choose an encrypted author-state part first.")?;
        super::recovery::import_part(selected, history, file).await?
    } else {
        super::recovery::export_part(selected, history).await?
    };
    status.set_text_content(Some(&notice.message));
    let _ = status.set_attribute(
        "data-complete",
        if notice.complete { "true" } else { "false" },
    );
    Ok(())
}

/// A cursor belongs to one exact room and peer, never to the whole network.
#[derive(Clone, Copy)]
pub(super) struct FeedPosition {
    scope: RoomScope,
    peer: [u8; 32],
    after: u64,
}

pub(super) async fn fresh_peer(
    app: &App,
    session: &Session,
    index: usize,
    publish: bool,
    budget: &mut usize,
) -> Result<([u8; 32], vhalla_public_protocol::Endpoint), String> {
    let raw = app
        .borrow()
        .peers
        .get(index)
        .cloned()
        .ok_or("Select a serving peer first.")?;
    let old = PeerAdvertisement::decode(&raw).map_err(|_| "Saved peer evidence is invalid.")?;
    let anchor = old
        .restore_sequence_anchor(session.client.network_id())
        .map_err(|_| "Saved peer signature is invalid.")?;
    let key = *anchor.application_key();
    for endpoint in old
        .unverified_claims()
        .endpoints
        .iter()
        .filter(|e| e.scheme() == Scheme::Https)
    {
        if *budget == 0 {
            return Err(
                "This action's network attempt budget is exhausted. Retry to rotate peers.".into(),
            );
        }
        *budget -= 1;
        let request = transport::request(ReadKind::Advertisement)
            .map_err(|_| "Browser randomness is unavailable.")?;
        let Ok(renewed) =
            transport::read(endpoint, session.client.network_id(), key, &request).await
        else {
            continue;
        };
        let Ok(ad) = PeerAdvertisement::decode(&renewed) else {
            continue;
        };
        let clock = now(app.borrow().clock_floor)?;
        let Ok(verified) = ad.verify(
            &policy(session.client.network_id(), clock),
            if raw == renewed { None } else { Some(&anchor) },
        ) else {
            continue;
        };
        if verified.claims().endpoints != old.unverified_claims().endpoints
            || !verified.claims().capabilities.contains(Capabilities::READ)
            || (publish
                && !verified
                    .claims()
                    .capabilities
                    .contains(Capabilities::PUBLISH))
        {
            continue;
        }
        let mut peers = app.borrow().peers.clone();
        peers[index] = renewed;
        save_selection(app, session.head.scope(), &peers, clock).await?;
        app.borrow_mut().peers = peers;
        return Ok((key, endpoint.clone()));
    }
    Err("None of this peer's selected HTTPS routes returned valid evidence for the required service.".into())
}

async fn deliver(app: &App, session: &Session) -> Result<(), String> {
    use vhalla_public_protocol::activity::ActivityRequest;
    let author = ui::activity_author()?;
    let room = scope(app, session)?;
    let author_scope = AuthorScope::new(room, author);
    let mut storage = outbox().await?;
    let Some(local) = storage
        .load_head(author_scope)
        .await
        .map_err(|_| "Could not read the local author floor.")?
    else {
        return Err("There are no saved posts for this room.".into());
    };
    if local.sequence() == 0 {
        return Err("There are no signed posts to send yet.".into());
    }
    let (count, start) = {
        let state = app.borrow();
        (state.peers.len(), state.next_peer)
    };
    if count == 0 {
        return Err("Select a peer before sending posts.".into());
    }
    let mut confirmations = Vec::new();
    let mut budget = READS_PER_ACTION;
    for offset in 0..count.min(2) {
        let index = (start + offset) % count;
        app.borrow_mut().next_peer = (index + 1) % count;
        message(app, "Checking a selected peer before sending saved posts…");
        let Ok((peer, route)) = fresh_peer(app, session, index, true, &mut budget).await else {
            if app.borrow().failed {
                return Err("Peer selection changed. Reload before continuing.".into());
            }
            continue;
        };
        let mut prior = storage
            .load_delivery(author_scope, peer)
            .await
            .map_err(|_| {
                "Could not verify the saved delivery receipt. Reload before continuing."
            })?;
        let after = prior.as_ref().map_or(0, |head| head.sequence());
        if after >= local.sequence() {
            confirmations.push(format!(
                "{}… already acknowledged through post {}",
                &hex(&peer)[..12],
                after
            ));
            continue;
        }
        let page = storage
            .read_page(
                author_scope,
                after.checked_add(1).ok_or("Author sequence exhausted.")?,
                3,
                128 * 1024,
            )
            .await
            .map_err(|_| "Could not verify the retained signed outbox.")?;
        let mut acknowledged = after;
        for event in page.events {
            if budget == 0 {
                break;
            }
            budget -= 1;
            message(
                app,
                &format!(
                    "Sending saved post {} to peer {}…",
                    event.claims().sequence,
                    &hex(&peer)[..12]
                ),
            );
            let body = event.encode();
            let request = ActivityRequest::post(
                transport::nonce().map_err(|_| "Browser randomness is unavailable.")?,
                *room.room.as_bytes(),
                &body,
            )
            .map_err(|_| "The saved event exceeds protocol bounds.")?;
            let Ok(reply) = transport::activity(
                &route,
                session.client.network_id(),
                peer,
                &request,
                Some(&body),
            )
            .await
            else {
                break;
            };
            let next = storage.record_delivery(author_scope, peer, prior.as_ref(), &request, &reply.proof, &reply.body).await.map_err(|_| {
                app.borrow_mut().failed = true;
                "The peer replied, but its exact receipt could not be saved or verified. Reload and retry the same outbox; no post has been deleted."
            })?;
            acknowledged = next.sequence();
            prior = Some(next);
        }
        if acknowledged > after {
            confirmations.push(format!(
                "{}… acknowledged through post {}",
                &hex(&peer)[..12],
                acknowledged
            ));
        }
    }
    if confirmations.is_empty() {
        return Err("No new durable receipt was confirmed. Your signed posts remain saved; retry after syncing or choosing another serving peer.".into());
    }
    message(
        app,
        &format!(
            "{}. Receipts are saved locally and attest only to each peer's storage. Up to three posts per peer are sent in one attempt; send again for remaining history.",
            confirmations.join("; ")
        ),
    );
    Ok(())
}

async fn read_public(app: &App, session: &Session, more: bool) -> Result<(), String> {
    use vhalla_public_protocol::activity::{ActivityPage, ActivityRequest};
    let room = scope(app, session)?;
    let (peers, previous, start) = {
        let state = app.borrow();
        (state.peers.clone(), state.feed, state.next_peer)
    };
    if peers.is_empty() {
        return Err("Select a serving peer first.".into());
    }
    let prior = previous.filter(|p| more && p.scope == room);
    let index = if let Some(prior) = prior {
        peers.iter().position(|raw| PeerAdvertisement::decode(raw).is_ok_and(|a| a.unverified_claims().application_key == prior.peer)).ok_or("The previous peer is no longer selected. Read from the beginning using another peer.")?
    } else {
        start % peers.len()
    };
    app.borrow_mut().next_peer = (index + 1) % peers.len();
    let mut budget = READS_PER_ACTION;
    let (peer, route) = fresh_peer(app, session, index, false, &mut budget).await?;
    if budget == 0 {
        return Err("This action exhausted its route-attempt budget. Retry to continue.".into());
    }
    let after = prior.map_or(0, |p| p.after);
    let request = ActivityRequest::page(
        transport::nonce().map_err(|_| "Browser randomness is unavailable.")?,
        *room.room.as_bytes(),
        after,
        16,
    )
    .map_err(|_| "Invalid activity cursor.")?;
    message(app, "Reading a bounded page of signed public posts…");
    let reply = transport::activity(&route, session.client.network_id(), peer, &request, None).await.map_err(|_| "The selected peer could not supply a valid activity page. Read again to try another peer.")?;
    let page = ActivityPage::decode(&reply.body, &request)
        .map_err(|_| "The peer supplied invalid activity framing or signatures.")?;
    if page
        .entries()
        .iter()
        .any(|entry| entry.event().claims().scope != room)
    {
        return Err("The peer returned activity for a different network or room.".into());
    }
    let document = app.borrow().document.clone();
    let list = document.get_element_by_id("activity-list").unwrap();
    list.set_text_content(None);
    for entry in page.entries() {
        let event = entry.event();
        super::puzzles::observe(app, event);
        let item = document.create_element("article").unwrap();
        item.set_class_name("room-card");
        let label = document.create_element("small").unwrap();
        label.set_text_content(Some(&format!(
            "Key {} · author sequence {} · peer cursor {}",
            hex(&event.claims().author),
            event.claims().sequence,
            entry.cursor()
        )));
        let text = document.create_element("p").unwrap();
        let Content::Text(content) = &event.claims().content;
        text.set_text_content(Some(content.as_str()));
        let _ = item.append_child(&label);
        let _ = item.append_child(&text);
        let _ = list.append_child(&item);
    }
    let next = page.entries().last().map_or(after, |entry| entry.cursor());
    app.borrow_mut().feed = Some(FeedPosition {
        scope: room,
        peer,
        after: next,
    });
    message(
        app,
        &format!(
            "Verified {} author signatures from peer {}… · cursor {}/{}. This is one peer's public history, not a globally certified activity order. {}",
            page.entries().len(),
            &hex(&peer)[..12],
            next,
            page.local_tip(),
            if next < page.local_tip() {
                "Use Next page to continue."
            } else {
                "This matches the peer's reported activity tip."
            }
        ),
    );
    Ok(())
}
