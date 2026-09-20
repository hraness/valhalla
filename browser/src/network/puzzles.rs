//! Public artifact parts over existing signed room activity; never execution.
use super::*;
#[path = "../puzzle_model.rs"]
mod model;
pub(super) use model::PreparedPart;
use model::{Assembly, Context, Derived, Selection};
use vhalla_room_activity::{puzzle_share::Kind, RoomScope, VerifiedEvent};
use web_sys::{HtmlAnchorElement, HtmlSelectElement, HtmlTextAreaElement};

thread_local! {
    static DERIVED: RefCell<Derived> = RefCell::new(Derived::default());
    static DOWNLOAD: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn message(app: &App, id: &str, text: &str) {
    app.borrow()
        .document
        .get_element_by_id(id)
        .unwrap()
        .set_text_content(Some(text));
}
fn input(app: &App) -> HtmlTextAreaElement {
    app.borrow()
        .document
        .get_element_by_id("puzzle-part")
        .unwrap()
        .unchecked_into()
}
pub(super) fn part_input(app: &App) -> String {
    input(app).value()
}
fn kind(app: &App) -> Result<Kind, &'static str> {
    match app
        .borrow()
        .document
        .get_element_by_id("puzzle-kind")
        .unwrap()
        .unchecked_into::<HtmlSelectElement>()
        .value()
        .as_str()
    {
        "challenges" => Ok(Kind::PublicChallenges),
        "responses" => Ok(Kind::Responses),
        "admission" => Ok(Kind::Admission),
        _ => Err("Choose one supported public artifact kind."),
    }
}
fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::PublicChallenges => "public-challenges",
        Kind::Responses => "responses",
        Kind::Admission => "admission",
    }
}
fn idle(app: &App) -> bool {
    let state = app.borrow();
    !state.busy && !state.failed
}
pub(super) fn prepared(app: &App) -> Result<PreparedPart, String> {
    let preview = DERIVED
        .with(|s| s.borrow().preview.clone())
        .ok_or("Validate this part before signing it.")?;
    preview.queue_text(&part_input(app), false)?;
    Ok(preview)
}
pub(super) fn queued(app: &App, result: &Result<(), String>) {
    match result {
        Ok(()) => {
            DERIVED.with(|s| s.borrow_mut().preview = None);
            input(app).set_value("");
            message(app, "puzzle-preview", "Part signed and saved in your local outbox. Peer delivery is unconfirmed. Paste and validate the next part explicitly.");
        }
        Err(error) => message(app, "puzzle-preview", error),
    }
}
pub(super) fn render(
    app: &App,
    session: Option<&Session>,
    room: Option<RoomScope>,
    available: bool,
) {
    let context = room.zip(session).map(|(room, s)| Context {
        room,
        bootstrap_pin: s.head.scope().bootstrap_pin(),
    });
    let (changed, preview, complete) = DERIVED.with(|s| {
        let mut s = s.borrow_mut();
        let changed = s.set_context(context);
        (
            changed,
            s.preview.is_some(),
            s.assembly.as_ref().is_some_and(|a| a.bytes().is_some()),
        )
    });
    if changed {
        message(app, "puzzle-preview", "Room or network changed. Validate the outgoing part again. Your saved drafts and outbox are untouched.");
        message(app, "puzzle-collection", "Choose a full sharer key, artifact kind and SHA-256 digest, then start collecting from verified activity pages.");
    }
    let enabled = available && context.is_some();
    input(app).set_disabled(!enabled);
    for id in ["puzzle-author", "puzzle-digest"] {
        field(app, id).set_disabled(!enabled);
    }
    app.borrow()
        .document
        .get_element_by_id("puzzle-kind")
        .unwrap()
        .unchecked_into::<HtmlSelectElement>()
        .set_disabled(!enabled);
    for (id, active) in [
        ("preview-puzzle", enabled),
        ("queue-puzzle", enabled && preview),
        ("collect-puzzle", enabled),
        ("download-puzzle", enabled && complete),
    ] {
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .unchecked_into::<HtmlButtonElement>()
            .set_disabled(!active);
    }
}
fn progress(app: &App) {
    let text = DERIVED.with(|s| {
        let s = s.borrow();
        let Some(a) = &s.assembly else { return String::from("No artifact collection selected."); };
        let selected = a.selection;
        let state = if let Some(raw) = a.bytes() {
            format!("Complete: {} bytes match the selected SHA-256 digest.", raw.len())
        } else {
            format!("Incomplete: {} / {} parts collected. Read public posts and Next page to continue; View local outbox also includes its latest 16 posts.", a.received(), a.total().map_or_else(|| "unknown".into(), |n| n.to_string()))
        };
        format!("{state} Network {} · realm {} · directory {} · room {} · sharer {} · {} · digest {}. Signatures attribute these bytes to this sharer only. Issuer authority, response correctness and solve/admission results are unverified.", hex(&selected.context.room.network), selected.context.room.realm.0, hex(selected.context.room.directory.as_bytes()), hex(selected.context.room.room.as_bytes()), hex(&selected.author), kind_name(selected.kind), hex(&selected.digest))
    });
    message(app, "puzzle-collection", &text);
}
pub(super) fn observe(app: &App, event: &VerifiedEvent) {
    let result = DERIVED.with(|s| {
        let mut s = s.borrow_mut();
        s.assembly.as_mut().map(|a| a.observe(event))
    });
    match result {
        Some(Ok(true)) => progress(app),
        Some(Err(error)) => message(app, "puzzle-collection", error),
        _ => {}
    }
}
fn start_collection(app: &App) -> Result<(), String> {
    let context = DERIVED
        .with(|s| s.borrow().context)
        .ok_or("Choose a verified room first.")?;
    let author = model::hex32(&field(app, "puzzle-author").value())
        .ok_or("Enter the sharer's complete 64-character lowercase public key.")?;
    let digest = model::hex32(&field(app, "puzzle-digest").value())
        .ok_or("Enter the artifact's complete 64-character lowercase SHA-256 digest.")?;
    let assembly = Assembly::new(Selection {
        context,
        author,
        kind: kind(app)?,
        digest,
    })?;
    DERIVED.with(|s| s.borrow_mut().assembly = Some(assembly));
    progress(app);
    Ok(())
}
fn download(app: &App) -> Result<(), String> {
    if DOWNLOAD.with(|s| s.borrow().is_some()) {
        return Err("Wait ten seconds before downloading again.".into());
    }
    let (raw, name) = DERIVED.with(|s| {
        let s = s.borrow();
        let a = s
            .assembly
            .as_ref()
            .ok_or("Start an explicit artifact collection first.")?;
        let bytes = a
            .bytes()
            .ok_or("The complete artifact digest has not been verified.")?;
        Ok::<_, String>((
            bytes.to_vec(),
            format!(
                "vhalla-{}-{}.json",
                kind_name(a.selection.kind),
                hex(&a.selection.digest)
            ),
        ))
    })?;
    let document = app.borrow().document.clone();
    let window = web_sys::window().ok_or("Browser unavailable.")?;
    let parts = js_sys::Array::new();
    parts.push(&Uint8Array::from(raw.as_slice()));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)
        .map_err(|_| "Could not prepare artifact download.")?;
    let link: HtmlAnchorElement = document
        .create_element("a")
        .map_err(|_| "Could not create download link.")?
        .unchecked_into();
    let body = document.body().ok_or("Browser document unavailable.")?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|_| "Could not prepare artifact URL.")?;
    link.set_href(&url);
    link.set_download(&name);
    if link
        .set_attribute("hidden", "")
        .and_then(|()| body.append_child(&link).map(|_| ()))
        .is_err()
    {
        let _ = web_sys::Url::revoke_object_url(&url);
        return Err("Could not attach artifact download.".into());
    }
    let cleanup_url = url.clone();
    let cleanup = Closure::once(move || {
        let _ = web_sys::Url::revoke_object_url(&cleanup_url);
        DOWNLOAD.with(|s| {
            let matches = s.borrow().as_ref() == Some(&cleanup_url);
            if matches {
                *s.borrow_mut() = None;
            }
        });
    });
    if window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            cleanup.as_ref().unchecked_ref(),
            10_000,
        )
        .is_err()
    {
        link.remove();
        let _ = web_sys::Url::revoke_object_url(&url);
        return Err("Could not schedule bounded download cleanup.".into());
    }
    cleanup.forget();
    DOWNLOAD.with(|s| *s.borrow_mut() = Some(url));
    link.click();
    link.remove();
    progress(app);
    let status = app
        .borrow()
        .document
        .get_element_by_id("puzzle-collection")
        .unwrap();
    let mut text = status.text_content().unwrap_or_default();
    text.push_str(" Download offered; retaining the file is your responsibility. Use the explicit native CLI verification workflow before treating any issuer or solve claim as verified. No code or model was executed.");
    status.set_text_content(Some(&text));
    Ok(())
}
pub(super) fn bind_actions(app: &App) {
    for (id, action) in [
        ("preview-puzzle", 0),
        ("collect-puzzle", 1),
        ("download-puzzle", 2),
    ] {
        let a = app.clone();
        let callback = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            if !idle(&a) {
                return;
            }
            let result = match action {
                0 => PreparedPart::new(&part_input(&a)).map(|preview| {
                    let part = preview.part();
                    message(&a, "puzzle-preview", &format!("{} · part {} of {} · artifact {} bytes · digest {}. This part is public. Signing attributes it to your key; it does not verify issuer authority or solve results.", kind_name(part.kind()), part.index()+1, part.count(), part.artifact_len(), hex(part.digest())));
                    DERIVED.with(|s| s.borrow_mut().preview = Some(preview));
                }).map_err(String::from),
                1 => start_collection(&a),
                _ => download(&a),
            };
            if let Err(error) = result {
                if action == 0 {
                    DERIVED.with(|s| s.borrow_mut().preview = None);
                }
                message(
                    &a,
                    if action == 0 {
                        "puzzle-preview"
                    } else {
                        "puzzle-collection"
                    },
                    &error,
                );
            }
            super::render(&a);
        });
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .unwrap();
        callback.forget();
    }
    for id in [
        "puzzle-part",
        "puzzle-author",
        "puzzle-kind",
        "puzzle-digest",
    ] {
        let a = app.clone();
        let callback = Closure::<dyn FnMut(Event)>::new(move |_: Event| {
            if !idle(&a) {
                return;
            }
            DERIVED.with(|s| {
                let mut s = s.borrow_mut();
                if id == "puzzle-part" {
                    s.preview = None;
                } else {
                    s.assembly = None;
                }
            });
            message(&a, if id == "puzzle-part" { "puzzle-preview" } else { "puzzle-collection" }, "Selection changed. Validate or start collecting again. Saved author state and outbox bytes are unchanged.");
            super::render(&a);
        });
        app.borrow()
            .document
            .get_element_by_id(id)
            .unwrap()
            .add_event_listener_with_callback("input", callback.as_ref().unchecked_ref())
            .unwrap();
        callback.forget();
    }
}
