//! Public artifact parts over existing signed room activity; never execution.
use super::*;
use crate::ui;
#[path = "../puzzle_model.rs"]
mod model;
pub(super) use model::PreparedPart;
use model::{Assembly, Context, Derived, PreparedArtifact, ReleaseScope, Selection};
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
fn artifact_input(app: &App) -> String {
    app.borrow()
        .document
        .get_element_by_id("puzzle-artifact")
        .unwrap()
        .unchecked_into::<HtmlTextAreaElement>()
        .value()
}
fn release_scope() -> Result<ReleaseScope, String> {
    Ok(ReleaseScope {
        context: DERIVED
            .with(|s| s.borrow().context)
            .ok_or("Choose a verified room first.")?,
        author: ui::activity_author()?,
    })
}
pub(super) fn validate_prepared(
    app: &App,
    preview: &PreparedPart,
    room: RoomScope,
    bootstrap_pin: [u8; 32],
    author: [u8; 32],
    pending: bool,
) -> Result<vhalla_room_activity::Text, String> {
    preview
        .queue_text(
            &part_input(app),
            &artifact_input(app),
            ReleaseScope {
                context: Context {
                    room,
                    bootstrap_pin,
                },
                author,
            },
            pending,
        )
        .map_err(String::from)
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
    let scope = release_scope()?;
    preview.queue_text(&part_input(app), &artifact_input(app), scope, false)?;
    Ok(preview)
}
pub(super) fn queued(app: &App, result: &Result<(), String>) {
    match result {
        Ok(()) => {
            DERIVED.with(|s| s.borrow_mut().preview = None);
            input(app).set_value("");
            message(app, "puzzle-preview", "Part signed and saved in your local outbox. Peer delivery is unconfirmed. The complete artifact remains approved for this room and author. Paste the next matching part.");
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
    let (changed, preview, artifact, approved, complete) = DERIVED.with(|s| {
        let mut s = s.borrow_mut();
        let changed = s.set_context(context);
        if s.artifact.as_ref().is_some_and(|a| {
            ui::activity_author().map_or(true, |author| {
                !a.matches(
                    &artifact_input(app),
                    ReleaseScope {
                        context: context.unwrap(),
                        author,
                    },
                )
            })
        }) {
            s.artifact = None;
            s.approved = false;
            s.preview = None;
        }
        (
            changed,
            s.preview.is_some(),
            s.artifact.is_some(),
            s.approved,
            s.assembly.as_ref().is_some_and(|a| a.bytes().is_some()),
        )
    });
    if changed {
        message(app, "puzzle-preview", "Room or network changed. Validate the outgoing part again. Your saved drafts and outbox are untouched.");
        message(app, "puzzle-collection", "Choose a full sharer key, artifact kind and SHA-256 digest, then start collecting from verified activity pages.");
    }
    if !artifact {
        message(app, "puzzle-readable", "");
    }
    let enabled = available && context.is_some();
    input(app).set_disabled(!enabled);
    app.borrow()
        .document
        .get_element_by_id("puzzle-artifact")
        .unwrap()
        .unchecked_into::<HtmlTextAreaElement>()
        .set_disabled(!enabled);
    app.borrow()
        .document
        .get_element_by_id("puzzle-release-kind")
        .unwrap()
        .unchecked_into::<HtmlSelectElement>()
        .set_disabled(!enabled);
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
        ("preview-puzzle-artifact", enabled),
        ("approve-puzzle-artifact", enabled && artifact && !approved),
        ("preview-puzzle", enabled && approved),
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
        ("preview-puzzle-artifact", 3),
        ("approve-puzzle-artifact", 4),
    ] {
        let a = app.clone();
        let callback = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            event.prevent_default();
            if !idle(&a) {
                return;
            }
            let result = match action {
                0 => (|| -> Result<(), String> {
                    let scope = release_scope()?;
                    let preview = DERIVED.with(|s| {
                        let s = s.borrow();
                        let artifact = s
                            .artifact
                            .as_ref()
                            .filter(|_| s.approved)
                            .ok_or("Review and approve the complete artifact first.")?;
                        if !artifact.matches(&artifact_input(&a), scope) {
                            return Err("Artifact or destination changed. Review it again.");
                        }
                        PreparedPart::new(&part_input(&a), artifact, scope)
                    })?;
                    let part = preview.part();
                    message(&a, "puzzle-preview", &format!("Part {} of {} matches the approved complete artifact. Signing saves this public part under your selected identity.", part.index()+1, part.count()));
                    DERIVED.with(|s| s.borrow_mut().preview = Some(preview));
                    Ok(())
                })(),
                3 => (|| -> Result<(), String> {
                    let scope = release_scope()?;
                    let selected = a
                        .borrow()
                        .document
                        .get_element_by_id("puzzle-release-kind")
                        .unwrap()
                        .unchecked_into::<HtmlSelectElement>()
                        .value();
                    let kind = match selected.as_str() {
                        "public-challenges" => Kind::PublicChallenges,
                        "responses" => Kind::Responses,
                        "admission" => Kind::Admission,
                        _ => return Err("Choose an artifact kind.".into()),
                    };
                    let artifact = PreparedArtifact::new(&artifact_input(&a), kind, scope)?;
                    message(&a, "puzzle-readable", artifact.readable());
                    let part = artifact.part();
                    let room_name = super::activity::selected_room_name(&a);
                    message(&a, "puzzle-preview", &format!("Review the complete decoded JSON below and the exact input above. Public destination: {room_name} · author {}… · {} · {} bytes · {} parts · SHA-256 {}. Every prompt, subject, context and answer will be public. No issuer or solve verification is implied.", &hex(&scope.author)[..12], kind_name(kind), part.artifact_len(), part.count(), hex(part.digest())));
                    DERIVED.with(|s| {
                        let mut s = s.borrow_mut();
                        s.artifact = Some(artifact);
                        s.approved = false;
                        s.preview = None;
                    });
                    Ok(())
                })(),
                4 => (|| -> Result<(), String> {
                    let scope = release_scope()?;
                    DERIVED.with(|s| {
                        let mut s = s.borrow_mut();
                        if !s
                            .artifact
                            .as_ref()
                            .is_some_and(|v| v.matches(&artifact_input(&a), scope))
                        {
                            return Err("Artifact or destination changed. Review it again.");
                        }
                        s.approved = true;
                        Ok(())
                    })?;
                    message(&a, "puzzle-preview", "Complete artifact approved for this room and author. Paste a matching CLI part to sign and save. Changed content or destination requires a new review.");
                    Ok(())
                })(),
                1 => start_collection(&a),
                _ => download(&a),
            };
            if let Err(error) = result {
                if matches!(action, 0 | 3 | 4) {
                    DERIVED.with(|s| {
                        let mut s = s.borrow_mut();
                        s.preview = None;
                        if matches!(action, 3 | 4) {
                            s.artifact = None;
                            s.approved = false;
                        }
                    });
                }
                message(
                    &a,
                    if matches!(action, 0 | 3 | 4) {
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
        "puzzle-artifact",
        "puzzle-release-kind",
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
                if matches!(id, "puzzle-artifact" | "puzzle-release-kind") {
                    s.artifact = None;
                    s.approved = false;
                    s.preview = None;
                } else if id == "puzzle-part" {
                    s.preview = None;
                } else {
                    s.assembly = None;
                }
            });
            message(&a, if matches!(id, "puzzle-part" | "puzzle-artifact" | "puzzle-release-kind") { "puzzle-preview" } else { "puzzle-collection" }, "Selection changed. Validate or start collecting again. Saved author state and outbox bytes are unchanged.");
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
