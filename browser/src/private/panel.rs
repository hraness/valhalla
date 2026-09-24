//! Opt-in trusted private-room DOM with explicit local-gateway sync.
#[path = "panel/actions.rs"]
mod actions;
#[path = "panel/archive_save.rs"]
mod archive_save;
#[path = "panel_model.rs"]
mod model;
use crate::{private_rooms as broker, private_wire::*};
use js_sys::{Array, Uint8Array};
use std::{cell::RefCell, rc::Rc};
use vhalla_private_kernel::{
    protocol::{ControlFloor, Key, SignedOwnerControl, Validity},
    ContactBootstrap, Context, OperationId, Phase, Status, MAX_BODY_BYTES,
};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    Blob, BlobPropertyBag, Document, Element, Event, HtmlAnchorElement, HtmlButtonElement,
    HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement, Url,
};
use zeroize::Zeroizing;

type App = Rc<RefCell<State>>;
type Result<T> = std::result::Result<T, String>;
const IDS: &[(&str, Action)] = &[
    ("private-enter", Action::Enter),
    ("private-leave", Action::Leave),
    ("private-create", Action::Create),
    ("private-review-offer", Action::ReviewOffer),
    ("private-open", Action::Open),
    ("private-download-locator", Action::Locator),
    ("private-commit", Action::Commit),
    ("private-refresh", Action::Refresh),
    ("private-delivery-create", Action::DeliveryCreate),
    ("private-delivery-open", Action::DeliveryOpen),
    ("private-delivery-sync", Action::DeliverySync),
    ("private-generation-drain", Action::GenerationDrain),
    ("private-generation-restart", Action::GenerationRestart),
    ("private-generation-receipt", Action::GenerationReceipt),
    ("private-generation-review", Action::GenerationReview),
    ("private-generation-confirm", Action::GenerationConfirm),
    ("private-admission-download", Action::AdmissionDownload),
    ("private-admission-discard", Action::AdmissionDiscard),
    ("private-admission-review", Action::AdmissionReview),
    ("private-admission-confirm", Action::AdmissionConfirm),
    ("private-join-review", Action::JoinReview),
    ("private-join-confirm", Action::JoinConfirm),
    ("private-prepare-message", Action::Prepare),
    ("private-save-message", Action::Send),
    ("private-download-output", Action::Download),
    ("private-receive", Action::Receive),
    ("private-offer", Action::Offer),
    ("private-download-secret", Action::Secret),
    ("private-request", Action::Request),
    ("private-accept", Action::Accept),
    ("private-join", Action::Join),
    ("private-apply-control", Action::Apply),
    ("private-controls", Action::Controls),
    ("private-controls-next", Action::ControlsNext),
    ("private-download-control", Action::DownloadControl),
    ("private-proofs", Action::Proofs),
    ("private-proofs-next", Action::ProofsNext),
    ("private-download-proof", Action::DownloadProof),
    ("private-observe", Action::Observe),
    ("private-fork-evidence", Action::ForkEvidence),
    ("private-remove", Action::Remove),
    ("private-remove-review", Action::RemoveReview),
    ("private-renew", Action::Renew),
    ("private-succeed", Action::Succeed),
    ("private-succeed-review", Action::SucceedReview),
    ("private-outbox", Action::Outbox),
    ("private-outbox-next", Action::OutboxNext),
    ("private-download-outbox", Action::DownloadOutbox),
    ("private-inbox", Action::Inbox),
    ("private-inbox-next", Action::InboxNext),
    ("private-export-archive", Action::ExportArchive),
    ("private-import-archive", Action::ImportArchive),
    ("private-open-archive", Action::OpenArchive),
    ("private-archive-outbox", Action::ArchiveOutbox),
    ("private-archive-outbox-next", Action::ArchiveOutboxNext),
    (
        "private-archive-outbox-download",
        Action::ArchiveOutboxDownload,
    ),
    ("private-archive-inbox", Action::ArchiveInbox),
    ("private-archive-inbox-next", Action::ArchiveInboxNext),
    ("private-archive-close", Action::ArchiveClose),
];
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    GenerationDrain,
    GenerationRestart,
    GenerationReceipt,
    GenerationReview,
    GenerationConfirm,
    DeliveryCreate,
    DeliveryOpen,
    DeliverySync,
    Enter,
    Leave,
    Create,
    ReviewOffer,
    Open,
    Locator,
    Commit,
    Refresh,
    Prepare,
    Send,
    Download,
    Receive,
    Offer,
    Secret,
    Request,
    Accept,
    Join,
    Apply,
    Controls,
    ControlsNext,
    DownloadControl,
    Proofs,
    ProofsNext,
    DownloadProof,
    Observe,
    ForkEvidence,
    Remove,
    RemoveReview,
    Renew,
    Succeed,
    SucceedReview,
    Outbox,
    OutboxNext,
    DownloadOutbox,
    Inbox,
    InboxNext,
    ExportArchive,
    ImportArchive,
    OpenArchive,
    ArchiveOutbox,
    ArchiveOutboxNext,
    ArchiveOutboxDownload,
    ArchiveInbox,
    ArchiveInboxNext,
    ArchiveClose,
    AdmissionDownload,
    AdmissionDiscard,
    AdmissionReview,
    AdmissionConfirm,
    JoinReview,
    JoinConfirm,
}
struct Secret {
    operation: OperationId,
    recipient: Key,
    bytes: Bytes,
}
struct State {
    document: Document,
    generation: u64,
    busy: bool,
    entered: bool,
    account: Option<Key>,
    prepared: Option<Context>,
    locator_downloaded: bool,
    room: Option<Box<Membership>>,
    offer: Option<Bytes>,
    consent: Option<Box<Consent>>,
    intent: Option<OperationId>,
    output: Option<Artifact>,
    secret: Option<Secret>,
    outbox: Vec<Artifact>,
    controls: Vec<Control>,
    proofs: Vec<Control>,
    outbox_next: Option<u64>,
    inbox_next: Option<u64>,
    controls_next: Option<ControlFloor>,
    proofs_next: Option<ControlFloor>,
    archive: Option<ArchivePanel>,
    archive_in_flight: bool,
    delivery_connected: bool,
    delivery_ready: bool,
    admissions: Vec<AdmissionItem>,
    admission_consent: Option<Box<AdmissionConsent>>,
    join_consent: Option<Box<JoinConsent>>,
    generation_consent: Option<Box<GenerationConsent>>,
    owner_consent: Option<Box<OwnerConsent>>,
    pause_receipt: Option<Bytes>,
    delivery_paused: bool,
    archive_sink: Option<Rc<archive_save::Sink>>,
    downloads: Vec<(String, usize)>,
    handlers: Vec<Closure<dyn FnMut(Event)>>,
}
/// Read-only archive view state, mirroring the worker's authenticated report.
struct ArchivePanel {
    context: Context,
    archive_id: [u8; 32],
    source_revision: u64,
    status: vhalla_private_kernel::Status,
    outbox: Vec<Artifact>,
    outbox_next: Option<u64>,
    inbox_next: Option<u64>,
}
thread_local! {static PANEL:RefCell<Option<App>>=const{RefCell::new(None)};}
fn element(app: &App, id: &str) -> Element {
    app.borrow()
        .document
        .get_element_by_id(id)
        .expect("fixed private panel markup")
}
fn input(app: &App, id: &str) -> HtmlInputElement {
    element(app, id).dyn_into().expect("fixed input")
}
fn area(app: &App) -> HtmlTextAreaElement {
    element(app, "private-message")
        .dyn_into()
        .expect("fixed message input")
}
fn selected(app: &App, id: &str) -> Result<usize> {
    element(app, id)
        .dyn_into::<HtmlSelectElement>()
        .map_err(|_| "Missing selection.")?
        .value()
        .parse()
        .map_err(|_| "Select one retained record.".into())
}
fn text(app: &App, id: &str, value: &str) {
    element(app, id).set_text_content(Some(value));
}
fn visible(app: &App, id: &str, on: bool) {
    let node = element(app, id);
    if on {
        let _ = node.remove_attribute("hidden");
    } else {
        let _ = node.set_attribute("hidden", "");
    }
}
fn status(app: &App, value: &str, error: bool) {
    let node = element(app, "private-status");
    node.set_text_content(Some(value));
    let _ = node.set_attribute("data-error", if error { "true" } else { "false" });
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|v| format!("{v:02x}")).collect()
}
fn label(raw: &[u8]) -> String {
    format!("{}…", hex(&raw[..6]))
}
fn key(value: &str) -> Result<Key> {
    Key::from_bytes(hex32(value)?).map_err(|_| "Invalid or weak key.".into())
}
fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("Enter the complete 64-character lowercase account or device key.".into());
    }
    let mut raw = [0; 32];
    for (out, pair) in raw.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *out = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| "Invalid key.")?, 16)
            .map_err(|_| "Invalid key.")?;
    }
    if raw == [0; 32] {
        return Err("Enter a nonzero full identifier.".into());
    }
    Ok(raw)
}
fn now() -> Result<u64> {
    let time = js_sys::Date::now();
    if !time.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&time) {
        return Err("Local clock is unavailable.".into());
    }
    Ok((time / 1000.0) as u64)
}
fn validity(seconds: u64) -> Result<Validity> {
    let start = now()?;
    Validity::new(start, start.checked_add(seconds).ok_or("Clock overflow.")?)
        .map_err(|_| "Invalid validity interval.".into())
}
fn operation() -> Result<OperationId> {
    let mut id = [0; 16];
    web_sys::window()
        .ok_or("No browser window.")?
        .crypto()
        .map_err(|_| "Secure randomness unavailable.")?
        .get_random_values_with_u8_array(&mut id)
        .map_err(|_| "Secure randomness failed.")?;
    OperationId::from_bytes(id)
        .map_err(|_| "Secure randomness returned an invalid operation identifier.".into())
}
fn context(app: &App) -> Result<Context> {
    app.borrow()
        .room
        .as_ref()
        .map(|m| m.status.context)
        .ok_or("Open the exact private room first.".into())
}
fn live(app: &App, ticket: u64) -> Result<()> {
    let state = app.borrow();
    if state.generation == ticket && state.busy {
        Ok(())
    } else {
        Err("Private operation ended. Unlock and reopen its exact locator.".into())
    }
}
async fn call(app: &App, ticket: u64, request: Request) -> Result<Response> {
    live(app, ticket)?;
    let reply = broker::execute(request).await?;
    live(app, ticket)?;
    Ok(reply)
}
async fn file(app: &App, ticket: u64, id: &str, max: usize) -> Result<Bytes> {
    let selected = input(app, id)
        .files()
        .and_then(|f| f.get(0))
        .ok_or("Choose one file first.")?;
    if selected.size() > max as f64 || selected.size() == 0.0 {
        return Err(format!("This file must contain between 1 and {max} bytes."));
    }
    let buffer = JsFuture::from(selected.array_buffer())
        .await
        .map_err(|_| "Could not read the selected file.")?;
    live(app, ticket)?;
    let raw = Uint8Array::new(&buffer);
    if raw.length() as usize > max || f64::from(raw.length()) != selected.size() {
        return Err("The selected file changed or exceeds its bound.".into());
    }
    let bytes = Zeroizing::new(raw.to_vec());
    // Zero the JS-heap copy now that the file bytes live in zeroed Rust custody.
    Uint8Array::fill(&raw, 0, 0, raw.length());
    Ok(bytes)
}
fn metadata(c: Context) -> String {
    format!(
        "Room {}\nAnchor {}\nAccount {}\nDevice {}",
        hex(c.scope.room.as_bytes()),
        hex(c.scope.anchor.as_bytes()),
        hex(c.account.as_bytes()),
        hex(c.device.as_bytes())
    )
}
fn public_composition(app: &App, hide: bool, clear: bool) {
    let document = app.borrow().document.clone();
    if clear {
        for id in ["activity-text", "puzzle-artifact", "puzzle-part"] {
            if let Some(node) = document.get_element_by_id(id) {
                if let Ok(field) = node.dyn_into::<HtmlTextAreaElement>() {
                    field.set_value("");
                    if let Ok(event) = Event::new("input") {
                        let _ = field.dispatch_event(&event);
                    }
                }
            }
        }
    }
    if let Some(heading) = document.get_element_by_id("activity-heading") {
        if let Ok(Some(panel)) = heading.closest(".activity") {
            if hide {
                let _ = panel.set_attribute("hidden", "");
            } else {
                let _ = panel.remove_attribute("hidden");
            }
        }
    }
}
/// Called only at the central worker-stop boundary. No controller/IDENTITY access,
/// no event dispatch, and no borrow is held while calling this hook from the panel.
pub fn clear_sensitive_state() {
    let app = PANEL.with(|s| s.borrow().clone());
    let Some(app) = app else { return };
    {
        let mut s = app.borrow_mut();
        s.generation = s.generation.saturating_add(1);
        s.busy = false;
        s.entered = false;
        s.account = None;
        s.prepared = None;
        s.locator_downloaded = false;
        s.room = None;
        s.offer = None;
        s.consent = None;
        s.intent = None;
        s.output = None;
        s.secret = None;
        s.outbox.clear();
        s.controls.clear();
        s.proofs.clear();
        s.outbox_next = None;
        s.inbox_next = None;
        s.controls_next = None;
        s.proofs_next = None;
        s.archive = None;
        s.archive_in_flight = false;
        s.delivery_connected = false;
        s.delivery_ready = false;
        s.admissions.clear();
        s.admission_consent = None;
        s.join_consent = None;
        s.generation_consent = None;
        s.owner_consent = None;
        s.pause_receipt = None;
        s.delivery_paused = false;
        if let Some(sink) = s.archive_sink.take() {
            sink.abort();
        }
        for (url, _) in s.downloads.drain(..) {
            let _ = Url::revoke_object_url(&url);
        }
    }
    for id in model::PRIVATE_INPUTS {
        input(&app, id).set_value("");
    }
    input(&app, "private-locator-retained").set_checked(false);
    input(&app, "private-archive-legacy").set_checked(false);
    area(&app).set_value("");
    for id in [
        "private-delivery-status",
        "private-generation-status",
        "private-generation-consent",
        "private-owner-consent",
        "private-device-list",
        "private-owner-targets",
        "private-prepared-details",
        "private-room-title",
        "private-membership-summary",
        "private-membership-details",
        "private-consent",
        "private-output-label",
        "private-secret-label",
        "private-inbox-content",
        "private-outbox-acceptances",
        "private-control-select",
        "private-proof-select",
        "private-evidence",
        "private-outbox-select",
        "private-admission-select",
        "private-admission-consent",
        "private-join-consent",
        "private-join-commitments",
        "private-archive-title",
        "private-archive-summary",
        "private-archive-details",
        "private-archive-inbox-content",
        "private-archive-outbox-select",
    ] {
        text(&app, id, "");
    }
    public_composition(&app, false, false);
    status(
        &app,
        "Private custody closed. Explicitly unlock and reopen the retained locator. A failed operation may already be saved; inspect retained outputs before a new intent.",
        false,
    );
    render(&app);
}
fn owner(s: &State) -> bool {
    s.room.as_ref().is_some_and(|m| {
        m.status.context.account == m.owner.claims().account
            && m.status.context.device == m.owner.claims().device
            && !m.status.quarantined
    })
}
fn joined(s: &State) -> bool {
    s.room.as_ref().is_some_and(|m| {
        !m.status.quarantined
            && matches!(
                m.status.phase,
                Phase::OwnerGenesis
                    | Phase::OwnerJoined
                    | Phase::OwnerAfterRemoval
                    | Phase::MemberJoined
            )
    })
}
fn render(app: &App) {
    let s = app.borrow();
    let idle = !s.busy;
    let active = s.entered && idle;
    let room = s.room.is_some();
    let prepared = s.prepared.is_some();
    let archived = s.archive.is_some();
    let ready = joined(&s) && !s.delivery_paused;
    let awaiting = s
        .room
        .as_ref()
        .is_some_and(|m| m.status.phase == Phase::AwaitingWelcome && !m.status.quarantined);
    let is_owner = owner(&s);
    let admission_select = s
        .document
        .get_element_by_id("private-admission-select")
        .unwrap()
        .dyn_into::<HtmlSelectElement>()
        .unwrap();
    admission_select.set_disabled(s.busy);
    let admission_index = admission_select.selected_index();
    let request_selected = usize::try_from(admission_index)
        .ok()
        .and_then(|index| s.admissions.get(index))
        .is_some_and(|item| item.kind == vhalla_private_kernel::OutboxKind::ContactRequest);
    let retained = input_unborrowed(&s.document, "private-locator-retained").checked();
    for (id, action) in IDS {
        let enabled = match action {
            Action::GenerationDrain | Action::GenerationRestart => active && s.delivery_ready,
            Action::GenerationReceipt => active && s.pause_receipt.is_some(),
            Action::GenerationReview => active && s.delivery_ready && s.delivery_paused,
            Action::GenerationConfirm => active && s.generation_consent.is_some(),
            Action::Enter => idle && !s.entered,
            Action::Leave => s.entered,
            // An open archive view must be closed explicitly before any live
            // room or another archive can be selected in this session.
            Action::Create | Action::ReviewOffer | Action::Open => {
                active && !room && !prepared && !archived
            }
            Action::Locator => active && prepared,
            Action::Commit => active && prepared && s.locator_downloaded && retained,
            Action::Prepare => active && ready,
            Action::Send => active && ready && s.consent.is_some() && s.intent.is_some(),
            Action::Download => {
                active
                    && s.output.as_ref().is_some_and(|a| {
                        a.bytes.is_some() && model::encrypted_export(a.kind).is_some()
                    })
            }
            Action::Secret => active && s.secret.is_some(),
            Action::Join => active && awaiting && !s.delivery_ready,
            Action::Request => {
                active
                    && s.room
                        .as_ref()
                        .is_some_and(|m| m.status.phase == Phase::AwaitingWelcome)
            }
            Action::Offer
            | Action::Accept
            | Action::RemoveReview
            | Action::Renew
            | Action::SucceedReview => active && is_owner && ready,
            Action::Remove => {
                active
                    && is_owner
                    && ready
                    && s.owner_consent.as_ref().is_some_and(|c| !c.succession)
            }
            Action::Succeed => {
                active
                    && is_owner
                    && ready
                    && s.owner_consent.as_ref().is_some_and(|c| c.succession)
            }
            Action::Receive | Action::Apply => active && ready,
            Action::DeliveryCreate | Action::DeliveryOpen => {
                active && (ready || awaiting) && !s.delivery_ready
            }
            Action::DeliverySync => active && (ready || awaiting) && s.delivery_ready,
            Action::AdmissionDownload | Action::AdmissionDiscard => {
                active && s.delivery_connected && !s.admissions.is_empty()
            }
            Action::AdmissionReview => {
                active && is_owner && s.delivery_connected && request_selected
            }
            Action::AdmissionConfirm => active && is_owner && s.admission_consent.is_some(),
            Action::JoinReview => {
                active && awaiting && s.delivery_connected && !s.admissions.is_empty()
            }
            Action::JoinConfirm => active && awaiting && s.join_consent.is_some(),
            Action::ControlsNext => active && s.controls_next.is_some(),
            Action::ProofsNext => active && s.proofs_next.is_some(),
            Action::DownloadProof => active && !s.proofs.is_empty(),
            Action::OutboxNext => active && s.outbox_next.is_some(),
            Action::InboxNext => active && s.inbox_next.is_some(),
            Action::DownloadControl => active && !s.controls.is_empty(),
            Action::DownloadOutbox => active && !s.outbox.is_empty(),
            Action::ImportArchive | Action::OpenArchive => {
                active && !room && !prepared && !archived
            }
            Action::ArchiveOutbox | Action::ArchiveInbox | Action::ArchiveClose => {
                active && s.archive.is_some()
            }
            Action::ArchiveOutboxNext => {
                active && s.archive.as_ref().is_some_and(|a| a.outbox_next.is_some())
            }
            Action::ArchiveInboxNext => {
                active && s.archive.as_ref().is_some_and(|a| a.inbox_next.is_some())
            }
            Action::ArchiveOutboxDownload => {
                active && s.archive.as_ref().is_some_and(|a| !a.outbox.is_empty())
            }
            // ExportArchive and remaining room actions require an open room.
            _ => active && room,
        };
        s.document
            .get_element_by_id(id)
            .unwrap()
            .dyn_into::<HtmlButtonElement>()
            .unwrap()
            .set_disabled(!enabled);
    }
    for id in model::PRIVATE_INPUTS
        .iter()
        .copied()
        .chain(["private-locator-retained", "private-archive-legacy"])
    {
        input_unborrowed(&s.document, id).set_disabled(s.busy);
    }
    s.document
        .get_element_by_id("private-message")
        .unwrap()
        .dyn_into::<HtmlTextAreaElement>()
        .unwrap()
        .set_disabled(!active || !ready);
    let archive = s.archive.as_ref().map(|a| {
        (
            a.context,
            a.archive_id,
            a.source_revision,
            a.status,
            a.outbox
                .iter()
                .map(|entry| {
                    format!(
                        "{} · {} · operation {}",
                        entry.sequence,
                        model::encrypted_export(entry.kind)
                            .map_or("Metadata / non-exportable bootstrap", |(label, _)| label),
                        hex(entry.operation.as_bytes())
                    )
                })
                .collect::<Vec<_>>(),
        )
    });
    drop(s);
    visible(app, "private-workspace", app.borrow().entered);
    visible(app, "private-setup", !room && !prepared && !archived);
    visible(app, "private-prepared", prepared);
    visible(app, "private-room", room);
    visible(app, "private-archive", archive.is_some());
    if let Some((context, archive_id, revision, status, outbox_labels)) = archive {
        text(app, "private-archive-title", "Read-only encrypted archive");
        text(
            app,
            "private-archive-summary",
            &format!(
                "Source revision {revision} · epoch {} · {} admitted devices · {} archived inbox messages. Historical evidence only — this view cannot send, invite, or mutate the live room.",
                status.epoch, status.members, status.inbox_head
            ),
        );
        text(
            app,
            "private-archive-details",
            &format!(
                "{}\nArchive {}\nSource revision {}\nEpoch {}\nRoster {}\nControl floor {}",
                metadata(context),
                hex(&archive_id),
                revision,
                status.epoch,
                hex(&status.roster),
                status.control_sequence,
            ),
        );
        options(app, "private-archive-outbox-select", outbox_labels);
    }
    visible(app, "private-output", app.borrow().output.is_some());
    visible(app, "private-secret-output", app.borrow().secret.is_some());
}
fn input_unborrowed(document: &Document, id: &str) -> HtmlInputElement {
    document.get_element_by_id(id).unwrap().dyn_into().unwrap()
}
fn membership(app: &App, view: Box<Membership>) {
    let owner_changed = app
        .borrow()
        .room
        .as_ref()
        .is_some_and(|old| old.owner != view.owner);
    let status = view.status;
    let mut details = format!(
        "{}\nEpoch {}\nRoster {}\nControl floor {}\n",
        metadata(status.context),
        status.epoch,
        hex(&status.roster),
        status.control_sequence
    );
    for member in &view.members {
        let c = member.claims();
        details.push_str(&format!(
            "\nAccount {}\nDevice {}\nValid until {} UTC seconds\n",
            hex(c.account.as_bytes()),
            hex(c.device.as_bytes()),
            c.validity.expires_at()
        ));
    }
    text(app, "private-device-list", "");
    text(app, "private-owner-targets", "");
    for member in &view.members {
        let claims = member.claims();
        let role = if claims.device == view.owner.claims().device {
            "Current owner"
        } else {
            "Member"
        };
        let local = if claims.device == status.context.device {
            " · this device"
        } else {
            ""
        };
        let expiry = if now().is_ok_and(|n| n > claims.validity.expires_at()) {
            "Expired"
        } else {
            "Valid until"
        };
        let description = app
            .borrow()
            .document
            .create_element("pre")
            .expect("device details");
        description.set_class_name("artifact-preview");
        description.set_text_content(Some(&format!(
            "{role}{local}\nAccount {}\nDevice {}\n{expiry} {} UTC seconds",
            hex(claims.account.as_bytes()),
            hex(claims.device.as_bytes()),
            claims.validity.expires_at()
        )));
        element(app, "private-device-list")
            .append_child(&description)
            .expect("device list");
        if claims.device != view.owner.claims().device {
            let option = app
                .borrow()
                .document
                .create_element("option")
                .expect("device choice");
            option
                .set_attribute("value", &hex(claims.device.as_bytes()))
                .expect("device key");
            option.set_text_content(Some(&format!(
                "{role}{local} · account {}",
                hex(claims.account.as_bytes())
            )));
            element(app, "private-owner-targets")
                .append_child(&option)
                .expect("device choices");
        }
    }
    for grant in &view.successions {
        let c = grant.claims();
        details.push_str(&format!(
            "\nSuccession at control {}\nFrom device {}\nTo device {}\n",
            c.sequence,
            hex(c.predecessor.as_bytes()),
            hex(c.successor.claims().device.as_bytes()),
        ));
    }
    {
        let mut s = app.borrow_mut();
        if s.consent.as_ref().is_some_and(|c| {
            c.context != status.context || c.epoch != status.epoch || c.roster != status.roster
        }) {
            s.consent = None;
            s.intent = None;
        }
        if owner_changed {
            // Renewal invalidates old offers; retain their durable evidence,
            // but do not present an obsolete secret as a usable invitation.
            s.secret = None;
            s.offer = None;
        }
        s.prepared = None;
        s.locator_downloaded = false;
        s.room = Some(view);
    }
    if owner_changed {
        text(app, "private-secret-label", "");
    }
    text(
        app,
        "private-room-title",
        &format!(
            "Private room {}",
            label(status.context.scope.room.as_bytes())
        ),
    );
    text(
        app,
        "private-membership-summary",
        &format!(
            "Epoch {} · {} admitted devices · {} local messages. {}",
            status.epoch,
            status.members,
            status.inbox_head,
            if status.quarantined {
                "Quarantined: no new sharing."
            } else {
                "Local verified membership; newer controls may exist."
            }
        ),
    );
    text(app, "private-membership-details", &details);
    if app.borrow().consent.is_none() {
        text(app, "private-consent", "");
    }
}
async fn refresh(app: &App, ticket: u64) -> Result<()> {
    let Response::Membership(view) = call(app, ticket, Request::Membership).await? else {
        return Err("Unexpected membership report.".into());
    };
    membership(app, view);
    Ok(())
}
fn output(app: &App, artifact: Artifact) {
    let caption = model::encrypted_export(artifact.kind)
        .map_or("Output is not an ordinary ciphertext artifact.", |(s, _)| s);
    text(
        app,
        "private-output-label",
        &format!(
            "{} · saved local output {} · operation {}. This view reports local retention only.",
            caption,
            artifact.sequence,
            hex(artifact.operation.as_bytes())
        ),
    );
    app.borrow_mut().output = Some(artifact);
}
fn options(app: &App, id: &str, labels: Vec<String>) {
    let select = element(app, id);
    select.set_text_content(None);
    let document = app.borrow().document.clone();
    for (index, label) in labels.into_iter().enumerate() {
        let option = document.create_element("option").unwrap();
        let _ = option.set_attribute("value", &index.to_string());
        option.set_text_content(Some(&label));
        let _ = select.append_child(&option);
    }
}
fn download(app: &App, name: &str, raw: &[u8]) -> Result<()> {
    download_parts(app, name, &[raw])
}
fn download_parts(app: &App, name: &str, contents: &[&[u8]]) -> Result<()> {
    if app.borrow().downloads.len() >= 8 {
        return Err("Wait for recent downloads to finish before exporting another file.".into());
    }
    let bytes = contents.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or("Download size overflow.")
    })?;
    let retained = app.borrow().downloads.iter().map(|(_, bytes)| bytes).sum();
    model::admit_download(retained, bytes)?;
    let parts = Array::new();
    for raw in contents {
        parts.push(&Uint8Array::from(*raw));
    }
    let props = BlobPropertyBag::new();
    props.set_type("application/octet-stream");
    let blob = Blob::new_with_u8_array_sequence_and_options(&parts, &props)
        .map_err(|_| "Could not prepare download.")?;
    let url =
        Url::create_object_url_with_blob(&blob).map_err(|_| "Could not prepare download URL.")?;
    app.borrow_mut().downloads.push((url.clone(), bytes));
    let clicked = (|| -> Result<()> {
        let document = app.borrow().document.clone();
        let link: HtmlAnchorElement = document
            .create_element("a")
            .map_err(|_| "Could not prepare download link.")?
            .dyn_into()
            .map_err(|_| "Invalid download link.")?;
        link.set_href(&url);
        link.set_download(name);
        document
            .body()
            .ok_or("Missing page body.")?
            .append_child(&link)
            .map_err(|_| "Could not attach download.")?;
        link.click();
        link.remove();
        Ok(())
    })();
    if let Err(error) = clicked {
        let _ = Url::revoke_object_url(&url);
        app.borrow_mut().downloads.retain(|(u, _)| u != &url);
        return Err(error);
    }
    let weak = Rc::downgrade(app);
    let expire = Closure::once_into_js(move || {
        let _ = Url::revoke_object_url(&url);
        if let Some(app) = weak.upgrade() {
            app.borrow_mut().downloads.retain(|(u, _)| u != &url);
        }
    });
    web_sys::window()
        .ok_or("No browser window.")?
        .set_timeout_with_callback_and_timeout_and_arguments_0(expire.unchecked_ref(), 30_000)
        .map_err(|_| {
            "Download started; lock this workspace to release its temporary file handle."
        })?;
    Ok(())
}

fn action(app: &App, selected: Action) {
    // Disabled UI is only a usability gate; the closed worker verifies all
    // scope, membership, phase, and exact consent before any publication.
    let button = IDS
        .iter()
        .find(|(_, a)| *a == selected)
        .expect("known action")
        .0;
    if element(app, button)
        .dyn_into::<HtmlButtonElement>()
        .unwrap()
        .disabled()
    {
        return;
    }
    if matches!(selected, Action::Leave) {
        // stop_worker calls clear_sensitive_state synchronously. No panel
        // borrow, root App borrow or async controller callback is held here.
        if let Err(error) = broker::leave_and_lock() {
            clear_sensitive_state();
            status(app, &error, true);
        }
        return;
    }
    let ticket = {
        let mut s = app.borrow_mut();
        if s.busy {
            return;
        }
        let Some(next) = s.generation.checked_add(1) else {
            drop(s);
            status(
                app,
                "Session counter exhausted. Reload and reopen the retained locator.",
                true,
            );
            return;
        };
        s.generation = next;
        s.busy = true;
        if selected != Action::AdmissionConfirm {
            s.admission_consent = None;
        }
        if selected != Action::JoinConfirm {
            s.join_consent = None;
        }
        if selected != Action::GenerationConfirm {
            s.generation_consent = None;
        }
        if !matches!(selected, Action::Remove | Action::Succeed) {
            s.owner_consent = None;
        }
        next
    };
    if selected != Action::AdmissionConfirm {
        text(app, "private-admission-consent", "");
    }
    if selected != Action::JoinConfirm {
        text(app, "private-join-consent", "");
        text(app, "private-join-commitments", "");
    }
    if selected != Action::GenerationConfirm {
        text(app, "private-generation-consent", "");
    }
    if !matches!(selected, Action::Remove | Action::Succeed) {
        text(app, "private-owner-consent", "");
    }
    status(
        app,
        "Working locally… Preserve the exact locator if this operation is interrupted.",
        false,
    );
    render(app);
    // File picker permission requires this original user activation. Its future
    // is awaited before any archive worker operation begins.
    let selected_file = if selected == Action::ExportArchive {
        match archive_save::choose() {
            Ok(selection) => selection,
            Err(error) => {
                app.borrow_mut().busy = false;
                status(app, &error, true);
                render(app);
                return;
            }
        }
    } else {
        None
    };
    let app = app.clone();
    spawn_local(async move {
        let result = actions::perform(&app, ticket, selected, selected_file).await;
        // Abort on every error, including generation changes caused by lock.
        if result.is_err() && live(&app, ticket).is_ok() {
            if let Some(sink) = app.borrow_mut().archive_sink.take() {
                sink.abort();
            }
        }
        if live(&app, ticket).is_err() {
            return;
        }
        app.borrow_mut().busy = false;
        if let Err(error) = result {
            let archive_in_flight = app.borrow().archive_in_flight;
            if archive_in_flight {
                // A local file/DOM error can occur between successful worker
                // requests. End custody so a durable importer cannot remain
                // hidden behind an idle panel; retained progress is untouched.
                let locked = broker::leave_and_lock().is_ok();
                let next = if selected == Action::ImportArchive {
                    "Preserve the complete original archive. Unlock, enter private custody, and select that same complete file to resume its retained progress."
                } else {
                    "Unlock and reopen the exact room locator before retrying export. Retained room data is unchanged."
                };
                status(
                    &app,
                    &format!(
                        "{error} {} {next}",
                        if locked {
                            "Private custody was locked."
                        } else {
                            "Reload before unlocking again."
                        }
                    ),
                    true,
                );
                return;
            }
            status(&app, &error, true);
        }
        render(&app);
    });
}

/// Mount only in an explicitly enabled private build. Static HTML is the only
/// inner-HTML assignment; imported/decrypted bytes always use text_content.
pub fn start() {
    let document = web_sys::window()
        .expect("browser window")
        .document()
        .expect("browser document");
    if document.get_element_by_id("private-panel").is_some() {
        return;
    }
    let container = document
        .create_element("div")
        .expect("private panel container");
    container.set_inner_html(include_str!("panel.html"));
    let main = document
        .query_selector("main")
        .expect("main query")
        .expect("main element");
    let before = document
        .get_element_by_id("activity-heading")
        .and_then(|h| h.closest(".activity").ok().flatten());
    if let Some(before) = before.filter(|e| e.parent_element().as_ref() == Some(&main)) {
        main.insert_before(&container, Some(&before))
            .expect("private panel mount");
    } else {
        main.append_child(&container).expect("private panel mount");
    }
    let app = Rc::new(RefCell::new(State {
        document,
        generation: 0,
        busy: false,
        entered: false,
        account: None,
        prepared: None,
        locator_downloaded: false,
        room: None,
        offer: None,
        consent: None,
        intent: None,
        output: None,
        secret: None,
        outbox: Vec::new(),
        controls: Vec::new(),
        proofs: Vec::new(),
        outbox_next: None,
        inbox_next: None,
        controls_next: None,
        proofs_next: None,
        archive: None,
        archive_in_flight: false,
        delivery_connected: false,
        delivery_ready: false,
        admissions: Vec::new(),
        admission_consent: None,
        join_consent: None,
        generation_consent: None,
        owner_consent: None,
        pause_receipt: None,
        delivery_paused: false,
        archive_sink: None,
        downloads: Vec::new(),
        handlers: Vec::new(),
    }));
    PANEL.with(|slot| *slot.borrow_mut() = Some(app.clone()));
    for (id, command) in IDS {
        let weak = Rc::downgrade(&app);
        let command = *command;
        let callback = Closure::wrap(Box::new(move |_: Event| {
            if let Some(app) = weak.upgrade() {
                action(&app, command);
            }
        }) as Box<dyn FnMut(Event)>);
        element(&app, id)
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .expect("private button handler");
        app.borrow_mut().handlers.push(callback);
    }
    let weak = Rc::downgrade(&app);
    let edit = Closure::wrap(Box::new(move |_: Event| {
        if let Some(app) = weak.upgrade() {
            {
                let mut s = app.borrow_mut();
                s.consent = None;
                s.intent = None;
            }
            text(
                &app,
                "private-consent",
                "Text changed. Review the exact message and current roster again.",
            );
            render(&app);
        }
    }) as Box<dyn FnMut(Event)>);
    area(&app)
        .add_event_listener_with_callback("input", edit.as_ref().unchecked_ref())
        .expect("private draft handler");
    app.borrow_mut().handlers.push(edit);
    for id in [
        "private-remove-device",
        "private-succeed-device",
        "private-generation-transition",
        "private-generation-head",
        "private-generation-fence",
        "private-generation-profile",
        "private-generation-attempts",
    ] {
        let weak = Rc::downgrade(&app);
        let changed = Closure::wrap(Box::new(move |_: Event| {
            if let Some(app) = weak.upgrade() {
                {
                    let mut state = app.borrow_mut();
                    state.owner_consent = None;
                    state.generation_consent = None;
                }
                text(
                    &app,
                    "private-owner-consent",
                    "Selection changed. Review the exact device again.",
                );
                text(
                    &app,
                    "private-generation-consent",
                    "Selection changed. Review the next mailbox again.",
                );
                render(&app);
            }
        }) as Box<dyn FnMut(Event)>);
        element(&app, id)
            .add_event_listener_with_callback("input", changed.as_ref().unchecked_ref())
            .expect("private authority selection handler");
        element(&app, id)
            .add_event_listener_with_callback("change", changed.as_ref().unchecked_ref())
            .expect("private authority file handler");
        app.borrow_mut().handlers.push(changed);
    }
    for id in [
        "private-recipient",
        "private-resume-offer-file",
        "private-admission-select",
    ] {
        let weak = Rc::downgrade(&app);
        let changed = Closure::wrap(Box::new(move |_: Event| {
            if let Some(app) = weak.upgrade() {
                {
                    let mut state = app.borrow_mut();
                    state.admission_consent = None;
                    state.join_consent = None;
                }
                text(
                    &app,
                    "private-join-consent",
                    "Selection changed. Review the invitation again before joining.",
                );
                text(&app, "private-join-commitments", "");
                text(
                    &app,
                    "private-admission-consent",
                    "Selection changed. Review this request again before admitting its device.",
                );
                render(&app);
            }
        }) as Box<dyn FnMut(Event)>);
        element(&app, id)
            .add_event_listener_with_callback(
                if id == "private-recipient" {
                    "input"
                } else {
                    "change"
                },
                changed.as_ref().unchecked_ref(),
            )
            .expect("admission selection handler");
        app.borrow_mut().handlers.push(changed);
    }
    let weak = Rc::downgrade(&app);
    let retained = Closure::wrap(Box::new(move |_: Event| {
        if let Some(app) = weak.upgrade() {
            render(&app);
        }
    }) as Box<dyn FnMut(Event)>);
    input(&app, "private-locator-retained")
        .add_event_listener_with_callback("change", retained.as_ref().unchecked_ref())
        .expect("locator retention handler");
    app.borrow_mut().handlers.push(retained);
    render(&app);
}
