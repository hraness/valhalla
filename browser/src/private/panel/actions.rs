//! Explicit user actions. Every await is followed by a panel-generation check.
use super::*;

const WEEK: u64 = 7 * 24 * 60 * 60;
const PAGE: usize = 16;

fn artifact(app: &App, reply: Response) -> Result<()> {
    let Response::Artifact { artifact, .. } = reply else {
        return Err("Unexpected retained output report.".into());
    };
    output(app, artifact);
    Ok(())
}
fn prepared(app: &App, preview: Preview, extra: &str) {
    let c = preview.context;
    text(
        app,
        "private-prepared-details",
        &format!("{}\n{}", metadata(c), extra),
    );
    input(app, "private-locator-retained").set_checked(false);
    let mut s = app.borrow_mut();
    s.prepared = Some(c);
    s.locator_downloaded = false;
}
fn inbox_text(message: &Inbound) -> String {
    format!(
        "Message {} · device {}\n{}\n",
        message.sequence,
        hex(message.sender.as_bytes()),
        String::from_utf8_lossy(&message.body)
    )
}
pub(super) async fn perform(app: &App, ticket: u64, action: Action) -> Result<()> {
    match action {
        Action::Enter => {
            let account = Key::from_bytes(crate::ui::activity_author()?)
                .map_err(|_| "The unlocked account key is invalid.")?;
            // No await occurs between the idle identity check and private entry.
            // Clearing invokes only the existing public draft's input handlers.
            public_composition(app, true, true);
            {
                let mut s = app.borrow_mut();
                s.entered = true;
                s.account = Some(account);
            }
            render(app);
            broker::enter().await?;
            live(app, ticket)?;
            status(app, "Private account custody is ready. Create, join or open one exact room. Public signing stays unavailable until Leave and lock.", false);
        }
        Action::Create => {
            let Response::Prepared(preview) =
                call(app, ticket, Request::PrepareOwner(validity(WEEK)?)).await?
            else {
                return Err("Unexpected creation preview.".into());
            };
            prepared(app, *preview, "Fresh owner device · seven-day enrollment. No private room state has been committed yet.");
            status(
                app,
                "Review the full locator, download it, then acknowledge retention before creation.",
                false,
            );
        }
        Action::ReviewOffer => {
            let owner = key(&input(app, "private-owner").value())?;
            let recipient = app.borrow().account.ok_or("Enter private custody first.")?;
            let raw = file(app, ticket, "private-offer-file", MAX_OFFER).await?;
            let info = ContactBootstrap::inspect(&raw, owner, recipient, now()?).map_err(|_| {
                "The offer failed its full signature, account pins or current-time checks."
            })?;
            let scope = info.scope();
            let extra = format!("Trusted owner account {}\nRecipient account {}\nOffer expires at {} UTC seconds.\nFresh recipient device · seven-day enrollment. This does not yet join the room.", hex(owner.as_bytes()), hex(recipient.as_bytes()), info.validity().expires_at());
            let Response::Prepared(preview) = call(
                app,
                ticket,
                Request::PrepareContact {
                    offer: raw.clone(),
                    owner,
                    validity: validity(WEEK)?,
                },
            )
            .await?
            else {
                return Err("Unexpected recipient preview.".into());
            };
            if preview.context.scope != scope || preview.context.account != recipient {
                return Err("Recipient preview does not match the reviewed offer.".into());
            }
            prepared(app, *preview, &extra);
            app.borrow_mut().offer = Some(raw);
            status(app, "The signed offer matches your independent owner pin. Review the room and save this fresh device's locator before creation.", false);
        }
        Action::Open => {
            let raw = file(app, ticket, "private-locator-file", model::LOCATOR_BYTES).await?;
            let c = model::decode_locator(&raw)?;
            if app.borrow().account != Some(c.account) {
                return Err(
                    "This locator belongs to another account. Nothing was opened or replaced."
                        .into(),
                );
            }
            let Response::Membership(view) = call(app, ticket, Request::Open(c)).await? else {
                return Err("Unexpected open report.".into());
            };
            membership(app, view);
            status(app, "Opened the exact retained room. After an uncertain write, inspect retained outputs before starting a new intent.", false);
        }
        Action::Locator => {
            let c = app
                .borrow()
                .prepared
                .ok_or("Prepare a fresh room or recipient first.")?;
            download(
                app,
                &format!(
                    "private-{}-{}.vhroom",
                    hex(c.scope.room.as_bytes()),
                    hex(c.device.as_bytes())
                ),
                &model::locator(c),
            )?;
            app.borrow_mut().locator_downloaded = true;
            status(app, "Locator download requested. Confirm that you saved the file before checking the retention box.", false);
        }
        Action::Commit => {
            if !input(app, "private-locator-retained").checked() || !app.borrow().locator_downloaded
            {
                return Err("Download and explicitly retain the exact locator first.".into());
            }
            let c = app
                .borrow()
                .prepared
                .ok_or("No prepared creation remains.")?;
            broker::acknowledge_retained_locator(c)?;
            let Response::Membership(view) = call(app, ticket, Request::CommitCreation(c)).await?
            else {
                return Err("Unexpected creation result.".into());
            };
            membership(app, view);
            status(app, "This exact private device state was saved. A recipient must now create its encrypted request and obtain the owner's response.", false);
        }
        Action::Refresh => {
            refresh(app, ticket).await?;
            status(app, "Retained local membership rechecked. This does not prove no newer owner control exists elsewhere.", false);
        }
        Action::Prepare => {
            let body = Zeroizing::new(area(app).value().into_bytes());
            if body.is_empty() || body.len() > MAX_BODY_BYTES {
                return Err("Write between 1 and 4,096 UTF-8 bytes.".into());
            }
            let c = context(app)?;
            let Response::Draft(consent) =
                call(app, ticket, Request::PrepareMessage(body.clone())).await?
            else {
                return Err("Unexpected consent preview.".into());
            };
            if consent.context != c || consent.body != body {
                return Err("The preview changed the selected room or message.".into());
            }
            let op = operation()?;
            text(
                app,
                "private-consent",
                &format!(
                    "Room {} · your device {}\nEpoch {} · roster {}\nOperation {}\n\n{}",
                    label(c.scope.room.as_bytes()),
                    label(c.device.as_bytes()),
                    consent.epoch,
                    label(&consent.roster),
                    hex(op.as_bytes()),
                    String::from_utf8_lossy(&consent.body)
                ),
            );
            let mut s = app.borrow_mut();
            s.consent = Some(consent);
            s.intent = Some(op);
            drop(s);
            status(app, "Review this exact text and displayed membership. Encrypting saves locally; it does not send to a network.", false);
        }
        Action::Send => {
            let body = Zeroizing::new(area(app).value().into_bytes());
            let (operation, consent) = {
                let mut s = app.borrow_mut();
                let current = s.room.as_ref().ok_or("No current room.")?.status;
                let draft = s
                    .consent
                    .as_ref()
                    .ok_or("Review the exact message first.")?;
                let reviewed = model::Disclosure {
                    context: draft.context,
                    epoch: draft.epoch,
                    roster: draft.roster,
                    body: &draft.body,
                };
                let selected = model::Disclosure {
                    context: current.context,
                    epoch: current.epoch,
                    roster: current.roster,
                    body: &body,
                };
                if !reviewed.matches(&selected) {
                    return Err("The room, roster or text changed. Review a new draft; no message was queued.".into());
                }
                let op = s.intent.take().ok_or("No reviewed operation remains.")?;
                (op, s.consent.take().ok_or("No reviewed draft remains.")?)
            };
            artifact(
                app,
                call(app, ticket, Request::Send { operation, consent }).await?,
            )?;
            if area(app).value().as_bytes() == body.as_slice() {
                area(app).set_value("");
            }
            text(app, "private-consent", "");
            refresh(app, ticket).await?;
            status(app, "Exact encrypted message saved in this room's outbox. Download it explicitly; downloading or saving is not delivery.", false);
        }
        Action::Download => {
            // Detach only a bounded encrypted output, not the State borrow, across DOM callbacks.
            let (name, bytes) = {
                let s = app.borrow();
                let a = s.output.as_ref().ok_or("No output selected.")?;
                export_parts(a)?
            };
            download(app, &name, &bytes)?;
            status(app, "Requested a download of the exact retained ciphertext. No new encryption or network delivery occurred.", false);
        }
        Action::Receive => {
            let raw = file(app, ticket, "private-message-file", MAX_ARTIFACT).await?;
            let Response::Received { message, .. } =
                call(app, ticket, Request::Receive(raw)).await?
            else {
                return Err("Unexpected committed inbox report.".into());
            };
            text(app, "private-inbox-content", &inbox_text(&message));
            refresh(app, ticket).await?;
            status(app, "Authenticated message saved before plaintext was shown. Its content is inert, untrusted text.", false);
        }
        Action::Offer => {
            let recipient = key(&input(app, "private-recipient").value())?;
            let op = operation()?;
            let Response::Offer {
                operation, secret, ..
            } = call(
                app,
                ticket,
                Request::Offer {
                    operation: op,
                    recipient,
                    validity: validity(3600)?,
                },
            )
            .await?
            else {
                return Err("Unexpected confidential offer result.".into());
            };
            text(
                app,
                "private-secret-label",
                &format!(
                    "Only for account {} · operation {}",
                    hex(recipient.as_bytes()),
                    hex(operation.as_bytes())
                ),
            );
            app.borrow_mut().secret = Some(Secret {
                operation,
                recipient,
                bytes: secret,
            });
            // A newly selected offer must not inherit a stale imported file.
            input(app, "private-resume-offer-file").set_value("");
            status(app, "A one-use offer was saved. Its download contains confidential bootstrap keys; ordinary outbox export never includes them.", false);
        }
        Action::Secret => {
            let (name, bytes) = {
                let s = app.borrow();
                let offer = s
                    .secret
                    .as_ref()
                    .ok_or("No live confidential offer output.")?;
                (
                    format!(
                        "confidential-offer-{}-{}.vhoffer",
                        hex(offer.recipient.as_bytes()),
                        hex(offer.operation.as_bytes())
                    ),
                    offer.bytes.clone(),
                )
            };
            download(app, &name, &bytes)?;
            status(app, "Confidential offer download requested. Transfer only to the named account through a confidential channel.", false);
        }
        Action::Request => {
            let retained = app.borrow().offer.clone();
            let raw = match retained {
                Some(raw) => raw,
                None => file(app, ticket, "private-resume-offer-file", MAX_OFFER).await?,
            };
            let (owner, recipient) = {
                let s = app.borrow();
                let m = s.room.as_ref().ok_or("Open this recipient device first.")?;
                (m.owner.claims().account, m.status.context.account)
            };
            let info = ContactBootstrap::inspect(&raw, owner, recipient, now()?).map_err(|_| {
                "This is not a current valid offer for the retained owner and recipient."
            })?;
            if info.scope() != context(app)?.scope {
                return Err("The offer belongs to another private room.".into());
            }
            artifact(
                app,
                call(
                    app,
                    ticket,
                    Request::ContactRequest {
                        operation: operation()?,
                        offer: raw,
                    },
                )
                .await?,
            )?;
            app.borrow_mut().offer = None;
            status(app, "Encrypted recipient request saved. Export it to the pinned owner; use the retained outbox for exact retries.", false);
        }
        Action::Accept => {
            let recipient = key(&input(app, "private-recipient").value())?;
            let raw = file(app, ticket, "private-request-file", MAX_ARTIFACT).await?;
            // An explicit original file takes precedence over the last live
            // offer. With no file, do not ignore a changed recipient field.
            let selected_file = input(app, "private-resume-offer-file")
                .files()
                .is_some_and(|files| files.length() != 0);
            let offer = if selected_file {
                file(app, ticket, "private-resume-offer-file", MAX_OFFER).await?
            } else {
                let s = app.borrow();
                let retained = s.secret.as_ref().ok_or("Reselect the original confidential offer and its recipient account before accepting this request.")?;
                if retained.recipient != recipient {
                    return Err("The selected recipient differs from the live offer. Choose the correct original offer file explicitly.".into());
                }
                retained.bytes.clone()
            };
            let (context, owner) = {
                let s = app.borrow();
                let view = s.room.as_ref().ok_or("Open the owner room first.")?;
                (view.status.context, view.owner.clone())
            };
            let start = now()?;
            let (info, enrollment) = ContactBootstrap::inspect_request(
                &offer,
                &raw,
                owner.claims().account,
                recipient,
                start,
            )
            .map_err(|_| "The selected offer and request do not form a current authenticated request for this exact recipient.")?;
            if info.scope() != context.scope || info.owner() != &owner {
                return Err(
                    "The request's signed offer belongs to another room or owner enrollment."
                        .into(),
                );
            }
            let end = info
                .validity()
                .expires_at()
                .min(enrollment.claims().validity.expires_at())
                .min(
                    start
                        .checked_add(3600)
                        .ok_or("Invitation expiry overflow.")?,
                );
            let validity = Validity::new(start, end).map_err(|_| {
                "The offer or recipient enrollment has expired; no request was consumed."
            })?;
            status(app, &format!("Accepting the authenticated request for account {} · device {}. Its invitation expires no later than the original signed offer and recipient enrollment.", hex(recipient.as_bytes()), hex(enrollment.claims().device.as_bytes())), false);
            artifact(
                app,
                call(
                    app,
                    ticket,
                    Request::Accept {
                        operation: operation()?,
                        request: raw,
                        validity,
                    },
                )
                .await?,
            )?;
            refresh(app, ticket).await?;
            status(app, &format!("Request for account {} consumed and encrypted response saved. Transfer this response to that recipient and the next encrypted control to existing members.", hex(recipient.as_bytes())), false);
        }
        Action::Join | Action::Apply => {
            let id = if matches!(action, Action::Join) {
                "private-join-file"
            } else {
                "private-control-file"
            };
            let raw = file(app, ticket, id, MAX_ARTIFACT).await?;
            let request = if matches!(action, Action::Join) {
                Request::Join(raw)
            } else {
                Request::ApplyControl(raw)
            };
            let Response::Membership(view) = call(app, ticket, request).await? else {
                return Err("Unexpected membership transition report.".into());
            };
            membership(app, view);
            status(app, "The exact authenticated transition was saved. Review current membership before preparing any new message.", false);
        }
        Action::Remove => {
            let device = key(&input(app, "private-remove-device").value())?;
            // Validate the selected full key against this displayed roster before worker mutation.
            {
                let s = app.borrow();
                let m = s.room.as_ref().ok_or("No selected room.")?;
                if device == m.owner.claims().device
                    || !m.members.iter().any(|e| e.claims().device == device)
                {
                    return Err(
                        "Select an admitted device other than this fixed owner device.".into(),
                    );
                }
            }
            artifact(
                app,
                call(
                    app,
                    ticket,
                    Request::Remove {
                        operation: operation()?,
                        device,
                    },
                )
                .await?,
            )?;
            refresh(app, ticket).await?;
            status(app, "Removal and rekey saved. Explicitly distribute this encrypted owner control; old received plaintext cannot be revoked.", false);
        }
        Action::Renew => {
            let old = app
                .borrow()
                .room
                .as_ref()
                .ok_or("No selected room.")?
                .owner
                .claims()
                .validity;
            let start = now()?;
            let end = old
                .expires_at()
                .max(start)
                .checked_add(WEEK)
                .ok_or("Enrollment expiry overflow.")?;
            let validity =
                Validity::new(old.not_before(), end).map_err(|_| "Invalid renewed interval.")?;
            artifact(
                app,
                call(
                    app,
                    ticket,
                    Request::Renew {
                        operation: operation()?,
                        validity,
                    },
                )
                .await?,
            )?;
            refresh(app, ticket).await?;
            status(app, "Same owner device renewed and epoch advanced. Prior message consent is invalid; this does not recover a lost owner device.", false);
        }
        Action::Controls | Action::ControlsNext => {
            controls(app, ticket, matches!(action, Action::ControlsNext)).await?
        }
        Action::Outbox | Action::OutboxNext => {
            outbox(app, ticket, matches!(action, Action::OutboxNext)).await?
        }
        Action::Inbox | Action::InboxNext => {
            inbox(app, ticket, matches!(action, Action::InboxNext)).await?
        }
        Action::DownloadControl => {
            let index = selected(app, "private-control-select")?;
            let (name, bytes) = {
                let s = app.borrow();
                let c = s
                    .controls
                    .get(index)
                    .ok_or("Select a retained encrypted control.")?;
                (
                    format!("private-control-{}.vhcontrol", c.floor.sequence()),
                    c.bytes.clone(),
                )
            };
            download(app, &name, &bytes)?;
            status(app, "Exact encrypted control download requested. Recipients must apply their next control in order.", false);
        }
        Action::DownloadOutbox => {
            let index = selected(app, "private-outbox-select")?;
            let (name, bytes) = {
                let s = app.borrow();
                export_parts(s.outbox.get(index).ok_or("Select a retained output.")?)?
            };
            download(app, &name, &bytes)?;
            status(app, "Exact retained ciphertext download requested; this did not create a new intent or delivery claim.", false);
        }
        Action::Leave => return Err("Leave is handled synchronously before any await.".into()),
    }
    Ok(())
}

fn export_parts(a: &Artifact) -> Result<(String, Bytes)> {
    let (_, suffix) = model::encrypted_export(a.kind).ok_or(
        "Secret offers and legacy plaintext bootstrap are not ordinary ciphertext exports.",
    )?;
    let bytes = a
        .bytes
        .as_ref()
        .ok_or("Secret offers are metadata-only in the outbox.")?;
    Ok((
        format!(
            "private-{}-{}.{}",
            a.sequence,
            hex(a.operation.as_bytes()),
            suffix
        ),
        bytes.clone(),
    ))
}
async fn controls(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow().controls_next.ok_or("No next control page.")?
    } else {
        let head = app
            .borrow()
            .room
            .as_ref()
            .ok_or("No selected room.")?
            .status
            .control_floor;
        // Fresh members lack predecessor keys for their own admission. Ask at
        // the known head to learn the distinct encrypted-history base first.
        let Response::Controls { base, .. } = call(
            app,
            ticket,
            Request::Controls {
                after: head,
                limit: PAGE,
            },
        )
        .await?
        else {
            return Err("Unexpected control boundary report.".into());
        };
        base
    };
    let Response::Controls {
        records,
        next,
        base,
        head,
        ..
    } = call(app, ticket, Request::Controls { after, limit: PAGE }).await?
    else {
        return Err("Unexpected encrypted control page.".into());
    };
    options(
        app,
        "private-control-select",
        records
            .iter()
            .map(|c| format!("Encrypted control {}", c.floor.sequence()))
            .collect(),
    );
    let count = records.len();
    {
        let mut s = app.borrow_mut();
        s.controls = records;
        s.controls_next = next;
    }
    status(app, &format!("Read {count} encrypted controls. This device's retained wire history begins after floor {}; observed head {}. Earlier plaintext bootstrap is not exported.", base.sequence(), head.sequence()), false);
    Ok(())
}
async fn outbox(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow().outbox_next.ok_or("No next outbox page.")?
    } else {
        0
    };
    let Response::Outbox {
        records,
        next,
        head,
        ..
    } = call(app, ticket, Request::Outbox { after, limit: PAGE }).await?
    else {
        return Err("Unexpected outbox page.".into());
    };
    options(
        app,
        "private-outbox-select",
        records
            .iter()
            .map(|a| {
                format!(
                    "{} · {} · operation {}",
                    a.sequence,
                    model::encrypted_export(a.kind)
                        .map_or("Metadata / non-exportable bootstrap", |(label, _)| label),
                    hex(a.operation.as_bytes())
                )
            })
            .collect(),
    );
    {
        let mut s = app.borrow_mut();
        s.outbox = records;
        s.outbox_next = next;
    }
    status(app, &format!("Retained outbox through local sequence {head}. Select exact ciphertext for retry; secret offers remain metadata-only. No delivery claim."), false);
    Ok(())
}
async fn inbox(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow().inbox_next.ok_or("No next inbox page.")?
    } else {
        0
    };
    let Response::Inbox {
        records,
        next,
        head,
        ..
    } = call(app, ticket, Request::Inbox { after, limit: PAGE }).await?
    else {
        return Err("Unexpected inbox page.".into());
    };
    let mut contents = Zeroizing::new(String::new());
    for record in records {
        contents.push_str(&inbox_text(&record));
        contents.push('\n');
    }
    text(app, "private-inbox-content", &contents);
    app.borrow_mut().inbox_next = next;
    status(app, &format!("Showing one bounded page of already committed messages; local inbox head {head}. Imported text is not an instruction or authority."), false);
    Ok(())
}
