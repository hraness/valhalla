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
                        "Select an admitted device other than the current owner device.".into(),
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
        Action::Succeed => {
            let successor = key(&input(app, "private-succeed-device").value())?;
            let validity = {
                let s = app.borrow();
                let m = s.room.as_ref().ok_or("No selected room.")?;
                let owner = m.owner.claims();
                let target = m
                    .members
                    .iter()
                    .find(|e| e.claims().device == successor)
                    .ok_or("Select an already-admitted member device; an unknown key cannot take ownership.")?;
                if successor == owner.device {
                    return Err("That device already holds owner authority.".into());
                }
                if target.claims().account != owner.account {
                    return Err(
                        "Succession stays inside this account; select a device with the same account key."
                            .into(),
                    );
                }
                target.claims().validity
            };
            artifact(
                app,
                call(
                    app,
                    ticket,
                    Request::Succeed {
                        operation: operation()?,
                        successor,
                        validity,
                    },
                )
                .await?,
            )?;
            refresh(app, ticket).await?;
            status(app, "Ownership handed to the selected device and epoch advanced. This device keeps ordinary membership; only the new owner issues controls now.", false);
        }
        Action::Controls | Action::ControlsNext => {
            controls(app, ticket, matches!(action, Action::ControlsNext)).await?
        }
        Action::Proofs | Action::ProofsNext => {
            proofs(app, ticket, matches!(action, Action::ProofsNext)).await?
        }
        Action::Observe => {
            let raw = file(app, ticket, "private-proof-file", MAX_ARTIFACT).await?;
            let Response::Observed { verdict, .. } =
                call(app, ticket, Request::ObserveControl(raw)).await?
            else {
                return Err("Unexpected observation report.".into());
            };
            status(app, match verdict {
                ObserveVerdict::Retained => "That exact signed control is already retained history on this device.",
                ObserveVerdict::UnknownHistory => "Valid owner signature at a floor this device has not retained. Apply the missing encrypted controls in order; an observed proof is never adopted as state.",
                ObserveVerdict::BeforeBase => "Valid owner signature below this device's retained history base. This device joined later and cannot confirm or apply predecessor floors; the proof is never adopted as state.",
            }, false);
        }
        Action::ForkEvidence => {
            let Response::ForkEvidence { proof, .. } =
                call(app, ticket, Request::ForkEvidence).await?
            else {
                return Err("Unexpected fork evidence report.".into());
            };
            match proof {
                Some(proof) => {
                    let conflicting = SignedOwnerControl::decode(&proof.conflicting)
                        .and_then(|c| c.verify())
                        .map(|c| hex(c.id().as_bytes()))
                        .unwrap_or_else(|_| "unverifiable".into());
                    text(app, "private-evidence", &format!(
                        "Retained fork proof\nAccepted floor {} · control {}\nConflicting valid owner control {}\nAccepted-side proof: {} bytes{}\nThis device is durably quarantined: history stays readable, new sends are refused, and this evidence never grants succession.",
                        proof.accepted.sequence(),
                        proof.accepted.id().map(|id| hex(id.as_bytes())).unwrap_or_else(|| "joining checkpoint".into()),
                        conflicting,
                        proof.accepted_proof.len(),
                        if proof.accepted_from_checkpoint { " (joining checkpoint)" } else { "" },
                    ));
                    status(app, "A conflicting owner signature was proven at a retained floor. Preserve this device and evidence; do not reset or recreate it.", false);
                }
                None => {
                    text(app, "private-evidence", "");
                    status(app, "No locally retained fork proof. Absence is not a freshness or fork-freedom claim.", false);
                }
            }
        }
        Action::DownloadProof => {
            let index = selected(app, "private-proof-select")?;
            let (name, bytes) = {
                let s = app.borrow();
                let c = s
                    .proofs
                    .get(index)
                    .ok_or("Select a retained signed proof.")?;
                (
                    format!("private-proof-{}.vhproof", c.floor.sequence()),
                    c.bytes.clone(),
                )
            };
            download(app, &name, &bytes)?;
            status(app, "Exact signed control proof downloaded. It is a plaintext inspection record, not the encrypted control members apply.", false);
        }
        Action::Outbox | Action::OutboxNext => {
            outbox(app, ticket, matches!(action, Action::OutboxNext)).await?
        }
        Action::Inbox | Action::InboxNext => {
            inbox(app, ticket, matches!(action, Action::InboxNext)).await?
        }
        Action::ExportArchive => export_archive(app, ticket).await?,
        Action::ImportArchive => import_archive(app, ticket).await?,
        Action::OpenArchive => open_archive(app, ticket).await?,
        Action::ArchiveOutbox | Action::ArchiveOutboxNext => {
            archive_outbox(app, ticket, matches!(action, Action::ArchiveOutboxNext)).await?
        }
        Action::ArchiveInbox | Action::ArchiveInboxNext => {
            archive_inbox(app, ticket, matches!(action, Action::ArchiveInboxNext)).await?
        }
        Action::ArchiveOutboxDownload => {
            let index = selected(app, "private-archive-outbox-select")?;
            let (name, bytes) = {
                let s = app.borrow();
                let archive = s.archive.as_ref().ok_or("No open archive view.")?;
                export_parts(
                    archive
                        .outbox
                        .get(index)
                        .ok_or("Select an archived output.")?,
                )?
            };
            download(app, &name, &bytes)?;
            status(app, "Exact archived ciphertext download requested; this is historical evidence, not a new send.", false);
        }
        Action::ArchiveClose => {
            let Response::ArchiveClosed { .. } = call(app, ticket, Request::ArchiveClose).await?
            else {
                return Err("Unexpected archive close report.".into());
            };
            app.borrow_mut().archive = None;
            for id in [
                "private-archive-title",
                "private-archive-summary",
                "private-archive-details",
                "private-archive-inbox-content",
                "private-archive-outbox-select",
            ] {
                text(app, id, "");
            }
            status(app, "Archive view closed. The durable read-only destination is unchanged; reopen it with the same .vharchive file.", false);
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
async fn proofs(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow().proofs_next.ok_or("No next proof page.")?
    } else {
        let head = app
            .borrow()
            .room
            .as_ref()
            .ok_or("No selected room.")?
            .status
            .control_floor;
        // Probe at the observed head to learn the retained base first, exactly
        // like the encrypted-control path; late joiners lack earlier proofs.
        let Response::ControlProofs { base, .. } = call(
            app,
            ticket,
            Request::ControlProofs {
                after: head,
                limit: PAGE,
            },
        )
        .await?
        else {
            return Err("Unexpected proof boundary report.".into());
        };
        base
    };
    let Response::ControlProofs {
        records,
        next,
        base,
        head,
        ..
    } = call(app, ticket, Request::ControlProofs { after, limit: PAGE }).await?
    else {
        return Err("Unexpected signed-proof page.".into());
    };
    options(
        app,
        "private-proof-select",
        records
            .iter()
            .map(|c| format!("Signed control {}", c.floor.sequence()))
            .collect(),
    );
    let count = records.len();
    {
        let mut s = app.borrow_mut();
        s.proofs = records;
        s.proofs_next = next;
    }
    status(app, &format!("Read {count} signed control proofs from floor {} through observed head {}. These plaintext proofs are for inspection; members still apply the encrypted envelopes in order.", base.sequence(), head.sequence()), false);
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

fn archive_file(app: &App) -> Result<web_sys::File> {
    input(app, "private-archive-file")
        .files()
        .and_then(|files| files.get(0))
        .ok_or("Choose one complete .vharchive file first.".into())
}
/// Read one bounded slice of a selected file. File size is a u53-safe bound.
async fn slice(
    app: &App,
    ticket: u64,
    file: &web_sys::File,
    start: u64,
    end: u64,
) -> Result<Bytes> {
    let part = file
        .slice_with_f64_and_f64(start as f64, end as f64)
        .map_err(|_| "Could not slice the selected archive.")?;
    let buffer = JsFuture::from(part.array_buffer())
        .await
        .map_err(|_| "Could not read the selected archive.")?;
    live(app, ticket)?;
    let raw = Uint8Array::new(&buffer);
    if raw.length() as u64 != end - start {
        return Err("The selected archive changed while it was being read.".into());
    }
    Ok(Zeroizing::new(raw.to_vec()))
}
/// Read one length-prefixed encrypted page, or the explicit end marker.
/// Truncated, oversized or trailing bytes are refused before any worker call.
async fn archive_page(
    app: &App,
    ticket: u64,
    file: &web_sys::File,
    size: u64,
    offset: &mut u64,
) -> Result<Option<Bytes>> {
    if offset.checked_add(4).ok_or("Archive offset overflow.")? > size {
        return Err("Truncated archive: missing page length.".into());
    }
    let head = slice(app, ticket, file, *offset, *offset + 4).await?;
    let length = u32::from_be_bytes(head[..4].try_into().expect("four-byte length")) as u64;
    *offset += 4;
    if length == 0 {
        if *offset != size {
            return Err("Bytes follow the archive's explicit end marker.".into());
        }
        return Ok(None);
    }
    if length > vhalla_private_kernel::recovery::MAX_ARCHIVE_PAGE_BYTES as u64 {
        return Err("An archive page exceeds the kernel's fixed bound.".into());
    }
    if offset
        .checked_add(length)
        .ok_or("Archive offset overflow.")?
        > size
    {
        return Err("Truncated archive: missing page content.".into());
    }
    let page = slice(app, ticket, file, *offset, *offset + length).await?;
    *offset += length;
    Ok(Some(page))
}
fn checked_archive_file(file: &web_sys::File) -> Result<u64> {
    let size = file.size();
    if !size.is_finite()
        || size <= model::ARCHIVE_HEADER as f64 + 4.0
        || size > model::ARCHIVE_FILE_MAX as f64
    {
        return Err("Choose a complete .vharchive file within the bounded archive format.".into());
    }
    Ok(size as u64)
}
fn archive_opened(
    app: &App,
    context: Context,
    archive_id: [u8; 32],
    source_revision: u64,
    status: Status,
) {
    app.borrow_mut().archive = Some(ArchivePanel {
        context,
        archive_id,
        source_revision,
        status,
        outbox: Vec::new(),
        outbox_next: None,
        inbox_next: None,
    });
}
fn archive_inspected(app: &App, reply: Response) -> Result<()> {
    let Response::ArchiveInspect {
        context,
        archive_id,
        source_revision,
        status,
    } = reply
    else {
        return Err("Unexpected archive inspection report.".into());
    };
    archive_opened(app, context, archive_id, source_revision, status);
    Ok(())
}
async fn export_archive(app: &App, ticket: u64) -> Result<()> {
    let Response::ArchiveBegin {
        context,
        archive_id,
    } = call(app, ticket, Request::ArchiveExport).await?
    else {
        return Err("Unexpected archive start report.".into());
    };
    let mut parts: Vec<Vec<u8>> = vec![model::archive_header(context, archive_id)];
    let mut total = model::ARCHIVE_HEADER as u64;
    let mut pages = 0u64;
    loop {
        let Response::ArchivePage {
            context: reported,
            page,
        } = call(app, ticket, Request::ArchiveExportNext).await?
        else {
            return Err("Unexpected archive page report.".into());
        };
        if reported != context {
            return Err("An archive page arrived bound to a different room.".into());
        }
        let Some(page) = page else { break };
        pages = pages.checked_add(1).ok_or("Archive page overflow.")?;
        total = total
            .checked_add(4)
            .and_then(|v| v.checked_add(page.len() as u64))
            .ok_or("Archive size overflow.")?;
        if pages > model::ARCHIVE_PAGES_MAX || total > model::ARCHIVE_FILE_MAX {
            return Err("Archive exceeds the bounded browser file format.".into());
        }
        parts.push(
            u32::try_from(page.len())
                .expect("bounded page")
                .to_be_bytes()
                .to_vec(),
        );
        parts.push(page.to_vec());
        status(
            app,
            &format!("Streaming encrypted archive: {pages} pages, {total} bytes so far."),
            false,
        );
    }
    parts.push(0u32.to_be_bytes().to_vec());
    total += 4;
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    download_parts(
        app,
        &format!(
            "private-archive-{}-{}.vharchive",
            hex(context.scope.room.as_bytes()),
            hex(&archive_id)
        ),
        &parts,
    )?;
    status(app, &format!("Exported {pages} encrypted pages ({total} bytes) as one .vharchive file. Keep it private: this account's key opens it, and it never grants live membership."), false);
    Ok(())
}
async fn import_archive(app: &App, ticket: u64) -> Result<()> {
    let file = archive_file(app)?;
    let size = checked_archive_file(&file)?;
    let header = slice(app, ticket, &file, 0, model::ARCHIVE_HEADER as u64).await?;
    let (context, archive_id) = model::decode_archive_header(&header)?;
    if app.borrow().account != Some(context.account) {
        return Err("This archive belongs to another account. Nothing was imported.".into());
    }
    let Response::ArchiveBegin {
        context: reported,
        archive_id: reported_id,
    } = call(
        app,
        ticket,
        Request::ArchiveImportBegin {
            context,
            archive_id,
        },
    )
    .await?
    else {
        return Err("Unexpected archive destination report.".into());
    };
    if reported != context || reported_id != archive_id {
        return Err("The archive destination does not match the selected file.".into());
    }
    let mut offset = model::ARCHIVE_HEADER as u64;
    let mut index = 0u64;
    let mut ready = false;
    let mut next_page = 0u64;
    let mut held: Option<(u64, Bytes)> = None;
    // One page of lookahead identifies the authenticated final page, which must
    // go to finish rather than the record append path.
    while let Some(page) = archive_page(app, ticket, &file, size, &mut offset).await? {
        if index >= model::ARCHIVE_PAGES_MAX {
            return Err("Archive exceeds the bounded browser file format.".into());
        }
        if let Some((held_index, held_page)) = held.replace((index, page)) {
            // Skip only pages confirmed durably committed; the last committed
            // page is re-fed so the worker validates its exact retry.
            if !ready || held_index + 1 >= next_page {
                let Response::ArchiveProgress {
                    context: reported,
                    source_ready,
                    next_page: advanced,
                    records,
                    bytes,
                } = call(app, ticket, Request::ArchiveImportFeed(held_page)).await?
                else {
                    return Err("Unexpected archive progress report.".into());
                };
                if reported != context {
                    return Err("Archive progress reported a different room.".into());
                }
                ready = source_ready;
                next_page = advanced;
                status(
                    app,
                    &format!(
                        "Importing encrypted archive: {records} records, {bytes} bytes durable; file page {held_index}."
                    ),
                    false,
                );
            }
        }
        index += 1;
    }
    let Some((_, final_page)) = held.take() else {
        return Err("The archive file has no pages.".into());
    };
    let reply = call(app, ticket, Request::ArchiveImportFinish(final_page)).await?;
    archive_inspected(app, reply)?;
    status(app, "Archive imported into read-only storage and verified complete. This view cannot send, invite, or mutate the live room.", false);
    Ok(())
}
async fn open_archive(app: &App, ticket: u64) -> Result<()> {
    let file = archive_file(app)?;
    let size = checked_archive_file(&file)?;
    let header = slice(app, ticket, &file, 0, model::ARCHIVE_HEADER as u64).await?;
    let (context, archive_id) = model::decode_archive_header(&header)?;
    if app.borrow().account != Some(context.account) {
        return Err("This archive belongs to another account. Nothing was opened.".into());
    }
    // Length-prefixed pages cannot be sought; walk the bounded file once and
    // retain only the authenticated final page for the worker's seal check.
    let mut offset = model::ARCHIVE_HEADER as u64;
    let mut index = 0u64;
    let mut last: Option<Bytes> = None;
    while let Some(page) = archive_page(app, ticket, &file, size, &mut offset).await? {
        index += 1;
        if index > model::ARCHIVE_PAGES_MAX {
            return Err("Archive exceeds the bounded browser file format.".into());
        }
        last = Some(page);
    }
    let final_page = last.ok_or("The archive file has no pages.")?;
    let reply = call(
        app,
        ticket,
        Request::ArchiveOpen {
            context,
            archive_id,
            final_page,
        },
    )
    .await?;
    archive_inspected(app, reply)?;
    status(app, "Opened the completed archive read-only. It shows the source room's last exported state only; it cannot send or mint membership.", false);
    Ok(())
}
async fn archive_outbox(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow()
            .archive
            .as_ref()
            .and_then(|a| a.outbox_next)
            .ok_or("No next archive outbox page.")?
    } else {
        0
    };
    let Response::Outbox {
        records,
        next,
        head,
        ..
    } = call(app, ticket, Request::ArchiveOutbox { after, limit: PAGE }).await?
    else {
        return Err("Unexpected archive outbox page.".into());
    };
    options(
        app,
        "private-archive-outbox-select",
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
        if let Some(archive) = s.archive.as_mut() {
            archive.outbox = records;
            archive.outbox_next = next;
        }
    }
    status(app, &format!("Archived outbox through local sequence {head}. Historical evidence only; no delivery or send authority."), false);
    Ok(())
}
async fn archive_inbox(app: &App, ticket: u64, next: bool) -> Result<()> {
    let after = if next {
        app.borrow()
            .archive
            .as_ref()
            .and_then(|a| a.inbox_next)
            .ok_or("No next archive inbox page.")?
    } else {
        0
    };
    let Response::Inbox {
        records,
        next,
        head,
        ..
    } = call(app, ticket, Request::ArchiveInbox { after, limit: PAGE }).await?
    else {
        return Err("Unexpected archive inbox page.".into());
    };
    let mut contents = Zeroizing::new(String::new());
    for record in records {
        contents.push_str(&inbox_text(&record));
        contents.push('\n');
    }
    text(app, "private-archive-inbox-content", &contents);
    {
        let mut s = app.borrow_mut();
        if let Some(archive) = s.archive.as_mut() {
            archive.inbox_next = next;
        }
    }
    status(app, &format!("Showing one bounded page of archived committed messages; archived inbox head {head}. This content is inert history, not live input."), false);
    Ok(())
}
