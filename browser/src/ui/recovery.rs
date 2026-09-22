//! Typed worker bridge; no recovery operation exposes seed or generic signing.
use super::*;
use vhalla_browser_vault::backup::{AuthorBackupPage, MAX_ENCRYPTED_AUTHOR_PAGE_BYTES};

/// Offer one bounded encrypted part for explicit recovery export. Browser download
/// initiation is not confirmation that the user retained the file.
pub fn download_author_part(raw: &[u8], backup: [u8; 32], index: u64) -> Result<(), String> {
    if raw.len() > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES || raw.get(..8) != Some(b"VHBENC01".as_slice()) {
        return Err("Invalid encrypted author backup part.".into());
    }
    let part = index
        .checked_add(1)
        .ok_or("The author backup part number is exhausted.")?;
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    let document = {
        let state = app.borrow();
        if !state.can_operate() || state.downloads.len() >= MAX_DOWNLOADS {
            return Err(
                "Wait ten seconds for the previous downloads, then retry this part.".into(),
            );
        }
        state.document.clone()
    };
    let perform = || -> Result<String, JsValue> {
        let parts = Array::new();
        parts.push(&Uint8Array::from(raw));
        let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)?;
        let link: HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
        let body = document.body().ok_or(JsValue::NULL)?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)?;
        link.set_href(&url);
        link.set_download(&format!(
            "vhalla-author-{}-part-{part:020}.vhauthor",
            hex(&backup)
        ));
        if let Err(error) = link
            .set_attribute("hidden", "")
            .and_then(|()| body.append_child(&link).map(|_| ()))
        {
            let _ = web_sys::Url::revoke_object_url(&url);
            return Err(error);
        }
        link.click();
        link.remove();
        Ok(url)
    };
    let url = perform().map_err(|_| "Could not start this part's download.")?;
    let mut state = app.borrow_mut();
    let deadline = state.clock.now() + 10_000.0;
    state.downloads.push((url, deadline));
    Ok(())
}

/// Exact authenticated saved identity, captured only while idle and unlocked.
pub fn recovery_identity() -> Result<IdentitySnapshot, String> {
    let author = activity_author()?;
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    let state = app.borrow();
    let envelope = state
        .saved
        .vault()
        .and_then(|v| v.records().next())
        .and_then(|raw| Envelope::from_bytes(raw).ok())
        .ok_or("No saved identity.")?;
    if envelope.claimed_public_key() != author {
        return Err("The unlocked identity changed.".into());
    }
    Ok(state.saved.clone())
}
/// Protect a bounded canonical author-state page in the unlocked identity worker.
pub async fn encrypt_author_page(page: AuthorBackupPage) -> Result<Vec<u8>, String> {
    let raw = page.encode();
    request(raw, Some(page)).await
}
/// Authenticate a bounded page with the restored key. The storage controller
/// still checks independently selected scope/pin, full history and import CAS.
pub async fn decrypt_author_page(raw: Vec<u8>) -> Result<AuthorBackupPage, String> {
    let raw = request(raw, None).await?;
    AuthorBackupPage::decode(&raw)
        .map_err(|_| "The worker returned an invalid recovery page.".into())
}
async fn request(raw: Vec<u8>, expected: Option<AuthorBackupPage>) -> Result<Vec<u8>, String> {
    if raw.len() > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES {
        return Err("Author backup page exceeds its bound.".into());
    }
    let author = activity_author()?;
    if expected
        .as_ref()
        .is_some_and(|p| p.scope()[112..144] != author)
    {
        return Err("This backup belongs to another identity.".into());
    }
    let app = IDENTITY
        .with(|slot| slot.borrow().as_ref().and_then(Weak::upgrade))
        .ok_or("Identity support is not ready.")?;
    let token = begin_operation(&app, Stage::Backup, READY_MS).ok_or("Identity is busy.")?;
    let encrypt = expected.is_some();
    let (sender, receiver) = oneshot::channel();
    app.borrow_mut().pending.as_mut().unwrap().kind = PendingKind::Backup {
        expected,
        author,
        reply: sender,
    };
    let guard = OperationGuard {
        app: Rc::downgrade(&app),
        token,
        stage: Stage::Backup,
        message: "Author recovery was interrupted. Preserve the backup and reload before retrying.",
    };
    let mut token_raw = [0; 16];
    token_raw[..8].copy_from_slice(&token.generation.to_be_bytes());
    token_raw[8..].copy_from_slice(&token.operation.to_be_bytes());
    let fields = Array::new();
    fields.push(&JsValue::from_str(if encrypt {
        "encrypt-author-page"
    } else {
        "decrypt-author-page"
    }));
    fields.push(&Uint8Array::from(token_raw.as_slice()));
    fields.push(&Uint8Array::from(raw.as_slice()));
    let sent = app
        .borrow()
        .worker
        .as_ref()
        .is_some_and(|worker| worker.post_message(&fields).is_ok());
    if !sent {
        fail(
            &app,
            "Could not reach the identity worker. Preserve the backup and reload.",
        );
    } else {
        render(&app);
    }
    let result = receiver.await.unwrap_or_else(|_| {
        Err("Author recovery was interrupted. Reload to reconcile retained state.".into())
    });
    drop(guard);
    result
}
pub(super) fn finish_page(app: &App, fields: &Array) {
    let (Ok(token), Ok(raw)) = (
        fields.get(1).dyn_into::<Uint8Array>(),
        fields.get(2).dyn_into::<Uint8Array>(),
    ) else {
        fail(app, "Invalid recovery worker response. Reload to retry.");
        return;
    };
    if token.length() != 16 || raw.length() as usize > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES {
        fail(
            app,
            "Invalid recovery worker response size. Reload to retry.",
        );
        return;
    }
    let token = token.to_vec();
    let token = Token {
        generation: u64::from_be_bytes(token[..8].try_into().unwrap()),
        operation: u64::from_be_bytes(token[8..].try_into().unwrap()),
    };
    if !app.borrow().current(token, Stage::Backup) {
        return;
    }
    let bytes = raw.to_vec();
    let valid = {
        let state = app.borrow();
        match &state.pending.as_ref().unwrap().kind {
            PendingKind::Backup {
                expected: Some(page),
                author,
                ..
            } => {
                bytes.len() == 285 + page.payload().len() + 16
                    && bytes.get(..8) == Some(b"VHBENC01".as_slice())
                    && bytes.get(8..184) == Some(page.scope().as_slice())
                    && bytes.get(184..216) == Some(page.backup_id().as_slice())
                    && bytes.get(216..224) == Some(page.index().to_be_bytes().as_slice())
                    && bytes.get(224..256) == Some(page.previous().as_slice())
                    && bytes.get(256) == Some(&u8::from(page.is_final()))
                    && page.scope()[112..144] == *author
            }
            PendingKind::Backup {
                expected: None,
                author,
                ..
            } => AuthorBackupPage::decode(&bytes).is_ok_and(|p| p.scope()[112..144] == *author),
            _ => false,
        }
    };
    if !valid {
        fail(app,"Recovery worker response did not match the selected identity or page. Reload to retry.");
        return;
    }
    let pending = app.borrow_mut().pending.take().unwrap();
    if let PendingKind::Backup { reply, .. } = pending.kind {
        let _ = reply.send(Ok(bytes));
    }
    render(app);
}
