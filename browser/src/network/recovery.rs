//! Explicit multipart author backup/recovery; never a key-only sequence reset.
use crate::ui;
use std::cell::RefCell;
use vhalla_browser_storage::{
    browser::outbox::IndexedOutbox,
    history::HistoryScope,
    outbox::{recovery::Export, AuthorScope},
    Namespace,
};
use vhalla_browser_vault::backup::MAX_ENCRYPTED_AUTHOR_PAGE_BYTES;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

thread_local! { static EXPORT:RefCell<Option<Export>>=const {RefCell::new(None)}; }
const PROFILE: [u8; 32] = *b"vhalla-browser-local-profile-v01";

/// Result text for the activity recovery status surface.
pub(super) struct Notice {
    /// True only after the final export part was offered or import activated.
    /// A download event itself does not prove a file was retained.
    pub complete: bool,
    /// Concrete progress and next action, with no secret or unsigned content.
    pub message: String,
}
async fn storage() -> Result<IndexedOutbox, String> {
    IndexedOutbox::open(Namespace::new(PROFILE))
        .await
        .map_err(|_| "Could not open author storage. Reload to reconcile it.".into())
}

/// Offer one next encrypted part. The network controller owns the action's busy
/// state and deadline, and supplies scope from its verified selected room.
pub(super) async fn export_part(
    scope: AuthorScope,
    history: HistoryScope,
) -> Result<Notice, String> {
    if ui::activity_author()? != scope.author() {
        return Err("Choose a room for the unlocked identity.".into());
    }
    let mut storage = storage().await?;
    // Take before awaiting; a canceled export loses only its continuation. It
    // cannot leave a partial file falsely marked complete or change author state.
    let saved = EXPORT.with(|slot| slot.borrow_mut().take());
    let export = match saved {
        Some(export)
            if export.snapshot().head().scope() == scope
                && export.snapshot().history_scope() == history =>
        {
            export
        }
        _ => {
            let mut id = [0; 32];
            web_sys::window()
                .ok_or("Browser unavailable.")?
                .crypto()
                .map_err(|_| "Secure randomness unavailable.")?
                .get_random_values_with_u8_array(&mut id)
                .map_err(|_| "Secure randomness failed.")?;
            storage.begin_export(scope,history,id).await.map_err(|_|"No complete author state exists for this room, or it changed. Reload before exporting.")?
        }
    };
    let result = if export.ended() {
        storage
            .finish_export(&export)
            .await
            .map(|page| (None, page))
    } else {
        storage
            .export_page(&export)
            .await
            .map(|(next, page)| (Some(next), page))
    };
    let (next,page)=match result {Ok(value)=>value,Err(_)=>return Err("Author state changed or is incomplete. Keep earlier parts separate and start a new backup while other tabs and devices are idle.".into())};
    let final_part = page.is_final();
    let index = page.index();
    let part = index
        .checked_add(1)
        .ok_or("The author backup part number is exhausted.")?;
    let backup = page.backup_id();
    let encrypted = ui::encrypt_author_page(page).await?;
    if let Err(error) = ui::download_author_part(&encrypted, backup, index) {
        EXPORT.with(|slot| *slot.borrow_mut() = Some(export));
        return Err(error);
    }
    EXPORT.with(|slot| *slot.borrow_mut() = next);
    Ok(Notice {
        complete: final_part,
        message: if final_part {
            format!("Final part {part} offered (filename ends in part-{part:020}.vhauthor). Keep every numbered part together with the encrypted identity key backup. This captures a local state, not proof it is the latest; stop the old authoring device before restoring.")
        } else {
            format!("Part {part} offered (filename ends in part-{part:020}.vhauthor). Save it, then select Export next author-state part again. The backup is incomplete until its final part. Keep authoring and delivery idle during export.")
        },
    })
}

/// Import one bounded encrypted file, or continue receipt verification by
/// selecting the same final part again. Staging survives reload; it grants no
/// authoring authority until the complete exact namespace is activated.
pub(super) async fn import_part(
    scope: AuthorScope,
    history: HistoryScope,
    file: web_sys::File,
) -> Result<Notice, String> {
    if ui::activity_author()? != scope.author() {
        return Err("Unlock the recovered identity first.".into());
    }
    if !file.size().is_finite()
        || file.size() < 1.0
        || file.size() > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES as f64
    {
        return Err("Choose one bounded .vhauthor backup part.".into());
    }
    let value = JsFuture::from(file.array_buffer())
        .await
        .map_err(|_| "Could not read this backup part.")?;
    let buffer = value
        .dyn_into::<js_sys::ArrayBuffer>()
        .map_err(|_| "Invalid backup file.")?;
    if buffer.byte_length() as usize > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES {
        return Err("Backup part exceeds its bound.".into());
    }
    let page = ui::decrypt_author_page(js_sys::Uint8Array::new(&buffer).to_vec()).await?;
    let identity = ui::recovery_identity()?;
    let mut storage = storage().await?;
    let prior = storage
        .load_import(scope)
        .await
        .map_err(|_| "Saved recovery state could not be read. Reload before retrying.")?;
    let prior=match prior {Some(prior)=>prior,None=>storage.begin_import(scope,history,&identity,&page).await.map_err(|_|"This part does not match the selected room, identity or network, or author state already exists. No state was replaced.")?};
    if prior.snapshot().history_scope() != history || prior.snapshot().head().scope() != scope {
        return Err("Recovery belongs to a different selected network or room.".into());
    }
    let mut next=storage.import_page(&prior,&page).await.map_err(|_|"Part is out of order, incomplete or conflicts with saved recovery. Reload and resume the exact backup; no sequence was reset.")?;
    if next.received_final() && !next.ready_to_activate() {
        next = storage.verify_import_page(&next).await.map_err(|_| {
            "Receipt verification failed or was interrupted. Preserve all parts and reload."
        })?;
    }
    if next.ready_to_activate() {
        let head=storage.activate_import(&next).await.map_err(|_|"Activation outcome is uncertain. Reload and inspect the retained author state before any retry.")?;
        return Ok(Notice{complete:true,message:format!("Author state restored through local sequence {} with its exact pending intent and peer receipts. Use only this authoring device. An old backup cannot prove a newer signature does not exist elsewhere.",head.sequence())});
    }
    Ok(Notice {
        complete: false,
        message: if next.received_final() {
            "All parts retained. Select the same final part again to continue bounded receipt verification; authoring remains unavailable.".into()
        } else {
            let part = next
                .next_page()
                .checked_add(1)
                .ok_or("The author backup part number is exhausted.")?;
            format!("Part retained safely. Select backup part {part} next (filename ends in part-{part:020}.vhauthor). Authoring remains unavailable until complete verification and activation.")
        },
    })
}
