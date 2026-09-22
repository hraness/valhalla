//! Optional user-selected file streaming. No handle persists beyond this action.
use super::*;
use js_sys::{Function, Object, Promise, Reflect};
use std::cell::Cell;

fn method(object: &JsValue, name: &str) -> Result<Function> {
    Reflect::get(object, &name.into())
        .map_err(|_| "File save is unavailable.")?
        .dyn_into()
        .map_err(|_| "File save is unavailable.".into())
}
fn promise(object: &JsValue, name: &str, argument: Option<&JsValue>) -> Result<Promise> {
    let function = method(object, name)?;
    let value = match argument {
        Some(value) => function.call1(object, value),
        None => function.call0(object),
    }
    .map_err(|_| "The archive file operation failed.")?;
    value
        .dyn_into()
        .map_err(|_| "The archive file operation failed.".into())
}
/// Must run in the original click stack, before any worker request/await.
/// Unsupported browsers use the capped Blob path; picker refusal never falls
/// back to an unsolicited download or starts an archive export.
pub(super) fn choose() -> Result<Option<Promise>> {
    let window = web_sys::window().ok_or("File save is unavailable.")?;
    let picker = Reflect::get(window.as_ref(), &"showSaveFilePicker".into())
        .map_err(|_| "File save is unavailable.")?;
    if picker.is_undefined() {
        return Ok(None);
    }
    let options = Object::new();
    Reflect::set(
        &options,
        &"suggestedName".into(),
        &"private-room.vharchive".into(),
    )
    .map_err(|_| "File save is unavailable.")?;
    let picker: Function = picker.dyn_into().map_err(|_| "File save is unavailable.")?;
    let selected = picker
        .call1(window.as_ref(), &options)
        .map_err(|_| "File save was refused; no archive export started.")?;
    Ok(Some(
        selected
            .dyn_into()
            .map_err(|_| "File save is unavailable.")?,
    ))
}

/// Dropping or locking aborts the temporary file. Only successful close publishes
/// its complete contents. Browser-managed atomic-file semantics are not fsync.
pub(super) struct Sink {
    stream: JsValue,
    closed: Cell<bool>,
}
impl Sink {
    pub(super) async fn open(selection: Promise, app: &App, ticket: u64) -> Result<Rc<Self>> {
        let handle = JsFuture::from(selection)
            .await
            .map_err(|_| "Archive save canceled or refused; no export started.")?;
        live(app, ticket)?;
        let stream = JsFuture::from(promise(&handle, "createWritable", None)?)
            .await
            .map_err(|_| "Could not open the chosen archive file; no export started.")?;
        let sink = Rc::new(Self {
            stream,
            closed: Cell::new(false),
        });
        if let Err(error) = live(app, ticket) {
            sink.abort();
            return Err(error);
        }
        Ok(sink)
    }
    pub(super) async fn write(&self, bytes: &[u8]) -> Result<()> {
        if self.closed.get() {
            return Err("Archive save canceled.".into());
        }
        let bytes = Uint8Array::from(bytes);
        JsFuture::from(promise(&self.stream, "write", Some(bytes.as_ref()))?)
            .await
            .map_err(|_| "Archive write failed; the temporary file is being aborted.")?;
        if self.closed.get() {
            return Err("Archive save canceled.".into());
        }
        Ok(())
    }
    pub(super) async fn close(&self) -> Result<()> {
        if self.closed.get() {
            return Err("Archive save canceled.".into());
        }
        JsFuture::from(promise(&self.stream, "close", None)?)
            .await
            .map_err(|_| "Archive close failed; preserve the chosen file and retry explicitly.")?;
        self.closed.set(true);
        Ok(())
    }
    pub(super) fn abort(&self) {
        if self.closed.replace(true) {
            return;
        }
        if let Ok(pending) = promise(&self.stream, "abort", None) {
            spawn_local(async move {
                let _ = JsFuture::from(pending).await;
            });
        }
    }
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.abort();
    }
}
