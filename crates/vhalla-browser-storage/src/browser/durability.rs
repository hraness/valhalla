//! Require the standard strict durability hint for application writes.
//!
//! This requests persistent-media completion; it cannot detect broken hardware,
//! eviction, coherent rollback, or a browser that lies about its implementation.
use super::{storage, OBJECT_STORE};
use crate::Error;
use js_sys::{Function, Object, Reflect};
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{IdbDatabase, IdbTransaction, IdbTransactionMode};

pub(super) fn begin(database: &IdbDatabase, write: bool) -> Result<IdbTransaction, Error> {
    if !write {
        return database
            .transaction_with_str_and_mode(OBJECT_STORE, IdbTransactionMode::Readonly)
            .map_err(storage);
    }
    // web-sys 0.3.85 gates the typed options overload behind an unstable cfg.
    // Call the standard overload through stable bindings, without weakening
    // every WASM build or silently falling back to default/relaxed durability.
    let options = Object::new();
    if !Reflect::set(&options, &"durability".into(), &"strict".into()).map_err(storage)? {
        return Err(Error::Storage);
    }
    let method = Reflect::get(database.as_ref(), &"transaction".into())
        .map_err(storage)?
        .dyn_into::<Function>()
        .map_err(storage)?;
    let transaction = method
        .call3(
            database.as_ref(),
            &OBJECT_STORE.into(),
            &"readwrite".into(),
            &options,
        )
        .map_err(storage)?
        .dyn_into::<IdbTransaction>()
        .map_err(storage)?;
    // Old engines may silently ignore the third argument. Refuse before any
    // application request is queued if strict durability was not selected.
    let strict = Reflect::get(transaction.as_ref(), &JsValue::from_str("durability"))
        .ok()
        .and_then(|value| value.as_string())
        .is_some_and(|value| value == "strict");
    if !strict {
        let _ = transaction.abort();
        return Err(Error::Storage);
    }
    Ok(transaction)
}
