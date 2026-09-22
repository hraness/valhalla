//! The password KDF and unlocked key live in a dedicated browser worker.
#[cfg(all(target_arch = "wasm32", feature = "private-rooms"))]
#[path = "../private/wire.rs"]
pub mod private_wire;
#[cfg(all(target_arch = "wasm32", feature = "private-rooms"))]
#[path = "../private/worker.rs"]
mod private_worker;
#[cfg(target_arch = "wasm32")]
mod runtime {
    use js_sys::{Array, Uint8Array};
    use std::{cell::RefCell, rc::Rc};
    use vhalla_browser_vault::{
        seal, unlock, UnlockedIdentity, ENVELOPE_BYTES, MAX_PASSWORD_BYTES, MIN_PASSWORD_BYTES,
    };
    use wasm_bindgen::{prelude::*, JsCast};
    use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};
    use zeroize::Zeroizing;

    pub fn start() -> Result<(), JsValue> {
        let scope: DedicatedWorkerGlobalScope = js_sys::global().dyn_into()?;
        let identity: Rc<RefCell<Option<UnlockedIdentity>>> = Rc::new(RefCell::new(None));
        #[cfg(feature = "private-rooms")]
        let authenticated = Rc::new(RefCell::new(None));
        #[cfg(feature = "private-rooms")]
        let private = crate::private_worker::Broker::new(
            scope.clone(),
            identity.clone(),
            authenticated.clone(),
        );
        let send = scope.clone();
        let handler = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            #[cfg(feature = "private-rooms")]
            if private.dispatch(&event.data()) {
                return;
            }
            let result = (|| -> Result<Array, &'static str> {
                if !Array::is_array(&event.data()) {
                    return Err("Invalid identity request.");
                }
                let fields = Array::from(&event.data());
                let operation = fields
                    .get(0)
                    .as_string()
                    .ok_or("Invalid identity request.")?;
                if operation == "encrypt-author-page" || operation == "decrypt-author-page" {
                    use vhalla_browser_vault::backup::{
                        AuthorBackupPage, MAX_ENCRYPTED_AUTHOR_PAGE_BYTES,
                    };
                    if fields.length() != 3 {
                        return Err("Invalid author backup request.");
                    }
                    let token = fields
                        .get(1)
                        .dyn_into::<Uint8Array>()
                        .map_err(|_| "Invalid backup token.")?;
                    let raw = fields
                        .get(2)
                        .dyn_into::<Uint8Array>()
                        .map_err(|_| "Invalid author backup page.")?;
                    if token.length() != 16
                        || raw.length() as usize > MAX_ENCRYPTED_AUTHOR_PAGE_BYTES
                    {
                        return Err("Author backup page exceeds its bound.");
                    }
                    let key = identity.borrow();
                    let key = key
                        .as_ref()
                        .ok_or("Unlock this identity before recovery.")?;
                    let result = if operation == "encrypt-author-page" {
                        let page = AuthorBackupPage::decode(&raw.to_vec())
                            .map_err(|_| "Invalid author backup page.")?;
                        let mut nonce = [0; 24];
                        send.crypto()
                            .map_err(|_| "Secure randomness is unavailable.")?
                            .get_random_values_with_u8_array(&mut nonce)
                            .map_err(|_| "Secure randomness failed.")?;
                        key.encrypt_author_page(&page, nonce)
                            .map_err(|_| "Could not protect author state.")?
                    } else {
                        key.decrypt_author_page(&raw.to_vec())
                            .map_err(|_| "Author backup authentication failed.")?
                            .encode()
                    };
                    let response = Array::new();
                    response.push(&JsValue::from_str("author-page"));
                    response.push(&token);
                    response.push(&Uint8Array::from(result.as_slice()));
                    return Ok(response);
                }
                if operation == "sign-activity" {
                    if fields.length() != 3 {
                        return Err("Invalid typed activity request.");
                    }
                    // Opaque 16-byte caller token carries exact u64 generation
                    // and operation counters without JavaScript number loss.
                    let token = fields
                        .get(1)
                        .dyn_into::<Uint8Array>()
                        .map_err(|_| "Invalid activity request token.")?;
                    let raw = fields
                        .get(2)
                        .dyn_into::<Uint8Array>()
                        .map_err(|_| "Invalid typed activity request.")?;
                    if token.length() != 16
                        || raw.length() as usize > vhalla_room_activity::MAX_UNSIGNED_BYTES
                    {
                        return Err("Invalid typed activity request size.");
                    }
                    let request = vhalla_room_activity::UnsignedEvent::decode(&raw.to_vec())
                        .map_err(|_| "Invalid typed activity request.")?;
                    let key = identity.borrow();
                    let key = key.as_ref().ok_or("Unlock this identity before signing.")?;
                    let event = key
                        .sign_activity(request)
                        .map_err(|_| "Activity author differs from the unlocked identity.")?;
                    let response = Array::new();
                    response.push(&JsValue::from_str("activity-signed"));
                    response.push(&token);
                    response.push(&Uint8Array::from(event.id().as_bytes().as_slice()));
                    response.push(&Uint8Array::from(event.encode().as_slice()));
                    return Ok(response);
                }
                let password = Zeroizing::new(
                    fields
                        .get(1)
                        .as_string()
                        .ok_or("Enter a password.")?
                        .into_bytes(),
                );
                if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&password.len()) {
                    return Err("Use a password between 12 and 1,024 bytes.");
                }
                let raw = match operation.as_str() {
                    "create" if fields.length() == 2 => {
                        if identity.borrow().is_some() {
                            return Err("Lock this identity before creating another.");
                        }
                        let crypto = send
                            .crypto()
                            .map_err(|_| "Secure randomness is unavailable.")?;
                        let mut seed = Zeroizing::new([0u8; 32]);
                        let mut salt = [0u8; 16];
                        let mut nonce = [0u8; 24];
                        crypto
                            .get_random_values_with_u8_array(&mut seed[..])
                            .map_err(|_| "Secure randomness failed.")?;
                        crypto
                            .get_random_values_with_u8_array(&mut salt)
                            .map_err(|_| "Secure randomness failed.")?;
                        crypto
                            .get_random_values_with_u8_array(&mut nonce)
                            .map_err(|_| "Secure randomness failed.")?;
                        seal(seed, &password, salt, nonce)
                            .map_err(|_| "Could not protect the identity.")?
                            .as_bytes()
                            .to_vec()
                    }
                    "unlock" if fields.length() == 3 => {
                        let array = fields
                            .get(2)
                            .dyn_into::<Uint8Array>()
                            .map_err(|_| "Invalid encrypted backup.")?;
                        if array.length() as usize != ENVELOPE_BYTES {
                            return Err("Invalid encrypted backup size.");
                        }
                        array.to_vec()
                    }
                    _ => return Err("Invalid identity request."),
                };
                let key =
                    unlock(&raw, &password).map_err(|_| "The password or backup is incorrect.")?;
                let public = key.public_key();
                *identity.borrow_mut() = Some(key);
                #[cfg(feature = "private-rooms")]
                {
                    *authenticated.borrow_mut() = Some(raw.clone());
                }
                let response = Array::new();
                response.push(&JsValue::from_str("unlocked"));
                response.push(&Uint8Array::from(raw.as_slice()));
                response.push(&Uint8Array::from(public.as_slice()));
                Ok(response)
            })();
            let response = result.unwrap_or_else(|message| {
                let response = Array::new();
                response.push(&JsValue::from_str("error"));
                response.push(&JsValue::from_str(message));
                response
            });
            let _ = send.post_message(&response);
        });
        scope.set_onmessage(Some(handler.as_ref().unchecked_ref()));
        // One handler for this worker's bounded lifetime; termination destroys it
        // and the private key. No command exports plaintext secret material.
        handler.forget();
        let ready = Array::new();
        ready.push(&JsValue::from_str("ready"));
        scope.post_message(&ready)
    }
}
fn main() {
    #[cfg(target_arch = "wasm32")]
    let _ = runtime::start();
}
