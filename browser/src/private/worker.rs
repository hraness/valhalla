//! Irreversible private mode in the existing account worker. No parallel signer.
#[path = "session.rs"]
mod session;
use crate::private_wire::{Request, Response, MAX_FRAME};
use js_sys::{Array, JsString, Uint8Array};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use vhalla_browser_vault::UnlockedIdentity;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::DedicatedWorkerGlobalScope;
use zeroize::Zeroizing;

enum State {
    Dormant,
    Busy([u8; 16]),
    Ready(Box<session::Session>),
    Dead,
}
enum Job {
    Enter {
        identity: UnlockedIdentity,
        authenticated: Vec<u8>,
        expected: Zeroizing<Vec<u8>>,
        birth: bool,
    },
    Run {
        session: Box<session::Session>,
        request: Request,
    },
}
#[derive(Clone)]
pub struct Broker {
    scope: DedicatedWorkerGlobalScope,
    private: Rc<Cell<bool>>,
    state: Rc<RefCell<State>>,
    identity: Rc<RefCell<Option<UnlockedIdentity>>>,
    authenticated: Rc<RefCell<Option<Vec<u8>>>>,
}
impl Broker {
    pub fn new(
        scope: DedicatedWorkerGlobalScope,
        identity: Rc<RefCell<Option<UnlockedIdentity>>>,
        authenticated: Rc<RefCell<Option<Vec<u8>>>>,
    ) -> Self {
        Self {
            scope,
            private: Rc::new(Cell::new(false)),
            state: Rc::new(RefCell::new(State::Dormant)),
            identity,
            authenticated,
        }
    }
    fn dead(&self) {
        session::abort_delivery();
        *self.state.borrow_mut() = State::Dead;
        self.identity.borrow_mut().take();
        self.authenticated.borrow_mut().take();
        let reply = Array::new();
        reply.push(&"private-error".into());
        // The UI must terminate on this terminal, deliberately content-free error.
        let _ = self.scope.post_message(&reply);
    }
    fn current(&self, token: [u8; 16]) -> bool {
        matches!(*self.state.borrow(), State::Busy(current) if current == token)
    }
    /// Return true for a consumed private message or any message after mode entry.
    /// The marker is never derived from an Option temporarily taken across await.
    pub fn dispatch(&self, data: &JsValue) -> bool {
        // Borrow the checked array object. Array::from would copy an arbitrarily
        // long outer array before the fixed three-field bound is inspected.
        let array = Array::is_array(data).then(|| data.clone().unchecked_into::<Array>());
        let named_private = array.as_ref().is_some_and(|fields| {
            let tag = fields.get(0);
            tag.is_string()
                && JsString::from(tag.clone()).length() == 7
                && tag.as_string().as_deref() == Some("private")
        });
        if !named_private {
            if self.private.get() {
                self.dead();
                return true;
            }
            return false;
        }
        // This is irreversible, even for malformed requests or failed entry.
        self.private.set(true);
        let parse = || -> Result<([u8; 16], Request), ()> {
            let fields = array.as_ref().ok_or(())?;
            if fields.length() != 3 {
                return Err(());
            }
            let token = fields.get(1).dyn_into::<Uint8Array>().map_err(|_| ())?;
            let raw = fields.get(2).dyn_into::<Uint8Array>().map_err(|_| ())?;
            if token.length() != 16 || raw.length() as usize > MAX_FRAME {
                return Err(());
            }
            let token = token.to_vec().try_into().map_err(|_| ())?;
            let bytes = Zeroizing::new(raw.to_vec());
            // The request bytes were copied into zeroed Rust custody; remove
            // the JS-heap copy before decoding or touching storage.
            Uint8Array::fill(&raw, 0, 0, raw.length());
            Ok((token, Request::decode(&bytes).map_err(|_| ())?))
        };
        let Ok((token, request)) = parse() else {
            self.dead();
            return true;
        };
        let old = std::mem::replace(&mut *self.state.borrow_mut(), State::Busy(token));
        let job = match (old, request) {
            (State::Dormant, Request::Enter { vault, local_birth }) => {
                let identity = self.identity.borrow_mut().take();
                let authenticated = self.authenticated.borrow_mut().take();
                match (identity, authenticated) {
                    (Some(identity), Some(authenticated)) => Job::Enter {
                        identity,
                        authenticated,
                        expected: vault,
                        birth: local_birth,
                    },
                    _ => {
                        self.dead();
                        return true;
                    }
                }
            }
            (State::Ready(session), request) if !matches!(request, Request::Enter { .. }) => {
                Job::Run { session, request }
            }
            _ => {
                self.dead();
                return true;
            }
        };
        let broker = self.clone();
        spawn_local(async move {
            // The sole custody value belongs to this future. No RefCell borrow
            // spans an await; a second request fails and cannot reach a signer.
            let result = match job {
                Job::Enter {
                    identity,
                    authenticated,
                    expected,
                    birth,
                } => {
                    let account = identity.public_key();
                    session::Session::enter(identity, &authenticated, &expected, birth)
                        .await
                        .and_then(|session| {
                            let key = vhalla_private_kernel::protocol::Key::from_bytes(account)
                                .map_err(|_| session::Failure::Invalid)?;
                            Ok((Box::new(session), Response::Entered(key)))
                        })
                }
                Job::Run {
                    mut session,
                    request,
                } => session.execute(request).await.map(|reply| (session, reply)),
            };
            if !broker.current(token) {
                return;
            }
            let Ok((session, reply)) = result else {
                broker.dead();
                return;
            };
            let Ok(raw) = reply.encode() else {
                broker.dead();
                return;
            };
            *broker.state.borrow_mut() = State::Ready(session);
            let response = Array::new();
            response.push(&"private-reply".into());
            response.push(&Uint8Array::from(token.as_slice()));
            response.push(&Uint8Array::from(raw.as_slice()));
            if broker.scope.post_message(&response).is_err() {
                broker.dead();
            }
        });
        true
    }
}
