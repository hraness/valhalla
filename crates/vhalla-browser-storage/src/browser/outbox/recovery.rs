//! Paged author recovery. An incomplete namespace never has an active head.
use super::super::{
    history::{bounded, Transaction},
    identity::read_identity,
};
use super::IndexedOutbox;
use crate::outbox::delivery::DeliveryRecord;
use crate::outbox::recovery::{
    decode_page, Entry, Export, Import, Snapshot, MAX_ENTRY_BYTES, MAX_ENTRY_KEY, MAX_IMPORT_BYTES,
    PAGE_ENTRIES,
};
use crate::outbox::{
    prefix, AuthorHead, AuthorScope, ReservedDraft, AUTHOR_HEAD_BYTES, MAX_RESERVATION_BYTES,
};
use crate::{
    history::HistoryScope,
    identity::{compare_identity, vault_public, IdentitySnapshot},
    Error, PublishError,
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use vhalla_browser_vault::backup::AuthorBackupPage;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::IdbKeyRange;

fn stage_key(scope: AuthorScope) -> String {
    format!("{}recovery/stage", prefix(scope))
}

impl IndexedOutbox {
    /// Capture a live scope, including an explicit zero-event head and pending
    /// intent. `backup` must be a fresh caller-generated CSPRNG identifier.
    pub async fn begin_export(
        &mut self,
        scope: AuthorScope,
        history: HistoryScope,
        backup: [u8; 32],
    ) -> Result<Export, Error> {
        self.read(move |state| {
            read_snapshot(state, scope, history, move |state, snapshot| {
                *state.result.borrow_mut() = Some(Ok(Export::new(snapshot, backup)));
                Ok(())
            })
        })
        .await
    }
    /// Read and verify one bounded canonical page under the captured snapshot.
    /// The returned continuation replaces the prior one only after success.
    /// Keep exporting until its `ended()` is true, then call `finish_export`.
    pub async fn export_page(
        &mut self,
        expected: &Export,
    ) -> Result<(Export, AuthorBackupPage), Error> {
        if expected.ended {
            return Err(Error::Stale);
        }
        let expected = expected.clone();
        self.read(move |state| {
            read_snapshot(
                state,
                expected.snapshot.head().scope(),
                expected.snapshot.history_scope(),
                move |state, observed| {
                    expected.snapshot.compare(&observed)?;
                    let scope = observed.head().scope();
                    let start = prefix(scope);
                    scan(
                        state,
                        start,
                        expected.last().to_owned(),
                        move |state, entries, ended| {
                            let entries = entries
                                .into_iter()
                                .map(|(key, value)| Entry::new(key, value, &observed))
                                .collect::<Result<Vec<_>, _>>()?;
                            if entries.is_empty() {
                                return Err(Error::Corrupt);
                            }
                            join_entries(
                                state,
                                scope,
                                entries.clone().into(),
                                false,
                                move |state| {
                                    let page = expected.page(&entries, false)?;
                                    let mut next = expected.advance(&page)?;
                                    if ended {
                                        next.validator.finish(&observed)?;
                                        next.ended = true;
                                    }
                                    *state.result.borrow_mut() = Some(Ok((next, page)));
                                    Ok(())
                                },
                            )
                        },
                    )
                },
            )
        })
        .await
    }
    /// Recheck exact author head, pending intent and receipt revision, then issue
    /// the final frame. Without this authenticated frame the archive is incomplete.
    /// This establishes one captured local state, never global latestness.
    pub async fn finish_export(&mut self, expected: &Export) -> Result<AuthorBackupPage, Error> {
        if !expected.ended {
            return Err(Error::Stale);
        }
        expected.validator.finish(&expected.snapshot)?;
        let expected = expected.clone();
        self.read(move |state| {
            read_snapshot(
                state,
                expected.snapshot.head().scope(),
                expected.snapshot.history_scope(),
                move |state, observed| {
                    expected.snapshot.compare(&observed)?;
                    *state.result.borrow_mut() = Some(Ok(expected.page(&[], true)?));
                    Ok(())
                },
            )
        })
        .await
    }
    /// Load an interrupted exact import. A missing marker is not fresh authority.
    pub async fn load_import(&mut self, scope: AuthorScope) -> Result<Option<Import>, Error> {
        self.read(move |state| {
            state.read(
                &JsValue::from_str(&stage_key(scope)),
                move |state, value| {
                    let import = bounded(value, MAX_IMPORT_BYTES)?
                        .map(|raw| Import::decode(&raw))
                        .transpose()?;
                    if import
                        .as_ref()
                        .is_some_and(|i| i.snapshot().head().scope() != scope)
                    {
                        return Err(Error::WrongScope);
                    }
                    *state.result.borrow_mut() = Some(Ok(import));
                    Ok(())
                },
            )
        })
        .await
    }
    /// Reserve an entirely absent author namespace for one authenticated stream.
    /// The caller authenticates/decrypts `first` in its unlocked identity worker,
    /// independently selects the exact scope/pin, and confirms single-device use.
    /// No head, event or birth authority is created here. An exact interrupted
    /// initialization may resume; unrelated surviving data is never overwritten.
    pub async fn begin_import(
        &mut self,
        scope: AuthorScope,
        history: HistoryScope,
        identity: &IdentitySnapshot,
        first: &AuthorBackupPage,
    ) -> Result<Import, PublishError> {
        let (snapshot, _) = decode_page(first).map_err(PublishError::Rejected)?;
        if first.index() != 0
            || first.previous() != [0; 32]
            || snapshot.head().scope() != scope
            || snapshot.history_scope() != history
            || vault_public(
                identity
                    .vault()
                    .ok_or(PublishError::Rejected(Error::RecoveryRequired))?,
            )
            .map_err(PublishError::Rejected)?
                != scope.author()
        {
            return Err(PublishError::Rejected(Error::WrongScope));
        }
        let candidate = Import {
            stream: Export::new(snapshot, first.backup_id()),
            identity: identity.clone(),
            verified_after: String::new(),
            verified: false,
        };
        // Refuse an invalid first prefix before reserving a previously absent
        // scope. Later missing/corrupt parts still leave their exact stage intact.
        candidate.advance(first).map_err(PublishError::Rejected)?;
        let output = Rc::new(RefCell::new(None));
        let answer = output.clone();
        self.write(move |state| {
            read_identity(state, move |state, observed| {
                compare_identity(&candidate.identity, &observed)?;
                let key = stage_key(scope);
                state.read(&JsValue::from_str(&key), move |state, value| {
                    if let Some(raw) = bounded(value, MAX_IMPORT_BYTES)? {
                        let prior = Import::decode(&raw)?;
                        if prior.identity != candidate.identity
                            || prior.stream.backup != candidate.stream.backup
                            || prior.snapshot() != candidate.snapshot()
                        {
                            return Err(Error::Stale);
                        }
                        return absent_head(state, scope, move |state| {
                            *answer.borrow_mut() = Some(prior);
                            *state.result.borrow_mut() = Some(Ok(()));
                            Ok(())
                        });
                    }
                    let start = prefix(scope);
                    let range = key_range(&start, "")?;
                    let request = state.store.get_key(&range).map_err(super::super::storage)?;
                    state.handle(request, move |state, value| {
                        if !value.is_undefined() {
                            return Err(Error::Stale);
                        }
                        state.add(&key, &candidate.encode())?;
                        *answer.borrow_mut() = Some(candidate);
                        *state.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    });
                    Ok(())
                })
            })
        })
        .await?;
        output
            .take()
            .ok_or(PublishError::ReopenRequired(Error::Corrupt))
    }
    /// Stage one exact next authenticated page, never publishing the author head.
    /// Unknown outcomes require reopen/load; only the exact latest page retry can
    /// reconcile successfully. Every immutable record is added, never replaced.
    pub async fn import_page(
        &mut self,
        expected: &Import,
        page: &AuthorBackupPage,
    ) -> Result<Import, PublishError> {
        let (_, entries) = decode_page(page).map_err(PublishError::Rejected)?;
        let next = expected.advance(page).map_err(PublishError::Rejected)?;
        let expected = expected.clone();
        let output = Rc::new(RefCell::new(None));
        let answer = output.clone();
        self.write(move |state| {
            guarded_import(state, expected.clone(), move |state, observed| {
                if observed == next {
                    *answer.borrow_mut() = Some(next);
                    *state.result.borrow_mut() = Some(Ok(()));
                    return Ok(());
                }
                if observed != expected {
                    return Err(Error::Stale);
                }
                let scope = next.snapshot().head().scope();
                stage_entries(state, scope, entries.into(), move |state| {
                    state.put(&stage_key(scope), &next.encode())?;
                    *answer.borrow_mut() = Some(next);
                    *state.result.borrow_mut() = Some(Ok(()));
                    Ok(())
                })
            })
        })
        .await?;
        output
            .take()
            .ok_or(PublishError::ReopenRequired(Error::Corrupt))
    }
    /// Join a bounded page of original peer receipt evidence to staged signed
    /// events after the final frame. Repeat until `ready_to_activate()`.
    /// Missing prefixes, altered signed bytes or incomplete evidence fail closed.
    pub async fn verify_import_page(&mut self, expected: &Import) -> Result<Import, PublishError> {
        if !expected.received_final() || expected.verified {
            return Err(PublishError::Rejected(Error::Stale));
        }
        let expected = expected.clone();
        let output = Rc::new(RefCell::new(None));
        let answer = output.clone();
        self.write(move |state| {
            guarded_import(state, expected.clone(), move |state, observed| {
                if observed != expected {
                    return Err(Error::Stale);
                }
                let scope = expected.snapshot().head().scope();
                let start = format!("{}delivery/", prefix(scope));
                let after = expected
                    .verified_after
                    .strip_prefix("delivery/")
                    .unwrap_or("")
                    .to_owned();
                scan(state, start, after, move |state, raw, ended| {
                    let entries = raw
                        .into_iter()
                        .map(|(key, value)| {
                            Entry::new(format!("delivery/{key}"), value, expected.snapshot())
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let mut next = expected;
                    if let Some(last) = entries.last() {
                        next.verified_after = last.key().to_owned();
                    }
                    next.verified = ended;
                    join_entries(state, scope, entries.into(), true, move |state| {
                        state.put(&stage_key(scope), &next.encode())?;
                        *answer.borrow_mut() = Some(next);
                        *state.result.borrow_mut() = Some(Ok(()));
                        Ok(())
                    })
                })
            })
        })
        .await?;
        output
            .take()
            .ok_or(PublishError::ReopenRequired(Error::Corrupt))
    }
    /// Publish the validated author head only after complete stream verification.
    /// Exact identity/progress/head-absence CAS occurs in the same transaction.
    /// No existing active scope can be imported over, including an older backup.
    pub async fn activate_import(&mut self, expected: &Import) -> Result<AuthorHead, PublishError> {
        if !expected.ready_to_activate() {
            return Err(PublishError::Rejected(Error::RecoveryRequired));
        }
        expected
            .stream
            .validator
            .finish(expected.snapshot())
            .map_err(PublishError::Rejected)?;
        let head = expected.snapshot().head();
        let expected = expected.clone();
        self.write(move |state| {
            guarded_import(state, expected.clone(), move |state, observed| {
                if observed != expected {
                    return Err(Error::Stale);
                }
                state.add(&format!("{}head", prefix(head.scope())), &head.encode())?;
                state
                    .store
                    .delete(&JsValue::from_str(&stage_key(head.scope())))
                    .map_err(super::super::storage)?;
                *state.result.borrow_mut() = Some(Ok(()));
                Ok(())
            })
        })
        .await?;
        Ok(head)
    }
}

fn read_snapshot<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    history: HistoryScope,
    done: impl FnOnce(&Rc<Transaction<T>>, Snapshot) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let start = prefix(scope);
    state.read(
        &JsValue::from_str(&format!("{start}head")),
        move |state, value| {
            let head = AuthorHead::decode(
                &bounded(value, AUTHOR_HEAD_BYTES)?.ok_or(Error::RecoveryRequired)?,
            )?;
            if head.scope() != scope {
                return Err(Error::WrongScope);
            }
            state.read(
                &JsValue::from_str(&format!("{start}pending")),
                move |state, value| {
                    let pending = bounded(value, MAX_RESERVATION_BYTES)?
                        .map(|v| ReservedDraft::decode(&v))
                        .transpose()?;
                    state.read(
                        &JsValue::from_str(&format!("{start}receipt-revision")),
                        move |state, value| {
                            let revision = bounded(value, 8)?
                                .map(|v| {
                                    v.try_into()
                                        .map(u64::from_be_bytes)
                                        .map_err(|_| Error::Corrupt)
                                })
                                .transpose()?;
                            done(state, Snapshot::new(head, history, pending, revision)?)
                        },
                    )
                },
            )
        },
    )
}
fn key_range(start: &str, after: &str) -> Result<IdbKeyRange, Error> {
    IdbKeyRange::bound_with_lower_open_and_upper_open(
        &JsValue::from_str(&format!("{start}{after}")),
        &JsValue::from_str(&format!("{start}\u{ffff}")),
        !after.is_empty(),
        true,
    )
    .map_err(super::super::storage)
}
type Values = Vec<(String, Vec<u8>)>;
fn scan<T: 'static>(
    state: &Rc<Transaction<T>>,
    start: String,
    after: String,
    done: impl FnOnce(&Rc<Transaction<T>>, Values, bool) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let range = key_range(&start, &after)?;
    let request = state
        .store
        .get_all_keys_with_key_and_limit(&range, (PAGE_ENTRIES + 1) as u32)
        .map_err(super::super::storage)?;
    state.handle(request, move |state, value| {
        let array = value
            .dyn_into::<js_sys::Array>()
            .map_err(|_| Error::Corrupt)?;
        if array.length() as usize > PAGE_ENTRIES + 1 {
            return Err(Error::Bounds);
        }
        let ended = array.length() as usize <= PAGE_ENTRIES;
        let mut keys = VecDeque::new();
        for raw in array.iter().take(PAGE_ENTRIES) {
            let key_string = raw.dyn_ref::<js_sys::JsString>().ok_or(Error::Corrupt)?;
            if key_string.length() as usize > start.len() + MAX_ENTRY_KEY {
                return Err(Error::Bounds);
            }
            let key = raw.as_string().ok_or(Error::Corrupt)?;
            if key.len() > start.len() + MAX_ENTRY_KEY || !key.starts_with(&start) {
                return Err(Error::Bounds);
            }
            keys.push_back(key);
        }
        scan_values(state, start, keys, Vec::new(), ended, done)
    });
    Ok(())
}
fn scan_values<T: 'static>(
    state: &Rc<Transaction<T>>,
    start: String,
    mut keys: VecDeque<String>,
    mut values: Values,
    ended: bool,
    done: impl FnOnce(&Rc<Transaction<T>>, Values, bool) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let Some(key) = keys.pop_front() else {
        return done(state, values, ended);
    };
    state.read(&JsValue::from_str(&key), move |state, value| {
        let raw = bounded(value, MAX_ENTRY_BYTES)?.ok_or(Error::Corrupt)?;
        values.push((key[start.len()..].to_owned(), raw));
        scan_values(state, start, keys, values, ended, done)
    })
}
fn absent_head<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    done: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    state.read(
        &JsValue::from_str(&format!("{}head", prefix(scope))),
        move |state, value| {
            if !value.is_undefined() {
                return Err(Error::Stale);
            }
            done(state)
        },
    )
}
fn guarded_import<T: 'static>(
    state: &Rc<Transaction<T>>,
    expected: Import,
    done: impl FnOnce(&Rc<Transaction<T>>, Import) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let scope = expected.snapshot().head().scope();
    read_identity(state, move |state, identity| {
        state.read(
            &JsValue::from_str(&format!("{}head", prefix(scope))),
            move |state, head| {
                state.read(
                    &JsValue::from_str(&stage_key(scope)),
                    move |state, value| {
                        let observed = Import::decode(
                            &bounded(value, MAX_IMPORT_BYTES)?.ok_or(Error::Stale)?,
                        )?;
                        expected.guard(&observed, &identity, !head.is_undefined())?;
                        done(state, observed)
                    },
                )
            },
        )
    })
}
fn stage_entries<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    mut entries: VecDeque<Entry>,
    done: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let Some(entry) = entries.pop_front() else {
        return done(state);
    };
    if entry.key() == "head" {
        return stage_entries(state, scope, entries, done);
    }
    let key = format!("{}{}", prefix(scope), entry.key());
    if let Some(sequence) = entry.key().strip_prefix("outbox/") {
        let event_key = format!("{}event/{sequence}", prefix(scope));
        state.read(&JsValue::from_str(&event_key), move |state, value| {
            if bounded(value, MAX_ENTRY_BYTES)?.as_deref() != Some(entry.value()) {
                return Err(Error::Corrupt);
            }
            state.add(&key, entry.value())?;
            stage_entries(state, scope, entries, done)
        })
    } else {
        state.add(&key, entry.value())?;
        stage_entries(state, scope, entries, done)
    }
}
fn join_entries<T: 'static>(
    state: &Rc<Transaction<T>>,
    scope: AuthorScope,
    mut entries: VecDeque<Entry>,
    receipts_only: bool,
    done: impl FnOnce(&Rc<Transaction<T>>) -> Result<(), Error> + 'static,
) -> Result<(), Error> {
    let Some(entry) = entries.pop_front() else {
        return done(state);
    };
    if entry.key().starts_with("delivery/") && entry.key().contains("/receipt/") {
        let receipt = DeliveryRecord::decode(entry.value())?;
        let key = format!("{}outbox/{:016x}", prefix(scope), receipt.head().sequence());
        state.read(&JsValue::from_str(&key), move |state, value| {
            receipt.check_event(&bounded(value, MAX_ENTRY_BYTES)?.ok_or(Error::Corrupt)?)?;
            join_entries(state, scope, entries, receipts_only, done)
        })
    } else if !receipts_only && entry.key().starts_with("outbox/") {
        let key = format!(
            "{}event/{}",
            prefix(scope),
            entry.key().strip_prefix("outbox/").ok_or(Error::Corrupt)?
        );
        state.read(&JsValue::from_str(&key), move |state, value| {
            if bounded(value, MAX_ENTRY_BYTES)?.as_deref() != Some(entry.value()) {
                return Err(Error::Corrupt);
            }
            join_entries(state, scope, entries, receipts_only, done)
        })
    } else {
        join_entries(state, scope, entries, receipts_only, done)
    }
}
