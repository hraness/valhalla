use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use vhalla_room_activity::UnsignedEvent;

pub(crate) struct Fixture {
    pub events: Vec<VerifiedEvent>,
    pub scope: SessionScope,
    pub limits: Limits,
}
impl Fixture {
    pub fn new(count: usize) -> Self {
        let key = SigningKey::from_bytes(&[3; 32]);
        let mut previous = EventId::ZERO;
        let mut events = Vec::new();
        for n in 1..=count {
            let text = format!("continuity fixture {n}");
            let mut raw = b"VHRA\x01".to_vec();
            raw.extend([7; 32]);
            raw.extend(77u128.to_be_bytes());
            raw.extend([5; 32]);
            raw.extend([8; 32]);
            raw.extend([9; 32]);
            raw.extend(key.verifying_key().to_bytes());
            raw.extend((n as u64).to_be_bytes());
            raw.extend(previous.as_bytes());
            raw.extend(1234u64.to_be_bytes());
            raw.push(0);
            raw.extend((text.len() as u16).to_be_bytes());
            raw.extend(text.as_bytes());
            let event = UnsignedEvent::decode(&raw)
                .unwrap()
                .sign_with_key(&key)
                .unwrap()
                .verify()
                .unwrap();
            previous = event.id();
            events.push(event);
        }
        let first = &events[0];
        let scope = SessionScope::new(
            AuthorScope::new(first.claims().scope, first.claims().author),
            HistoryScope::new([7; 32], [10; 32]),
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap(),
        )
        .unwrap();
        Self {
            events,
            scope,
            limits: Limits {
                max_records: 100,
                max_bytes: 4 * 1024 * 1024,
            },
        }
    }
    pub fn fresh(&self) -> Snapshot {
        Snapshot::fresh(self.scope.clone(), self.limits).unwrap()
    }
    pub fn selected(&self) -> Snapshot {
        self.fresh()
            .prepare_job(ContinuityJob::new([1; 16], self.events.last().unwrap()).unwrap())
            .unwrap()
            .after
    }
    pub fn context(&self, nonce: u8) -> wire::RequestContext {
        wire::RequestContext {
            scope: self.scope.wire_scope(),
            nonce: [nonce; 32],
            operation: [1; 16],
            floor: wire::Observed {
                height: 7,
                frontier: [6; 32],
            },
        }
    }
    pub fn status(&self, state: &Snapshot, nonce: u8) -> wire::Request {
        wire::Request::new(
            self.context(nonce),
            wire::Selection::Author(self.scope.author.author),
            wire::Kind::Status {
                minimum: state.retention.position,
            },
        )
        .unwrap()
    }
    pub fn proof(
        &self,
        request: wire::Request,
        reply: &wire::Reply,
    ) -> (wire::ResponseProof, Vec<u8>) {
        let body = reply.encode(&request).unwrap();
        let proof = wire::UnsignedResponse::new(self.scope.peer, request, &body)
            .unwrap()
            .sign_with_key(&SigningKey::from_bytes(&[8; 32]))
            .unwrap();
        (proof, body)
    }
    pub fn check(&self, change: &Publication) {
        let last = self.events.last().unwrap();
        let mut raw = AuthorHead::fresh_scope_authorized(self.scope.author).encode();
        raw[152..160].copy_from_slice(&last.claims().sequence.to_be_bytes());
        raw[160..].copy_from_slice(last.id().as_bytes());
        let head = AuthorHead::decode(&raw).unwrap();
        change
            .check_sources(head, |n| Ok(self.events[n as usize - 1].encode()))
            .unwrap();
    }
    pub fn evidence(
        &self,
        state: &Snapshot,
        nonce: u8,
        first: usize,
        last: usize,
        terminal: usize,
        cursor: u64,
    ) -> (Snapshot, Publication) {
        let request = wire::Request::new(
            self.context(nonce),
            wire::Selection::Author(self.scope.author.author),
            wire::Kind::Evidence {
                after: state.retention.position,
                count: (last - first) as u8,
            },
        )
        .unwrap();
        let reserved = state.prepare_attempt(request, &[]).unwrap().after;
        let entries = self.events[first..last]
            .iter()
            .enumerate()
            .map(|(n, e)| wire::Entry {
                role: if first + n + 1 == terminal {
                    wire::EvidenceRole::CurrentAdmission
                } else {
                    wire::EvidenceRole::HistoricalContinuity
                },
                committed_by: cursor,
                registry: if first + n + 1 == terminal {
                    [9; 32]
                } else {
                    [n as u8 + 1; 32]
                },
                event: e.clone(),
            })
            .collect();
        let reply = wire::Reply::Evidence(wire::EvidencePage {
            observed: self.context(nonce).floor,
            tip: wire::Position::of(&self.events[terminal - 1]),
            entries,
        });
        let (proof, body) = self.proof(request, &reply);
        let change = reserved.prepare_response(&proof, &body).unwrap();
        self.check(&change);
        (reserved, change)
    }
}
fn retain(records: &mut BTreeMap<u64, ContinuityEvidenceRecord>, change: Publication) -> Snapshot {
    if let Some(record) = change.record() {
        records.insert(record.reference().index(), record.clone());
    }
    change.after
}
#[test]
fn continuity_stage_and_status_are_hints_terminal_needs_exact_evidence() {
    let f = Fixture::new(33);
    let mut state = f.selected();
    let mut records = BTreeMap::new();
    let request = f.status(&state, 1);
    state = state.prepare_attempt(request, &[]).unwrap().after;
    let (proof, raw) = f.proof(
        request,
        &wire::Reply::Status(wire::Status {
            observed: f.context(1).floor,
            published: wire::Position::EMPTY,
            stage: None,
        }),
    );
    state = retain(&mut records, state.prepare_response(&proof, &raw).unwrap());
    assert_eq!(state.retention.position, wire::Position::EMPTY);
    let body = wire::Body::stage(f.events[..32].to_vec()).unwrap();
    let request = wire::Request::stage(
        f.context(2),
        f.scope.author.author,
        wire::Position::EMPTY,
        None,
        &body,
    )
    .unwrap();
    state = state
        .prepare_attempt(request, &body.encode())
        .unwrap()
        .after;
    let ticket = wire::StageRef::new(
        [4; 32],
        wire::Position::EMPTY,
        wire::Position::of(&f.events[31]),
        1,
        2000,
    )
    .unwrap();
    let (proof, raw) = f.proof(
        request,
        &wire::Reply::Staged(wire::StageAck {
            observed: f.context(2).floor,
            base: wire::Position::EMPTY,
            ticket,
            submitted_end: wire::Position::of(&f.events[31]),
            submitted_body: hash(&body.encode()),
        }),
    );
    state = retain(&mut records, state.prepare_response(&proof, &raw).unwrap());
    assert_eq!(state.retention.position, wire::Position::EMPTY);
    let body = wire::Body::commit(vec![], f.events[32].clone()).unwrap();
    let request = wire::Request::commit(
        f.context(3),
        f.scope.author.author,
        wire::Position::EMPTY,
        Some(ticket),
        &body,
    )
    .unwrap();
    state = state
        .prepare_attempt(request, &body.encode())
        .unwrap()
        .after;
    let (proof, raw) = f.proof(
        request,
        &wire::Reply::Committed(Box::new(wire::TerminalReceipt {
            observed: f.context(3).floor,
            event: f.events[32].clone(),
            cursor: 7,
            registry: [9; 32],
            reconciled: true,
        })),
    );
    state = retain(&mut records, state.prepare_response(&proof, &raw).unwrap());
    assert!(!state.complete());
    assert_eq!(state.retention.position, wire::Position::EMPTY);
    let (_, change) = f.evidence(&state, 4, 0, 32, 33, 7);
    state = retain(&mut records, change);
    assert!(!state.complete());
    let (_, change) = f.evidence(&state, 5, 32, 33, 33, 7);
    state = retain(&mut records, change);
    assert!(state.complete());
    assert_eq!(Snapshot::decode(&state.encode()).unwrap(), state);
    state
        .validate_records(|i| records.get(&i).cloned().ok_or(Error::Corrupt))
        .unwrap();
    let terminal = state.terminal.unwrap();
    records.remove(&terminal.record.index);
    assert_eq!(
        state.validate_records(|i| records.get(&i).cloned().ok_or(Error::Corrupt)),
        Err(Error::Corrupt)
    );
}
#[test]
fn continuity_late_nonce_wrong_peer_and_corrupt_local_bytes_cannot_install() {
    let f = Fixture::new(1);
    let state = f.selected();
    let request = f.status(&state, 1);
    let old = state.prepare_attempt(request, &[]).unwrap().after;
    let newer = old.prepare_attempt(f.status(&old, 2), &[]).unwrap().after;
    let reply = wire::Reply::Status(wire::Status {
        observed: f.context(1).floor,
        published: wire::Position::of(&f.events[0]),
        stage: None,
    });
    let (proof, raw) = f.proof(request, &reply);
    assert!(newer.prepare_response(&proof, &raw).is_err());
    assert!(old.prepare_attempt(request, &[]).is_err());
    let candidate = old.prepare_response(&proof, &raw).unwrap();
    let wrong = Fixture::new(2);
    let head = AuthorHead {
        scope: f.scope.author,
        sequence: 1,
        event: f.events[0].id(),
    };
    assert!(candidate
        .check_sources(head, |_| Ok(wrong.events[1].encode()))
        .is_err());
    let mut bad = proof.encode();
    *bad.last_mut().unwrap() ^= 1;
    assert!(wire::ResponseProof::decode(&bad)
        .unwrap()
        .verify(f.scope.peer, &request, &raw)
        .is_err());
    let other = SigningKey::from_bytes(&[9; 32]);
    let forged = wire::UnsignedResponse::new(other.verifying_key().to_bytes(), request, &raw)
        .unwrap()
        .sign_with_key(&other)
        .unwrap();
    assert!(old.prepare_response(&forged, &raw).is_err());
}
#[test]
fn continuity_cross_page_roles_and_terminal_basis_are_checked() {
    let f = Fixture::new(33);
    let state = f.selected();
    let (_, first) = f.evidence(&state, 1, 0, 32, 33, 7);
    let state = first.after;
    let request = wire::Request::new(
        f.context(2),
        wire::Selection::Author(f.scope.author.author),
        wire::Kind::Evidence {
            after: state.retention.position,
            count: 1,
        },
    )
    .unwrap();
    let reserved = state.prepare_attempt(request, &[]).unwrap().after;
    let reply = wire::Reply::Evidence(wire::EvidencePage {
        observed: f.context(2).floor,
        tip: wire::Position::of(&f.events[32]),
        entries: vec![wire::Entry {
            role: wire::EvidenceRole::CurrentAdmission,
            committed_by: 8,
            registry: [9; 32],
            event: f.events[32].clone(),
        }],
    });
    let (proof, raw) = f.proof(request, &reply);
    assert!(reserved.prepare_response(&proof, &raw).is_err());
    assert_eq!(
        reserved.retention.position,
        wire::Position::of(&f.events[31])
    );
}
#[test]
fn continuity_bounds_strict_codecs_and_monotone_jobs() {
    let f = Fixture::new(2);
    let state = f.selected();
    assert!(state
        .prepare_job(ContinuityJob::new([2; 16], &f.events[0]).unwrap())
        .is_err());
    let request = f.status(&state, 1);
    assert!(state
        .prepare_attempt(request, &vec![0; wire::MAX_BODY_BYTES + 1])
        .is_err());
    assert!(state
        .prepare_attempt(request, b"unexpected GET body")
        .is_err());
    let changed = state.prepare_attempt(request, &[]).unwrap();
    let intent = changed.encode();
    assert_eq!(Publication::decode(&intent).unwrap().after, changed.after);
    for n in 0..intent.len() {
        assert!(Publication::decode(&intent[..n]).is_err());
    }
    let mut extra = intent.clone();
    extra.push(0);
    assert!(Publication::decode(&extra).is_err());
    let mut changed_hash = intent;
    *changed_hash.last_mut().unwrap() ^= 1;
    assert!(Publication::decode(&changed_hash).is_err());
    let mut limited = state.clone();
    limited.limits.max_records = 1;
    let reserved = limited.prepare_attempt(request, &[]).unwrap().after;
    let (proof, raw) = f.proof(
        request,
        &wire::Reply::Status(wire::Status {
            observed: f.context(1).floor,
            published: wire::Position::EMPTY,
            stage: None,
        }),
    );
    let done = reserved.prepare_response(&proof, &raw).unwrap().after;
    let request = f.status(&done, 2);
    let pending = done.prepare_attempt(request, &[]).unwrap().after;
    let (proof, raw) = f.proof(
        request,
        &wire::Reply::Status(wire::Status {
            observed: f.context(2).floor,
            published: wire::Position::EMPTY,
            stage: None,
        }),
    );
    assert!(pending.prepare_response(&proof, &raw).is_err());
    assert_eq!(pending.records, 1);
}
#[test]
fn continuity_exact_source_check_includes_signed_frame_not_only_content_id() {
    let f = Fixture::new(1);
    let selected = f.selected();
    let source = SourceCheck {
        position: wire::Position::of(&f.events[0]),
        frame: Some([7; 32]),
    };
    let head = AuthorHead {
        scope: f.scope.author,
        sequence: 1,
        event: f.events[0].id(),
    };
    assert_eq!(
        source.check(&f.scope, head, &f.events[0].encode()),
        Err(Error::Corrupt)
    );
    assert!(!selected.complete());
    assert_eq!(selected.retention, RetentionHead::empty());
}

#[test]
fn continuity_unpublished_prefix_is_bound_to_exact_state_and_structural_lengths() {
    let f = Fixture::new(1);
    let state = f.selected();
    let request = f.status(&state, 1);
    let change = state.prepare_attempt(request, &[]).unwrap();
    let raw = change.encode();
    for n in 0..raw.len() {
        assert!(
            codec::incomplete_prefix(&raw[..n], &state),
            "valid prefix {n}"
        );
    }
    assert!(!codec::incomplete_prefix(&raw, &state));
    let mut changed = raw[..30].to_vec();
    changed[20] ^= 1;
    assert!(!codec::incomplete_prefix(&changed, &state));
    let mut changed = raw[..12].to_vec();
    changed[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(!codec::incomplete_prefix(&changed, &state));
    let tag = 12 + 4 + state.encode().len();
    let mut changed = raw[..tag + 1].to_vec();
    changed[tag] = 255;
    assert!(!codec::incomplete_prefix(&changed, &state));
    assert!(!codec::incomplete_prefix(&raw[..30], &f.fresh()));
}

#[test]
fn continuity_impossible_available_lengths_are_preserved_not_incomplete_cleanup() {
    let f = Fixture::new(1);
    let selected = f.selected();
    let request = f.status(&selected, 1);
    assert_eq!(request.encode().len(), 279);
    let attempt = selected.prepare_attempt(request, &[]).unwrap();
    let mut raw = attempt.encode();
    let op = 12 + 4 + selected.encode().len() + 1;
    raw.truncate(op + 4);
    raw[op..op + 4].copy_from_slice(&1u32.to_be_bytes());
    assert!(!codec::incomplete_prefix(&raw, &selected));
    let state = attempt.after;
    let (proof, body) = f.proof(
        request,
        &wire::Reply::Status(wire::Status {
            observed: f.context(1).floor,
            published: wire::Position::EMPTY,
            stage: None,
        }),
    );
    let response = state.prepare_response(&proof, &body).unwrap();
    let raw = response.encode();
    for n in 0..raw.len() {
        assert!(
            codec::incomplete_prefix(&raw[..n], &state),
            "response prefix {n}"
        );
    }
    let op = 12 + 4 + state.encode().len() + 1;
    let mut short = raw[..op + 4 + 8].to_vec();
    short[8..12].copy_from_slice(&((op + 4 + 88 + 32) as u32).to_be_bytes());
    short[op..op + 4].copy_from_slice(&88u32.to_be_bytes());
    assert!(!codec::incomplete_prefix(&short, &state));
    let mut partial = short[..op + 1].to_vec();
    partial[op] = 255;
    assert!(!codec::incomplete_prefix(&partial, &state));
}
