//! Deterministic synthetic signatures only. No secret or network input.
use ed25519_dalek::SigningKey;
use vhalla_browser_storage::{
    browser::{history::IndexedHistory, outbox::IndexedOutbox},
    history::{HistoryFrontier, HistoryHead, HistoryScope},
    outbox::{
        continuity::{ContinuityJob, Limits, SessionScope, Snapshot},
        AuthorHead, AuthorScope, ReservedDraft,
    },
    Namespace,
};
use vhalla_public_protocol::{activity, continuity as wire, Endpoint};
use vhalla_room_activity::{EventId, UnsignedEvent, VerifiedEvent};
use wasm_bindgen::JsValue;

pub fn fail(error: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("continuity qualification: {error:?}"))
}
pub fn ensure(value: bool, message: &str) -> Result<(), JsValue> {
    if value {
        Ok(())
    } else {
        Err(fail(message))
    }
}
pub struct Fixture {
    pub scope: SessionScope,
    pub events: Vec<VerifiedEvent>,
    pub limits: Limits,
}
impl Fixture {
    pub fn new(count: usize) -> Result<Self, JsValue> {
        ensure((1..=33).contains(&count), "fixed source count")?;
        let author = SigningKey::from_bytes(&[3; 32]);
        let mut previous = EventId::ZERO;
        let mut events = Vec::with_capacity(count);
        for n in 1..=count {
            // Decode the maintained canonical unsigned frame; no dummy signature.
            let text = format!("synthetic IDB continuity {n}");
            let mut raw = b"VHRA\x01".to_vec();
            raw.extend([7; 32]);
            raw.extend(77u128.to_be_bytes());
            raw.extend([5; 32]);
            raw.extend([8; 32]);
            raw.extend([9; 32]);
            raw.extend(author.verifying_key().to_bytes());
            raw.extend((n as u64).to_be_bytes());
            raw.extend(previous.as_bytes());
            raw.extend(1234u64.to_be_bytes());
            raw.push(0);
            raw.extend((text.len() as u16).to_be_bytes());
            raw.extend(text.as_bytes());
            let event = UnsignedEvent::decode(&raw)
                .map_err(fail)?
                .sign_with_key(&author)
                .map_err(fail)?
                .verify()
                .map_err(fail)?;
            previous = event.id();
            events.push(event);
        }
        let scope = SessionScope::new(
            AuthorScope::new(events[0].claims().scope, events[0].claims().author),
            HistoryScope::new([7; 32], [10; 32]),
            Self::peer().verifying_key().to_bytes(),
            Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").map_err(fail)?,
        )
        .map_err(fail)?;
        Ok(Self {
            scope,
            events,
            limits: Limits {
                max_records: 12,
                max_bytes: 4 * 1024 * 1024,
            },
        })
    }
    fn peer() -> SigningKey {
        SigningKey::from_bytes(&[8; 32])
    }
    pub fn terminal(&self) -> &VerifiedEvent {
        self.events.last().unwrap()
    }
    pub fn context(&self, nonce: u8) -> wire::RequestContext {
        wire::RequestContext {
            scope: self.events[0].claims().scope.into(),
            nonce: [nonce; 32],
            operation: [1; 16],
            floor: wire::Observed {
                height: 7,
                frontier: [6; 32],
            },
        }
    }
    pub fn status(&self, state: &Snapshot, nonce: u8) -> Result<wire::Request, JsValue> {
        wire::Request::new(
            self.context(nonce),
            wire::Selection::Author(self.scope.author().author()),
            wire::Kind::Status {
                minimum: state.retention().position(),
            },
        )
        .map_err(fail)
    }
    pub fn proof(
        &self,
        request: wire::Request,
        reply: wire::Reply,
    ) -> Result<(wire::ResponseProof, Vec<u8>), JsValue> {
        let body = reply.encode(&request).map_err(fail)?;
        let proof = wire::UnsignedResponse::new(self.scope.peer(), request, &body)
            .map_err(fail)?
            .sign_with_key(&Self::peer())
            .map_err(fail)?;
        Ok((proof, body))
    }
    pub fn status_reply(
        &self,
        request: wire::Request,
    ) -> Result<(wire::ResponseProof, Vec<u8>), JsValue> {
        self.proof(
            request,
            wire::Reply::Status(wire::Status {
                observed: request.context().floor,
                published: wire::Position::of(self.terminal()),
                stage: None,
            }),
        )
    }
    pub fn evidence(
        &self,
        request: wire::Request,
        first: usize,
        end: usize,
    ) -> Result<(wire::ResponseProof, Vec<u8>), JsValue> {
        let entries = self.events[first..end]
            .iter()
            .enumerate()
            .map(|(i, event)| wire::Entry {
                role: if first + i + 1 == self.events.len() {
                    wire::EvidenceRole::CurrentAdmission
                } else {
                    wire::EvidenceRole::HistoricalContinuity
                },
                committed_by: 7,
                registry: if first + i + 1 == self.events.len() {
                    [9; 32]
                } else {
                    [i as u8 + 1; 32]
                },
                event: event.clone(),
            })
            .collect();
        self.proof(
            request,
            wire::Reply::Evidence(wire::EvidencePage {
                observed: request.context().floor,
                tip: wire::Position::of(self.terminal()),
                entries,
            }),
        )
    }
    /// Real storage publication, not fabricated database frames or certified policy.
    /// These opaque genesis bytes deliberately make no consensus/admission claim.
    pub async fn initialize(&self, namespace: Namespace) -> Result<IndexedOutbox, JsValue> {
        let policy = HistoryHead::new(
            self.scope.history(),
            HistoryFrontier {
                height: 0,
                value: [1; 32],
                registry: [2; 32],
                social: [3; 32],
                control: [4; 32],
                time: 1234,
            },
            [0; 32],
        )
        .map_err(fail)?;
        let mut history = IndexedHistory::open(namespace, self.scope.history())
            .await
            .map_err(fail)?;
        ensure(
            history.load_head().await.map_err(fail)?.is_none(),
            "fresh history required",
        )?;
        history
            .initialize(b"synthetic storage-only bootstrap", &policy)
            .await
            .map_err(fail)?;
        drop(history);
        let mut outbox = IndexedOutbox::open(namespace).await.map_err(fail)?;
        let mut head = AuthorHead::fresh_scope_authorized(self.scope.author());
        outbox.initialize_fresh_author(&head).await.map_err(fail)?;
        for event in &self.events {
            let draft = ReservedDraft::new(
                head,
                policy,
                UnsignedEvent::new(event.claims().clone()).map_err(fail)?,
            )
            .map_err(fail)?;
            outbox.reserve(&draft).await.map_err(fail)?;
            outbox.finalize(&draft, event).await.map_err(fail)?;
            head = draft.signed_head(event).map_err(fail)?;
        }
        // Populate the real v1 delivery format too: all continuity steps must
        // preserve these exact bytes and this independent one-event floor.
        let event = &self.events[0];
        let request = activity::ActivityRequest::post(
            [88; 32],
            *event.claims().scope.room.as_bytes(),
            &event.encode(),
        )
        .map_err(fail)?;
        let body = activity::LocalReceipt::new(event, 1, [9; 32], 7, [6; 32], false)
            .map_err(fail)?
            .encode();
        let proof =
            activity::UnsignedActivityResponse::new([7; 32], self.scope.peer(), request, &body)
                .map_err(fail)?
                .sign_with_key(&Self::peer())
                .map_err(fail)?;
        outbox
            .record_delivery(
                self.scope.author(),
                self.scope.peer(),
                None,
                &request,
                &proof,
                &body,
            )
            .await
            .map_err(fail)?;
        Ok(outbox)
    }
    pub async fn select(
        &self,
        outbox: &mut IndexedOutbox,
        scope: SessionScope,
        limits: Limits,
    ) -> Result<Snapshot, JsValue> {
        let state = outbox
            .create_continuity(scope, limits)
            .await
            .map_err(fail)?;
        let job = ContinuityJob::new([1; 16], self.terminal()).map_err(fail)?;
        outbox
            .publish_continuity(state.prepare_job(job).map_err(fail)?)
            .await
            .map_err(fail)
    }
    pub fn route(&self, hostname: &str) -> Result<SessionScope, JsValue> {
        SessionScope::new(
            self.scope.author(),
            self.scope.history(),
            self.scope.peer(),
            Endpoint::parse(&format!("https://{hostname}.vhalla.dev:443/vhalla/v1"))
                .map_err(fail)?,
        )
        .map_err(fail)
    }
}
