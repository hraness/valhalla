//! One account plus one selected private room, owned only by the existing worker.
#[path = "admission.rs"]
mod admission;
#[path = "delivery.rs"]
mod delivery;
#[path = "owner_actions.rs"]
mod owner_actions;
pub(super) fn abort_delivery() {
    delivery::abort();
}
use crate::private_wire::types::*;
use vhalla_browser_storage::{
    browser::{
        private_rooms::{IndexedPrivateStore, Limits},
        IndexedStorage,
    },
    identity::IdentitySnapshot,
    Image, Namespace, Slot,
};
use vhalla_browser_vault::{Envelope, UnlockedIdentity};
use vhalla_private_kernel::{
    protocol::{Key, SignedDeviceEnrollment, SignedOwnerControl, SignedRoomAnchor},
    recovery::{ArchiveExport, ArchiveImport, ArchiveSeal, ArchiveSourceReader, ArchiveView},
    storage::ArchiveStore,
    CommittedOutbox, Context, Kernel, MemberDraft, MessageDraft, OutboxEntry, OwnerDraft, Phase,
};
use wasm_bindgen::JsCast;
use zeroize::Zeroizing;

pub use delivery::engine::Failure;
type Result<T> = std::result::Result<T, Failure>;

enum CreationKind {
    Owner(Box<OwnerDraft>),
    Member(Box<MemberDraft>),
}
struct Creation {
    context: Context,
    kind: CreationKind,
    anchor: SignedRoomAnchor,
    enrollment: SignedDeviceEnrollment,
}
struct PendingMessage {
    id: u64,
    draft: MessageDraft,
}

/// At most one archive operation per session. Source reading is memory-only and
/// may be replaced; an active durable export or import must finish or fail out.
enum Archive {
    Exporting {
        context: Context,
        inner: Box<ArchiveExport<IndexedPrivateStore>>,
    },
    Source {
        context: Context,
        legacy: bool,
        reader: Box<ArchiveSourceReader>,
        pages: u64,
    },
    Importing {
        context: Context,
        inner: Box<ArchiveImport<IndexedPrivateStore>>,
    },
    View(Box<ArchiveView<IndexedPrivateStore>>),
}
impl Archive {
    fn context(&self) -> Context {
        match self {
            Self::Exporting { context, .. }
            | Self::Source { context, .. }
            | Self::Importing { context, .. } => *context,
            Self::View(view) => view.seal().context(),
        }
    }
    /// Read-only or memory-only states are safe to replace with a new explicit
    /// archive selection; a durable receiving cursor must not be abandoned by
    /// switching to unrelated work inside this session.
    fn replaceable(&self) -> bool {
        !matches!(self, Self::Importing { .. })
    }
}

pub struct Session {
    // Kernel, drafts and archive handles drop before account custody. No public
    // accessor returns any of these fields or an alternate signing handle.
    kernel: Option<Kernel<IndexedPrivateStore>>,
    kernel_generation: Option<vhalla_browser_storage::private_rooms::DeliveryGeneration>,
    delivery: Option<delivery::Delivery>,
    generation_review: Option<delivery::ReviewedSuccessor>,
    owner_actions: owner_actions::OwnerActions,
    creation: Option<Creation>,
    message: Option<PendingMessage>,
    admission: admission::Admission,
    archive: Option<Archive>,
    identity: UnlockedIdentity,
    saved: IdentitySnapshot,
    // One read-only profile handle for identity revalidation. A foreign
    // version change closes it, which ends this session like any other
    // uncertain storage condition; it is never reopened silently.
    profile: IndexedStorage,
    counter: u64,
}
fn now() -> Result<u64> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || !(0.0..=9_007_199_254_740_991.0).contains(&millis) {
        return Err(Failure::Invalid);
    }
    Ok((millis / 1000.0) as u64)
}
fn artifact(value: &CommittedOutbox) -> Artifact {
    Artifact {
        sequence: value.sequence(),
        operation: value.operation(),
        kind: value.kind(),
        bytes: Some(Zeroizing::new(value.bytes().to_vec())),
        acceptances: Vec::new(),
    }
}

impl Session {
    pub async fn enter(
        identity: UnlockedIdentity,
        authenticated_envelope: &[u8],
        expected: &[u8],
        local_birth: bool,
    ) -> Result<Self> {
        if authenticated_envelope != expected {
            return Err(Failure::IdentityChanged);
        }
        let envelope = Envelope::from_bytes(expected).map_err(|_| Failure::Invalid)?;
        if envelope.claimed_public_key() != identity.public_key() {
            return Err(Failure::IdentityChanged);
        }
        let image = Image::new(Slot::Vault, &[expected]).map_err(|_| Failure::Invalid)?;
        let mut profile = IndexedStorage::open(Namespace::new(PROFILE))
            .await
            .map_err(|_| Failure::Storage)?;
        let saved = profile
            .load_identity()
            .await
            .map_err(|_| Failure::Storage)?;
        if saved.vault() != Some(&image)
            || saved.local_creation(identity.public_key()).is_ok() != local_birth
        {
            return Err(Failure::IdentityChanged);
        }
        let mut admission_session = [0; 16];
        js_sys::global()
            .dyn_into::<web_sys::DedicatedWorkerGlobalScope>()
            .map_err(|_| Failure::Invalid)?
            .crypto()
            .map_err(|_| Failure::Invalid)?
            .get_random_values_with_u8_array(&mut admission_session)
            .map_err(|_| Failure::Invalid)?;
        Ok(Self {
            kernel: None,
            kernel_generation: None,
            delivery: None,
            generation_review: None,
            owner_actions: owner_actions::OwnerActions::default(),
            creation: None,
            message: None,
            admission: admission::Admission::new(admission_session)?,
            archive: None,
            identity,
            saved,
            profile,
            counter: 0,
        })
    }
    async fn revalidate(&mut self) -> Result<()> {
        self.profile
            .revalidate_identity(&self.saved)
            .await
            .map_err(|_| Failure::IdentityChanged)?;
        Ok(())
    }
    fn account(&self) -> Result<Key> {
        Ok(Key::from_bytes(self.identity.public_key())?)
    }
    fn kernel(&mut self) -> Result<&mut Kernel<IndexedPrivateStore>> {
        if delivery::canceled() {
            return Err(Failure::State);
        }
        let kernel = self.kernel.as_mut().ok_or(Failure::State)?;
        if kernel.needs_reopen() {
            return Err(Failure::State);
        }
        Ok(kernel)
    }
    /// Reopen the exact same durable custody in place after a verdict-only
    /// operation that provably committed nothing but still latches
    /// needs_reopen. Equivalent to the fresh open every CLI invocation gets;
    /// an indeterminate write still ends this worker instead of reaching here.
    async fn reopen_kernel(&mut self, context: Context) -> Result<()> {
        let store = self.kernel.take().ok_or(Failure::State)?.into_store();
        let key = self
            .identity
            .private_storage_key(context)
            .map_err(|_| Failure::IdentityChanged)?;
        self.kernel = Some(Kernel::open(store, &key, context).await?);
        Ok(())
    }
    async fn reopen_after_generation(&mut self, context: Context) -> Result<()> {
        self.kernel.take().ok_or(Failure::State)?;
        let key = self.identity.private_storage_key(context)?;
        let store = IndexedPrivateStore::open(Namespace::new(PROFILE), context).await?;
        self.kernel_generation = store.generation();
        self.kernel = Some(Kernel::open(store, &key, context).await?);
        Ok(())
    }
    fn empty(&self) -> Result<()> {
        if self.kernel.is_some() || self.creation.is_some() {
            return Err(Failure::State);
        }
        Ok(())
    }
    /// Archive begin-type selections refuse a live room or an active durable
    /// receiving cursor; a memory-only source reader or inert view may be
    /// replaced by the caller's new explicit archive selection.
    fn archive_selectable(&self) -> Result<()> {
        self.empty()?;
        match &self.archive {
            Some(current) if !current.replaceable() => Err(Failure::State),
            _ => Ok(()),
        }
    }
    async fn archive_inspect(&mut self) -> Result<Response> {
        let Some(Archive::View(view)) = self.archive.as_mut() else {
            return Err(Failure::State);
        };
        let seal = view.seal().clone();
        let snapshot = view.membership().await?;
        Ok(Response::ArchiveInspect {
            context: seal.context(),
            archive_id: seal.archive_id(),
            source_revision: seal.source_revision(),
            status: snapshot.status(),
        })
    }
    fn prepared(&mut self, creation: Creation) -> Response {
        let preview = Preview {
            context: creation.context,
            anchor: creation.anchor.clone(),
            enrollment: creation.enrollment.clone(),
        };
        self.creation = Some(creation);
        Response::Prepared(Box::new(preview))
    }
    async fn membership(&mut self) -> Result<Response> {
        let value = self.kernel()?.membership().await?;
        Ok(Response::Membership(Box::new(Membership {
            status: value.status(),
            anchor: value.anchor().clone(),
            owner: value.owner().clone(),
            local: value.local().clone(),
            members: value.members().to_vec(),
            successions: value.successions().to_vec(),
        })))
    }

    /// A failure is terminal to this worker dispatch. Its caller must drop this
    /// value and reopen an exact retained Context in a new unlocked worker.
    pub async fn execute(&mut self, request: Request) -> Result<Response> {
        self.revalidate().await?;
        let reply = self.execute_selected(request).await?;
        // A vault replacement during an await withholds the output, even if a
        // private transaction already committed. Reopen resolves that exact
        // retained operation; it never regenerates a device or ciphertext.
        self.revalidate().await?;
        Ok(reply)
    }

    async fn execute_selected(&mut self, request: Request) -> Result<Response> {
        if !matches!(request, Request::ConfirmGeneration { .. }) {
            self.generation_review = None;
        }
        self.admission.before(&request);
        self.owner_actions.before(&request);
        if let Some(kernel) = &self.kernel {
            if !matches!(
                &request,
                Request::Membership
                    | Request::Outbox { .. }
                    | Request::Inbox { .. }
                    | Request::Controls { .. }
                    | Request::ControlProofs { .. }
                    | Request::ForkEvidence
                    | Request::ArchiveExport
                    | Request::ArchiveExportNext
            ) {
                let current = delivery::generation(kernel.status().context).await?;
                let allow_paused = matches!(
                    &request,
                    Request::DeliveryConnect { .. }
                        | Request::DeliveryDrain { .. }
                        | Request::ReviewGeneration { .. }
                        | Request::ConfirmGeneration { .. }
                        | Request::DeliveryAdmissions
                        | Request::DeliveryAdmission { .. }
                );
                if current != self.kernel_generation
                    || (current.is_some_and(|g| g.paused) && !allow_paused)
                {
                    return Err(Failure::State);
                }
            }
        }
        let time = now()?;
        match request {
            Request::ReviewOwnerAction { device, succession } => {
                self.message = None;
                let kernel = self.kernel.as_mut().ok_or(Failure::State)?;
                let consent = self
                    .owner_actions
                    .review(kernel, device, succession, || {
                        now().map_err(|_| vhalla_private_kernel::Error::Time)
                    })
                    .await?;
                Ok(Response::OwnerReview(Box::new(consent)))
            }
            Request::DeliveryDrain {
                transition,
                head,
                restart,
            } => {
                self.message = None;
                let context = self.kernel()?.status().context;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let report = delivery
                    .drain(self, context, transition, head, restart)
                    .await;
                self.delivery = Some(delivery);
                Ok(Response::Generation(report?))
            }
            Request::ReviewGeneration {
                profile,
                fence,
                attempt_ceiling,
            } => {
                self.message = None;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let review = delivery
                    .review_successor(self, profile, fence, attempt_ceiling)
                    .await;
                self.delivery = Some(delivery);
                let review = review?;
                let consent = review.consent.clone();
                self.generation_review = Some(review);
                Ok(Response::GenerationReview(Box::new(consent)))
            }
            Request::ConfirmGeneration { consent } => {
                let review = self.generation_review.take().ok_or(Failure::State)?;
                if *consent != review.consent {
                    return Err(Failure::State);
                }
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let report = delivery.confirm_successor(self, review).await;
                self.delivery = Some(delivery);
                Ok(Response::Delivery(report?))
            }
            Request::Enter { .. } => Err(Failure::State),
            Request::PrepareOwner(validity) => {
                self.empty()?;
                validity.check_at(time)?;
                let draft = OwnerDraft::new(self.account()?, validity)?;
                let enrollment = self
                    .identity
                    .sign_private_enrollment(draft.enrollment_request())?;
                let anchor = self.identity.sign_private_anchor(draft.anchor_request())?;
                let context = draft.context(&anchor)?;
                Ok(self.prepared(Creation {
                    context,
                    kind: CreationKind::Owner(Box::new(draft)),
                    anchor,
                    enrollment,
                }))
            }
            Request::PrepareContact {
                offer,
                owner,
                validity,
            } => {
                self.empty()?;
                let selected = vhalla_private_kernel::ContactBootstrap::inspect(
                    &offer,
                    owner,
                    self.account()?,
                    time,
                )?;
                let anchor = selected.anchor().clone();
                let draft = MemberDraft::new(
                    selected.scope(),
                    anchor.clone(),
                    selected.owner().clone(),
                    self.account()?,
                    validity,
                    time,
                )?;
                let enrollment = self
                    .identity
                    .sign_private_enrollment(draft.enrollment_request())?;
                let context = draft.context();
                Ok(self.prepared(Creation {
                    context,
                    kind: CreationKind::Member(Box::new(draft)),
                    anchor,
                    enrollment,
                }))
            }
            Request::CommitCreation(expected) => {
                if self.kernel.is_some() {
                    return Err(Failure::State);
                }
                let creation = self.creation.take().ok_or(Failure::State)?;
                if creation.context != expected {
                    return Err(Failure::State);
                }
                creation.enrollment.claims().validity.check_at(time)?;
                let key = self.identity.private_storage_key(expected)?;
                // Fixed local budgets, never inherited from an imported file.
                let store = IndexedPrivateStore::create_new(
                    Namespace::new(PROFILE),
                    expected,
                    Limits {
                        max_records: 100_000,
                        max_record_bytes: 256 * 1024 * 1024,
                    },
                )
                .await?;
                self.kernel_generation = store.generation();
                let kernel = match creation.kind {
                    CreationKind::Owner(draft) => {
                        draft
                            .create(store, &key, creation.enrollment, creation.anchor, time)
                            .await?
                    }
                    CreationKind::Member(draft) => {
                        draft
                            .initialize(store, &key, creation.enrollment, time)
                            .await?
                    }
                };
                self.kernel = Some(kernel);
                self.membership().await
            }
            Request::Open(context) => {
                self.empty()?;
                // This account check/derivation precedes backend access. Open
                // never initializes an absent image, FORMAT, device or ratchet.
                let key = self.identity.private_storage_key(context)?;
                let store = IndexedPrivateStore::open(Namespace::new(PROFILE), context).await?;
                self.kernel_generation = store.generation();
                self.kernel = Some(Kernel::open(store, &key, context).await?);
                self.membership().await
            }
            Request::Membership => self.membership().await,
            Request::DeliveryConnect { profile, create } => {
                if self.delivery.is_some() {
                    return Err(Failure::State);
                }
                let context = self.kernel()?.membership().await?.status().context;
                let delivery = delivery::Delivery::connect(self, context, &profile, create).await?;
                let report = delivery.status(context);
                self.delivery = Some(delivery);
                Ok(Response::Delivery(report))
            }
            Request::DeliverySync => {
                // Sync is a new disclosure boundary even when its page is
                // empty or the roster stays unchanged. Reject any old preview
                // at worker custody, independently of the panel clearing it.
                self.message = None;
                let context = self.kernel()?.status().context;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let report = delivery.sync(self, context).await;
                self.delivery = Some(delivery);
                Ok(Response::Delivery(report?))
            }
            Request::DeliveryAdmissions => {
                let context = self.kernel()?.status().context;
                let delivery = self.delivery.as_ref().ok_or(Failure::State)?;
                let items = delivery
                    .admissions()
                    .into_iter()
                    .map(|a| AdmissionItem {
                        position: a.position,
                        kind: a.kind,
                        len: u64::from(a.len),
                        digest: a.digest,
                    })
                    .collect();
                Ok(Response::Admissions { context, items })
            }
            Request::DeliveryAdmission { position } => {
                let context = self.kernel()?.status().context;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let item = delivery.retained(self, position).await;
                self.delivery = Some(delivery);
                let item = item?;
                Ok(Response::Artifact {
                    context,
                    artifact: Artifact {
                        sequence: item.sequence(),
                        operation: item.operation(),
                        kind: match item.kind() {
                            vhalla_private_relay::RelayKind::Outbox(kind) => kind,
                            vhalla_private_relay::RelayKind::Control => return Err(Failure::State),
                        },
                        bytes: Some(Zeroizing::new(item.payload().to_vec())),
                        acceptances: Vec::new(),
                    },
                })
            }
            Request::ReviewAdmission {
                position,
                recipient,
                offer,
            } => {
                self.message = None;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let item = delivery.retained(self, position).await;
                self.delivery = Some(delivery);
                let item = item?;
                self.kernel()?;
                let consent = self
                    .admission
                    .review(
                        self.kernel.as_mut().ok_or(Failure::State)?,
                        position,
                        &item,
                        &offer,
                        recipient,
                        now()?,
                    )
                    .await?;
                Ok(Response::AdmissionReview(Box::new(consent)))
            }
            Request::ReviewJoinResponse { position } => {
                self.message = None;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let binding = delivery.binding();
                let item = delivery.retained(self, position).await;
                self.delivery = Some(delivery);
                let item = item?;
                self.kernel()?;
                let consent = self
                    .admission
                    .review_join(
                        self.kernel.as_mut().ok_or(Failure::State)?,
                        binding,
                        position,
                        &item,
                        now()?,
                    )
                    .await?;
                Ok(Response::JoinReview(Box::new(consent)))
            }
            Request::ConfirmJoinResponse { consent } => {
                self.message = None;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let binding = delivery.binding();
                let item = delivery.retained(self, consent.position).await;
                self.delivery = Some(delivery);
                let item = item?;
                self.kernel()?;
                self.admission
                    .authorize_join(
                        self.kernel.as_mut().ok_or(Failure::State)?,
                        binding,
                        &consent,
                        &item,
                        now()?,
                    )
                    .await?;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let result = delivery
                    .join_reviewed(
                        self,
                        consent.pending.context,
                        consent.position,
                        consent.digest,
                        consent.validity,
                    )
                    .await;
                self.delivery = Some(delivery);
                result?;
                self.membership().await
            }
            Request::ConfirmAdmission { operation, consent } => {
                self.message = None;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let item = delivery.retained(self, consent.position).await;
                self.delivery = Some(delivery);
                let item = item?;
                self.kernel()?;
                let output = self
                    .admission
                    .confirm(
                        self.kernel.as_mut().ok_or(Failure::State)?,
                        operation,
                        &consent,
                        &item,
                        now()?,
                    )
                    .await?;
                Ok(Response::Artifact {
                    context: consent.context,
                    artifact: artifact(&output),
                })
            }
            Request::DeliveryDiscard { position } => {
                let context = self.kernel()?.status().context;
                let mut delivery = self.delivery.take().ok_or(Failure::State)?;
                let report = delivery.discard(self, context, position).await;
                self.delivery = Some(delivery);
                Ok(Response::Delivery(report?))
            }
            Request::PrepareMessage(body) => {
                self.kernel()?.membership().await?;
                let draft = self.kernel()?.prepare_message(&body)?;
                self.counter = self.counter.checked_add(1).ok_or(Failure::State)?;
                let preview = Consent {
                    id: self.counter,
                    context: draft.context(),
                    epoch: draft.epoch(),
                    roster: *draft.roster(),
                    body: Zeroizing::new(draft.body().to_vec()),
                };
                self.message = Some(PendingMessage {
                    id: self.counter,
                    draft,
                });
                Ok(Response::Draft(Box::new(preview)))
            }
            Request::Send { operation, consent } => {
                let current = self.kernel()?.membership().await?.status();
                let pending = self.message.take().ok_or(Failure::State)?;
                if pending.id != consent.id
                    || pending.draft.context() != consent.context
                    || pending.draft.epoch() != consent.epoch
                    || pending.draft.roster() != &consent.roster
                    || pending.draft.body() != consent.body.as_slice()
                    || current.context != consent.context
                    || current.epoch != consent.epoch
                    || current.roster != consent.roster
                    || current.quarantined
                    || !matches!(
                        current.phase,
                        Phase::OwnerGenesis
                            | Phase::OwnerJoined
                            | Phase::OwnerAfterRemoval
                            | Phase::MemberJoined
                    )
                {
                    return Err(Failure::State);
                }
                let output = self.kernel()?.send(operation, &pending.draft, time).await?;
                self.message = Some(pending);
                Ok(Response::Artifact {
                    context: current.context,
                    artifact: artifact(&output),
                })
            }
            Request::Offer {
                operation,
                recipient,
                validity,
            } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let offer = kernel
                    .create_contact_offer(operation, recipient, validity, time)
                    .await?;
                Ok(Response::Offer {
                    context,
                    operation,
                    secret: Zeroizing::new(offer.confidential_bytes().to_vec()),
                })
            }
            Request::ContactRequest { operation, offer } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let output = kernel.contact_request(operation, &offer, time).await?;
                Ok(Response::Artifact {
                    context,
                    artifact: artifact(&output),
                })
            }
            Request::Accept {
                operation,
                request,
                validity,
            } => {
                self.message = None;
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let output = kernel
                    .accept_contact(operation, &request, validity, time)
                    .await?;
                Ok(Response::Artifact {
                    context,
                    artifact: artifact(&output),
                })
            }
            Request::Join(raw) => {
                self.message = None;
                let context = self.kernel()?.status().context;
                let retained = delivery::retained_image(context).await?;
                self.revalidate().await?;
                admission::Admission::join_file(self.kernel()?, retained.as_deref(), &raw, time)
                    .await?;
                self.membership().await
            }
            Request::Receive(raw) => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let output = kernel.receive(&raw, time).await?;
                Ok(Response::Received {
                    context,
                    message: Inbound {
                        sequence: output.sequence(),
                        sender: output.sender(),
                        body: Zeroizing::new(output.body().to_vec()),
                    },
                })
            }
            Request::Remove { operation, device } => {
                self.message = None;
                let kernel = self.kernel.as_mut().ok_or(Failure::State)?;
                self.owner_actions
                    .confirm(kernel, device, false, || {
                        now().map_err(|_| vhalla_private_kernel::Error::Time)
                    })
                    .await?;
                let context = kernel.status().context;
                let output = kernel.remove(operation, device, now()?).await?;
                Ok(Response::Artifact {
                    context,
                    artifact: artifact(&output),
                })
            }
            Request::Renew {
                operation,
                validity,
            } => {
                self.message = None;
                let request = self.kernel()?.owner_renewal_request(validity)?;
                let enrollment = self.identity.sign_private_enrollment(&request)?;
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let output = kernel.renew_owner(operation, enrollment, time).await?;
                Ok(Response::Artifact {
                    context,
                    artifact: artifact(&output),
                })
            }
            Request::Succeed {
                operation,
                successor,
                validity,
            } => {
                self.message = None;
                let reviewed = self
                    .owner_actions
                    .confirm(
                        self.kernel.as_mut().ok_or(Failure::State)?,
                        successor,
                        true,
                        || now().map_err(|_| vhalla_private_kernel::Error::Time),
                    )
                    .await?;
                if reviewed.target.claims().validity != validity {
                    return Err(Failure::State);
                }
                let request = self
                    .kernel()?
                    .succession_request(successor, validity)
                    .await?;
                let grant = self.identity.sign_private_succession(&request)?;
                reviewed.validity.check_at(now()?)?;
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let output = kernel.succeed(operation, grant, now()?).await?;
                Ok(Response::Artifact {
                    context,
                    artifact: artifact(&output),
                })
            }
            Request::ApplyControl(raw) => {
                self.message = None;
                self.kernel()?.apply_control(&raw, time).await?;
                self.membership().await
            }
            Request::Controls { after, limit } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let page = kernel.encrypted_controls(after, limit).await?;
                let records = page
                    .records
                    .into_iter()
                    .map(|r| Control {
                        floor: r.floor(),
                        bytes: Zeroizing::new(r.bytes().to_vec()),
                    })
                    .collect();
                Ok(Response::Controls {
                    context,
                    base: page.base,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::ControlProofs { after, limit } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let page = kernel.controls(after, limit).await?;
                let records = page
                    .records
                    .into_iter()
                    .map(|r| Control {
                        floor: r.floor(),
                        bytes: Zeroizing::new(r.bytes().to_vec()),
                    })
                    .collect();
                Ok(Response::ControlProofs {
                    context,
                    base: page.base,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::ObserveControl(raw) => {
                // A retained verdict clears the in-flight flag; a missing
                // verdict commits nothing but leaves the kernel requiring
                // reopen, so custody is reopened in place before replying.
                // A proven conflict quarantines and ends this worker anyway.
                let context = self.kernel()?.status().context;
                let verdict = match self.kernel()?.observe_owner_control(&raw, time).await {
                    Ok(_) => ObserveVerdict::Retained,
                    Err(vhalla_private_kernel::Error::Missing) => {
                        self.reopen_kernel(context).await?;
                        // The kernel reports both future floors and floors below
                        // this device's retained base as missing; only the first
                        // can ever be caught up by applying controls.
                        let base = self.kernel()?.status().history_base.sequence();
                        let below = SignedOwnerControl::decode(&raw)
                            .ok()
                            .and_then(|c| c.claims().sequence().ok())
                            .is_some_and(|sequence| sequence < base);
                        if below {
                            ObserveVerdict::BeforeBase
                        } else {
                            ObserveVerdict::UnknownHistory
                        }
                    }
                    Err(e) => return Err(e.into()),
                };
                Ok(Response::Observed { context, verdict })
            }
            Request::ForkEvidence => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let proof = kernel.fork_evidence().await?.map(|p| ForkProof {
                    accepted: p.accepted,
                    conflicting: Zeroizing::new(p.conflicting.encode()),
                    accepted_proof: Zeroizing::new(p.accepted_proof),
                    accepted_from_checkpoint: p.accepted_from_checkpoint,
                });
                Ok(Response::ForkEvidence { context, proof })
            }
            #[cfg(feature = "local-qualification")]
            Request::Divergent { sequence } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let control = kernel.qualification_divergent_control(sequence).await?;
                Ok(Response::Divergent {
                    context,
                    control: Zeroizing::new(control),
                })
            }
            #[cfg(feature = "local-qualification")]
            Request::ApplyControlAt { envelope, at } => {
                self.message = None;
                self.kernel()?.apply_control(&envelope, at).await?;
                self.membership().await
            }
            Request::Outbox { after, limit } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let page = kernel.outbox(after, limit).await?;
                let mut records = Vec::new();
                for r in page.records {
                    let entry = match r {
                        OutboxEntry::Artifact(a) => {
                            let mut entry = artifact(&a);
                            if a.kind() == vhalla_private_kernel::OutboxKind::Application {
                                entry.acceptances = kernel
                                    .acceptances(a.sequence())
                                    .await?
                                    .into_iter()
                                    .map(|a| DeviceAcceptance {
                                        recipient: a.recipient(),
                                        received_sequence: a.received_sequence(),
                                    })
                                    .collect();
                            }
                            entry
                        }
                        OutboxEntry::ConfidentialOffer {
                            sequence,
                            operation,
                        } => Artifact {
                            sequence,
                            operation,
                            kind: vhalla_private_kernel::OutboxKind::ContactOffer,
                            bytes: None,
                            acceptances: Vec::new(),
                        },
                    };
                    records.push(entry);
                }
                Ok(Response::Outbox {
                    context,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::Inbox { after, limit } => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                let page = kernel.inbox(after, limit).await?;
                let records = page
                    .records
                    .into_iter()
                    .map(|r| Inbound {
                        sequence: r.sequence(),
                        sender: r.sender(),
                        body: Zeroizing::new(r.body().to_vec()),
                    })
                    .collect();
                Ok(Response::Inbox {
                    context,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::ArchiveExport => {
                let kernel = self.kernel()?;
                let context = kernel.status().context;
                match &self.archive {
                    Some(current) if !current.replaceable() => return Err(Failure::State),
                    _ => (),
                }
                let key = self.identity.private_storage_key(context)?;
                // A second read handle on the exact open room prefix. Export
                // revalidates accounting around every page; a concurrent write
                // is a terminal conflict, never a spliced stream.
                let store = IndexedPrivateStore::open(Namespace::new(PROFILE), context).await?;
                let export = ArchiveExport::open(store, &key, context).await?;
                let archive_id = export.archive_id();
                self.archive = Some(Archive::Exporting {
                    context,
                    inner: Box::new(export),
                });
                Ok(Response::ArchiveBegin {
                    context,
                    archive_id,
                })
            }
            Request::ArchiveExportNext => {
                let Some(Archive::Exporting { context, inner }) = self.archive.as_mut() else {
                    return Err(Failure::State);
                };
                let context = *context;
                let page = inner.next_page().await?;
                let response = Response::ArchivePage {
                    context,
                    page: page.map(|p| Zeroizing::new(p.encrypted_bytes().to_vec())),
                };
                if matches!(response, Response::ArchivePage { page: None, .. }) {
                    self.archive = None;
                }
                Ok(response)
            }
            Request::ArchiveImportBegin {
                context,
                archive_id,
                legacy,
            } => {
                self.archive_selectable()?;
                if context.account != self.account()? {
                    return Err(Failure::Invalid);
                }
                let key = self.identity.private_storage_key(context)?;
                let reader = ArchiveSourceReader::new(&key, context, archive_id)?;
                self.archive = Some(Archive::Source {
                    context,
                    legacy,
                    reader: Box::new(reader),
                    pages: 0,
                });
                Ok(Response::ArchiveBegin {
                    context,
                    archive_id,
                })
            }
            Request::ArchiveImportFeed(page) => {
                let Some(archive) = self.archive.as_mut() else {
                    return Err(Failure::State);
                };
                match archive {
                    Archive::Source {
                        context,
                        reader,
                        pages,
                        ..
                    } => {
                        let context = *context;
                        if !reader.push(&page)? {
                            *pages = pages.checked_add(1).ok_or(Failure::State)?;
                            return Ok(Response::ArchiveProgress {
                                context,
                                source_ready: false,
                                next_page: *pages,
                                records: 0,
                                bytes: 0,
                            });
                        }
                        let Some(Archive::Source { reader, legacy, .. }) = self.archive.take()
                        else {
                            return Err(Failure::State);
                        };
                        let source = reader.finish()?;
                        let key = self.identity.private_storage_key(context)?;
                        // No destination or catalog access precedes source
                        // authentication. Legacy routing is an explicit choice,
                        // never a fallback after another destination refuses.
                        let mut store = if legacy {
                            IndexedPrivateStore::open(
                                vhalla_browser_storage::private_archives::LEGACY,
                                context,
                            )
                            .await?
                        } else {
                            let reservation =
                                vhalla_browser_storage::browser::private_archives::reserve(&source)
                                    .await
                                    .map_err(|_| Failure::Storage)?;
                            IndexedPrivateStore::open_or_create_archive(reservation).await?
                        };
                        let has_image = store
                            .accounting(context)
                            .await
                            .map_err(|_| Failure::Storage)?
                            .image
                            .is_some();
                        // A completed read-only image or another archive's
                        // cursor fails resume; nothing is reset or overwritten.
                        let import = if has_image {
                            ArchiveImport::resume(store, &key, source).await?
                        } else {
                            if legacy {
                                return Err(Failure::State);
                            }
                            ArchiveImport::begin(store, &key, source).await?
                        };
                        let progress = import.progress()?;
                        self.archive = Some(Archive::Importing {
                            context,
                            inner: Box::new(import),
                        });
                        Ok(Response::ArchiveProgress {
                            context,
                            source_ready: true,
                            next_page: progress.next_page,
                            records: progress.records,
                            bytes: progress.bytes,
                        })
                    }
                    Archive::Importing { context, inner } => {
                        let progress = inner.append(&page).await?;
                        Ok(Response::ArchiveProgress {
                            context: *context,
                            source_ready: true,
                            next_page: progress.next_page,
                            records: progress.records,
                            bytes: progress.bytes,
                        })
                    }
                    _ => Err(Failure::State),
                }
            }
            Request::ArchiveImportFinish(page) => {
                let Some(Archive::Importing { inner, .. }) = self.archive.take() else {
                    return Err(Failure::State);
                };
                let view = inner.finish(&page).await?;
                self.archive = Some(Archive::View(Box::new(view)));
                self.archive_inspect().await
            }
            Request::ArchiveOpen {
                context,
                archive_id,
                legacy,
                final_page,
            } => {
                self.archive_selectable()?;
                if context.account != self.account()? {
                    return Err(Failure::Invalid);
                }
                let key = self.identity.private_storage_key(context)?;
                let seal = ArchiveSeal::from_final_page(&key, context, archive_id, &final_page)?;
                let namespace = if legacy {
                    vhalla_browser_storage::private_archives::LEGACY
                } else {
                    vhalla_browser_storage::private_archives::sealed_namespace(&seal)
                };
                let store = IndexedPrivateStore::open(namespace, context).await?;
                let view = ArchiveView::open(store, &key, seal).await?;
                self.archive = Some(Archive::View(Box::new(view)));
                self.archive_inspect().await
            }
            Request::ArchiveInspect => self.archive_inspect().await,
            Request::ArchiveInbox { after, limit } => {
                let Some(Archive::View(view)) = self.archive.as_mut() else {
                    return Err(Failure::State);
                };
                let context = view.seal().context();
                let page = view.inbox(after, limit).await?;
                let records = page
                    .records
                    .into_iter()
                    .map(|r| Inbound {
                        sequence: r.sequence(),
                        sender: r.sender(),
                        body: Zeroizing::new(r.body().to_vec()),
                    })
                    .collect();
                Ok(Response::Inbox {
                    context,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::ArchiveOutbox { after, limit } => {
                let Some(Archive::View(view)) = self.archive.as_mut() else {
                    return Err(Failure::State);
                };
                let context = view.seal().context();
                let page = view.outbox(after, limit).await?;
                let records = page
                    .records
                    .into_iter()
                    .map(|r| match r {
                        OutboxEntry::Artifact(a) => artifact(&a),
                        OutboxEntry::ConfidentialOffer {
                            sequence,
                            operation,
                        } => Artifact {
                            sequence,
                            operation,
                            kind: vhalla_private_kernel::OutboxKind::ContactOffer,
                            bytes: None,
                            acceptances: Vec::new(),
                        },
                    })
                    .collect();
                Ok(Response::Outbox {
                    context,
                    head: page.head,
                    next: page.next,
                    records,
                })
            }
            Request::ArchiveClose => {
                let Some(archive) = self.archive.take() else {
                    return Err(Failure::State);
                };
                Ok(Response::ArchiveClosed {
                    context: archive.context(),
                })
            }
        }
    }
}
