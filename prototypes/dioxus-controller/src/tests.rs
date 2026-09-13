use super::*;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use vhalla_attention::Attention;
use vhalla_dioxus_services_spike::{Engine, MemoryStorage, ReadState};
use vhalla_discovery::DiscoveryState;
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    Actor, Body, ControlAction, Facet, FacetKind, FacetedText, MentionTarget,
    Operation as SocialOperation, Placement, References, SignedRecord, Text, UnsignedRecord,
    MAX_RECORD_BYTES,
};

// Public deterministic fixture keys only. No native/browser adapter is instantiated.
fn signed(seed: u8, body: Body) -> SignedRecord {
    let key = SigningKey::from_bytes(&[seed; 32]);
    UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .finish()
        .unwrap()
}
fn fixture(profile: u8) -> Engine {
    let mut archive = Archive::new(vhalla_core::RealmId(51), Limits::default()).unwrap();
    let genesis = |seed| {
        signed(
            seed,
            Body::OwnerGenesis {
                controller: SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .to_bytes(),
                recovery: None,
                nonce: [seed; 32],
            },
        )
    };
    let source = genesis(1);
    let recipient = genesis(2);
    let owner = OwnerId::from_bytes(*recipient.id().as_bytes());
    let writer = OwnerId::from_bytes(*source.id().as_bytes());
    let mut records = vec![source.clone(), recipient];
    let mut previous = None;
    for sequence in 0..3 {
        let post = signed(
            1,
            Body::Social {
                actor: Actor::Owner {
                    owner: writer,
                    control: source.id(),
                },
                realm: archive.realm(),
                sequence,
                previous,
                operation: SocialOperation::PostFaceted {
                    placement: Placement::Profile,
                    content: FacetedText::new(
                        Text::new(&format!("@reader message {sequence}")).unwrap(),
                        vec![Facet {
                            start: 0,
                            end: 7,
                            kind: FacetKind::Mention(MentionTarget::Owner(owner)),
                        }],
                    )
                    .unwrap(),
                    reply: None,
                    quote: None,
                },
            },
        );
        previous = Some(post.id());
        records.push(post);
    }
    records.push(signed(
        1,
        Body::Control {
            owner: writer,
            previous: source.id(),
            action: ControlAction::Seal {
                realm: archive.realm(),
                heads: References::sorted(vec![previous.unwrap()]).unwrap(),
            },
        },
    ));
    for record in records {
        archive
            .ingest(
                &record.encode(),
                &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
            )
            .unwrap();
    }
    let scope = ReaderScope::new(&archive, 10, owner, None, [profile; 32], [0; 32]).unwrap();
    Engine::new(
        archive,
        scope,
        Attention::new(scope),
        DiscoveryState::new(scope.digest()),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    ErrorBefore,
    ErrorAfter,
    WaitAfter,
    PublishedModel,
    Foreign,
}
struct FixtureBackend {
    engine: Engine,
    mode: Mode,
    gate: Rc<Cell<bool>>,
    queries: Rc<Cell<usize>>,
    submissions: Rc<Cell<usize>>,
    applied: Rc<Cell<usize>>,
    memory: Option<Rc<RefCell<MemoryStorage>>>,
}
struct Backend {
    bound: BoundBackend<FixtureBackend>,
}
impl std::ops::Deref for Backend {
    type Target = FixtureBackend;
    fn deref(&self) -> &FixtureBackend {
        &self.bound.inner
    }
}
impl std::ops::DerefMut for Backend {
    fn deref_mut(&mut self) -> &mut FixtureBackend {
        &mut self.bound.inner
    }
}
impl Backend {
    fn new(profile: u8) -> Self {
        Self::from_engine(fixture(profile))
    }
    fn from_engine(engine: Engine) -> Self {
        let scope = engine.reader();
        let inner = FixtureBackend {
            engine,
            mode: Mode::Normal,
            gate: Rc::new(Cell::new(true)),
            queries: Rc::new(Cell::new(0)),
            submissions: Rc::new(Cell::new(0)),
            applied: Rc::new(Cell::new(0)),
            memory: None,
        };
        Self {
            bound: BoundBackend::new(scope, inner).unwrap(),
        }
    }
}
impl Service for FixtureBackend {
    fn project(&mut self, screen: Screen) -> Result<Projection, Error> {
        self.queries.set(self.queries.get() + 1);
        self.engine.project(screen, 10)
    }
    fn submit(
        &mut self,
        intent: Intent,
    ) -> Pin<Box<dyn Future<Output = Result<Projection, Error>> + '_>> {
        Box::pin(async move {
            self.submissions.set(self.submissions.get() + 1);
            if matches!(self.mode, Mode::ErrorBefore) {
                return Err(Error::Storage);
            }
            if !matches!(self.mode, Mode::WaitAfter) {
                wait(&self.gate).await;
            }
            let mut page = if let Some(memory) = &self.memory {
                memory
                    .borrow_mut()
                    .submit(&mut self.engine, intent, 10, false)?
            } else {
                self.engine.apply_ephemeral(intent, 10)?
            };
            self.applied.set(self.applied.get() + 1);
            match self.mode {
                Mode::ErrorAfter => return Err(Error::Storage),
                Mode::WaitAfter => wait(&self.gate).await,
                // Exercise classification of a trusted backend's report only.
                // This is not native persistence evidence.
                Mode::PublishedModel => page.persistence = Persistence::Native,
                Mode::Foreign => page.reader = fixture(99).reader(),
                _ => {}
            }
            Ok(page)
        })
    }
}
async fn wait(gate: &Cell<bool>) {
    std::future::poll_fn(|_| {
        if gate.get() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}
fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready(operation: Operation, backend: &mut Backend) -> Completion {
    let mut future = Box::pin(operation.run(&mut backend.bound));
    match poll(future.as_mut()) {
        Poll::Ready(done) => done,
        Poll::Pending => panic!("unexpected pending"),
    }
}
fn setup() -> (Controller, Backend) {
    let mut backend = Backend::new(1);
    let controller = Controller::new(vec![backend.engine.reader()]).unwrap();
    ready(controller.project(Screen::Inbox).unwrap(), &mut backend);
    (controller, backend)
}
fn first_ack(controller: &Controller) -> Mutation {
    let cached = controller.display().page.unwrap();
    Mutation::Acknowledge {
        page: cached.lease,
        ids: vec![cached.projection.notifications[0].id],
    }
}
fn read_count(page: &Projection) -> usize {
    page.notifications
        .iter()
        .filter(|n| n.read == ReadState::Read)
        .count()
}

#[test]
fn renders_only_read_cached_dtos_and_do_not_issue_new_receipts() {
    let (controller, backend) = setup();
    let cached = controller.display().page.unwrap();
    for _ in 0..100 {
        let again = controller.display().page.unwrap();
        assert_eq!(again.lease, cached.lease);
        assert!(Rc::ptr_eq(&again.projection, &cached.projection));
    }
    assert_eq!(backend.queries.get(), 2);
    assert_eq!(backend.submissions.get(), 0);
}

#[test]
fn exact_membership_and_old_lease_replay_reject_before_backend_call() {
    let (controller, mut backend) = setup();
    let old = first_ack(&controller);
    let page = controller.display().page.unwrap().lease;
    assert_eq!(
        controller
            .mutate(Mutation::Acknowledge {
                page: page.clone(),
                ids: vec![[255; 32]]
            })
            .err(),
        Some(Reject::NotObserved)
    );
    let id = controller.display().page.unwrap().projection.notifications[0].id;
    assert_eq!(
        controller
            .mutate(Mutation::Acknowledge {
                page: page.clone(),
                ids: vec![id, id]
            })
            .err(),
        Some(Reject::Bounds)
    );
    assert_eq!(backend.submissions.get(), 0);
    let done = ready(controller.mutate(old.clone()).unwrap(), &mut backend);
    assert_eq!(done.outcome, Outcome::AppliedEphemeral);
    assert_eq!(
        read_count(&controller.display().page.unwrap().projection),
        1
    );
    assert_eq!(controller.mutate(old).err(), Some(Reject::StalePage));
    assert_eq!(backend.submissions.get(), 1);
}

#[test]
fn one_operation_per_reader_is_bounded_and_other_reader_progresses() {
    let mut a = Backend::new(1);
    let mut b = Backend::new(2);
    let controller = Controller::new(vec![a.engine.reader(), b.engine.reader()]).unwrap();
    ready(controller.project(Screen::Inbox).unwrap(), &mut a);
    let held = controller.mutate(first_ack(&controller)).unwrap();
    assert_eq!(controller.project(Screen::Inbox).err(), Some(Reject::Busy));
    assert_eq!(
        controller.mutate(first_ack(&controller)).err(),
        Some(Reject::Busy)
    );
    controller.select(1).unwrap();
    ready(controller.project(Screen::Inbox).unwrap(), &mut b);
    assert_eq!(controller.display().status, Status::Ready);
    drop(held);
    controller.select(0).unwrap();
    assert_eq!(controller.display().status, Status::Ready);
    assert!(!controller.display().fresh);
    assert_eq!(a.submissions.get(), 0);
}

#[test]
fn cancellation_before_first_poll_is_definitely_before_submission() {
    let (controller, mut backend) = setup();
    let operation = controller.mutate(first_ack(&controller)).unwrap();
    let future = operation.run(&mut backend.bound);
    drop(future);
    assert_eq!(
        controller.display().outcome,
        Some(Outcome::CanceledBeforeStart)
    );
    assert_eq!(controller.display().status, Status::Ready);
    assert_eq!(backend.submissions.get(), 0);
}

#[test]
fn cancellation_before_or_after_write_preserves_reopen_obligation() {
    for mode in [Mode::Normal, Mode::WaitAfter] {
        let (controller, mut backend) = setup();
        backend.mode = mode;
        backend.gate.set(false);
        let old = first_ack(&controller);
        let mut future = Box::pin(
            controller
                .mutate(old.clone())
                .unwrap()
                .run(&mut backend.bound),
        );
        assert!(poll(future.as_mut()).is_pending());
        drop(future);
        assert_eq!(
            controller.display().outcome,
            Some(Outcome::CanceledUncertain)
        );
        assert_eq!(controller.display().status, Status::NeedsReopen);
        assert_eq!(
            controller.project(Screen::Inbox).err(),
            Some(Reject::NeedsReopen)
        );
        assert_eq!(
            controller.mutate(old.clone()).err(),
            Some(Reject::NeedsReopen)
        );
        let expected = usize::from(matches!(mode, Mode::WaitAfter));
        assert_eq!(backend.applied.get(), expected);
        // A new service is reconstructed from the surviving in-memory image.
        // Native/IndexedDB recovery remains their separately owned runtime gate.
        let image = backend.engine.image();
        let mut reopened =
            Backend::from_engine(Engine::from_image(image, Persistence::Ephemeral).unwrap());
        controller
            .attach_reopened(0, &mut reopened.bound, Screen::Inbox)
            .unwrap();
        assert_eq!(
            read_count(&controller.display().page.unwrap().projection),
            expected
        );
        assert_eq!(controller.display().status, Status::Ready);
        assert_eq!(controller.mutate(old).err(), Some(Reject::StalePage));
    }
}

#[test]
fn unphased_backend_errors_cannot_be_labeled_definitely_rejected() {
    for mode in [Mode::ErrorBefore, Mode::ErrorAfter] {
        let (controller, mut backend) = setup();
        backend.mode = mode;
        let done = ready(
            controller.mutate(first_ack(&controller)).unwrap(),
            &mut backend,
        );
        assert_eq!(done.outcome, Outcome::Uncertain(Error::Storage));
        assert_eq!(controller.display().status, Status::NeedsReopen);
        assert_eq!(
            backend.applied.get(),
            usize::from(matches!(mode, Mode::ErrorAfter))
        );
    }
}

#[test]
fn foreign_success_after_write_is_uncertain_and_does_not_replace_cache() {
    let (controller, mut backend) = setup();
    backend.mode = Mode::Foreign;
    let before = controller.display().page.unwrap();
    let done = ready(
        controller.mutate(first_ack(&controller)).unwrap(),
        &mut backend,
    );
    assert_eq!(done.outcome, Outcome::InvalidProjection);
    assert_eq!(controller.display().status, Status::NeedsReopen);
    assert_eq!(controller.display().page.unwrap().lease, before.lease);
    assert!(!controller.display().fresh);
    assert_eq!(backend.applied.get(), 1);
}

#[test]
fn publication_label_requires_successful_trusted_backend_report() {
    let (controller, mut backend) = setup();
    backend.mode = Mode::PublishedModel;
    let done = ready(
        controller.mutate(first_ack(&controller)).unwrap(),
        &mut backend,
    );
    assert_eq!(done.outcome, Outcome::Published(Persistence::Native));
    assert_eq!(controller.display().status, Status::Ready);
}

#[test]
fn backend_receipt_cas_still_rejects_unseen_external_reprojection() {
    let (controller, mut backend) = setup();
    let cached = first_ack(&controller);
    // Host misuse/concurrent source refresh invalidates the engine's exact receipt.
    backend.project(Screen::Inbox).unwrap();
    let done = ready(controller.mutate(cached).unwrap(), &mut backend);
    assert_eq!(done.outcome, Outcome::Uncertain(Error::Stale));
    assert_eq!(backend.applied.get(), 0);
    assert_eq!(controller.display().status, Status::NeedsReopen);
}

#[test]
fn wrong_reader_mute_is_rejected_before_touching_the_supplied_backend() {
    let (controller, mut a) = setup();
    let mut b = Backend::new(2);
    let cached = controller.display().page.unwrap();
    let operation = controller
        .mutate(Mutation::MuteOwner {
            page: cached.lease,
            owner: cached.projection.reader.owner(),
            enabled: true,
        })
        .unwrap();
    let before = b.engine.image().encode();
    let done = ready(operation, &mut b);
    assert_eq!(
        done.outcome,
        Outcome::RejectedBeforeStart(Reject::ReaderMismatch)
    );
    assert_eq!(b.submissions.get(), 0);
    assert_eq!(b.engine.image().encode(), before);
    assert_eq!(controller.display().status, Status::Ready);
    ready(controller.project(Screen::Inbox).unwrap(), &mut a);
}

#[test]
fn foreign_controller_page_lease_cannot_acknowledge_a_sibling_namespace() {
    let (a, _) = setup();
    let mut backend = Backend::new(2);
    let b = Controller::new(vec![backend.engine.reader()]).unwrap();
    ready(b.project(Screen::Inbox).unwrap(), &mut backend);
    let foreign = first_ack(&a);
    assert_eq!(b.mutate(foreign).err(), Some(Reject::StalePage));
    assert_eq!(backend.submissions.get(), 0);
}

#[test]
fn independent_same_namespace_controller_cannot_reuse_an_old_callback_lease() {
    let (a, _) = setup();
    let (b, backend) = setup();
    assert_eq!(
        a.display().page.as_ref().unwrap().projection.reader,
        b.display().page.as_ref().unwrap().projection.reader
    );
    assert_eq!(b.mutate(first_ack(&a)).err(), Some(Reject::StalePage));
    assert_eq!(backend.submissions.get(), 0);
}

#[test]
fn switching_away_and_back_rejects_the_prior_view_callback() {
    let mut a = Backend::new(1);
    let b = Backend::new(2);
    let controller = Controller::new(vec![a.engine.reader(), b.engine.reader()]).unwrap();
    ready(controller.project(Screen::Inbox).unwrap(), &mut a);
    let old = first_ack(&controller);
    controller.select(1).unwrap();
    controller.select(0).unwrap();
    assert_eq!(
        controller.mutate(old.clone()).err(),
        Some(Reject::StalePage)
    );
    ready(controller.project(Screen::Inbox).unwrap(), &mut a);
    assert_eq!(controller.mutate(old).err(), Some(Reject::StalePage));
    assert_eq!(a.submissions.get(), 0);
}

#[test]
fn route_change_during_a_write_does_not_install_old_screen_completion() {
    let (controller, mut backend) = setup();
    let old = controller.display().page.unwrap().lease;
    backend.gate.set(false);
    let gate = backend.gate.clone();
    let mut future = Box::pin(
        controller
            .mutate(first_ack(&controller))
            .unwrap()
            .run(&mut backend.bound),
    );
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(
        controller
            .project(Screen::Feed(vhalla_discovery::FeedMode::Following))
            .err(),
        Some(Reject::Busy)
    );
    gate.set(true);
    let done = match poll(future.as_mut()) {
        Poll::Ready(done) => done,
        Poll::Pending => panic!("gate open"),
    };
    assert!(!done.current_view);
    assert_eq!(controller.display().page.unwrap().lease, old);
    assert!(!controller.display().fresh);
}

#[test]
fn real_u1_memory_image_cas_rejects_a_stale_concurrent_writer() {
    let image = fixture(1).image();
    let disk = Rc::new(RefCell::new(MemoryStorage::new(&image)));
    let mut a =
        Backend::from_engine(Engine::from_image(image.clone(), Persistence::Ephemeral).unwrap());
    let mut b = Backend::from_engine(Engine::from_image(image, Persistence::Ephemeral).unwrap());
    a.memory = Some(disk.clone());
    b.memory = Some(disk.clone());
    let ca = Controller::new(vec![a.engine.reader()]).unwrap();
    let cb = Controller::new(vec![b.engine.reader()]).unwrap();
    ready(ca.project(Screen::Inbox).unwrap(), &mut a);
    ready(cb.project(Screen::Inbox).unwrap(), &mut b);
    let stale = first_ack(&cb);
    ready(ca.mutate(first_ack(&ca)).unwrap(), &mut a);
    let saved = disk.borrow().bytes().to_vec();
    let done = ready(cb.mutate(stale).unwrap(), &mut b);
    assert_eq!(done.outcome, Outcome::Uncertain(Error::Stale));
    assert_eq!(cb.display().status, Status::NeedsReopen);
    assert_eq!(disk.borrow().bytes(), saved);
    assert_eq!(b.applied.get(), 0);
}

#[test]
fn reader_inventory_is_fixed_distinct_and_bounded() {
    assert_eq!(Controller::new(vec![]).err(), Some(Reject::Bounds));
    let scope = fixture(1).reader();
    assert_eq!(
        Controller::new(vec![scope, scope]).err(),
        Some(Reject::Bounds)
    );
    let readers = (0..=MAX_READERS)
        .map(|i| fixture(i as u8).reader())
        .collect();
    assert_eq!(Controller::new(readers).err(), Some(Reject::Bounds));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn arbitrary_reader_switches_cannot_install_a_stale_completion(switches in prop::collection::vec(0usize..2,0..24)) {
        let mut a=Backend::new(1);let mut b=Backend::new(2);
        let controller=Controller::new(vec![a.engine.reader(),b.engine.reader()]).unwrap();
        ready(controller.project(Screen::Inbox).unwrap(),&mut a);
        controller.select(1).unwrap();
        ready(controller.project(Screen::Inbox).unwrap(),&mut b);
        controller.select(0).unwrap();
        ready(controller.project(Screen::Inbox).unwrap(),&mut a);
        a.gate.set(false);let gate=a.gate.clone();
        let mut future=Box::pin(controller.mutate(first_ack(&controller)).unwrap().run(&mut a.bound));
        prop_assert!(poll(future.as_mut()).is_pending());
        for selected in &switches {controller.select(*selected).unwrap();}
        let before=controller.display();
        gate.set(true);
        let done=match poll(future.as_mut()){Poll::Ready(done)=>done,Poll::Pending=>panic!("gate open")};
        let after=controller.display();
        prop_assert_eq!(done.current_view,switches.is_empty());
        prop_assert_eq!(after.reader,switches.last().copied().unwrap_or(0));
        if !switches.is_empty() {
            prop_assert_eq!(after.page.unwrap().lease,before.page.unwrap().lease);
            prop_assert_eq!(after.outcome,before.outcome);
        } else {
            prop_assert_eq!(read_count(&after.page.unwrap().projection),1);
        }
    }

    #[test]
    fn exact_ack_subsets_follow_independent_membership_oracle(bits in prop::collection::vec(any::<bool>(),3)) {
        let (controller,mut backend)=setup();
        let cached=controller.display().page.unwrap();
        let ids:Vec<_>=cached.projection.notifications.iter().zip(&bits).filter_map(|(n,yes)|yes.then_some(n.id)).collect();
        let expected=bits.iter().filter(|yes|**yes).count();
        let operation=controller.mutate(Mutation::Acknowledge{page:cached.lease,ids});
        if expected==0 {
            prop_assert_eq!(operation.err(),Some(Reject::Bounds));
            prop_assert_eq!(backend.submissions.get(),0);
        } else {
            ready(operation.unwrap(),&mut backend);
            let page=controller.display().page.unwrap();
            prop_assert_eq!(read_count(&page.projection),expected);
            for (notice,yes) in page.projection.notifications.iter().zip(bits) {
                prop_assert_eq!(notice.read==ReadState::Read,yes);
            }
        }
    }
}
