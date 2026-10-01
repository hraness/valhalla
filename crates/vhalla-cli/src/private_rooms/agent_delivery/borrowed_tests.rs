use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    future::Future,
    net::TcpListener,
    task::{Context as TaskContext, Waker},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::Validity, CommittedOutbox, EncryptedControlPage, OutboxPage, Phase, ReceivedMessage,
    Status,
};
use vhalla_private_native::{
    client::AccountController,
    private_rooms::Limits as RoomLimits,
    relay::{
        tls::{self, Credential, Permissions, Service, ServiceLimits},
        FileStore, Limits as MailboxLimits,
    },
};

const NAME: &str = "borrowed-delivery.integration.invalid";
fn op(value: u8) -> OperationId {
    OperationId::from_bytes([value; 16]).unwrap()
}
fn ns() -> RelayNamespace {
    RelayNamespace::from_bytes([9; 32]).unwrap()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-borrowed-delivery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        custody::create_private_directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join().unwrap();
        }
    }
}

struct Fixture {
    // Join the owned test listener before removing its mailbox directory.
    _server: Server,
    owner_account: AccountController,
    member_account: AccountController,
    owner: RoomSession,
    member: RoomSession,
    owner_profile: PathBuf,
    member_profile: PathBuf,
    temp: Temp,
}
impl Fixture {
    async fn new() -> Self {
        let temp = Temp::new();
        let valid = Validity::new(now().unwrap() - 30, now().unwrap() + 3600).unwrap();
        let limits = RoomLimits {
            max_records: 128,
            max_record_bytes: 8 * 1024 * 1024,
        };
        let owner_account =
            AccountController::new(Identity::create_new(temp.0.join("owner-id")).unwrap());
        let member_account =
            AccountController::new(Identity::create_new(temp.0.join("member-id")).unwrap());
        let mut owner = owner_account
            .prepare_owner(valid)
            .unwrap()
            .commit(temp.0.join("owner-room"), limits)
            .await
            .unwrap();
        let membership = owner.membership().await.unwrap();
        let mut member = member_account
            .prepare_member(
                membership.status().context.scope,
                membership.anchor().clone(),
                membership.owner().clone(),
                valid,
            )
            .unwrap()
            .commit(temp.0.join("member-room"), limits)
            .await
            .unwrap();
        let request = member.key_package(op(1)).await.unwrap();
        let invitation = owner.invite(op(1), request.bytes(), valid).await.unwrap();
        member.join(invitation.bytes()).await.unwrap();

        let issuer_key = KeyPair::generate().unwrap();
        let mut issuer = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = issuer.self_signed(&issuer_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut leaf = CertificateParams::new(vec![NAME.to_owned()]).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&key, &issuer, &issuer_key).unwrap();
        let config = tls::server_config(vec![leaf.der().to_vec()], key.serialize_der()).unwrap();
        files::write(&temp.0.join("ca.der"), issuer.der()).unwrap();
        files::write(&temp.0.join("token"), hex(&[7; 32]).as_bytes()).unwrap();
        let mailbox = temp.0.join("mailbox");
        Service::initialize(
            FileStore::create_new(
                &mailbox,
                ns(),
                MailboxLimits {
                    max_items: 128,
                    max_bytes: 16 * 1024 * 1024,
                },
            )
            .unwrap(),
        )
        .unwrap();
        let service = Service::new(
            FileStore::open(&mailbox, ns()).unwrap(),
            config,
            vec![Credential {
                id: [8; 16],
                tokens: vec![RelayToken::from_bytes([7; 32]).unwrap()],
                namespace: ns(),
                permissions: Permissions {
                    put: true,
                    page: true,
                },
                storage: MailboxLimits {
                    max_items: 64,
                    max_bytes: 8 * 1024 * 1024,
                },
                max_inflight: 4,
                requests_per_window: 512,
                bytes_per_window: 32 * 1024 * 1024,
            }],
            ServiceLimits {
                request_timeout: Duration::from_secs(2),
                requests_per_window: 1024,
                ..ServiceLimits::default()
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let join = thread::spawn(move || service.serve_until(listener, None, worker_stop).unwrap());
        let server = Server {
            stop,
            join: Some(join),
        };

        let owner_profile = temp.0.join("owner-delivery.json");
        let member_profile = temp.0.join("member-delivery.json");
        for (name, profile, context) in [
            ("owner", &owner_profile, owner.status().unwrap().context),
            ("member", &member_profile, member.status().unwrap().context),
        ] {
            files::write(profile, &serde_json::to_vec(&json!({
                "version":2,
                "context":{"room":hex(context.scope.room.as_bytes()),"anchor":hex(context.scope.anchor.as_bytes()),"account":hex(context.account.as_bytes()),"device":hex(context.device.as_bytes())},
                "namespace":hex(ns().as_bytes()),"addr":address.to_string(),"tls_name":NAME,
                "ca":temp.0.join("ca.der"),"token":temp.0.join("token"),"state":temp.0.join(format!("{name}-delivery")),
                "max_jobs":64,"max_bytes":8388608,"max_attempts":8,"initial_backoff_secs":1,"max_backoff_secs":30,"emit_acceptance":true,"mailbox_polling":"interactive"
            })).unwrap()).unwrap();
            initialize(profile, context).unwrap();
        }
        Self {
            _server: server,
            owner_account,
            member_account,
            owner,
            member,
            owner_profile,
            member_profile,
            temp,
        }
    }

    fn owner_driver(&self) -> Driver {
        Driver::open_polling(&self.owner_profile, self.owner.status().unwrap().context).unwrap()
    }
    fn member_driver(&self) -> Driver {
        Driver::open_polling(&self.member_profile, self.member.status().unwrap().context).unwrap()
    }
}

async fn step(driver: &mut Driver, room: &mut RoomSession) {
    // Drive a deterministic cadence event rather than sleeping through idle
    // backoff. Production cadence is separately covered by polling::tests.
    driver.polling.success(Instant::now(), true);
    driver.tick_room(room, Instant::now() + TICK).await.unwrap();
    assert!(!driver.watch_enabled);
    assert!(driver.watch.is_none());
}

#[cfg(feature = "headless")]
#[test]
fn bound_open_refuses_named_tls_before_dns_and_preserves_initialized_profiles() {
    runtime().block_on(async {
        let fixture = Fixture::new().await;
        let before = fixture.owner.status().unwrap();
        let original = std::fs::read(&fixture.owner_profile).unwrap();
        for version in [2, 4] {
            let mut config: Config = serde_json::from_slice(&original).unwrap();
            config.state = config.state.canonicalize().unwrap();
            if version == 4 {
                config.version = 4;
                config.transport = Some(SelectedTransport::Tls {
                    addr: config.addr.take().unwrap(),
                    tls_name: config.tls_name.take().unwrap(),
                    ca: config.ca.take().unwrap(),
                });
            }
            let numeric = serde_json::to_vec(&config).unwrap();
            let numeric_hash = Sha256::digest(&numeric).into();
            std::fs::write(&fixture.owner_profile, &numeric).unwrap();
            let driver =
                Driver::open_polling_bound(&fixture.owner_profile, before.context, numeric_hash)
                    .unwrap();
            let checkpoint = driver.queue.driver_checkpoint().unwrap();
            drop(driver);

            let named = Endpoint::parse("bound-profile-must-not-resolve.invalid:443").unwrap();
            match &mut config.transport {
                Some(SelectedTransport::Tls { addr, .. }) => *addr = named,
                None => config.addr = Some(named),
                _ => unreachable!(),
            }
            let selected = serde_json::to_vec(&config).unwrap();
            let selected_hash = Sha256::digest(&selected).into();
            std::fs::write(&fixture.owner_profile, &selected).unwrap();
            assert_eq!(
                Driver::open_polling_bound(&fixture.owner_profile, before.context, numeric_hash)
                    .err(),
                Some(REFUSED.into()),
                "the exact file hash must still be checked first"
            );
            assert_eq!(
                Driver::open_polling_bound(&fixture.owner_profile, before.context, selected_hash)
                    .err(),
                Some(INIT_NUMERIC_TLS.into()),
                "named version {version} must fail local validation, before DNS resolution"
            );
            assert_eq!(std::fs::read(&fixture.owner_profile).unwrap(), selected);
            std::fs::write(&fixture.owner_profile, &numeric).unwrap();
            let reopened =
                Driver::open_polling_bound(&fixture.owner_profile, before.context, numeric_hash)
                    .unwrap();
            assert_eq!(reopened.queue.driver_checkpoint().unwrap(), checkpoint);
        }
        assert_eq!(fixture.owner.status().unwrap(), before);
    });
}

#[test]
fn borrowed_driver_distinguishes_relay_retention_from_member_receipts_and_reopens() {
    runtime().block_on(async {
        let mut fixture = Fixture::new().await;
        let mut owner_driver = fixture.owner_driver();
        let mut member_driver = fixture.member_driver();
        let binding = fixture.owner.status().unwrap();
        let draft = fixture
            .owner
            .prepare_message(b"borrowed controller delivery")
            .unwrap();
        let sent = fixture.owner.send(op(2), &draft).await.unwrap();
        for _ in 0..8 {
            step(&mut owner_driver, &mut fixture.owner).await;
            if owner_driver
                .outbox_jobs(0, PAGE)
                .unwrap()
                .iter()
                .any(|job| job.sequence == sent.sequence() && job.state == JobState::Retained)
            {
                break;
            }
        }
        let relay_job = owner_driver
            .outbox_jobs(0, PAGE)
            .unwrap()
            .into_iter()
            .find(|job| job.sequence == sent.sequence())
            .unwrap();
        assert_eq!(relay_job.state, JobState::Retained);
        assert!(fixture
            .owner
            .acceptances(sent.sequence())
            .await
            .unwrap()
            .is_empty());
        {
            let mut host = RoomHost::new(&mut fixture.owner);
            host.begin(binding.context).unwrap();
            let mut forged = relay_job.clone();
            forged.id[0] ^= 1;
            assert!(host.update_delivery(ns(), &forged).await.is_err());
            assert!(host
                .update_delivery(RelayNamespace::from_bytes([3; 32]).unwrap(), &relay_job)
                .await
                .is_err());
            host.update_delivery(ns(), &relay_job).await.unwrap();
        }
        for _ in 0..8 {
            step(&mut member_driver, &mut fixture.member).await;
            step(&mut owner_driver, &mut fixture.owner).await;
            if !fixture
                .owner
                .acceptances(sent.sequence())
                .await
                .unwrap()
                .is_empty()
            {
                break;
            }
        }
        let proofs = fixture.owner.acceptances(sent.sequence()).await.unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(
            proofs[0].recipient(),
            fixture.member.status().unwrap().context.device
        );
        assert_eq!(
            fixture
                .member
                .retained_received(sent.bytes())
                .await
                .unwrap()
                .unwrap()
                .body(),
            b"borrowed controller delivery"
        );
        let owner_status = fixture.owner.status().unwrap();
        let member_status = fixture.member.status().unwrap();
        drop(owner_driver);
        drop(member_driver);
        fixture.owner.lock();
        fixture.member.lock();
        fixture.owner = fixture
            .owner_account
            .open_room(fixture.temp.0.join("owner-room"), owner_status.context)
            .await
            .unwrap();
        fixture.member = fixture
            .member_account
            .open_room(fixture.temp.0.join("member-room"), member_status.context)
            .await
            .unwrap();
        let mut owner_driver = fixture.owner_driver();
        let mut member_driver = fixture.member_driver();
        step(&mut owner_driver, &mut fixture.owner).await;
        step(&mut member_driver, &mut fixture.member).await;
        assert_eq!(fixture.owner.status().unwrap(), owner_status);
        assert_eq!(fixture.member.status().unwrap(), member_status);
        assert_eq!(
            fixture.owner.acceptances(sent.sequence()).await.unwrap(),
            proofs
        );
        assert_eq!(
            fixture
                .owner
                .retained_send(
                    op(2),
                    binding.epoch,
                    binding.roster,
                    b"borrowed controller delivery"
                )
                .await
                .unwrap()
                .unwrap()
                .bytes(),
            sent.bytes()
        );
    });
}

#[test]
fn borrowed_driver_refuses_wrong_room_and_respects_membership_changes() {
    runtime().block_on(async {
        let mut fixture = Fixture::new().await;
        let mut owner_driver = fixture.owner_driver();
        let member_before = fixture.member.status().unwrap();
        assert!(owner_driver
            .tick_room(&mut fixture.member, Instant::now() + TICK)
            .await
            .is_err());
        assert_eq!(fixture.member.status().unwrap(), member_before);
        assert!(owner_driver.outbox_jobs(0, PAGE).unwrap().is_empty());
        let mut member_driver = fixture.member_driver();
        let removed = fixture.member.status().unwrap().context.device;
        fixture.owner.remove(op(2), removed).await.unwrap();
        for _ in 0..8 {
            step(&mut owner_driver, &mut fixture.owner).await;
            step(&mut member_driver, &mut fixture.member).await;
            if fixture.member.status().unwrap().phase == Phase::Removed {
                break;
            }
        }
        assert_eq!(fixture.member.status().unwrap().phase, Phase::Removed);
        let inbox_before = fixture.member.status().unwrap().inbox_head;
        let draft = fixture.owner.prepare_message(b"after removal").unwrap();
        let sent = fixture.owner.send(op(3), &draft).await.unwrap();
        for _ in 0..3 {
            step(&mut owner_driver, &mut fixture.owner).await;
            step(&mut member_driver, &mut fixture.member).await;
        }
        assert_eq!(fixture.member.status().unwrap().inbox_head, inbox_before);
        assert!(fixture
            .member
            .retained_received(sent.bytes())
            .await
            .unwrap()
            .is_none());
        assert!(fixture.member.prepare_message(b"cannot revive").is_err());
        assert!(fixture
            .owner
            .acceptances(sent.sequence())
            .await
            .unwrap()
            .is_empty());
    });
}

/// Suspend a harmless custody read at the first catch-up stage. No transport
/// or durable work is detached when the caller cancels the borrowed future.
struct PendingHost<'a>(RoomHost<'a>);
impl Host for PendingHost<'_> {
    fn begin(&mut self, c: Context) -> Result<Option<Instant>, String> {
        self.0.begin(c)
    }
    fn check_marker(&mut self) -> Result<(), String> {
        self.0.check_marker()
    }
    fn check_release(&mut self) -> Result<(), String> {
        self.0.check_release()
    }
    fn status(&mut self) -> Result<Status, ClientError> {
        self.0.status()
    }
    async fn outbox(&mut self, after: u64, limit: usize) -> Result<OutboxPage, ClientError> {
        self.0.outbox(after, limit).await
    }
    async fn encrypted_controls(
        &mut self,
        _after: Option<u64>,
        _limit: usize,
    ) -> Result<EncryptedControlPage, ClientError> {
        std::future::pending().await
    }
    async fn receive(&mut self, raw: &[u8]) -> Result<ReceivedMessage, ClientError> {
        self.0.receive(raw).await
    }
    async fn apply_control(&mut self, raw: &[u8]) -> Result<Status, ClientError> {
        self.0.apply_control(raw).await
    }
    async fn issue_acceptance(
        &mut self,
        op: OperationId,
        raw: &[u8],
    ) -> Result<CommittedOutbox, ClientError> {
        self.0.issue_acceptance(op, raw).await
    }
    async fn retained_received(
        &mut self,
        raw: &[u8],
    ) -> Result<Option<ReceivedMessage>, ClientError> {
        self.0.retained_received(raw).await
    }
    async fn retained_control(&mut self, raw: &[u8]) -> Result<bool, ClientError> {
        self.0.retained_control(raw).await
    }
    async fn original(&mut self, hash: &[u8; 32]) -> Result<Option<CommittedOutbox>, ClientError> {
        self.0.original(hash).await
    }
    async fn update_delivery(
        &mut self,
        ns: RelayNamespace,
        status: &JobStatus,
    ) -> Result<(), String> {
        self.0.update_delivery(ns, status).await
    }
    async fn record_member_acceptance(
        &mut self,
        sequence: u64,
        proof: MemberAcceptance,
    ) -> Result<(), String> {
        self.0.record_member_acceptance(sequence, proof).await
    }
}

#[test]
fn cancelled_read_and_expired_tick_release_only_driver_custody_without_a_watch() {
    runtime().block_on(async {
        let mut fixture = Fixture::new().await;
        let before = fixture.owner.status().unwrap();
        let mut driver = fixture.owner_driver();
        driver
            .tick_room(&mut fixture.owner, Instant::now())
            .await
            .unwrap();
        assert!(driver.watch.is_none());
        assert!(driver.outbox_jobs(0, PAGE).unwrap().is_empty());
        {
            let mut host = PendingHost(RoomHost::new(&mut fixture.owner));
            let mut pending = Box::pin(driver.tick_host(&mut host, None));
            let mut cx = TaskContext::from_waker(Waker::noop());
            assert!(pending.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(fixture.owner.status().unwrap(), before);
        assert!(driver.watch.is_none());
        assert!(driver.outbox_jobs(0, PAGE).unwrap().is_empty());
        drop(driver);
        // The previous driver has no watch/network clone retaining its queue.
        let mut reopened = fixture.owner_driver();
        let draft = fixture
            .owner
            .prepare_message(b"custody remains usable")
            .unwrap();
        fixture.owner.send(op(2), &draft).await.unwrap();
        step(&mut reopened, &mut fixture.owner).await;
        drop(reopened);
        let mut legacy = Driver::open(&fixture.owner_profile, before.context).unwrap();
        assert!(legacy
            .tick_room(&mut fixture.owner, Instant::now() + TICK)
            .await
            .is_err());
        assert!(legacy.watch.is_none());
    });
}

#[test]
fn native_clock_failures_defer_while_uncertainty_and_control_policy_stop() {
    for error in [
        ClientError::Clock,
        ClientError::Kernel(KernelError::ClockRegressed),
        ClientError::Kernel(KernelError::Time),
    ] {
        assert!(matches!(
            host_outcome(error, application_outcome),
            Outcome::Retry
        ));
        assert!(matches!(
            host_outcome(error, control_outcome),
            Outcome::Retry
        ));
    }
    assert!(matches!(
        host_outcome(
            ClientError::Kernel(KernelError::NeedsReopen),
            application_outcome
        ),
        Outcome::Fatal
    ));
    assert!(matches!(
        host_outcome(ClientError::Kernel(KernelError::Policy), control_outcome),
        Outcome::Fatal
    ));
}

#[test]
fn borrowed_host_rejects_peer_bytes_and_selected_cursors_without_fencing_native_custody() {
    runtime().block_on(async {
        let mut fixture = Fixture::new().await;
        let owner_status = fixture.owner.status().unwrap();
        {
            let mut host = RoomHost::new(&mut fixture.owner);
            host.begin(owner_status.context).unwrap();
            assert!(host.receive(b"not an MLS message").await.is_err());
            assert!(host
                .apply_control(b"not an encrypted control")
                .await
                .is_err());
            assert!(host.retained_received(b"").await.is_err());
            assert!(host
                .retained_control(b"not a retained control")
                .await
                .is_err());
            assert!(host.original(&[0; 32]).await.is_err());
            assert!(host.outbox(owner_status.outbox_head + 1, 1).await.is_err());
            assert!(host
                .encrypted_controls(Some(owner_status.control_sequence + 1), 1)
                .await
                .is_err());
            assert!(!host.native_unavailable());
            host.check_release().unwrap();
        }
        assert_eq!(fixture.owner.status().unwrap(), owner_status);

        let member_status = fixture.member.status().unwrap();
        let removal = fixture
            .owner
            .remove(op(2), member_status.context.device)
            .await
            .unwrap();
        let mut damaged = removal.bytes().to_vec();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(vhalla_private_kernel::control_sequence_hint(&damaged).is_ok());
        {
            let mut host = RoomHost::new(&mut fixture.member);
            host.begin(member_status.context).unwrap();
            assert!(host.encrypted_controls(Some(0), 1).await.is_err());
            assert!(host.apply_control(&damaged).await.is_err());
            assert!(!host.retained_control(&damaged).await.unwrap());
            assert!(!host.native_unavailable());
            host.check_release().unwrap();
        }
        assert_eq!(fixture.member.status().unwrap(), member_status);
        assert!(fixture
            .member
            .prepare_message(b"native custody remains usable")
            .is_ok());
    });
}
