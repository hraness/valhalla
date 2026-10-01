//! Selection history, profile custody and retained delivery evidence.

use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    io::Write,
    net::TcpListener,
    os::unix::fs::{symlink, PermissionsExt},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use vhalla_identity::Identity;
use vhalla_private_kernel::{protocol::Validity, OperationId};
use vhalla_private_native::{
    client::AccountController,
    private_rooms::Limits as RoomLimits,
    relay::{
        iroh::{endpoint_id_from_secret, IrohEndpoint, IrohListener, IrohRelay, DEFAULT_RELAY_URL},
        net::RelayToken,
        tls::{self, Credential, Permissions, Service, ServiceLimits},
        FileStore, Limits as MailboxLimits, RelayNamespace,
    },
};

fn id(value: u8) -> Id {
    Hex([value; 16])
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn write(path: &Path, bytes: &[u8]) {
    let mut file = custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn hash(path: &Path) -> Hash {
    Hex(Sha256::digest(std::fs::read(path).unwrap()).into())
}
fn validity() -> Validity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Validity::new(now - 1, now + 3600).unwrap()
}
fn room_limits() -> RoomLimits {
    RoomLimits {
        max_records: 256,
        max_record_bytes: 16 * 1024 * 1024,
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
struct Fixture {
    _server: Server,
    room: RoomSession,
    account: AccountController,
    address: String,
    base: PathBuf,
    _temp: TempDir,
}
impl Fixture {
    async fn new(accept: bool) -> Self {
        let temp = TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = temp.path().canonicalize().unwrap();
        let account = AccountController::new(Identity::create_new(base.join("identity")).unwrap());
        let room = account
            .prepare_owner(validity())
            .unwrap()
            .commit(base.join("room"), room_limits())
            .await
            .unwrap();
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
        let mut leaf = CertificateParams::new(vec!["selection.invalid".to_owned()]).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&key, &issuer, &issuer_key).unwrap();
        let config = tls::server_config(vec![leaf.der().to_vec()], key.serialize_der()).unwrap();
        write(&base.join("ca.der"), issuer.der());
        write(&base.join("token"), format!("{}", Hex([7; 32])).as_bytes());
        let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
        let mailbox = base.join("mailbox");
        let mailbox_limits = MailboxLimits {
            max_items: 256,
            max_bytes: 16 * 1024 * 1024,
        };
        Service::initialize(FileStore::create_new(&mailbox, namespace, mailbox_limits).unwrap())
            .unwrap();
        let service = Service::new(
            FileStore::open(&mailbox, namespace).unwrap(),
            config,
            vec![Credential {
                id: [8; 16],
                tokens: vec![RelayToken::from_bytes([7; 32]).unwrap()],
                namespace,
                permissions: Permissions {
                    put: accept,
                    page: true,
                },
                storage: MailboxLimits {
                    max_items: 128,
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
        let address = listener.local_addr().unwrap().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker =
            thread::spawn(move || service.serve_until(listener, None, worker_stop).unwrap());
        Self {
            _server: Server {
                stop,
                worker: Some(worker),
            },
            room,
            account,
            address,
            base,
            _temp: temp,
        }
    }
    fn context(&self) -> Context {
        self.room.status().unwrap().context
    }
    fn account_hash(&self) -> Hash {
        Hex(*self.context().account.as_bytes())
    }
    fn manager(&self) -> Manager {
        Manager::initialize(&self.base.join("manager"), self.account_hash()).unwrap()
    }
    fn reopen(&self) -> Manager {
        Manager::open(&self.base.join("manager"), self.account_hash()).unwrap()
    }
    fn profile(&self, label: &str, context: Context, initialize: bool) -> Profile {
        let path = self.base.join(format!("{label}.json"));
        let value = json!({"version":2,"context":context_json(context),"namespace":Hex([9;32]),"addr":self.address,"tls_name":"selection.invalid","ca":self.base.join("ca.der"),"token":self.base.join("token"),"state":self.base.join(format!("{label}-queue")),"max_jobs":64,"max_bytes":8388608,"max_attempts":1,"initial_backoff_secs":1,"max_backoff_secs":30,"emit_acceptance":false});
        write(&path, &serde_json::to_vec(&value).unwrap());
        if initialize {
            crate::private_rooms::agent_delivery::initialize(&path, context).unwrap();
        }
        Profile {
            hash: hash(&path),
            path,
        }
    }
    fn iroh_profile(
        &self,
        label: &str,
        endpoint: &IrohEndpoint,
        relay_only: Option<bool>,
        initialize: bool,
    ) -> Profile {
        let mut profile = self.profile(label, self.context(), false);
        let mut value: Value =
            serde_json::from_slice(&std::fs::read(&profile.path).unwrap()).unwrap();
        value["version"] = json!(4);
        for field in ["addr", "tls_name", "ca"] {
            value.as_object_mut().unwrap().remove(field);
        }
        value["transport"] = json!({"kind":"iroh","endpoint":endpoint});
        if let Some(relay_only) = relay_only {
            value["transport"]["relay_only"] = json!(relay_only);
        }
        std::fs::write(&profile.path, serde_json::to_vec(&value).unwrap()).unwrap();
        if initialize {
            crate::private_rooms::agent_delivery::initialize(&profile.path, self.context())
                .unwrap();
        }
        profile.hash = hash(&profile.path);
        profile
    }
}

fn iroh_server(fixture: &Fixture) -> (Server, IrohEndpoint) {
    let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
    let mailbox = fixture.base.join("iroh-mailbox");
    let limits = MailboxLimits {
        max_items: 128,
        max_bytes: 8 * 1024 * 1024,
    };
    Service::initialize(
        FileStore::create_new(
            &mailbox,
            namespace,
            MailboxLimits {
                max_items: 256,
                max_bytes: 16 * 1024 * 1024,
            },
        )
        .unwrap(),
    )
    .unwrap();
    let service = Service::new_iroh(
        FileStore::open(&mailbox, namespace).unwrap(),
        vec![Credential {
            id: [8; 16],
            tokens: vec![RelayToken::from_bytes([7; 32]).unwrap()],
            namespace,
            permissions: Permissions {
                put: true,
                page: true,
            },
            storage: limits,
            max_inflight: 4,
            requests_per_window: 64,
            bytes_per_window: 32 * 1024 * 1024,
        }],
        ServiceLimits::default(),
    )
    .unwrap();
    let listener = IrohListener::bind([55; 32], "127.0.0.1:0".parse().unwrap(), None).unwrap();
    listener.set_namespace(namespace);
    let endpoint = listener.endpoint();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let worker = thread::spawn(move || service.serve_iroh_until(listener, None, stopping).unwrap());
    let server = Server {
        stop,
        worker: Some(worker),
    };
    let readiness = IrohRelay::new(
        endpoint.clone(),
        RelayToken::from_bytes([7; 32]).unwrap(),
        namespace,
    )
    .unwrap();
    readiness
        .page_until(0, 1, Instant::now() + Duration::from_secs(5))
        .unwrap();
    (server, endpoint)
}

#[test]
fn iroh_profile_defaults_preserve_compatibility_and_relay_only_is_explicit() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let mut endpoint = IrohEndpoint {
            endpoint_id: endpoint_id_from_secret(&[55; 32]),
            relay_url: None,
            addresses: vec!["127.0.0.1:9".parse().unwrap()],
        };
        let mut manager = fixture.manager();
        for (operation, label, mode) in [(1, "default", None), (2, "automatic", Some(false))] {
            let profile = fixture.iroh_profile(label, &endpoint, mode, true);
            let report = attach(&mut manager, operation, 1, context, &profile);
            assert_eq!(
                report["current"]["transport"],
                json!({"kind":"iroh","relay_only":false})
            );
            assert!(report["current"]["last_transport_observation"].is_null());
        }
        let missing = fixture.iroh_profile("missing-relay", &endpoint, Some(true), false);
        assert!(crate::private_rooms::agent_delivery::initialize(&missing.path, context).is_err());
        assert!(!fixture.base.join("missing-relay-queue").exists());
        endpoint.relay_url = Some("http://relay.invalid".into());
        let insecure = fixture.iroh_profile("insecure-relay", &endpoint, Some(true), false);
        assert!(crate::private_rooms::agent_delivery::initialize(&insecure.path, context).is_err());
        assert!(!fixture.base.join("insecure-relay-queue").exists());
        endpoint.relay_url = Some(DEFAULT_RELAY_URL.into());
        let forced = fixture.iroh_profile("forced", &endpoint, Some(true), true);
        let report = attach(&mut manager, 3, 1, context, &forced);
        assert_eq!(
            report["current"]["transport"],
            json!({"kind":"iroh","relay_only":true})
        );
        assert!(report["current"]["last_transport_observation"].is_null());
        // No tick or network exchange occurs in this configuration test.
        let legacy = fixture.profile("legacy", context, true);
        let report = attach(&mut manager, 4, 1, context, &legacy);
        assert_eq!(report["current"]["transport"], json!({"kind":"tls"}));
        assert!(report["current"]["last_transport_observation"].is_null());
    });
}

#[test]
fn private_route_status_is_diagnostic_and_resets_only_for_fresh_selections_or_reopen() {
    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let (_server, endpoint) = iroh_server(&fixture);
        let context = fixture.context();
        let first = fixture.iroh_profile("first-iroh", &endpoint, None, true);
        let second = fixture.iroh_profile("second-iroh", &endpoint, Some(false), true);
        let draft = fixture
            .room
            .prepare_message(b"observation is not a recipient receipt")
            .unwrap();
        fixture
            .room
            .send(OperationId::from_bytes([31; 16]).unwrap(), &draft)
            .await
            .unwrap();
        let mut manager = fixture.manager();
        assert!(attach(&mut manager, 1, 1, context, &first)["current"]
            ["last_transport_observation"]
            .is_null());
        manager.tick_room(id(1), &mut fixture.room).await.unwrap();
        let report = manager.status(id(1), 0, 16).unwrap();
        let observation = report["last_transport_observation"].clone();
        assert_eq!(
            report["transport"],
            json!({"kind":"iroh","relay_only":false})
        );
        assert!(matches!(
            observation["operation"].as_str(),
            Some("put" | "page")
        ));
        for name in ["before", "after"] {
            assert_eq!(
                observation[name],
                json!({"selected":"direct","nonempty":true,"all_relay":false})
            );
        }
        assert!(report["transport_observation_scope"]
            .as_str()
            .unwrap()
            .contains("last successful"));
        assert_eq!(
            attach(&mut manager, 1, 1, context, &first)["current"]["last_transport_observation"],
            observation
        );
        let selected = attach(&mut manager, 2, 1, context, &first);
        assert!(selected["current"]["last_transport_observation"].is_null());
        assert_eq!(selected["current"]["application"], report["application"]);
        manager.tick_room(id(1), &mut fixture.room).await.unwrap();
        let latest = manager.status(id(1), 0, 16).unwrap()["last_transport_observation"].clone();
        assert!(!latest.is_null());
        manager.close_room(id(1));
        let closed = manager.status(id(1), 0, 16).unwrap();
        assert_eq!(closed["state"], "refused");
        assert_eq!(closed["last_transport_observation"], latest);
        drop(manager);
        let mut manager = fixture.reopen();
        let reopened = manager.status(id(1), 0, 16).unwrap();
        assert_eq!(reopened["state"], "active");
        assert!(reopened["last_transport_observation"].is_null());
        manager.tick_room(id(1), &mut fixture.room).await.unwrap();
        assert!(!manager.status(id(1), 0, 16).unwrap()["last_transport_observation"].is_null());
        assert!(attach(&mut manager, 3, 1, context, &second)["current"]
            ["last_transport_observation"]
            .is_null());
    });
}

fn attach(
    manager: &mut Manager,
    operation: u8,
    slot: u8,
    context: Context,
    profile: &Profile,
) -> Value {
    manager
        .attach(
            id(operation),
            id(slot),
            context,
            profile.path.clone(),
            profile.hash,
        )
        .unwrap()
}

#[test]
fn exact_selection_retry_does_not_reactivate_an_old_selection_or_renew_a_driver() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let first = fixture.profile("first", context, true);
        let second = fixture.profile("second", context, true);
        let mut manager = fixture.manager();
        assert_eq!(
            attach(&mut manager, 1, 1, context, &first)["current"]["state"],
            "active"
        );
        let prior = manager.store.accounting().unwrap();
        assert_eq!(
            attach(&mut manager, 1, 1, context, &first)["exact_retry"],
            true
        );
        assert_eq!(manager.store.accounting().unwrap(), prior);
        assert_eq!(
            manager.attach(id(1), id(1), context, second.path.clone(), second.hash),
            Err(Error::Conflict)
        );
        attach(&mut manager, 2, 1, context, &second);
        let retry = attach(&mut manager, 1, 1, context, &first);
        assert_eq!(retry["current"]["profile"], json!(second.path));
        assert_eq!(retry["current"]["selection_operation"], json!(id(2)));
        assert_eq!(
            manager.detach(id(3), id(1), context).unwrap()["current"]["state"],
            "detached"
        );
        assert_eq!(
            attach(&mut manager, 2, 1, context, &second)["current"]["state"],
            "detached"
        );
        assert!(manager.active_rooms().is_empty());
        drop(manager);
        let mut manager = fixture.reopen();
        assert_eq!(
            attach(&mut manager, 1, 1, context, &first)["current"]["state"],
            "detached"
        );
        assert_eq!(manager.state.operations, 3);
        assert!(first.path.exists());
        assert!(second.path.exists());
    });
}

#[test]
fn missing_uninitialized_and_wrong_digest_profiles_never_create_or_replace_a_queue() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let ready = fixture.profile("ready", context, true);
        let absent = fixture.profile("uninitialized", context, false);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &ready);
        let before = manager.store.accounting().unwrap();
        assert_eq!(
            manager.attach(id(2), id(1), context, absent.path.clone(), absent.hash),
            Err(Error::Refused)
        );
        assert!(!fixture.base.join("uninitialized-queue").exists());
        assert_eq!(
            manager.attach(id(2), id(1), context, ready.path.clone(), Hex([42; 32])),
            Err(Error::StaleProfile)
        );
        assert_eq!(
            manager.attach(
                id(2),
                id(1),
                context,
                fixture.base.join("missing.json"),
                ready.hash
            ),
            Err(Error::StaleProfile)
        );
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["profile"],
            json!(ready.path)
        );
        assert_eq!(manager.store.accounting().unwrap(), before);
        drop(manager);
        let manager = fixture.reopen();
        assert_eq!(manager.active_rooms(), vec![id(1)]);
    });
}

#[test]
fn restart_reopens_only_exact_selected_bytes_and_isolates_a_failed_room() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let second_room = fixture
            .account
            .prepare_owner(validity())
            .unwrap()
            .commit(fixture.base.join("second-room"), room_limits())
            .await
            .unwrap();
        let second_context = second_room.status().unwrap().context;
        let first = fixture.profile("first", fixture.context(), true);
        let second = fixture.profile("second", second_context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, fixture.context(), &first);
        attach(&mut manager, 2, 2, second_context, &second);
        drop(manager);
        let mut raw = std::fs::read(&first.path).unwrap();
        raw.push(b' ');
        std::fs::write(&first.path, &raw).unwrap();
        let mut manager = fixture.reopen();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["state"],
            "stale_profile"
        );
        assert_eq!(manager.status(id(2), 0, 16).unwrap()["state"], "active");
        assert_eq!(
            attach(&mut manager, 1, 1, fixture.context(), &first)["current"]["state"],
            "stale_profile"
        );
        std::fs::write(&first.path, &raw[..raw.len() - 1]).unwrap();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["state"],
            "stale_profile"
        );
        assert_eq!(
            attach(&mut manager, 3, 1, fixture.context(), &first)["current"]["state"],
            "active"
        );
        drop(manager);
        drop(second_room);
    });
}

#[test]
fn live_profile_replacement_is_refused_even_with_identical_bytes() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let profile = fixture.profile("profile", fixture.context(), true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, fixture.context(), &profile);
        let original = std::fs::read(&profile.path).unwrap();
        let replacement = fixture.base.join("replacement");
        write(&replacement, &original);
        std::fs::rename(&profile.path, fixture.base.join("prior-profile")).unwrap();
        std::fs::rename(&replacement, &profile.path).unwrap();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["state"],
            "stale_profile"
        );
        assert_eq!(
            attach(&mut manager, 1, 1, fixture.context(), &profile)["current"]["state"],
            "stale_profile"
        );
        assert_eq!(
            attach(&mut manager, 2, 1, fixture.context(), &profile)["current"]["state"],
            "active"
        );
    });
}

#[test]
fn profile_symlinks_and_state_symlink_redirection_are_not_daemon_authority() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let profile = fixture.profile("profile", fixture.context(), true);
        let mut manager = fixture.manager();
        let alias = fixture.base.join("alias.json");
        symlink(&profile.path, &alias).unwrap();
        assert_eq!(
            manager.attach(id(1), id(1), fixture.context(), alias, profile.hash),
            Err(Error::StaleProfile)
        );
        let state = fixture.base.join("profile-queue");
        let alias = fixture.base.join("queue-alias");
        symlink(&state, &alias).unwrap();
        let mut config: Value =
            serde_json::from_slice(&std::fs::read(&profile.path).unwrap()).unwrap();
        config["state"] = json!(alias);
        std::fs::write(&profile.path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(
            manager.attach(
                id(1),
                id(1),
                fixture.context(),
                profile.path.clone(),
                hash(&profile.path)
            ),
            Err(Error::Refused)
        );
        assert_eq!(manager.state.operations, 0);
    });
}

#[test]
fn bound_config_check_precedes_transport_loading_and_live_state_directory_is_pinned() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let profile = fixture.profile("profile", fixture.context(), true);
        assert!(Driver::open_polling_bound(&profile.path, fixture.context(), [4; 32]).is_err());
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, fixture.context(), &profile);
        let state = fixture.base.join("profile-queue");
        std::fs::rename(&state, fixture.base.join("preserved-queue")).unwrap();
        custody::create_private_directory(&state).unwrap();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["state"],
            "stale_profile"
        );
        assert!(fixture.base.join("preserved-queue/jobs").exists());
        assert!(!state.join("jobs").exists());
    });
}

#[test]
fn delivery_retention_remains_distinct_and_replacement_preserves_the_old_queue() {
    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let context = fixture.context();
        let first = fixture.profile("first", context, true);
        let second = fixture.profile("second", context, true);
        let draft = fixture
            .room
            .prepare_message(b"private body must never appear in the selection ledger")
            .unwrap();
        let sent = fixture
            .room
            .send(OperationId::from_bytes([3; 16]).unwrap(), &draft)
            .await
            .unwrap();
        let before = fixture.room.status().unwrap().outbox_head;
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &first);
        manager.tick_room(id(1), &mut fixture.room).await.unwrap();
        let report = manager.status(id(1), 0, 16).unwrap();
        let jobs = report["application"]["records"].as_array().unwrap();
        let job = jobs
            .iter()
            .find(|job| job["sequence"] == sent.sequence())
            .unwrap();
        assert_eq!(job["state"], "retained");
        assert!(report["recipient_acceptance"]
            .as_str()
            .unwrap()
            .contains("not inferred"));
        assert_eq!(fixture.room.status().unwrap().outbox_head, before);
        assert!(!report.to_string().contains("private body"));
        let original = report["application"].clone();
        drop(manager);
        let mut manager = fixture.reopen();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["application"],
            original
        );
        attach(&mut manager, 2, 1, context, &second);
        let prior = Driver::open_polling_bound(&first.path, context, first.hash.0).unwrap();
        assert_eq!(
            prior
                .outbox_jobs(0, 16)
                .unwrap()
                .iter()
                .find(|job| job.sequence == sent.sequence())
                .unwrap()
                .state,
            JobState::Retained
        );
        drop(prior);
        manager.detach(id(4), id(1), context).unwrap();
        drop(manager);
        assert!(fixture.reopen().active_rooms().is_empty());
    });
}

#[test]
fn charged_refusal_and_stopped_attempts_survive_restart_and_exact_attach_retry() {
    runtime().block_on(async {
        let mut fixture = Fixture::new(false).await;
        let context = fixture.context();
        let profile = fixture.profile("profile", context, true);
        let draft = fixture
            .room
            .prepare_message(b"retained despite denied host")
            .unwrap();
        fixture
            .room
            .send(OperationId::from_bytes([3; 16]).unwrap(), &draft)
            .await
            .unwrap();
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        assert_eq!(
            manager.tick_room(id(1), &mut fixture.room).await,
            Err(Error::Refused)
        );
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "refused");
        assert_eq!(
            attach(&mut manager, 1, 1, context, &profile)["current"]["state"],
            "refused"
        );
        drop(manager);
        let mut manager = fixture.reopen();
        let report = manager.status(id(1), 0, 16).unwrap();
        let mut jobs = report["application"]["records"].as_array().unwrap().clone();
        jobs.extend(report["controls"]["records"].as_array().unwrap().clone());
        assert!(jobs
            .iter()
            .any(|job| job["attempts"].as_u64().unwrap() > 0 && job["state"] == "stopped"));
        let before = manager.store.accounting().unwrap();
        assert_eq!(
            attach(&mut manager, 1, 1, context, &profile)["exact_retry"],
            true
        );
        assert_eq!(manager.store.accounting().unwrap(), before);
        assert_eq!(manager.status(id(1), 0, 16).unwrap(), report);
    });
}

#[test]
fn wrong_room_and_account_refuse_without_retuning_the_selected_profile() {
    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let context = fixture.context();
        let profile = fixture.profile("profile", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        let mut other = fixture
            .account
            .prepare_owner(validity())
            .unwrap()
            .commit(fixture.base.join("other-room"), room_limits())
            .await
            .unwrap();
        assert_eq!(
            manager.tick_room(id(1), &mut other).await,
            Err(Error::RoomMismatch)
        );
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "active");
        assert_eq!(
            manager.detach(id(2), id(1), other.status().unwrap().context),
            Err(Error::RoomMismatch)
        );
        let mut wrong = context;
        wrong.account = other.status().unwrap().context.device;
        assert_eq!(
            manager.detach(id(2), id(2), wrong),
            Err(Error::RoomMismatch)
        );
        manager.tick_room(id(1), &mut fixture.room).await.unwrap();
    });
}

#[test]
fn slot_and_selection_capacity_never_erase_intents_or_reinterpret_an_operation() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let mut manager = fixture.manager();
        let context = fixture.context();
        for number in 1..=64 {
            manager.detach(id(number), id(number), context).unwrap();
        }
        let before = manager.store.accounting().unwrap();
        assert_eq!(
            manager.detach(id(65), id(65), context),
            Err(Error::Capacity)
        );
        assert_eq!(manager.store.accounting().unwrap(), before);
        assert_eq!(
            manager.detach(id(1), id(1), context).unwrap()["exact_retry"],
            true
        );
        for (after, limit) in [(0, 0), (0, 17)] {
            assert_eq!(manager.status(id(1), after, limit), Err(Error::Invalid));
        }
        assert_eq!(
            manager.detach(Hex([0; 16]), id(1), context),
            Err(Error::Invalid)
        );
        assert_eq!(
            manager.attach(id(66), id(1), context, "relative.json".into(), Hex([1; 32])),
            Err(Error::Invalid)
        );
        assert_eq!(
            manager.attach(
                id(66),
                id(1),
                context,
                fixture.base.join("a/../b"),
                Hex([1; 32])
            ),
            Err(Error::Invalid)
        );
        drop(manager);
        let manager = fixture.reopen();
        assert_eq!(manager.state.slots.len(), 64);
        assert_eq!(manager.state.operations, 64);
    });
}

#[test]
fn replay_reconstructs_the_selection_instead_of_trusting_a_coherent_saved_image() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let mut manager = fixture.manager();
        let intent = Intent {
            operation: id(1),
            slot: id(1),
            context: fixture.context(),
            action: Action::Detach,
        };
        let raw = encode_intent(&intent).unwrap();
        let record = Record::new(record_key(id(1)), &raw).unwrap();
        let mut forged = manager.state.clone();
        apply(&mut forged, &intent, raw.len()).unwrap();
        forged.slots.get_mut(&id(1)).unwrap().active = Some(id(1));
        let image = encode_state(&forged).unwrap();
        manager
            .store
            .publish(Some(&manager.image), &image, &[record])
            .unwrap();
        drop(manager);
        assert!(matches!(
            Manager::open(&fixture.base.join("manager"), fixture.account_hash()),
            Err(Error::Store(disk::Error::Corrupt))
        ));
    });
}

#[test]
fn invalidation_and_drop_release_only_driver_custody_and_keep_selection_history() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let profile = fixture.profile("profile", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        assert!(Driver::open_polling_bound(&profile.path, context, profile.hash.0).is_err());
        manager.close_room(id(1));
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "refused");
        assert!(Driver::open_polling_bound(&profile.path, context, profile.hash.0).is_ok());
        attach(&mut manager, 2, 1, context, &profile);
        manager.invalidate();
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "refused");
        drop(manager);
        let mut manager = fixture.reopen();
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "active");
        assert_eq!(manager.state.operations, 2);
    });
}

#[test]
fn a_committed_replacement_reopens_after_the_old_runtime_drops_before_acknowledgement() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let old = fixture.profile("old", context, true);
        let next = fixture.profile("next", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &old);
        let intent = Intent {
            operation: id(2),
            slot: id(1),
            context,
            action: Action::Attach(next.clone()),
        };
        let raw = encode_intent(&intent).unwrap();
        let mut state = manager.state.clone();
        apply(&mut state, &intent, raw.len()).unwrap();
        manager
            .store
            .publish(
                Some(&manager.image),
                &encode_state(&state).unwrap(),
                &[Record::new(record_key(id(2)), &raw).unwrap()],
            )
            .unwrap();
        // The runtime still holds the old profile at this simulated process
        // boundary; only the durable selection determines the next startup.
        drop(manager);
        let mut manager = fixture.reopen();
        assert_eq!(
            manager.status(id(1), 0, 16).unwrap()["profile"],
            json!(next.path)
        );
        assert_eq!(
            attach(&mut manager, 2, 1, context, &next)["exact_retry"],
            true
        );
        assert!(Driver::open_polling_bound(&old.path, context, old.hash.0).is_ok());
        assert_eq!(
            attach(&mut manager, 1, 1, context, &old)["current"]["profile"],
            json!(next.path)
        );
    });
}

#[test]
fn a_missing_retained_child_refuses_restart_without_recreating_it() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let profile = fixture.profile("profile", fixture.context(), true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, fixture.context(), &profile);
        drop(manager);
        let jobs = fixture.base.join("profile-queue/jobs");
        let preserved = fixture.base.join("profile-queue/old-jobs");
        std::fs::rename(&jobs, &preserved).unwrap();
        let mut manager = fixture.reopen();
        assert_eq!(manager.status(id(1), 0, 16).unwrap()["state"], "refused");
        assert!(!jobs.exists());
        assert!(preserved.join("delivery.db").exists());
        assert_eq!(manager.state.operations, 1);
    });
}

#[test]
fn retained_selection_quota_refuses_new_intents_but_preserves_exact_receipts() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let initialized = fixture.manager();
        let image = initialized.image.clone();
        drop(initialized);
        let path = fixture.base.join("small-selection");
        let mut store = Store::create_new(
            &path,
            store_context(fixture.account_hash()).unwrap(),
            disk::Limits {
                max_records: 1,
                max_record_bytes: 1024,
            },
        )
        .unwrap();
        store.publish(None, &image, &[]).unwrap();
        drop(store);
        let mut manager = Manager::open(&path, fixture.account_hash()).unwrap();
        manager.detach(id(1), id(1), fixture.context()).unwrap();
        let before = manager.store.accounting().unwrap();
        assert_eq!(
            manager.detach(id(2), id(1), fixture.context()),
            Err(Error::Capacity)
        );
        assert_eq!(
            manager.detach(id(1), id(1), fixture.context()).unwrap()["exact_retry"],
            true
        );
        assert_eq!(manager.store.accounting().unwrap(), before);
        // Exercise the store's clean capacity refusal as well as prepare's
        // semantic limit check. Neither result may poison global selection.
        let refused = Intent {
            operation: id(2),
            slot: id(1),
            context: fixture.context(),
            action: Action::Detach,
        };
        let record = Record::new(
            record_key(refused.operation),
            &encode_intent(&refused).unwrap(),
        )
        .unwrap();
        assert_eq!(manager.publish(&refused, record), Err(Error::Refused));
        manager.check().unwrap();
        assert_eq!(manager.store.accounting().unwrap(), before);
        drop(manager);
        let reopened = Manager::open(&path, fixture.account_hash()).unwrap();
        assert_eq!(reopened.state.operations, 1);
    });
}

#[test]
fn clean_selection_record_conflict_keeps_existing_drivers_and_manager_usable() {
    runtime().block_on(async {
        let fixture = Fixture::new(true).await;
        let context = fixture.context();
        let profile = fixture.profile("clean-conflict", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        let before = manager.store.accounting().unwrap();
        let conflict = Intent {
            operation: id(1),
            slot: id(1),
            context,
            action: Action::Detach,
        };
        let record = Record::new(
            record_key(conflict.operation),
            &encode_intent(&conflict).unwrap(),
        )
        .unwrap();
        assert_eq!(manager.publish(&conflict, record), Err(Error::Conflict));
        manager.check().unwrap();
        assert_eq!(manager.store.accounting().unwrap(), before);
        assert_eq!(manager.status(id(1), 0, 1).unwrap()["state"], "active");
        assert!(manager.running[&id(1)].live.is_some());
    });
}

#[test]
fn a_cancelled_tick_drops_its_driver_and_exact_attach_retry_does_not_reopen_it() {
    use std::{
        future::Future as _,
        task::{Context as TaskContext, Waker},
    };

    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let context = fixture.context();
        let profile = fixture.profile("cancelled", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        let native = fixture.room.status().unwrap();
        manager.pause_tick = true;
        {
            let mut tick = Box::pin(manager.tick_room(id(1), &mut fixture.room));
            let mut cx = TaskContext::from_waker(Waker::noop());
            assert!(tick.as_mut().poll(&mut cx).is_pending());
        }
        manager.pause_tick = false;
        assert_eq!(fixture.room.status().unwrap(), native);
        assert_eq!(manager.status(id(1), 0, 1).unwrap()["state"], "refused");
        assert_eq!(
            attach(&mut manager, 1, 1, context, &profile)["current"]["state"],
            "refused"
        );
        assert_eq!(
            manager.tick_room(id(1), &mut fixture.room).await,
            Err(Error::Refused)
        );
        // No canceled future or detached worker keeps the selected queue open.
        let reopened = Driver::open_polling_bound(&profile.path, context, profile.hash.0).unwrap();
        drop(reopened);
        assert_eq!(
            attach(&mut manager, 2, 1, context, &profile)["current"]["state"],
            "active"
        );
    });
}

#[test]
fn locked_native_room_has_a_distinct_failure_and_releases_selected_driver() {
    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let context = fixture.context();
        let profile = fixture.profile("locked-native", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);
        fixture.room.lock();
        assert_eq!(
            manager.tick_room(id(1), &mut fixture.room).await,
            Err(Error::NativeUnavailable)
        );
        manager.close_room(id(1));
        assert_eq!(
            manager.status(id(1), 0, 1).unwrap()["state"],
            "native_unavailable"
        );
        assert_eq!(
            attach(&mut manager, 1, 1, context, &profile)["current"]["state"],
            "native_unavailable"
        );
        let reopened = Driver::open_polling_bound(&profile.path, context, profile.hash.0).unwrap();
        drop(reopened);
        manager.check().unwrap();
    });
}

#[test]
fn retained_native_authentication_failure_survives_healthy_cached_status() {
    use std::os::unix::fs::FileExt as _;
    use vhalla_private_native::private_rooms::{
        Context as NativeContext, NativePrivateStore, RecordKey as NativeRecordKey,
    };

    // Preserve opaque SQLite consistency while breaking one retained record's
    // AEAD. This isolates native authentication from queue/profile corruption;
    // it is deliberate fixture editing, not a production recovery interface.
    fn digest(context: &[u8], key: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private-native/record/v1");
        for part in [context, key, bytes] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }
    fn replace_once(bytes: &mut [u8], before: &[u8], after: &[u8]) {
        assert_eq!(before.len(), after.len());
        let positions: Vec<_> = bytes
            .windows(before.len())
            .enumerate()
            .filter_map(|(position, found)| (found == before).then_some(position))
            .collect();
        assert_eq!(positions.len(), 1);
        bytes[positions[0]..positions[0] + before.len()].copy_from_slice(after);
    }

    runtime().block_on(async {
        let mut fixture = Fixture::new(true).await;
        let context = fixture.context();
        let draft = fixture
            .room
            .prepare_message(b"retained native authentication")
            .unwrap();
        let sent = fixture
            .room
            .send(OperationId::from_bytes([5; 16]).unwrap(), &draft)
            .await
            .unwrap();
        let accepted = fixture.room.status().unwrap();
        fixture.room.lock();
        let native_context = NativeContext::new(
            *context.scope.room.as_bytes(),
            *context.scope.anchor.as_bytes(),
            *context.account.as_bytes(),
            *context.device.as_bytes(),
        )
        .unwrap();
        let room_path = fixture.base.join("room");
        let mut store = NativePrivateStore::open(&room_path, native_context).unwrap();
        let original = store
            .read(native_context, NativeRecordKey::Outbox(sent.sequence()))
            .unwrap()
            .unwrap();
        drop(store);
        fixture.room = fixture
            .account
            .open_room(&room_path, context)
            .await
            .unwrap();
        let profile = fixture.profile("native-record", context, true);
        let mut manager = fixture.manager();
        attach(&mut manager, 1, 1, context, &profile);

        let path = room_path.join("private.sqlite");
        let mut database = std::fs::read(&path).unwrap();
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        let mut key = vec![1];
        key.extend(sent.sequence().to_be_bytes());
        replace_once(&mut database, &original, &damaged);
        replace_once(
            &mut database,
            &digest(native_context.as_bytes(), &key, &original),
            &digest(native_context.as_bytes(), &key, &damaged),
        );
        let counter = u32::from_be_bytes(database[24..28].try_into().unwrap()) + 1;
        database[24..28].copy_from_slice(&counter.to_be_bytes());
        database[92..96].copy_from_slice(&counter.to_be_bytes());
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.write_all_at(&database, 0).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            fixture.room.outbox(0, 1).await,
            Err(vhalla_private_native::client::Error::Kernel(
                vhalla_private_kernel::Error::Authentication
            ))
        ));
        assert_eq!(fixture.room.status().unwrap(), accepted);
        assert_eq!(
            manager.tick_room(id(1), &mut fixture.room).await,
            Err(Error::NativeUnavailable)
        );
        assert_eq!(fixture.room.status().unwrap(), accepted);
        assert_eq!(
            manager.status(id(1), 0, 1).unwrap()["state"],
            "native_unavailable"
        );
        assert!(manager.running[&id(1)].live.is_none());
        assert_eq!(
            attach(&mut manager, 1, 1, context, &profile)["current"]["state"],
            "native_unavailable"
        );
        manager.check().unwrap();
    });
}
