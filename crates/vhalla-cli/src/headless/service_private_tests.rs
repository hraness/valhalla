//! Private owner JSON, scoped grants and the real finite delivery actor step.

#[path = "service_fairness_tests.rs"]
mod fairness_tests;

use super::*;
use crate::headless::{backend::Room, catalog::Hex, local::Backend as _};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Write,
    net::TcpListener,
    os::unix::fs::{FileExt as _, PermissionsExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use vhalla_private_native::{
    private_rooms::{Context as StoreContext, NativePrivateStore, RecordKey},
    relay::{
        net::RelayToken,
        tls::{self, Credential, Permissions, Service, ServiceLimits},
        FileStore, Limits as MailboxLimits, RelayNamespace,
    },
};

fn id(value: u8) -> Id {
    Hex([value; 16])
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn limits() -> Value {
    json!({"max_records":10000,"max_record_bytes":8*1024*1024})
}
fn write(path: &Path, bytes: &[u8]) {
    let mut file = vhalla_custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn context(status: &Value) -> Value {
    let selected = &status["context"];
    json!({"room":selected["room"],"anchor":selected["anchor"],
        "account":selected["account"],"device":selected["device"]})
}
fn room_id(status: &Value) -> Id {
    serde_json::from_value(status["room"].clone()).unwrap()
}
async fn reply(service: &mut ServiceBackend, channel: Channel, request: Value) -> Result<Reply> {
    // This is the same heap boundary used by the local actor for native work.
    Box::pin(service.dispatch(channel, request)).await
}
async fn admin(service: &mut ServiceBackend, request: Value) -> Value {
    let label = request["op"].clone();
    reply(service, Channel::Admin, request)
        .await
        .unwrap_or_else(|error| panic!("{label}: {error:?}"))
        .checked_value()
        .unwrap()
        .clone()
}
async fn tick(service: &mut ServiceBackend) {
    Box::pin(service.tick()).await.unwrap();
}
async fn initialized(home: &Path, generation: u8) -> ServiceBackend {
    vhalla_custody::create_private_directory(home).unwrap();
    ServiceBackend::initialize(home, Hex([generation; 32]))
        .await
        .unwrap()
}
async fn create(service: &mut ServiceBackend, operation: u8, private: bool) -> Value {
    let time = now();
    admin(service, json!({"op":"room.create","operation":id(operation),
        "kind":if private {"private"} else {"public"},"limits":limits(),
        "validity":if private {json!({"not_before":time-1,"expires_at":time+3600})} else {Value::Null}})).await
}
async fn issue(service: &mut ServiceBackend, status: &Value, operation: u8) -> Reply {
    let scope = if status["kind"] == "private" {
        let mut scope = context(status);
        scope["kind"] = json!("private");
        scope["epoch"] = status["epoch"].clone();
        scope["roster"] = status["roster"].clone();
        scope
    } else {
        json!({"kind":"public","pin":status["pin"],"author":status["author"],
            "policy":status["policy"]["id"],"revision":status["policy"]["revision"]})
    };
    let time = now();
    reply(service, Channel::Admin, json!({"op":"grant.issue","operation":id(operation),
        "room":status["room"],"grant":{"scope":scope,
        "permissions":{"status":true,"messages":true,"send":true,"outbox_status":true},
        "budget":{"calls":32,"send_attempts":4,"body_bytes":16384,"read_records":64,"read_bytes":1048576},
        "not_before":time-1,"expires_at":time+600}})).await.unwrap()
}
fn agent(grant: &Reply, method: &str) -> Value {
    let grant = grant.checked_value().unwrap();
    json!({"generation":grant["generation"],"token":grant["token"],"method":method})
}
async fn pending(service: &mut ServiceBackend, grant: &Reply) -> Reply {
    reply(service, Channel::Agent, agent(grant, "agent.status"))
        .await
        .unwrap()
}
fn error_code<T>(value: Result<T>) -> ErrorCode {
    match value {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error.code,
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
struct Environment {
    // Join the finite relay before deleting any of its private temporary files.
    _server: Server,
    base: PathBuf,
    address: String,
    _temp: TempDir,
}
struct Profile {
    path: PathBuf,
    state: PathBuf,
    hash: Hash,
}
impl Environment {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let base = temp.path().canonicalize().unwrap();
        vhalla_custody::open_private_directory(&base).unwrap();
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
        let mut leaf = CertificateParams::new(vec!["private-service.invalid".to_owned()]).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = leaf.signed_by(&key, &issuer, &issuer_key).unwrap();
        let config = tls::server_config(vec![leaf.der().to_vec()], key.serialize_der()).unwrap();
        write(&base.join("ca.der"), issuer.der());
        write(&base.join("token"), Hex([7; 32]).to_string().as_bytes());
        let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
        let mailbox = base.join("mailbox");
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
        let service = Service::new(
            FileStore::open(&mailbox, namespace).unwrap(),
            config,
            vec![Credential {
                id: [8; 16],
                tokens: vec![RelayToken::from_bytes([7; 32]).unwrap()],
                namespace,
                permissions: Permissions {
                    put: true,
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
            base,
            address,
            _temp: temp,
        }
    }
    fn profile(&self, label: &str, status: &Value) -> Profile {
        let path = self.base.join(format!("{label}.json"));
        let state = self.base.join(format!("{label}-queue"));
        let value = json!({"version":4,"context":context(status),"namespace":Hex([9;32]),
            "transport":{"kind":"tls","addr":self.address,"tls_name":"private-service.invalid","ca":self.base.join("ca.der")},
            "token":self.base.join("token"),"state":state,"max_jobs":64,"max_bytes":8388608,
            "max_attempts":1,"initial_backoff_secs":1,"max_backoff_secs":30,
            "emit_acceptance":true,"mailbox_polling":"interactive"});
        let bytes = serde_json::to_vec(&value).unwrap();
        write(&path, &bytes);
        Profile {
            path,
            state,
            hash: Hex(Sha256::digest(bytes).into()),
        }
    }
}
fn setup(room: Id, profile: &Profile) -> Value {
    json!({"op":"private.delivery_init","room":room,"profile":profile.path,"profile_hash":profile.hash})
}
fn attach(room: Id, operation: u8, profile: &Profile) -> Value {
    json!({"op":"private.delivery_attach","room":room,"operation":id(operation),
        "profile":profile.path,"profile_hash":profile.hash})
}
async fn install(service: &mut ServiceBackend, room: Id, operation: u8, profile: &Profile) {
    assert_eq!(
        admin(service, setup(room, profile)).await["initialized"],
        true
    );
    assert_eq!(
        admin(service, attach(room, operation, profile)).await["current"]["state"],
        "active"
    );
}
async fn delivery(service: &mut ServiceBackend, room: Id) -> Value {
    admin(
        service,
        json!({"op":"private.delivery_status","room":room,"after":0,"limit":16}),
    )
    .await
}
async fn messages(service: &mut ServiceBackend, room: Id) -> Value {
    admin(
        service,
        json!({"op":"room.messages","room":room,"after":0,"limit":16}),
    )
    .await
}
fn message_count(page: &Value, body: &str, sender: &Value) -> usize {
    page["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["body"] == body && row["sender"] == *sender)
        .count()
}
fn send(status: &Value, operation: u8, body: &str) -> Value {
    json!({"op":"room.send","room":status["room"],"operation":id(operation),
        "body":body,"epoch":status["epoch"],"roster":status["roster"]})
}
async fn outbox_row(service: &mut ServiceBackend, room: Id, sequence: u64) -> Value {
    let page = admin(
        service,
        json!({"op":"room.outbox_status","room":room,
        "after":sequence-1,"limit":1}),
    )
    .await;
    assert_eq!(page["delivery"], "unconfirmed");
    assert!(page["acceptance_scope"].is_string());
    let row = page["records"][0].clone();
    assert_eq!(row["cursor"], sequence);
    row
}
async fn agent_acceptances(service: &mut ServiceBackend, grant: &Reply, sequence: u64) -> u64 {
    let mut request = agent(grant, "agent.outbox_status");
    request["after"] = json!(sequence - 1);
    request["limit"] = json!(1);
    let response = reply(service, Channel::Agent, request).await.unwrap();
    let page = response.checked_value().unwrap();
    assert_eq!(page["delivery"], "not asserted");
    assert!(page["acceptance_scope"].is_string());
    assert_eq!(page["records"][0]["cursor"], sequence);
    assert!(page["records"][0].get("device_acceptances").is_none());
    assert!(serde_json::to_vec(&page["records"][0]).unwrap().len() <= 256);
    page["records"][0]["member_acceptance_count"]
        .as_u64()
        .unwrap()
}
async fn retained(service: &mut ServiceBackend, room: Id, sequence: u64) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        tick(service).await;
        let status = delivery(service, room).await;
        assert_eq!(status["state"], "active", "{status}");
        if status["application"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["sequence"] == sequence && row["state"] == "retained")
        {
            return;
        }
        assert!(Instant::now() < deadline, "relay retention: {status}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn accepted(
    sender: &mut ServiceBackend,
    receiver: &mut ServiceBackend,
    sender_room: Id,
    sequence: u64,
    recipient: &Value,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        tick(receiver).await;
        tick(sender).await;
        let row = outbox_row(sender, sender_room, sequence).await;
        if row["member_acceptance_count"] == 1 {
            let claims = row["device_acceptances"].as_array().unwrap();
            assert_eq!(claims.len(), 1);
            assert_eq!(claims[0]["recipient"], *recipient);
            assert!(claims[0]["ciphertext"].is_string());
            assert!(claims[0]["received_sequence"].as_u64().unwrap() > 0);
            return row;
        }
        assert_eq!(row["member_acceptance_count"], 0);
        assert!(Instant::now() < deadline, "recipient acceptance: {row}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
async fn bootstrap(owner: &mut ServiceBackend, member: &mut ServiceBackend) -> (Value, Value) {
    let time = now();
    let valid = json!({"not_before":time-1,"expires_at":time+3600});
    let initial = admin(
        owner,
        json!({"op":"room.create","operation":id(1),
        "kind":"private","limits":limits(),"validity":valid}),
    )
    .await;
    let recipient = admin(member, json!({"op":"service.status"})).await["account"].clone();
    let offer = admin(
        owner,
        json!({"op":"private.offer","room":id(1),"operation":id(2),
        "recipient":recipient,"validity":valid}),
    )
    .await;
    let joined = admin(
        member,
        json!({"op":"room.join_private","operation":id(3),
        "offer":offer["offer"],"expected_owner":initial["context"]["account"],
        "validity":valid,"limits":limits()}),
    )
    .await;
    assert_eq!(joined["status"]["needs_owner_admission"], true);
    let admission = admin(
        owner,
        json!({"op":"private.accept_contact","room":id(1),
        "operation":id(4),"request":joined["request"],"validity":valid}),
    )
    .await;
    let member_status = admin(
        member,
        json!({"op":"private.join_contact","room":id(3),
        "response":admission["artifact"]}),
    )
    .await;
    let owner_status = admin(owner, json!({"op":"room.status","room":id(1)})).await;
    assert_eq!(member_status["phase"], "member_joined");
    assert_eq!(member_status["can_send"], true);
    assert_eq!(owner_status["roster"], member_status["roster"]);
    (owner_status, member_status)
}

#[tokio::test]
async fn owner_json_bootstrap_delivery_receipts_and_offline_reopen() {
    let environment = Environment::new();
    let owner_home = environment.base.join("owner");
    let member_home = environment.base.join("member");
    let mut owner = initialized(&owner_home, 80).await;
    let mut member = initialized(&member_home, 81).await;
    let (owner_room, member_room) = bootstrap(&mut owner, &mut member).await;
    let owner_profile = environment.profile("owner", &owner_room);
    let member_profile = environment.profile("member", &member_room);
    install(&mut owner, id(1), 10, &owner_profile).await;
    install(&mut member, id(3), 10, &member_profile).await;
    let owner_grant = issue(&mut owner, &owner_room, 20).await;
    let request = send(&owner_room, 30, "authenticated owner message");
    let sent = admin(&mut owner, request.clone()).await;
    assert_eq!(sent["exact_retry"], false);
    let sequence = sent["sequence"].as_u64().unwrap();

    // The receiver has not ticked. An opaque relay write cannot imply receipt.
    retained(&mut owner, id(1), sequence).await;
    assert_eq!(
        outbox_row(&mut owner, id(1), sequence).await["member_acceptance_count"],
        0
    );
    assert_eq!(
        agent_acceptances(&mut owner, &owner_grant, sequence).await,
        0
    );
    let accepted_row = accepted(
        &mut owner,
        &mut member,
        id(1),
        sequence,
        &member_room["context"]["device"],
    )
    .await;
    assert_eq!(
        agent_acceptances(&mut owner, &owner_grant, sequence).await,
        1
    );
    assert_eq!(
        message_count(
            &messages(&mut member, id(3)).await,
            "authenticated owner message",
            &owner_room["context"]["device"]
        ),
        1
    );
    let retry = admin(&mut owner, request).await;
    assert_eq!(retry["exact_retry"], true);
    assert_eq!(retry["artifact"], sent["artifact"]);

    let member_sent = admin(
        &mut member,
        send(&member_room, 31, "authenticated member reply"),
    )
    .await;
    let member_sequence = member_sent["sequence"].as_u64().unwrap();
    accepted(
        &mut member,
        &mut owner,
        id(3),
        member_sequence,
        &owner_room["context"]["device"],
    )
    .await;
    assert_eq!(
        message_count(
            &messages(&mut owner, id(1)).await,
            "authenticated member reply",
            &member_room["context"]["device"]
        ),
        1
    );

    drop(member);
    let offline_request = send(&owner_room, 32, "message while member is stopped");
    let offline = admin(&mut owner, offline_request.clone()).await;
    let offline_sequence = offline["sequence"].as_u64().unwrap();
    retained(&mut owner, id(1), offline_sequence).await;
    assert_eq!(
        outbox_row(&mut owner, id(1), offline_sequence).await["member_acceptance_count"],
        0
    );
    let mut member = ServiceBackend::open(&member_home, Hex([82; 32]))
        .await
        .unwrap();
    admin(&mut member, json!({"op":"room.status","room":id(3)})).await;
    accepted(
        &mut owner,
        &mut member,
        id(1),
        offline_sequence,
        &member_room["context"]["device"],
    )
    .await;
    assert_eq!(
        message_count(
            &messages(&mut member, id(3)).await,
            "message while member is stopped",
            &owner_room["context"]["device"]
        ),
        1
    );
    let retry = admin(&mut owner, offline_request).await;
    assert_eq!(retry["artifact"], offline["artifact"]);
    assert_eq!(retry["exact_retry"], true);
    drop(member);
    let mut member = ServiceBackend::open(&member_home, Hex([83; 32]))
        .await
        .unwrap();
    admin(&mut member, json!({"op":"room.status","room":id(3)})).await;
    tick(&mut member).await;
    assert_eq!(
        message_count(
            &messages(&mut member, id(3)).await,
            "message while member is stopped",
            &owner_room["context"]["device"]
        ),
        1
    );
    assert_eq!(
        outbox_row(&mut owner, id(1), sequence).await["device_acceptances"],
        accepted_row["device_acceptances"]
    );
    for (service, room) in [(&mut owner, id(1)), (&mut member, id(3))] {
        let detached = admin(
            service,
            json!({"op":"private.delivery_detach","room":room,"operation":id(40)}),
        )
        .await;
        assert_eq!(detached["current"]["state"], "detached");
        tick(service).await;
        assert_eq!(delivery(service, room).await["state"], "detached");
    }
    assert!(owner_grant.check_release().is_ok());
}

#[tokio::test]
async fn refused_setup_hash_and_replaced_profile_preserve_private_and_public_grants() {
    let environment = Environment::new();
    let mut service = initialized(&environment.base.join("home"), 84).await;
    let private = create(&mut service, 1, true).await;
    let public = create(&mut service, 2, false).await;
    let private_grant = issue(&mut service, &private, 20).await;
    let public_grant = issue(&mut service, &public, 21).await;
    let private_pending = pending(&mut service, &private_grant).await;
    let public_pending = pending(&mut service, &public_grant).await;
    let profile = environment.profile("selected", &private);
    let mut wrong_hash = setup(id(1), &profile);
    wrong_hash["profile_hash"] = json!(Hex([99; 32]));
    assert_eq!(
        error_code(reply(&mut service, Channel::Admin, wrong_hash).await),
        ErrorCode::Conflict
    );
    assert!(!profile.state.exists());
    let other = create(&mut service, 3, true).await;
    let wrong_context = environment.profile("wrong-context", &other);
    assert_eq!(
        error_code(reply(&mut service, Channel::Admin, setup(id(1), &wrong_context)).await),
        ErrorCode::Conflict
    );
    assert!(!wrong_context.state.exists());
    install(&mut service, id(1), 30, &profile).await;
    let mut wrong_hash = attach(id(1), 31, &profile);
    wrong_hash["profile_hash"] = json!(Hex([99; 32]));
    assert_eq!(
        error_code(reply(&mut service, Channel::Admin, wrong_hash).await),
        ErrorCode::Conflict
    );
    assert_eq!(delivery(&mut service, id(1)).await["state"], "active");
    assert_eq!(
        error_code(reply(&mut service, Channel::Admin, setup(id(1), &profile)).await),
        ErrorCode::Conflict
    );

    let bytes = fs::read(&profile.path).unwrap();
    fs::rename(&profile.path, profile.path.with_extension("previous")).unwrap();
    write(&profile.path, &bytes);
    tick(&mut service).await;
    assert_eq!(
        delivery(&mut service, id(1)).await["state"],
        "stale_profile"
    );
    for retained in [
        &private_grant,
        &public_grant,
        &private_pending,
        &public_pending,
    ] {
        assert!(retained.check_release().is_ok());
    }
    assert!(pending(&mut service, &private_grant)
        .await
        .check_release()
        .is_ok());
    assert!(pending(&mut service, &public_grant)
        .await
        .check_release()
        .is_ok());
    let sent = admin(
        &mut service,
        send(&private, 40, "native signing remains healthy"),
    )
    .await;
    assert_eq!(sent["queued_locally"], true);
    assert_eq!(sent["delivery"], "unconfirmed");
}

fn store_context(status: &Value) -> StoreContext {
    let key = |name: &str| {
        serde_json::from_value::<Hash>(status["context"][name].clone())
            .unwrap()
            .0
    };
    StoreContext::new(key("room"), key("anchor"), key("account"), key("device")).unwrap()
}
fn corrupt_retained_record(path: &Path, context: StoreContext, sequence: u64, original: &[u8]) {
    // Test-only corruption keeps the opaque-store checksum and SQLite image
    // consistent, so the failure must come from native AEAD authentication.
    fn digest(context: &[u8], key: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/private-native/record/v1");
        for part in [context, key, bytes] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }
    fn replace(image: &mut [u8], before: &[u8], after: &[u8]) {
        assert_eq!(before.len(), after.len());
        let positions: Vec<_> = image
            .windows(before.len())
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == before).then_some(offset))
            .collect();
        assert_eq!(positions.len(), 1);
        image[positions[0]..positions[0] + before.len()].copy_from_slice(after);
    }
    let mut image = fs::read(path).unwrap();
    let mut damaged = original.to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let mut key = vec![1];
    key.extend(sequence.to_be_bytes());
    replace(&mut image, original, &damaged);
    replace(
        &mut image,
        &digest(context.as_bytes(), &key, original),
        &digest(context.as_bytes(), &key, &damaged),
    );
    let counter = u32::from_be_bytes(image[24..28].try_into().unwrap()) + 1;
    image[24..28].copy_from_slice(&counter.to_be_bytes());
    image[92..96].copy_from_slice(&counter.to_be_bytes());
    let file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(&image, 0).unwrap();
    file.sync_all().unwrap();
}

#[tokio::test]
async fn private_tick_authentication_failure_closes_all_room_grants_and_preserves_other_rooms() {
    let environment = Environment::new();
    let home = environment.base.join("home");
    let mut service = initialized(&home, 85).await;
    let private = create(&mut service, 1, true).await;
    let public = create(&mut service, 2, false).await;
    let sent = admin(
        &mut service,
        send(&private, 10, "authenticate retained history"),
    )
    .await;
    let sequence = sent["sequence"].as_u64().unwrap();
    let profile = environment.profile("native-failure", &private);
    install(&mut service, id(1), 11, &profile).await;
    drop(service);

    // Read retained bytes under the documented store lock while the service
    // is stopped. No retained state is repaired, recreated or rolled back.
    let path = home
        .join("rooms/private")
        .join(room_id(&private).to_string());
    let context = store_context(&private);
    let mut store = NativePrivateStore::open(&path, context).unwrap();
    let original = store
        .read(context, RecordKey::Outbox(sequence))
        .unwrap()
        .unwrap();
    drop(store);
    let mut service = ServiceBackend::open(&home, Hex([86; 32])).await.unwrap();
    let private = admin(&mut service, json!({"op":"room.status","room":id(1)})).await;
    let first = issue(&mut service, &private, 20).await;
    let second = issue(&mut service, &private, 21).await;
    let unrelated = issue(&mut service, &public, 22).await;
    let first_pending = pending(&mut service, &first).await;
    let second_pending = pending(&mut service, &second).await;
    let unrelated_pending = pending(&mut service, &unrelated).await;
    let Room::Private(native) = service.backend.room_mut(id(1)).await.unwrap() else {
        panic!("private room")
    };
    let cached = native.status().unwrap();
    corrupt_retained_record(&path.join("private.sqlite"), context, sequence, &original);
    assert_eq!(native.status().unwrap(), cached);
    tick(&mut service).await;
    for retained in [&first, &second, &first_pending, &second_pending] {
        assert!(retained.check_release().is_err());
    }
    assert!(unrelated.check_release().is_ok());
    assert!(unrelated_pending.check_release().is_ok());
    assert!(pending(&mut service, &unrelated)
        .await
        .check_release()
        .is_ok());
    assert_eq!(
        delivery(&mut service, id(1)).await["state"],
        "native_unavailable"
    );
    assert_eq!(
        error_code(
            reply(
                &mut service,
                Channel::Admin,
                json!({"op":"room.messages","room":id(1),"after":0,"limit":1})
            )
            .await
        ),
        ErrorCode::OwnerUnavailable
    );
    let sent = admin(
        &mut service,
        json!({"op":"room.send","room":id(2),
        "operation":id(30),"body":"unrelated public room still signs"}),
    )
    .await;
    assert_eq!(sent["queued_locally"], true);
}
