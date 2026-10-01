//! Composition keeps native authority changes and retained output permits joined.

use super::super::{catalog::Hex, local::Backend as _};
use super::*;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

const GENERATION: Hash = Hex([90; 32]);

struct Temp {
    root: TempDir,
    home: PathBuf,
}
impl Temp {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let home = root.path().join("service");
        vhalla_custody::create_private_directory(&home).unwrap();
        Self { root, home }
    }
}
fn id(number: u8) -> Id {
    Hex([number; 16])
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn validity() -> Value {
    let now = now();
    json!({"not_before":now-1,"expires_at":now+3600})
}
fn limits() -> Value {
    json!({"max_records":10_000,"max_record_bytes":8*1024*1024})
}
fn create(number: u8, kind: &str) -> Value {
    json!({"op":"room.create","operation":id(number),"kind":kind,"limits":limits(),"validity":if kind == "private" { validity() } else { Value::Null }})
}
async fn admin(service: &mut ServiceBackend, request: Value) -> Value {
    let reply = service.dispatch(Channel::Admin, request).await.unwrap();
    reply.checked_value().unwrap().clone()
}
fn issue_request(status: &Value, operation: u8) -> Value {
    let scope = if status["kind"] == "public" {
        json!({"kind":"public","pin":status["pin"],"author":status["author"],"policy":status["policy"]["id"],"revision":status["policy"]["revision"]})
    } else {
        let context = &status["context"];
        json!({"kind":"private","room":context["room"],"anchor":context["anchor"],"account":context["account"],"device":context["device"],"epoch":status["epoch"],"roster":status["roster"]})
    };
    let now = now();
    json!({"op":"grant.issue","operation":id(operation),"room":status["room"],"grant":{
        "scope":scope,"permissions":{"status":true,"messages":true,"send":true,"outbox_status":true},
        "budget":{"calls":32,"send_attempts":4,"body_bytes":16_384,"read_records":32,"read_bytes":1_048_576},
        "not_before":now-1,"expires_at":now+600,
    }})
}
async fn issue(service: &mut ServiceBackend, status: &Value, operation: u8) -> Reply {
    service
        .dispatch(Channel::Admin, issue_request(status, operation))
        .await
        .unwrap()
}
fn credentials(reply: &Reply) -> Value {
    let value = reply.checked_value().unwrap();
    json!({"generation":value["generation"],"token":value["token"]})
}
fn agent(credentials: &Value, method: &str) -> Value {
    let mut request = credentials.clone();
    request["method"] = json!(method);
    request
}
async fn pending_status(service: &mut ServiceBackend, credentials: &Value) -> Reply {
    service
        .dispatch(Channel::Agent, agent(credentials, "agent.status"))
        .await
        .unwrap()
}
#[track_caller]
fn code<T>(result: Result<T>) -> ErrorCode {
    match result {
        Ok(_) => panic!("expected refusal"),
        Err(error) => error.code,
    }
}

#[tokio::test]
async fn public_owner_change_invalidates_already_prepared_replies_before_admin_returns() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    let private = admin(&mut service, create(2, "private")).await;
    let grant = issue(&mut service, &public, 20).await;
    let unrelated = issue(&mut service, &private, 21).await;
    let selected = credentials(&grant);
    let independent = credentials(&unrelated);
    let pending = pending_status(&mut service, &selected).await;
    admin(&mut service, json!({"op":"public.set_writers","room":public["room"],"operation":id(30),"writers":[public["owner"],public["author"]]})).await;
    assert!(grant.check_release().is_err());
    assert!(pending.check_release().is_err());
    assert!(unrelated.check_release().is_ok());
    assert!(pending_status(&mut service, &independent)
        .await
        .check_release()
        .is_ok());
    assert_eq!(
        code(
            service
                .dispatch(Channel::Agent, agent(&selected, "agent.status"))
                .await
        ),
        ErrorCode::PermissionDenied
    );
}

#[tokio::test]
async fn private_admission_closes_old_roster_output_and_preserves_an_unrelated_room() {
    let owner_home = Temp::new();
    let member_home = Temp::new();
    let mut owner = ServiceBackend::initialize(&owner_home.home, GENERATION)
        .await
        .unwrap();
    let mut member = ServiceBackend::initialize(&member_home.home, Hex([91; 32]))
        .await
        .unwrap();
    let valid = validity();
    let mut creation = create(1, "private");
    creation["validity"] = valid.clone();
    let private = admin(&mut owner, creation).await;
    let public = admin(&mut owner, create(2, "public")).await;
    let grant = issue(&mut owner, &private, 20).await;
    let unrelated = issue(&mut owner, &public, 21).await;
    let selected = credentials(&grant);
    let independent = credentials(&unrelated);
    let mut page = agent(&selected, "agent.messages");
    page["after"] = json!(0);
    page["limit"] = json!(1);
    let pending = owner.dispatch(Channel::Agent, page).await.unwrap();
    let recipient = admin(&mut member, json!({"op":"service.status"})).await["account"].clone();
    let offer = admin(&mut owner, json!({"op":"private.offer","room":private["room"],"operation":id(30),"recipient":recipient,"validity":valid.clone()})).await;
    assert!(pending.check_release().is_ok());
    let join = admin(&mut member, json!({"op":"room.join_private","operation":id(3),"offer":offer["offer"],"expected_owner":private["context"]["account"],"validity":valid.clone(),"limits":limits()})).await;
    admin(&mut owner, json!({"op":"private.accept_contact","room":private["room"],"operation":id(31),"request":join["request"],"validity":valid})).await;
    assert!(grant.check_release().is_err());
    assert!(pending.check_release().is_err());
    assert!(unrelated.check_release().is_ok());
    assert!(pending_status(&mut owner, &independent)
        .await
        .check_release()
        .is_ok());
}

#[tokio::test]
async fn reopening_identical_native_authority_still_closes_the_old_grant_lifetime() {
    for kind in ["public", "private"] {
        let temp = Temp::new();
        let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
            .await
            .unwrap();
        let initial = admin(&mut service, create(1, kind)).await;
        let request = issue_request(&initial, 20);
        let grant = service
            .dispatch(Channel::Admin, request.clone())
            .await
            .unwrap();
        let selected = credentials(&grant);
        let pending = pending_status(&mut service, &selected).await;
        let reopened = admin(&mut service, json!({"op":"room.reopen","room":id(1)})).await;
        for field in ["pin", "author", "context", "epoch", "roster", "policy"] {
            assert_eq!(reopened[field], initial[field]);
        }
        assert!(grant.check_release().is_err());
        assert!(pending.check_release().is_err());
        assert_eq!(
            code(service.dispatch(Channel::Admin, request).await),
            ErrorCode::PermissionDenied
        );
        assert!(issue(&mut service, &reopened, 21)
            .await
            .check_release()
            .is_ok());
    }
}

#[tokio::test]
async fn global_directory_loss_closes_all_pending_outputs_even_when_paths_are_restored() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    let private = admin(&mut service, create(2, "private")).await;
    let first = issue(&mut service, &public, 20).await;
    let second = issue(&mut service, &private, 21).await;
    let first_reply = pending_status(&mut service, &credentials(&first)).await;
    let second_reply = pending_status(&mut service, &credentials(&second)).await;
    let public_path = temp.home.join("rooms/public");
    let retained = temp.root.path().join("retained-public");
    fs::rename(&public_path, &retained).unwrap();
    vhalla_custody::create_private_directory(&public_path).unwrap();
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, json!({"op":"service.status"}))
                .await
        ),
        ErrorCode::PermissionDenied
    );
    for reply in [&first, &second, &first_reply, &second_reply] {
        assert!(reply.check_release().is_err());
    }
    fs::remove_dir(&public_path).unwrap();
    fs::rename(&retained, &public_path).unwrap();
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, json!({"op":"service.status"}))
                .await
        ),
        ErrorCode::OwnerUnavailable
    );
    for reply in [&first_reply, &second_reply] {
        assert!(reply.check_release().is_err());
    }
}

#[tokio::test]
async fn a_failed_native_operation_closes_its_room_but_leaves_other_rooms_usable() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let private = admin(&mut service, create(1, "private")).await;
    let public = admin(&mut service, create(2, "public")).await;
    let grant = issue(&mut service, &private, 20).await;
    let unrelated = issue(&mut service, &public, 21).await;
    let selected = credentials(&grant);
    let independent = credentials(&unrelated);
    let pending = pending_status(&mut service, &selected).await;
    let private_path = temp.home.join("rooms/private").join(id(1).to_string());
    let retained = temp.root.path().join("retained-private");
    fs::rename(&private_path, &retained).unwrap();
    assert_eq!(code(service.dispatch(Channel::Admin, json!({"op":"room.send","room":id(1),"operation":id(30),"body":"no detached publication","epoch":private["epoch"],"roster":private["roster"]})).await), ErrorCode::OwnerUnavailable);
    assert!(grant.check_release().is_err());
    assert!(pending.check_release().is_err());
    assert!(unrelated.check_release().is_ok());
    assert!(pending_status(&mut service, &independent)
        .await
        .check_release()
        .is_ok());
    let status = admin(&mut service, json!({"op":"service.status"})).await;
    assert_eq!(status["failed_rooms"], 1);
    fs::rename(&retained, &private_path).unwrap();
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, json!({"op":"room.status","room":id(1)}))
                .await
        ),
        ErrorCode::OwnerUnavailable
    );
    let reopened = admin(&mut service, json!({"op":"room.reopen","room":id(1)})).await;
    assert_eq!(reopened["context"], private["context"]);
    assert!(issue(&mut service, &reopened, 22)
        .await
        .check_release()
        .is_ok());
    assert!(pending.check_release().is_err());
}

#[tokio::test]
async fn channels_and_grant_schemas_are_strict_and_invalid_reopen_does_not_revoke() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    let request = issue_request(&public, 20);
    let grant = service
        .dispatch(Channel::Admin, request.clone())
        .await
        .unwrap();
    let selected = credentials(&grant);
    let mut revoke = selected.clone();
    revoke["op"] = json!("grant.revoke");
    for value in [
        request.clone(),
        revoke.clone(),
        json!({"op":"room.reopen","room":id(1)}),
        json!({"op":"public.sync_storage","room":id(1)}),
        json!({"op":"public.sync_expand_limits","room":id(1),"component":{"kind":"replica"},"limits":limits()}),
        json!({"op":"room.send","room":id(1),"operation":id(30),"body":"wrong channel"}),
    ] {
        assert_eq!(
            code(service.dispatch(Channel::Agent, value).await),
            ErrorCode::Usage
        );
    }
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, agent(&selected, "agent.status"))
                .await
        ),
        ErrorCode::Usage
    );
    for mut invalid in [request.clone(), revoke] {
        invalid["unexpected"] = json!(true);
        assert_eq!(
            code(service.dispatch(Channel::Admin, invalid).await),
            ErrorCode::Usage
        );
    }
    let mut invalid = request;
    invalid["operation"] = json!(id(21));
    invalid["grant"]["permissions"]["sign"] = json!(true);
    assert_eq!(
        code(service.dispatch(Channel::Admin, invalid).await),
        ErrorCode::Usage
    );
    assert_eq!(
        code(
            service
                .dispatch(
                    Channel::Admin,
                    json!({"op":"room.reopen","room":id(1),"unexpected":true})
                )
                .await
        ),
        ErrorCode::Usage
    );
    assert_eq!(service.backend.catalog_mut().unwrap().grant_claims(), 1);
    assert!(grant.check_release().is_ok());
    assert!(pending_status(&mut service, &selected)
        .await
        .check_release()
        .is_ok());
    let page = admin(
        &mut service,
        json!({"op":"room.messages","room":id(1),"after":0,"limit":1}),
    )
    .await;
    assert!(page["records"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn owner_sync_growth_preserves_live_grants_and_refuses_unsupported_targets() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    admin(
        &mut service,
        json!({"op":"public.publish","room":id(1),"operation":id(10)}),
    )
    .await;
    let grant = issue(&mut service, &public, 20).await;
    let before = admin(
        &mut service,
        json!({"op":"public.sync_storage","room":id(1)}),
    )
    .await;
    let request = json!({"op":"public.sync_expand_limits","room":id(1),"component":{"kind":"replica"},
        "limits":{"max_records":before["replica"]["max_records"].as_u64().unwrap()+10,
        "max_record_bytes":before["replica"]["max_record_bytes"].as_u64().unwrap()+1024}});
    let grown = admin(&mut service, request.clone()).await;
    assert_eq!(admin(&mut service, request.clone()).await, grown);
    assert!(grant.check_release().is_ok());
    for component in [
        json!({"kind":"metadata"}),
        json!({"kind":"replica","peer":Hex([99;32])}),
    ] {
        let mut invalid = request.clone();
        invalid["component"] = component;
        assert_eq!(
            code(service.dispatch(Channel::Admin, invalid).await),
            ErrorCode::Usage
        );
        assert!(grant.check_release().is_ok());
    }
    let mut invalid = request;
    invalid["limits"]["max_records"] = json!(1);
    assert_eq!(
        code(service.dispatch(Channel::Admin, invalid).await),
        ErrorCode::Usage
    );
    assert!(grant.check_release().is_ok());
    drop(service);
    let mut service = ServiceBackend::open(&temp.home, Hex([91; 32]))
        .await
        .unwrap();
    let reopened = admin(
        &mut service,
        json!({"op":"public.sync_storage","room":id(1)}),
    )
    .await;
    assert_eq!(reopened["replica"], grown["storage"]);
}

#[tokio::test]
async fn growth_revoke_invalidate_drop_and_restart_never_reconstruct_consumed_grants() {
    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    let request = issue_request(&public, 20);
    let first = service
        .dispatch(Channel::Admin, request.clone())
        .await
        .unwrap();
    let first_credentials = credentials(&first);
    let pending = pending_status(&mut service, &first_credentials).await;
    let before_growth = admin(&mut service, json!({"op":"service.status"})).await;
    assert_eq!(before_growth["consumed_grants"], 1);
    let target = json!({
        "max_records":before_growth["storage"]["max_records"].as_u64().unwrap()+10,
        "max_record_bytes":before_growth["storage"]["max_record_bytes"].as_u64().unwrap()+1024,
    });
    let grow = json!({"op":"service.expand_limits","limits":target});
    let grown = admin(&mut service, grow.clone()).await;
    assert_eq!(admin(&mut service, grow).await, grown);
    assert!(pending.check_release().is_ok());
    let replay = service
        .dispatch(Channel::Admin, request.clone())
        .await
        .unwrap();
    assert_eq!(credentials(&replay), first_credentials);
    let replay_status = pending_status(&mut service, &first_credentials).await;
    assert_eq!(
        replay_status.checked_value().unwrap()["remaining"]["calls"],
        pending.checked_value().unwrap()["remaining"]["calls"]
            .as_u64()
            .unwrap()
            - 1
    );
    let mut wrong = first_credentials.clone();
    wrong["op"] = json!("grant.revoke");
    wrong["generation"] = json!(Hex([91; 32]));
    assert_eq!(
        code(service.dispatch(Channel::Admin, wrong).await),
        ErrorCode::PermissionDenied
    );
    assert!(pending.check_release().is_ok());
    let mut revoke = first_credentials.clone();
    revoke["op"] = json!("grant.revoke");
    assert_eq!(admin(&mut service, revoke.clone()).await["revoked"], true);
    assert_eq!(admin(&mut service, revoke).await["revoked"], true);
    assert!(first.check_release().is_err());
    assert!(pending.check_release().is_err());
    let second = issue(&mut service, &public, 21).await;
    service.invalidate();
    assert!(second.check_release().is_err());
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, issue_request(&public, 22))
                .await
        ),
        ErrorCode::OwnerUnavailable
    );
    drop(service);
    let mut service = ServiceBackend::open(&temp.home, Hex([91; 32]))
        .await
        .unwrap();
    let after_growth = admin(&mut service, json!({"op":"service.status"})).await;
    assert_eq!(after_growth["consumed_grants"], 2);
    assert_eq!(
        after_growth["storage"]["max_records"],
        target["max_records"]
    );
    assert_eq!(
        after_growth["storage"]["max_record_bytes"],
        target["max_record_bytes"]
    );
    assert_eq!(
        code(service.dispatch(Channel::Admin, request).await),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        code(
            service
                .dispatch(Channel::Agent, agent(&first_credentials, "agent.status"))
                .await
        ),
        ErrorCode::PermissionDenied
    );
    let third_request = issue_request(&public, 23);
    let third = service
        .dispatch(Channel::Admin, third_request.clone())
        .await
        .unwrap();
    drop(service);
    assert!(third.check_release().is_err());
    let mut service = ServiceBackend::open(&temp.home, Hex([92; 32]))
        .await
        .unwrap();
    assert_eq!(
        code(service.dispatch(Channel::Admin, third_request).await),
        ErrorCode::PermissionDenied
    );
    assert!(issue(&mut service, &public, 24)
        .await
        .check_release()
        .is_ok());
}

#[tokio::test]
async fn a_zero_process_generation_is_rejected_before_initialization_writes() {
    let temp = Temp::new();
    assert!(ServiceBackend::initialize(&temp.home, Hex([0; 32]))
        .await
        .is_err());
    assert!(fs::read_dir(&temp.home).unwrap().next().is_none());
}

#[tokio::test]
async fn agent_signature_failure_fences_sibling_grants_even_when_native_status_stays_healthy() {
    use super::super::backend::Room;
    use sha2::{Digest as _, Sha256};
    use std::os::unix::fs::FileExt as _;

    // This deliberate fixture edit preserves opaque-store integrity to exercise
    // the separate room signature check. It is not a rollback/host containment
    // claim, and introduces no native fault-injection or recovery API.
    fn digest(context: &[u8], entry: &vhalla_direct_store::Entry, data: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"vhalla/direct-store/record/v1");
        let cursor = entry.cursor.to_be_bytes();
        for part in [context, cursor.as_slice(), entry.key.as_slice(), data] {
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
            .filter_map(|(index, slice)| (slice == before).then_some(index))
            .collect();
        assert_eq!(
            positions.len(),
            1,
            "fault fixture must identify exactly one retained field"
        );
        bytes[positions[0]..positions[0] + before.len()].copy_from_slice(after);
    }
    fn install(path: &Path, mut bytes: Vec<u8>, previous: &[u8]) {
        assert_eq!(bytes.len(), previous.len());
        assert_eq!(&bytes[..16], b"SQLite format 3\0");
        // Normal DELETE-mode SQLite readers observe the file change counter.
        // Keep the database-size validity counter equal; no page layout changes.
        let counter = u32::from_be_bytes(previous[24..28].try_into().unwrap()) + 1;
        bytes[24..28].copy_from_slice(&counter.to_be_bytes());
        bytes[92..96].copy_from_slice(&counter.to_be_bytes());
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_all().unwrap();
    }

    let temp = Temp::new();
    let mut service = ServiceBackend::initialize(&temp.home, GENERATION)
        .await
        .unwrap();
    let public = admin(&mut service, create(1, "public")).await;
    let other = admin(&mut service, create(2, "public")).await;
    admin(
        &mut service,
        json!({"op":"room.send","room":id(1),"operation":id(30),"body":"retained signed evidence"}),
    )
    .await;
    let first = issue(&mut service, &public, 20).await;
    let sibling = issue(&mut service, &public, 21).await;
    let unrelated = issue(&mut service, &other, 22).await;
    let selected = credentials(&first);
    let sibling_credentials = credentials(&sibling);
    let independent = credentials(&unrelated);
    let pending = pending_status(&mut service, &sibling_credentials).await;
    let independent_reply = pending_status(&mut service, &independent).await;
    let (context, entry) = {
        let Room::Public(room) = service.backend.loaded_room_mut(id(1)).unwrap() else {
            panic!()
        };
        let context = vhalla_direct_store::Context::new(
            *room.room_id().as_bytes(),
            room.genesis().claims().owner,
        )
        .unwrap();
        let entry = room
            .records(0, 32)
            .unwrap()
            .records
            .into_iter()
            .find(|entry| entry.key[0] == 5)
            .unwrap();
        (context, entry)
    };
    let path = temp
        .home
        .join("rooms/public")
        .join(id(1).to_string())
        .join("store/direct.sqlite");
    let original = fs::read(&path).unwrap();
    let mut changed = entry.data.clone();
    // Force the Ed25519 scalar out of canonical range without touching claims.
    *changed.last_mut().unwrap() = 0xff;
    assert_ne!(changed, entry.data);
    let mut database = original.clone();
    replace_once(&mut database, &entry.data, &changed);
    replace_once(
        &mut database,
        &digest(context.as_bytes(), &entry, &entry.data),
        &digest(context.as_bytes(), &entry, &changed),
    );
    install(&path, database, &original);
    {
        let Room::Public(room) = service.backend.loaded_room_mut(id(1)).unwrap() else {
            panic!()
        };
        assert!(room.status().is_ok());
        let retained = room.records(entry.cursor - 1, 1).unwrap();
        assert_eq!(retained.records[0].data, changed);
    }
    let mut request = agent(&selected, "agent.messages");
    request["after"] = json!(0);
    request["limit"] = json!(1);
    assert_eq!(
        code(service.dispatch(Channel::Agent, request).await),
        ErrorCode::OwnerUnavailable
    );
    let Room::Public(room) = service.backend.loaded_room_mut(id(1)).unwrap() else {
        panic!()
    };
    assert!(
        room.status().is_ok(),
        "the service must retain a stronger uncertainty fence than cached status"
    );
    for reply in [&first, &sibling, &pending] {
        assert!(reply.check_release().is_err());
    }
    assert!(unrelated.check_release().is_ok());
    assert!(independent_reply.check_release().is_ok());
    assert!(pending_status(&mut service, &independent)
        .await
        .check_release()
        .is_ok());
    assert_eq!(
        admin(&mut service, json!({"op":"service.status"})).await["failed_rooms"],
        1
    );

    // Restoring exact evidence does not silently revive the service handle or
    // old grants. Explicit reopen and a fresh authorization remain necessary.
    let damaged = fs::read(&path).unwrap();
    install(&path, original, &damaged);
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, json!({"op":"room.status","room":id(1)}))
                .await
        ),
        ErrorCode::OwnerUnavailable
    );
    assert_eq!(
        code(
            service
                .dispatch(Channel::Admin, issue_request(&public, 23))
                .await
        ),
        ErrorCode::OwnerUnavailable
    );
    let reopened = admin(&mut service, json!({"op":"room.reopen","room":id(1)})).await;
    assert!(issue(&mut service, &reopened, 24)
        .await
        .check_release()
        .is_ok());
    assert!(pending.check_release().is_err());
}
