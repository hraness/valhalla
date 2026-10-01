//! Real native stores exercise restart, exact retry and independent room custody.

use super::*;
use std::{fs, os::unix::fs::symlink};

struct Temp {
    root: tempfile::TempDir,
    home: PathBuf,
}

impl Temp {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("service");
        custody::create_private_directory(&home).unwrap();
        Self { root, home }
    }
}

fn id(number: u8) -> Id {
    Hex([number; 16])
}

fn limits() -> Value {
    json!({"max_records": 10_000, "max_record_bytes": 8 * 1024 * 1024})
}

#[tokio::test]
async fn catalog_capacity_expansion_is_monotone_and_retained_after_reopen() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let before = call(&mut backend, json!({"op":"service.status"})).await;
    let target = json!({"max_records":before["storage"]["max_records"].as_u64().unwrap() + 10,
        "max_record_bytes":before["storage"]["max_record_bytes"].as_u64().unwrap() + 1024});
    let request = json!({"op":"service.expand_limits","limits":target});
    let grown = call(&mut backend, request.clone()).await;
    assert_eq!(call(&mut backend, request).await, grown);
    assert_eq!(grown["storage"]["records"], before["storage"]["records"]);
    assert_eq!(grown["storage"]["bytes"], before["storage"]["bytes"]);
    let shrink = json!({"op":"service.expand_limits","limits":{
        "max_records":before["storage"]["max_records"],
        "max_record_bytes":before["storage"]["max_record_bytes"]}});
    assert_eq!(
        backend.dispatch_admin(shrink).await.unwrap_err().code,
        ErrorCode::Usage
    );
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    let after = call(&mut backend, json!({"op":"service.status"})).await;
    assert_eq!(after["storage"], grown["storage"]);
    assert_eq!(after["account"], before["account"]);
    assert_eq!(after["consumed_grants"], 0);
}

#[tokio::test]
async fn full_public_room_grows_without_losing_history_or_reissuing_signed_messages() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let mut request = create(id(1), Kind::Public, None);
    request["limits"] = json!({"max_records":80,"max_record_bytes":1024*1024});
    call(&mut backend, request).await;
    let mut retained = Vec::new();
    let mut refused = None;
    for n in 2..18 {
        let send =
            json!({"op":"room.send","room":id(1),"operation":id(n),"body":format!("retained {n}")});
        match backend.dispatch_admin(send.clone()).await {
            Ok(result) => retained.push((send, result)),
            Err(error) => {
                assert_eq!(error.code, ErrorCode::PermissionDenied);
                refused = Some(send);
                break;
            }
        }
    }
    assert!(!retained.is_empty());
    let refused = refused.expect("the finite room must stop before the test bound");
    let full = call(&mut backend, json!({"op":"room.status","room":id(1)})).await;
    assert_eq!(full["can_send"], false);
    let grown = call(
        &mut backend,
        json!({"op":"public.expand_limits","room":id(1),
        "limits":{"max_records":160,"max_record_bytes":1024*1024}}),
    )
    .await;
    assert_eq!(grown["can_send"], true);
    assert_eq!(grown["storage"]["records"], full["storage"]["records"]);
    let sent = call(&mut backend, refused.clone()).await;
    assert_eq!(sent["exact_retry"], false);
    call(&mut backend, json!({"op":"public.reconcile","room":id(1)})).await;
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    retained.push((refused, sent));
    for (request, original) in retained {
        let retry = call(&mut backend, request).await;
        assert_eq!(retry["exact_retry"], true);
        assert_eq!(retry["artifact"], original["artifact"]);
    }
    let current = call(&mut backend, json!({"op":"room.status","room":id(1)})).await;
    assert_eq!(current["storage"]["max_records"], 160);
}

fn validity() -> Value {
    let current = now().unwrap();
    json!({"not_before": current - 60, "expires_at": current + 7200})
}

fn create(operation: Id, kind: Kind, validity: Option<Value>) -> Value {
    json!({"op": "room.create", "operation": operation, "kind": kind,
        "limits": limits(), "validity": validity})
}

async fn call(backend: &mut Backend, value: Value) -> Value {
    backend.dispatch_admin(value).await.unwrap()
}

fn intent(value: Value) -> Hash {
    serde_json::from_value::<Request>(value)
        .unwrap()
        .creation_intent()
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn mixed_rooms_share_one_account_and_last_room_holds_its_custody() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let public = call(&mut backend, create(id(1), Kind::Public, None)).await;
    let private = call(&mut backend, create(id(2), Kind::Private, Some(validity()))).await;
    let service = call(&mut backend, json!({"op":"service.status"})).await;
    assert_eq!(service["rooms"], 2);
    assert_eq!(service["open_rooms"], 2);
    assert_eq!(public["owner"], service["account"]);
    assert_eq!(private["context"]["account"], service["account"]);
    assert!(Identity::open(temp.home.join("account")).is_err());
    assert!(Backend::open(&temp.home).await.is_err());
    let held_public = backend.rooms.remove(&id(1)).unwrap();
    let mut held_private = backend.rooms.remove(&id(2)).unwrap();
    drop(backend);
    assert!(Identity::open(temp.home.join("account")).is_err());
    drop(held_public);
    assert!(Identity::open(temp.home.join("account")).is_err());
    private_room(&mut held_private).unwrap().lock();
    drop(Identity::open(temp.home.join("account")).unwrap());
    let mut backend = Backend::open(&temp.home).await.unwrap();
    assert!(backend.loaded_room_ids().is_empty());
    let reopened = call(&mut backend, json!({"op":"room.status","room":id(2)})).await;
    assert_eq!(reopened["context"], private["context"]);
    assert_eq!(reopened["roster"], private["roster"]);
    assert_eq!(backend.loaded_room_ids(), vec![id(2)]);
}

#[tokio::test]
async fn public_creation_and_send_retry_keep_the_same_author_and_bytes_after_restart() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let request = create(id(3), Kind::Public, None);
    let first = call(&mut backend, request.clone()).await;
    let sent = call(
        &mut backend,
        json!({"op":"room.send","room":id(3),"operation":id(4),"body":"hello"}),
    )
    .await;
    assert_eq!(sent["delivery"], "unconfirmed");
    assert_eq!(sent["exact_retry"], false);
    let before = backend.catalog.accounting().unwrap();
    assert_eq!(
        call(&mut backend, request.clone()).await["author"],
        first["author"]
    );
    assert_eq!(backend.catalog.accounting().unwrap(), before);
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    let retried = call(&mut backend, request).await;
    assert_eq!(retried["pin"], first["pin"]);
    assert_eq!(retried["author"], first["author"]);
    let resend = call(
        &mut backend,
        json!({"op":"room.send","room":id(3),"operation":id(4),"body":"hello"}),
    )
    .await;
    assert_eq!(resend["artifact"], sent["artifact"]);
    assert_eq!(resend["exact_retry"], true);
    let error = backend
        .dispatch_admin(json!({"op":"room.send","room":id(3),"operation":id(4),"body":"changed"}))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let mut changed = create(id(3), Kind::Public, None);
    changed["limits"]["max_records"] = json!(20_000);
    assert_eq!(
        backend.dispatch_admin(changed).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    let messages = call(
        &mut backend,
        json!({"op":"room.messages","room":id(3),"after":0,"limit":32}),
    )
    .await;
    assert_eq!(messages["records"].as_array().unwrap().len(), 1);
    assert_eq!(messages["records"][0]["body"], "hello");
    let outbox = call(
        &mut backend,
        json!({"op":"room.outbox_status","room":id(3),"after":0,"limit":32}),
    )
    .await;
    assert_eq!(outbox["records"].as_array().unwrap().len(), 1);
    assert_eq!(outbox["records"][0]["operation"], json!(id(4)));
    assert!(outbox["records"][0].get("artifact").is_none());
    assert!(outbox["records"][0].get("body").is_none());
}

#[tokio::test]
async fn public_join_pins_genesis_and_never_inherits_owner_or_authority() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let owner = call(&mut backend, create(id(5), Kind::Public, None)).await;
    let request = json!({"op":"room.join_public","operation":id(6),
        "genesis":owner["genesis"],"pin":owner["pin"],"limits":limits()});
    let joined = call(&mut backend, request.clone()).await;
    assert_ne!(joined["author"], owner["author"]);
    assert_eq!(joined["pin"], owner["pin"]);
    assert_eq!(joined["created_here"], false);
    assert_eq!(joined["admission"], "needs_owner_admission");
    assert_eq!(joined["can_send"], false);
    assert!(backend
        .dispatch_admin(
            json!({"op":"room.send","room":id(6),"operation":id(7),"body":"not admitted"})
        )
        .await
        .is_err());
    assert!(backend.dispatch_admin(json!({"op":"public.set_writers","room":id(6),"operation":id(7),"writers":[owner["owner"],joined["author"]]})).await.is_err());
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    assert_eq!(
        call(&mut backend, request).await["author"],
        joined["author"]
    );
}

#[tokio::test]
async fn private_contact_flow_and_original_disclosure_retry_survive_membership_change() {
    let owner_home = Temp::new();
    let member_home = Temp::new();
    let mut owner = Backend::initialize(&owner_home.home).await.unwrap();
    let mut member = Backend::initialize(&member_home.home).await.unwrap();
    let valid = validity();
    let initial = call(
        &mut owner,
        create(id(8), Kind::Private, Some(valid.clone())),
    )
    .await;
    let send = json!({"op":"room.send","room":id(8),"operation":id(9),"body":"original recipients",
        "epoch":initial["epoch"],"roster":initial["roster"]});
    let original = call(&mut owner, send.clone()).await;
    let recipient = call(&mut member, json!({"op":"service.status"})).await["account"].clone();
    let offer_request = json!({"op":"private.offer","room":id(8),"operation":id(10),"recipient":recipient,"validity":valid});
    let offer = call(&mut owner, offer_request.clone()).await;
    assert_eq!(
        call(&mut owner, offer_request).await["offer"],
        offer["offer"]
    );
    let join = json!({"op":"room.join_private","operation":id(11),"offer":offer["offer"],
        "expected_owner":initial["context"]["account"],"validity":valid,"limits":limits()});
    let pending = call(&mut member, join.clone()).await;
    assert_eq!(pending["status"]["needs_owner_admission"], true);
    let accept = json!({"op":"private.accept_contact","room":id(8),"operation":id(12),
        "request":pending["request"],"validity":valid});
    let response = call(&mut owner, accept.clone()).await;
    assert_eq!(
        call(&mut owner, accept).await["artifact"],
        response["artifact"]
    );
    let joined = call(
        &mut member,
        json!({"op":"private.join_contact","room":id(11),"response":response["artifact"]}),
    )
    .await;
    assert_eq!(joined["phase"], "member_joined");
    assert_eq!(joined["can_send"], true);
    let changed = call(&mut owner, json!({"op":"room.status","room":id(8)})).await;
    assert_ne!(changed["roster"], initial["roster"]);
    assert_eq!(
        call(&mut owner, send.clone()).await["artifact"],
        original["artifact"]
    );
    let mut stale_fresh = send.clone();
    stale_fresh["operation"] = json!(id(13));
    assert_eq!(
        owner.dispatch_admin(stale_fresh).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    drop(owner);
    drop(member);
    let mut owner = Backend::open(&owner_home.home).await.unwrap();
    let mut member = Backend::open(&member_home.home).await.unwrap();
    let retry = call(&mut owner, send).await;
    assert_eq!(retry["artifact"], original["artifact"]);
    assert_eq!(retry["exact_retry"], true);
    let joined_again = call(&mut member, join).await;
    assert_eq!(joined_again["request"], pending["request"]);
    assert_eq!(
        joined_again["status"]["context"],
        pending["status"]["context"]
    );
    let outbox = call(
        &mut owner,
        json!({"op":"room.outbox_status","room":id(8),"after":0,"limit":16}),
    )
    .await;
    let encoded = serde_json::to_string(&outbox).unwrap();
    assert!(!encoded.contains(offer["offer"].as_str().unwrap()));
    assert!(outbox["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry.get("artifact").is_none()));
    let removed = call(&mut owner, json!({"op":"private.remove","room":id(8),"operation":id(14),"device":joined["context"]["device"]})).await;
    assert_eq!(removed["kind"], "removal");
}

#[tokio::test]
async fn incomplete_catalog_public_and_private_creation_recover_only_intact_native_state() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let public_request = create(id(15), Kind::Public, None);
    backend
        .catalog
        .reserve(id(15), Kind::Public, intent(public_request.clone()), None)
        .unwrap();
    let mut public = backend
        .account
        .create_public_room_bound(
            backend.room_path(id(15), Kind::Public),
            backend.catalog.slot(id(15)).unwrap().creation_nonce.0,
            Limits {
                max_records: 10_000,
                max_record_bytes: 8 * 1024 * 1024,
            }
            .public(),
        )
        .unwrap();
    let pin = public.room_id();
    let author = public.author_key();
    assert!(public.status().unwrap().created_here);
    drop(public);
    let private_request = create(id(16), Kind::Private, Some(validity()));
    backend
        .catalog
        .reserve(id(16), Kind::Private, intent(private_request.clone()), None)
        .unwrap();
    let Request::Create {
        validity: Some(interval),
        ..
    } = serde_json::from_value(private_request.clone()).unwrap()
    else {
        panic!()
    };
    let creation = backend
        .account
        .prepare_owner(interval.native().unwrap())
        .unwrap();
    let context = creation.context();
    backend.catalog.bind(id(16), locator(context)).unwrap();
    drop(
        creation
            .commit(
                backend.room_path(id(16), Kind::Private),
                Limits {
                    max_records: 10_000,
                    max_record_bytes: 8 * 1024 * 1024,
                }
                .private(),
            )
            .await
            .unwrap(),
    );
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    let recovered = call(&mut backend, public_request).await;
    assert_eq!(recovered["pin"], json!(Hex(*pin.as_bytes())));
    assert_eq!(recovered["author"], json!(Hex(author)));
    let recovered = call(&mut backend, private_request).await;
    assert_eq!(recovered["context"], json!(locator(context)));
    assert!(backend.catalog.slot(id(15)).unwrap().ready);
    assert!(backend.catalog.slot(id(16)).unwrap().ready);
}

#[tokio::test]
async fn interrupted_creation_is_preserved_and_one_failed_slot_does_not_block_other_rooms() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let pending = create(id(17), Kind::Public, None);
    backend
        .catalog
        .reserve(id(17), Kind::Public, intent(pending.clone()), None)
        .unwrap();
    let pending_path = backend.room_path(id(17), Kind::Public);
    custody::create_private_directory(&pending_path).unwrap();
    let marker = pending_path.join("keep-partial");
    fs::write(&marker, b"retained diagnostic evidence").unwrap();
    let working = call(
        &mut backend,
        create(id(18), Kind::Private, Some(validity())),
    )
    .await;
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    assert_eq!(
        backend
            .dispatch_admin(pending.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::OwnerUnavailable
    );
    assert_eq!(
        backend.dispatch_admin(pending).await.unwrap_err().code,
        ErrorCode::OwnerUnavailable
    );
    assert_eq!(fs::read(&marker).unwrap(), b"retained diagnostic evidence");
    assert!(!pending_path.join("author").exists());
    let status = call(&mut backend, json!({"op":"room.status","room":id(18)})).await;
    assert_eq!(status["context"], working["context"]);
    assert_eq!(
        call(&mut backend, json!({"op":"service.status"})).await["failed_rooms"],
        1
    );
    assert!(backend
        .dispatch_admin(json!({"op":"room.reopen","room":id(17)}))
        .await
        .is_err());
    assert_eq!(fs::read(&marker).unwrap(), b"retained diagnostic evidence");
}

#[tokio::test]
async fn foreign_or_joined_native_state_cannot_complete_an_owner_creation() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let existing = call(&mut backend, create(id(19), Kind::Public, None)).await;
    let pending = create(id(20), Kind::Public, None);
    backend
        .catalog
        .reserve(id(20), Kind::Public, intent(pending.clone()), None)
        .unwrap();
    let genesis: Artifact = serde_json::from_value(existing["genesis"].clone()).unwrap();
    let pin: Hash = serde_json::from_value(existing["pin"].clone()).unwrap();
    drop(
        backend
            .account
            .join_public_room(
                backend.room_path(id(20), Kind::Public),
                &genesis.0,
                PublicRoomId::from_bytes(pin.0),
                Limits {
                    max_records: 10_000,
                    max_record_bytes: 8 * 1024 * 1024,
                }
                .public(),
            )
            .unwrap(),
    );
    assert!(backend.dispatch_admin(pending).await.is_err());
    assert!(backend.catalog.slot(id(20)).unwrap().locator.is_none());

    let foreign_account = std::sync::Arc::new(
        Identity::create_new(temp.root.path().join("foreign-account")).unwrap(),
    );
    let request = create(id(21), Kind::Public, None);
    backend
        .catalog
        .reserve(id(21), Kind::Public, intent(request.clone()), None)
        .unwrap();
    let path = backend.room_path(id(21), Kind::Public);
    drop(
        public::RoomSession::create(
            foreign_account,
            &path,
            Limits {
                max_records: 10_000,
                max_record_bytes: 8 * 1024 * 1024,
            }
            .public(),
        )
        .unwrap(),
    );
    assert!(backend.dispatch_admin(request).await.is_err());
    assert!(path.join("author").exists());
    assert!(backend.catalog.slot(id(21)).unwrap().locator.is_none());

    // Same-account owner state still must prove this exact creation reservation.
    let request = create(id(26), Kind::Public, None);
    backend
        .catalog
        .reserve(id(26), Kind::Public, intent(request.clone()), None)
        .unwrap();
    let path = backend.room_path(id(26), Kind::Public);
    let wrong_nonce = [27; 32];
    assert_ne!(
        backend.catalog.slot(id(26)).unwrap().creation_nonce.0,
        wrong_nonce
    );
    drop(
        backend
            .account
            .create_public_room_bound(
                &path,
                wrong_nonce,
                Limits {
                    max_records: 10_000,
                    max_record_bytes: 8 * 1024 * 1024,
                }
                .public(),
            )
            .unwrap(),
    );
    assert_eq!(
        backend.dispatch_admin(request).await.unwrap_err().code,
        ErrorCode::OwnerUnavailable
    );
    assert!(path.join("author").exists());
    assert!(backend.catalog.slot(id(26)).unwrap().locator.is_none());
}

#[tokio::test]
async fn malformed_requests_do_not_reserve_slots_or_treat_paths_as_room_ids() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let baseline = backend.catalog.accounting().unwrap();
    for value in [
        json!({"op":"service.status","path":"/tmp/elsewhere"}),
        json!({"op":"room.list","unknown":true}),
        json!({"op":"room.status","room":"../account"}),
        json!({"op":"room.status","room":"AA".repeat(16)}),
        json!({"op":"room.status","room":"00".repeat(16)}),
        json!({"op":"room.create","operation":id(22),"kind":"public","limits":limits(),"path":"elsewhere"}),
        json!({"op":"room.create","operation":id(22),"kind":"private","limits":limits()}),
        json!({"op":"room.create","operation":id(22),"kind":"public","limits":{"max_records":0,"max_record_bytes":10}}),
        json!({"op":"room.join_public","operation":id(22),"pin":Hex([1;32]),"genesis":"GG","limits":limits()}),
        json!({"op":"room.join_private","operation":id(22),"offer":"ab".repeat(MAX_ARTIFACT+1),"expected_owner":Hex([1;32]),"validity":validity(),"limits":limits()}),
        json!({"op":"grant.issue"}),
        json!({"op":"sync.start"}),
    ] {
        assert!(backend.dispatch_admin(value).await.is_err());
    }
    assert_eq!(backend.catalog.accounting().unwrap(), baseline);
    assert!(backend.catalog.slots().is_empty());
    assert!(backend
        .dispatch_admin(json!({"op":"room.status","room":id(23)}))
        .await
        .is_err());
    assert!(backend.failed_rooms.is_empty());
    assert!(!backend.room_path(id(23), Kind::Public).exists());
}

#[tokio::test]
async fn replaced_parent_is_latched_and_existing_only_open_preserves_partial_home() {
    let temp = Temp::new();
    assert!(Backend::open(&temp.home).await.is_err());
    assert!(fs::read_dir(&temp.home).unwrap().next().is_none());
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let status = call(&mut backend, create(id(24), Kind::Public, None)).await;
    let identity = fs::read(temp.home.join("account/identity")).unwrap();
    assert!(Backend::initialize(&temp.home).await.is_err());
    assert_eq!(
        fs::read(temp.home.join("account/identity")).unwrap(),
        identity
    );
    let old = temp.home.join("old-public");
    fs::rename(temp.home.join("rooms/public"), &old).unwrap();
    symlink(&old, temp.home.join("rooms/public")).unwrap();
    assert_eq!(
        backend
            .dispatch_admin(json!({"op":"room.status","room":id(24)}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    fs::remove_file(temp.home.join("rooms/public")).unwrap();
    fs::rename(old, temp.home.join("rooms/public")).unwrap();
    assert_eq!(
        backend
            .dispatch_admin(json!({"op":"service.status"}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::OwnerUnavailable
    );
    drop(backend);
    let mut reopened = Backend::open(&temp.home).await.unwrap();
    assert_eq!(
        call(&mut reopened, json!({"op":"room.status","room":id(24)})).await["author"],
        status["author"]
    );
}

#[test]
fn typed_creation_intent_is_canonical_and_response_encoding_is_bounded() {
    let first = create(id(25), Kind::Public, None);
    let second = json!({"limits":limits(),"operation":id(25),"op":"room.create","kind":"public"});
    assert_eq!(intent(first), intent(second));
    assert!(bound_response(&json!({"body":"\u{1}".repeat(MAX_RESPONSE / 6 + 1)})).is_err());
    assert!(bound_response(&json!({"body":"small"})).is_ok());
}

#[path = "backend_provenance_tests.rs"]
mod provenance;
