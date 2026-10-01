//! Ordinary moved controller copies cannot satisfy a different local reservation.

use super::*;

fn join(operation: Id, owner: &Value) -> Value {
    json!({"op":"room.join_public","operation":operation,"genesis":owner["genesis"],
        "pin":owner["pin"],"limits":limits()})
}

#[tokio::test]
async fn moved_owner_and_joined_controllers_never_satisfy_pending_or_ready_join_slots() {
    for source_is_owner in [true, false] {
        for ready in [false, true] {
            let temp = Temp::new();
            let mut backend = Backend::initialize(&temp.home).await.unwrap();
            let owner = call(&mut backend, create(id(51), Kind::Public, None)).await;
            let source = if source_is_owner {
                id(51)
            } else {
                call(&mut backend, join(id(52), &owner)).await;
                id(52)
            };
            let target = id(53);
            let request = join(target, &owner);
            let pin: Hash = serde_json::from_value(owner["pin"].clone()).unwrap();
            if ready {
                call(&mut backend, request.clone()).await;
                drop(backend.rooms.remove(&target).unwrap());
                fs::rename(
                    backend.room_path(target, Kind::Public),
                    temp.root.path().join("original-target"),
                )
                .unwrap();
            } else {
                backend
                    .catalog
                    .reserve(
                        target,
                        Kind::Public,
                        intent(request.clone()),
                        Some(Locator::Public { pin }),
                    )
                    .unwrap();
            }
            let old_nonce = public_room(backend.rooms.get_mut(&source).unwrap())
                .unwrap()
                .creation_nonce();
            assert_ne!(
                old_nonce,
                backend.catalog.slot(target).unwrap().creation_nonce.0
            );
            drop(backend.rooms.remove(&source).unwrap());
            let target_path = backend.room_path(target, Kind::Public);
            fs::rename(backend.room_path(source, Kind::Public), &target_path).unwrap();
            let author_state = fs::read(target_path.join("author/identity")).unwrap();
            drop(backend);

            let mut backend = Backend::open(&temp.home).await.unwrap();
            assert_eq!(
                backend.dispatch_admin(request).await.unwrap_err().code,
                ErrorCode::OwnerUnavailable
            );
            assert!(!backend.rooms.contains_key(&target));
            assert_eq!(backend.catalog.slot(target).unwrap().ready, ready);
            assert_eq!(
                fs::read(target_path.join("author/identity")).unwrap(),
                author_state
            );
            let mut preserved = backend
                .account
                .open_public_room(&target_path, PublicRoomId::from_bytes(pin.0))
                .unwrap();
            assert_eq!(preserved.creation_nonce(), old_nonce);
            assert_eq!(preserved.status().unwrap().created_here, source_is_owner);
        }
    }
}

#[tokio::test]
async fn interrupted_same_slot_join_recovers_its_exact_author_and_local_nonce() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let owner = call(&mut backend, create(id(54), Kind::Public, None)).await;
    let target = id(55);
    let request = join(target, &owner);
    let pin: Hash = serde_json::from_value(owner["pin"].clone()).unwrap();
    let genesis: Artifact = serde_json::from_value(owner["genesis"].clone()).unwrap();
    backend
        .catalog
        .reserve(
            target,
            Kind::Public,
            intent(request.clone()),
            Some(Locator::Public { pin }),
        )
        .unwrap();
    let nonce = backend.catalog.slot(target).unwrap().creation_nonce.0;
    let native = backend
        .account
        .join_public_room_bound(
            backend.room_path(target, Kind::Public),
            &genesis.0,
            PublicRoomId::from_bytes(pin.0),
            nonce,
            Limits {
                max_records: 10_000,
                max_record_bytes: 8 * 1024 * 1024,
            }
            .public(),
        )
        .unwrap();
    let author = native.author_key();
    drop(native);
    assert!(!backend.catalog.slot(target).unwrap().ready);
    drop(backend);

    let mut backend = Backend::open(&temp.home).await.unwrap();
    let recovered = call(&mut backend, request.clone()).await;
    assert_eq!(recovered["author"], json!(Hex(author)));
    assert_eq!(recovered["created_here"], false);
    assert!(backend.catalog.slot(target).unwrap().ready);
    assert_eq!(
        public_room(backend.rooms.get_mut(&target).unwrap())
            .unwrap()
            .creation_nonce(),
        nonce
    );
    assert_eq!(recovered["genesis"], owner["genesis"]);
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    assert_eq!(
        call(&mut backend, request).await["author"],
        json!(Hex(author))
    );
}

#[tokio::test]
async fn completed_owner_slot_rejects_join_mode_even_when_local_nonce_matches() {
    let temp = Temp::new();
    let mut backend = Backend::initialize(&temp.home).await.unwrap();
    let target = id(56);
    let owner = call(&mut backend, create(target, Kind::Public, None)).await;
    let nonce = backend.catalog.slot(target).unwrap().creation_nonce.0;
    let genesis: Artifact = serde_json::from_value(owner["genesis"].clone()).unwrap();
    let pin: Hash = serde_json::from_value(owner["pin"].clone()).unwrap();
    let path = backend.room_path(target, Kind::Public);
    drop(backend.rooms.remove(&target).unwrap());
    fs::rename(&path, temp.root.path().join("preserved-owner")).unwrap();
    drop(
        backend
            .account
            .join_public_room_bound(
                &path,
                &genesis.0,
                PublicRoomId::from_bytes(pin.0),
                nonce,
                Limits {
                    max_records: 10_000,
                    max_record_bytes: 8 * 1024 * 1024,
                }
                .public(),
            )
            .unwrap(),
    );
    drop(backend);
    let mut backend = Backend::open(&temp.home).await.unwrap();
    assert_eq!(
        backend
            .dispatch_admin(json!({"op":"room.status","room":target}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::OwnerUnavailable
    );
    assert!(backend.catalog.slot(target).unwrap().ready);
    assert!(!backend.rooms.contains_key(&target));
    assert!(path.join("author/identity").exists());
}
