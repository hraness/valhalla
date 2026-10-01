use super::*;
use hegel::HealthCheck;
use iroh::SecretKey;
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::Waker,
};
use tempfile::TempDir;
use vhalla_direct_native::ReplicaFrame;
use vhalla_direct_room::{EventClaims, EventId, Text, UnsignedEvent};
use vhalla_direct_sync::FrameKind;
use vhalla_identity::Identity;

const LOCAL_KEY: [u8; 32] = [71; 32];
fn id(value: u8) -> Id {
    Hex([value; 16])
}
fn local_id() -> Hash {
    Hex(*SecretKey::from_bytes(&LOCAL_KEY).public().as_bytes())
}
fn source(value: u8, port: u16) -> network::Source {
    network::Source {
        endpoint_id: SecretKey::from_bytes(&[value; 32]).public().to_string(),
        relay_url: None,
        addresses: vec![format!("127.0.0.1:{port}").parse().unwrap()],
    }
}
fn limits() -> Limits {
    Limits {
        max_records: 10_000,
        max_record_bytes: 8 * 1024 * 1024,
    }
}

struct Fixture {
    root: TempDir,
    account: Arc<Identity>,
    room: RoomSession,
}
impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let account = Arc::new(Identity::create_new(root.path().join("account")).unwrap());
        let room =
            RoomSession::create(account.clone(), root.path().join("room"), limits()).unwrap();
        Self {
            root,
            account,
            room,
        }
    }
    fn path(&self) -> PathBuf {
        self.root.path().join("sync")
    }
    fn account_id(&self) -> Hash {
        Hex(self.account.public_key())
    }
    fn manager(&self) -> PublicSync {
        PublicSync::create_new(&self.path(), self.account_id(), local_id()).unwrap()
    }
    fn open(&self) -> PublicSync {
        PublicSync::open(&self.path(), self.account_id(), local_id()).unwrap()
    }
    fn published(&mut self) -> PublicSync {
        let mut manager = self.manager();
        manager.publish(id(1), id(1), &mut self.room).unwrap();
        manager
    }
    fn remote(&self, number: u8, count: usize) -> Replica {
        let remote = source_id(&source(number, 12345)).unwrap();
        let mut replica = Replica::create_new(
            self.root.path().join(format!("remote-{number}")),
            self.room.genesis().clone(),
            remote.0,
            limits(),
        )
        .unwrap();
        let mut previous = EventId::ZERO;
        for sequence in 1..count {
            let signed = self
                .account
                .sign_direct_event(
                    UnsignedEvent::new(EventClaims {
                        room: self.room.room_id(),
                        policy: self.room.room_id().initial_policy(),
                        author: self.account.public_key(),
                        sequence: sequence as u64,
                        previous,
                        created_at: sequence as u64,
                        text: Text::new(&format!("remote {number} event {sequence}")).unwrap(),
                    })
                    .unwrap(),
                )
                .unwrap();
            previous = signed.id();
            let frame = ReplicaFrame {
                kind: FrameKind::Event,
                bytes: signed.encode(),
            };
            replica.append(&[frame.as_frame()]).unwrap();
        }
        replica
    }
}

fn prepare(manager: &mut PublicSync, slot: Id, peer: Hash) -> Option<peer::Request> {
    let published = manager.metadata.slot(slot).unwrap().clone();
    let mut runtime = manager.runtime.remove(&slot).unwrap();
    let request = manager
        .prepare_request(slot, peer, &published, &mut runtime)
        .unwrap();
    manager.runtime.insert(slot, runtime);
    request
}
fn queue(
    manager: &mut PublicSync,
    slot: Id,
    peer: Hash,
    request: peer::Request,
    outcome: std::result::Result<peer::AuthenticatedReply, peer::PeerError>,
) {
    let selection = manager.metadata.slot(slot).unwrap().selected[&peer].operation;
    manager.completed.push_back(Completed {
        slot,
        peer,
        selection,
        request,
        outcome,
        observation: None,
    });
}
fn answer(request: &peer::Request, replica: &mut Replica, genesis: &PinnedGenesis) -> peer::Reply {
    match request {
        peer::Request::Genesis { .. } => peer::Reply::Genesis(genesis.encode()),
        peer::Request::Head { .. } => peer::Reply::Head(replica.checkpoint().unwrap()),
        peer::Request::Page {
            checkpoint,
            after,
            limit,
            ..
        } => peer::Reply::Page(replica.page(*checkpoint, *after, *limit).unwrap()),
    }
}
fn exchange(manager: &mut PublicSync, room: &mut RoomSession, peer: Hash, replica: &mut Replica) {
    let request = prepare(manager, id(1), peer).unwrap();
    let reply = answer(&request, replica, room.genesis());
    queue(
        manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply,
        }),
    );
    manager.tick_room(id(1), room, None).unwrap();
}
fn verified(manager: &PublicSync, peer: Hash) -> FollowerStatus {
    manager.runtime[&id(1)].sources[&peer].status.unwrap()
}

fn transport_observation() -> peer::PathObservation {
    let snapshot = peer::PathSnapshot {
        selected: peer::SelectedPath::Relay,
        nonempty: true,
        all_relay: true,
    };
    peer::PathObservation {
        before: snapshot,
        after: snapshot,
    }
}

#[test]
fn transport_observations_belong_only_to_the_current_live_source_selection() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let peer = source_id(&source(80, 10000)).unwrap();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    for reset in 0..3 {
        assert!(manager.status(id(1)).unwrap()["selected_sources"][0]
            ["last_transport_observation"]
            .is_null());
        let request = prepare(&mut manager, id(1), peer).unwrap();
        assert!(matches!(request, peer::Request::Genesis { .. }));
        queue(
            &mut manager,
            id(1),
            peer,
            request,
            Ok(peer::AuthenticatedReply {
                source: peer.0,
                reply: peer::Reply::Genesis(fixture.room.genesis().encode()),
            }),
        );
        manager.completed.back_mut().unwrap().observation = Some(transport_observation());
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert_eq!(
            manager.status(id(1)).unwrap()["selected_sources"][0]["last_transport_observation"],
            serde_json::to_value(transport_observation()).unwrap()
        );
        match reset {
            0 => {
                manager
                    .configure_source(id(3), id(1), source(80, 10001))
                    .unwrap();
            }
            1 => {
                manager.reopen_room(id(1), &mut fixture.room).unwrap();
            }
            _ => {
                drop(manager);
                manager = fixture.open();
                manager.publish(id(1), id(1), &mut fixture.room).unwrap();
            }
        }
        assert!(manager.status(id(1)).unwrap()["selected_sources"][0]
            ["last_transport_observation"]
            .is_null());
    }
}

#[test]
fn failed_foreign_and_obsolete_replies_cannot_supply_transport_observations() {
    for failure in 0..3 {
        let mut fixture = Fixture::new();
        let mut manager = fixture.published();
        let peer = source_id(&source(80, 10000)).unwrap();
        manager
            .configure_source(id(2), id(1), source(80, 10000))
            .unwrap();
        let request = prepare(&mut manager, id(1), peer).unwrap();
        let outcome = if failure == 0 {
            Err(peer::PeerError::Timeout)
        } else {
            Ok(peer::AuthenticatedReply {
                source: if failure == 1 { [99; 32] } else { peer.0 },
                reply: peer::Reply::Genesis(fixture.room.genesis().encode()),
            })
        };
        queue(&mut manager, id(1), peer, request, outcome);
        let completed = manager.completed.back_mut().unwrap();
        completed.observation = Some(transport_observation());
        if failure == 2 {
            completed.selection = id(99);
        }
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert!(manager.runtime[&id(1)].sources[&peer]
            .last_transport_observation
            .is_none());
        assert!(manager.status(id(1)).unwrap()["selected_sources"][0]
            ["last_transport_observation"]
            .is_null());
    }
}

#[test]
fn publication_is_explicit_native_bound_and_lazy_after_restart() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.manager();
    let room = fixture.room.room_id();
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }),
        Err(peer::PeerError::Unavailable)
    );
    assert!(manager
        .publish(Hex([0; 16]), id(1), &mut fixture.room)
        .is_err());
    assert!(manager.metadata.ids().next().is_none());
    manager.publish(id(1), id(1), &mut fixture.room).unwrap();
    let first = manager.peer_request(peer::Request::Head { room }).unwrap();
    assert!(
        matches!(manager.peer_request(peer::Request::Genesis { room }).unwrap(), peer::Reply::Genesis(raw) if raw == fixture.room.genesis().encode())
    );
    assert!(manager.publish(id(2), id(1), &mut fixture.room).is_err());
    assert!(manager.publish(id(2), id(2), &mut fixture.room).is_err());
    drop(manager);
    assert!(PublicSync::open(&fixture.path(), Hex([33; 32]), local_id()).is_err());
    assert!(PublicSync::open(&fixture.path(), fixture.account_id(), Hex([34; 32])).is_err());
    let mut manager = fixture.open();
    assert!(manager.runtime.is_empty());
    assert_eq!(manager.status(id(1)).unwrap()["state"], "unopened");
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }),
        Err(peer::PeerError::Unavailable)
    );
    manager.publish(id(1), id(1), &mut fixture.room).unwrap();
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }).unwrap(),
        first
    );
}

#[test]
fn publication_crash_boundaries_preserve_partial_state_without_reinitializing() {
    for point in [
        FaultPoint::PublishIntent,
        FaultPoint::ReplicaCreated,
        FaultPoint::ProjectionCreated,
        FaultPoint::PublishReady,
    ] {
        let mut fixture = Fixture::new();
        let mut manager = fixture.manager();
        manager.fault = Some(point);
        assert!(manager.publish(id(1), id(1), &mut fixture.room).is_err());
        let path = manager.path(id(1));
        drop(manager);
        let before = if point != FaultPoint::PublishIntent {
            let mut replica = Replica::open(
                path.join("replica"),
                fixture.room.genesis().clone(),
                local_id().0,
            )
            .unwrap();
            Some(replica.checkpoint().unwrap())
        } else {
            None
        };
        let mut manager = fixture.open();
        assert!(manager.runtime.is_empty());
        let retry = manager.publish(id(1), id(1), &mut fixture.room);
        if matches!(
            point,
            FaultPoint::PublishIntent | FaultPoint::ReplicaCreated
        ) {
            assert!(retry.is_err());
            assert!(manager.metadata.slot(id(1)).unwrap().ready.is_none());
            assert!(!path.join("projection").exists());
            if point == FaultPoint::PublishIntent {
                assert!(!path.exists());
            }
            drop(manager);
            if let Some(before) = before {
                let mut replica = Replica::open(
                    path.join("replica"),
                    fixture.room.genesis().clone(),
                    local_id().0,
                )
                .unwrap();
                assert_eq!(replica.checkpoint().unwrap(), before);
            }
        } else {
            assert!(retry.is_ok());
            assert_eq!(
                manager
                    .runtime
                    .get_mut(&id(1))
                    .unwrap()
                    .replica
                    .checkpoint()
                    .unwrap(),
                before.unwrap()
            );
        }
    }
}

#[test]
fn old_configuration_retries_never_restore_obsolete_settings_and_bounds_hold() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let original = source(80, 10001);
    let peer = source_id(&original).unwrap();
    manager
        .configure_source(id(2), id(1), original.clone())
        .unwrap();
    manager
        .configure_source(id(3), id(1), source(80, 10002))
        .unwrap();
    manager.disable_source(id(4), id(1), peer).unwrap();
    manager
        .configure_source(id(2), id(1), original.clone())
        .unwrap();
    assert!(manager.metadata.slot(id(1)).unwrap().selected.is_empty());
    manager
        .configure_source(id(5), id(1), source(80, 10003))
        .unwrap();
    manager.disable_source(id(4), id(1), peer).unwrap();
    assert_eq!(
        manager.metadata.slot(id(1)).unwrap().selected[&peer].source,
        source(80, 10003)
    );
    assert!(manager
        .configure_source(id(2), id(1), source(80, 10009))
        .is_err());
    assert!(manager.disable_source(id(2), id(1), peer).is_err());
    assert!(manager
        .configure_source(
            id(6),
            id(1),
            network::Source {
                endpoint_id: local_id().to_string(),
                relay_url: None,
                addresses: vec!["127.0.0.1:12345".parse().unwrap()]
            }
        )
        .is_err());
    for number in 81..88 {
        manager
            .configure_source(id(number), id(1), source(number, 10000))
            .unwrap();
    }
    assert!(manager
        .configure_source(id(88), id(1), source(88, 10000))
        .is_err());
    drop(manager);
    let mut manager = fixture.open();
    manager.configure_source(id(2), id(1), original).unwrap();
    manager.disable_source(id(4), id(1), peer).unwrap();
    assert_eq!(
        manager.metadata.slot(id(1)).unwrap().selected.len(),
        MAX_SOURCES
    );
    assert_eq!(
        manager.metadata.slot(id(1)).unwrap().selected[&peer].source,
        source(80, 10003)
    );
}

#[test]
fn full_metadata_refuses_new_source_target_without_fencing_native_or_existing_receipts() {
    let mut fixture = Fixture::new();
    drop(fixture.manager());
    let path = fixture.path().canonicalize().unwrap().join("metadata");
    let context = disk::Store::locate_context(&path).unwrap();
    let mut original = disk::Store::open(&path, context).unwrap();
    let empty = original.load().unwrap().unwrap();
    drop(original);
    fs::rename(&path, path.with_extension("preserved")).unwrap();
    let mut limited = disk::Store::create_new(
        &path,
        context,
        Limits {
            max_records: 3,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    limited.publish(None, &empty, &[]).unwrap();
    drop(limited);

    let mut manager = fixture.open();
    manager.publish(id(1), id(1), &mut fixture.room).unwrap();
    let selected = source(80, 10000);
    let peer = source_id(&selected).unwrap();
    manager
        .configure_source(id(2), id(1), selected.clone())
        .unwrap();
    assert_eq!(
        manager
            .configure_source(id(3), id(1), source(81, 10000))
            .unwrap_err()
            .code,
        ErrorCode::Usage
    );
    let mut remote = fixture.remote(80, 2);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);

    manager.check().unwrap();
    assert!(!manager.failed);
    assert!(manager.fenced.is_empty());
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert!(manager.runtime[&id(1)].sources[&peer].status.is_none());
    assert!(manager
        .metadata
        .initial_target(id(1), peer)
        .unwrap()
        .is_none());
    assert!(!manager
        .path(id(1))
        .join("followers")
        .join(peer.to_string())
        .exists());
    assert_eq!(manager.status(id(1)).unwrap()["state"], "ready");
    manager.configure_source(id(2), id(1), selected).unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    fixture
        .room
        .send(
            [99; 16],
            "healthy native room after source capacity refusal",
            1,
        )
        .unwrap();
    assert!(manager
        .peer_request(peer::Request::Head {
            room: fixture.room.room_id()
        })
        .is_ok());
}

#[test]
fn coherent_saved_selection_cannot_override_replayed_immutable_events() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    drop(manager);

    let path = fixture.path().canonicalize().unwrap().join("metadata");
    let context = disk::Store::locate_context(&path).unwrap();
    let mut original = disk::Store::open(&path, context).unwrap();
    let image = String::from_utf8(original.load().unwrap().unwrap()).unwrap();
    assert_eq!(image.matches("127.0.0.1:10000").count(), 1);
    let forged = image
        .replacen("127.0.0.1:10000", "127.0.0.1:10001", 1)
        .into_bytes();
    let accounting = original.accounting().unwrap();
    let records = original.page(0, 32).unwrap().records;
    assert_eq!(records.len() as u64, accounting.records);
    drop(original);
    fs::rename(&path, path.with_extension("preserved")).unwrap();

    // Rebuild coherent store digests, counts, bytes and generation, retaining
    // the actual original event history. Only semantic replay exposes the lie.
    let mut forged_store = disk::Store::create_new(&path, context, accounting.limits).unwrap();
    forged_store.publish(None, &forged, &[]).unwrap();
    for entry in records {
        let record = disk::Record::new(entry.key, &entry.data).unwrap();
        forged_store
            .publish(Some(&forged), &forged, &[record])
            .unwrap();
    }
    assert_eq!(forged_store.accounting().unwrap(), accounting);
    drop(forged_store);
    assert!(PublicSync::open(&fixture.path(), fixture.account_id(), local_id()).is_err());
    assert!(fixture.room.status().unwrap().can_send);
}

#[test]
fn clean_projection_and_replica_capacity_stop_sync_without_fencing_native_custody() {
    for component in ["projection", "replica"] {
        let mut fixture = Fixture::new();
        let mut manager = fixture.published();
        let peer = source_id(&source(80, 10000)).unwrap();
        manager
            .configure_source(id(2), id(1), source(80, 10000))
            .unwrap();
        fixture
            .room
            .send([51; 16], "public frame awaiting capacity", 1)
            .unwrap();
        let path = manager.path(id(1)).join(component);
        drop(manager);

        let context = disk::Store::locate_context(&path).unwrap();
        let mut original = disk::Store::open(&path, context).unwrap();
        let image = original.load().unwrap().unwrap();
        let accounting = original.accounting().unwrap();
        let records: Vec<_> = original
            .page(0, 32)
            .unwrap()
            .records
            .into_iter()
            .map(|entry| disk::Record::new(entry.key, &entry.data).unwrap())
            .collect();
        assert_eq!(accounting.generation, 1);
        assert_eq!(records.len() as u64, accounting.records);
        drop(original);
        fs::rename(&path, path.with_extension("preserved")).unwrap();
        let mut limited = disk::Store::create_new(
            &path,
            context,
            Limits {
                max_records: 1,
                max_record_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap();
        limited.publish(None, &image, &records).unwrap();
        let after = limited.accounting().unwrap();
        assert_eq!(after.generation, accounting.generation);
        assert_eq!(after.records, accounting.records);
        assert_eq!(after.bytes, accounting.bytes);
        drop(limited);

        let mut manager = fixture.open();
        let dropped = Arc::new(AtomicUsize::new(0));
        manager.flights.push(Flight {
            slot: id(1),
            peer,
            selection: id(2),
            request: peer::Request::Head {
                room: fixture.room.room_id(),
            },
            future: Box::pin(PendingRead(dropped.clone())),
        });
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(manager.status(id(1)).unwrap()["state"], "capacity");
        assert!(manager.fenced_rooms().is_empty());
        let pending = manager.runtime[&id(1)].projected.pending;
        assert_eq!(pending.is_some(), component == "replica");
        assert!(manager
            .peer_request(peer::Request::Head {
                room: fixture.room.room_id()
            })
            .is_ok());
        fixture
            .room
            .send([52; 16], "native signing remains available", 2)
            .unwrap();
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert_eq!(manager.runtime[&id(1)].projected.pending, pending);

        // Reopen alone neither erases the stop nor resets its pending transfer.
        assert_eq!(
            manager.reopen_room(id(1), &mut fixture.room).unwrap()["state"],
            "capacity"
        );
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert_eq!(manager.status(id(1)).unwrap()["state"], "capacity");
        assert_eq!(manager.runtime[&id(1)].projected.pending, pending);
        assert!(manager.fenced_rooms().is_empty());

        let selected = if component == "projection" {
            StorageComponent::Projection {}
        } else {
            StorageComponent::Replica {}
        };
        let target = || {
            serde_json::from_value(json!({
                "max_records":limits().max_records,
                "max_record_bytes":limits().max_record_bytes,
            }))
            .unwrap()
        };
        let before = manager.storage_status(id(1), &mut fixture.room).unwrap();
        let grown = manager
            .expand_storage(id(1), &mut fixture.room, selected, target())
            .unwrap();
        assert_eq!(
            manager
                .expand_storage(id(1), &mut fixture.room, selected, target())
                .unwrap(),
            grown
        );
        assert_eq!(grown["storage"]["records"], before[component]["records"]);
        assert_eq!(grown["storage"]["bytes"], before[component]["bytes"]);
        assert_eq!(
            grown["storage"]["generation"],
            before[component]["generation"]
        );
        let smaller =
            serde_json::from_value(json!({"max_records":1,"max_record_bytes":8*1024*1024}))
                .unwrap();
        assert_eq!(
            manager
                .expand_storage(id(1), &mut fixture.room, selected, smaller)
                .unwrap_err()
                .code,
            ErrorCode::Usage
        );
        assert_eq!(manager.runtime[&id(1)].projected.pending, pending);
        assert_eq!(manager.status(id(1)).unwrap()["state"], "capacity");
        assert_eq!(
            manager.reopen_room(id(1), &mut fixture.room).unwrap()["state"],
            "capacity"
        );
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        assert_eq!(manager.status(id(1)).unwrap()["state"], "ready");
        assert!(manager.fenced_rooms().is_empty());
        let grown_usage = manager.storage_status(id(1), &mut fixture.room).unwrap();
        drop(manager);
        let mut manager = fixture.open();
        let reopened_usage = manager.storage_status(id(1), &mut fixture.room).unwrap();
        assert_eq!(reopened_usage[component], grown_usage[component]);
        assert_eq!(reopened_usage["metadata_expandable"], false);
    }
}

#[test]
fn full_follower_can_grow_while_stopped_then_finish_the_original_snapshot() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 12);
    let mut manager = fixture.published();
    let peer = source_id(&source(80, 10000)).unwrap();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    for _ in 0..2 {
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    }
    let before = verified(&manager, peer);
    let path = manager.path(id(1)).join("followers").join(peer.to_string());
    drop(manager);
    let context = disk::Store::locate_context(&path).unwrap();
    let mut original = disk::Store::open(&path, context).unwrap();
    let image = original.load().unwrap().unwrap();
    let usage = original.accounting().unwrap();
    let rows = original.page(0, 32).unwrap();
    assert!(rows.next.is_none());
    let records: Vec<_> = rows
        .records
        .into_iter()
        .map(|entry| disk::Record::new(entry.key, &entry.data).unwrap())
        .collect();
    drop(original);
    fs::rename(&path, path.with_extension("preserved")).unwrap();
    let mut limited = disk::Store::create_new(
        &path,
        context,
        Limits {
            max_records: usage.records,
            max_record_bytes: usage.limits.max_record_bytes,
        },
    )
    .unwrap();
    limited.publish(None, &image, &records).unwrap();
    drop(limited);
    let mut manager = fixture.open();
    manager.storage_status(id(1), &mut fixture.room).unwrap();
    exchange(&mut manager, &mut fixture.room, peer, &mut remote); // genesis after reopen
    exchange(&mut manager, &mut fixture.room, peer, &mut remote); // full follower refuses page
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert!(manager.runtime[&id(1)].sources[&peer].follower.is_none());
    assert_eq!(verified(&manager, peer), before);
    let target = serde_json::from_value(json!({
        "max_records":usage.limits.max_records,"max_record_bytes":usage.limits.max_record_bytes,
    }))
    .unwrap();
    manager
        .expand_storage(
            id(1),
            &mut fixture.room,
            StorageComponent::Follower { peer },
            target,
        )
        .unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert_eq!(verified(&manager, peer), before);
    assert!(manager.fenced_rooms().is_empty());
    manager.reopen_room(id(1), &mut fixture.room).unwrap();
    for _ in 0..5 {
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
        if verified(&manager, peer).coverage == Coverage::Complete {
            break;
        }
    }
    assert_eq!(verified(&manager, peer).target, before.target);
    assert_eq!(verified(&manager, peer).coverage, Coverage::Complete);
    assert!(manager.fenced_rooms().is_empty());
}

#[test]
fn follower_growth_keeps_progress_and_refusals_and_reopens_without_reset() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let mut remote = fixture.remote(80, 2);
    let peer = source_id(&source(80, 10000)).unwrap();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    for _ in 0..3 {
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    }
    let before = verified(&manager, peer);
    assert_eq!(before.coverage, Coverage::Complete);
    let original = manager.storage_status(id(1), &mut fixture.room).unwrap();
    let old_limits = &original["followers"][0]["storage"];
    let target = || {
        serde_json::from_value(json!({
            "max_records":old_limits["max_records"].as_u64().unwrap()+10,
            "max_record_bytes":old_limits["max_record_bytes"].as_u64().unwrap()+1024,
        }))
        .unwrap()
    };
    let component = StorageComponent::Follower { peer };
    let grown = manager
        .expand_storage(id(1), &mut fixture.room, component, target())
        .unwrap();
    assert_eq!(
        manager
            .expand_storage(id(1), &mut fixture.room, component, target())
            .unwrap(),
        grown
    );
    assert_eq!(verified(&manager, peer), before);
    for field in ["records", "bytes", "generation", "tip"] {
        assert_eq!(grown["storage"][field], old_limits[field]);
    }
    let request = prepare(&mut manager, id(1), peer).unwrap();
    let mut fork = before.target;
    fork.digest[0] ^= 1;
    queue(
        &mut manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply: peer::Reply::Head(fork),
        }),
    );
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    let refusal = manager.runtime[&id(1)].sources[&peer].error;
    manager
        .expand_storage(id(1), &mut fixture.room, component, target())
        .unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert_eq!(manager.runtime[&id(1)].sources[&peer].error, refusal);
    assert_eq!(verified(&manager, peer), before);
    let smaller = serde_json::from_value(json!({
        "max_records":old_limits["max_records"],"max_record_bytes":old_limits["max_record_bytes"],
    }))
    .unwrap();
    assert_eq!(
        manager
            .expand_storage(id(1), &mut fixture.room, component, smaller)
            .unwrap_err()
            .code,
        ErrorCode::Usage
    );
    drop(manager);
    let mut manager = fixture.open();
    let reopened = manager.storage_status(id(1), &mut fixture.room).unwrap();
    assert_eq!(reopened["followers"][0]["storage"], grown["storage"]);
    assert_eq!(verified(&manager, peer), before);
    let foreign = StorageComponent::Follower {
        peer: Hex([99; 32]),
    };
    assert_eq!(
        manager
            .expand_storage(id(1), &mut fixture.room, foreign, target())
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert!(manager.fenced_rooms().is_empty());
}

#[test]
fn selected_snapshot_coverage_and_native_projection_are_distinct_and_durable() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 12);
    let peer = source_id(&source(80, 10000)).unwrap();
    let target = remote.checkpoint().unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    exchange(&mut manager, &mut fixture.room, peer, &mut remote); // genesis
    exchange(&mut manager, &mut fixture.room, peer, &mut remote); // initial target
    assert_eq!(verified(&manager, peer).progress.records, 0);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote); // eight frames
    assert_eq!(verified(&manager, peer).progress.records, 8);
    assert_eq!(verified(&manager, peer).coverage, Coverage::Pending);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    let final_status = verified(&manager, peer);
    assert_eq!(final_status.target, target);
    assert_eq!(final_status.coverage, Coverage::Complete);
    let projection = manager.runtime[&id(1)].projected;
    assert!(projection.inward_cursor < projection.replica_tip);
    let backing = manager
        .runtime
        .get_mut(&id(1))
        .unwrap()
        .replica
        .checkpoint()
        .unwrap();
    drop(manager);
    let mut manager = fixture.open();
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert!(matches!(
        prepare(&mut manager, id(1), peer),
        Some(peer::Request::Genesis { .. })
    ));
    assert_eq!(verified(&manager, peer).target, target);
    assert_eq!(verified(&manager, peer).coverage, Coverage::Complete);
    assert_eq!(
        manager
            .runtime
            .get_mut(&id(1))
            .unwrap()
            .replica
            .checkpoint()
            .unwrap(),
        backing
    );
    for _ in 0..32 {
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    }
    let native = fixture.room.replicated_records(0, 32).unwrap();
    let remote_page = remote.page(target, 0, 32).unwrap().unwrap();
    for frame in remote_page.frames {
        assert!(native
            .records
            .iter()
            .any(|record| record.bytes == frame.bytes));
    }
    assert!(!fixture.room.status().unwrap().owner_forked);
}

#[test]
fn missing_source_files_are_not_recreated_and_other_sources_keep_working() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 2);
    let mut second = fixture.remote(81, 1);
    let peer = source_id(&source(80, 10000)).unwrap();
    let other = source_id(&source(81, 10000)).unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    for _ in 0..3 {
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    }
    let initial = manager
        .metadata
        .initial_target(id(1), peer)
        .unwrap()
        .unwrap();
    manager.disable_source(id(3), id(1), peer).unwrap();
    let path = manager.path(id(1)).join("followers").join(peer.to_string());
    fs::rename(&path, path.with_extension("preserved")).unwrap();
    manager
        .configure_source(id(4), id(1), source(80, 10001))
        .unwrap();
    assert!(prepare(&mut manager, id(1), peer).is_none());
    assert!(!path.exists());
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert_eq!(
        manager.metadata.initial_target(id(1), peer).unwrap(),
        Some(initial)
    );
    manager
        .configure_source(id(5), id(1), source(81, 10000))
        .unwrap();
    for _ in 0..3 {
        exchange(&mut manager, &mut fixture.room, other, &mut second);
    }
    assert_eq!(verified(&manager, other).coverage, Coverage::Complete);
    assert_eq!(manager.status(id(1)).unwrap()["state"], "ready");
}

#[test]
fn initial_target_intent_precedes_files_and_exact_reopen_preserves_its_epoch() {
    for point in [FaultPoint::TargetIntent, FaultPoint::FollowerCreated] {
        let mut fixture = Fixture::new();
        let mut remote = fixture.remote(80, 2);
        let peer = source_id(&source(80, 10000)).unwrap();
        let target = remote.checkpoint().unwrap();
        let mut manager = fixture.published();
        manager
            .configure_source(id(2), id(1), source(80, 10000))
            .unwrap();
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
        let request = prepare(&mut manager, id(1), peer).unwrap();
        queue(
            &mut manager,
            id(1),
            peer,
            request,
            Ok(peer::AuthenticatedReply {
                source: peer.0,
                reply: peer::Reply::Head(target),
            }),
        );
        manager.fault = Some(point);
        assert!(manager.tick_room(id(1), &mut fixture.room, None).is_err());
        let path = manager.path(id(1)).join("followers").join(peer.to_string());
        drop(manager);
        let mut manager = fixture.open();
        assert_eq!(
            manager.metadata.initial_target(id(1), peer).unwrap(),
            Some(target)
        );
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
        let request = prepare(&mut manager, id(1), peer);
        if point == FaultPoint::TargetIntent {
            assert!(request.is_none());
            assert!(!path.exists());
            assert!(manager.runtime[&id(1)].sources[&peer].blocked);
        } else {
            assert!(matches!(request, Some(peer::Request::Genesis { .. })));
            assert_eq!(verified(&manager, peer).target, target);
            assert_eq!(verified(&manager, peer).progress.records, 0);
            for _ in 0..2 {
                exchange(&mut manager, &mut fixture.room, peer, &mut remote);
            }
            assert_eq!(verified(&manager, peer).coverage, Coverage::Complete);
        }
    }
}

#[test]
fn foreign_initial_follower_target_is_refused_even_when_its_latest_epoch_is_valid() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 2);
    let peer = source_id(&source(80, 10000)).unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    let foreign = remote.checkpoint().unwrap();
    let mut prefix = vhalla_direct_sync::SourceAccumulator::new(
        peer.0,
        fixture.room.genesis().clone(),
        foreign.epoch,
    )
    .unwrap();
    let genesis = fixture.room.genesis().encode();
    prefix
        .push(vhalla_direct_sync::Frame {
            kind: FrameKind::Genesis,
            bytes: &genesis,
        })
        .unwrap();
    let request = prepare(&mut manager, id(1), peer).unwrap();
    queue(
        &mut manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply: peer::Reply::Head(prefix.checkpoint().unwrap()),
        }),
    );
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    let initial = verified(&manager, peer).target;
    manager.disable_source(id(3), id(1), peer).unwrap();
    let path = manager.path(id(1)).join("followers").join(peer.to_string());
    fs::rename(&path, path.with_extension("preserved")).unwrap();
    assert_eq!(foreign.epoch, initial.epoch);
    assert!(foreign.records > initial.records);
    let mut runtime = manager.runtime.remove(&id(1)).unwrap();
    let foreign_follower = Follower::create_new(
        &path,
        fixture.room.genesis().clone(),
        peer.0,
        peer.0,
        foreign,
        &mut runtime.replica,
        LEDGER_LIMITS,
    )
    .unwrap();
    drop(foreign_follower);
    manager.runtime.insert(id(1), runtime);
    manager
        .configure_source(id(4), id(1), source(80, 10000))
        .unwrap();
    assert!(prepare(&mut manager, id(1), peer).is_none());
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert_eq!(
        manager.metadata.initial_target(id(1), peer).unwrap(),
        Some(initial)
    );
}

#[test]
fn foreign_follower_backing_is_source_only_while_healthy_room_and_other_sources_continue() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 2);
    let peer = source_id(&source(80, 10000)).unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    let initial = verified(&manager, peer).target;
    manager.disable_source(id(3), id(1), peer).unwrap();
    let path = manager.path(id(1)).join("followers").join(peer.to_string());
    fs::rename(&path, path.with_extension("preserved")).unwrap();

    // Same pinned room, selected peer, and exact first target; only this source
    // ledger's local backing incarnation belongs to another otherwise valid log.
    let mut foreign_backing = Replica::create_new(
        fixture.root.path().join("foreign-backing"),
        fixture.room.genesis().clone(),
        local_id().0,
        DATA_LIMITS,
    )
    .unwrap();
    let foreign = Follower::create_new(
        &path,
        fixture.room.genesis().clone(),
        peer.0,
        peer.0,
        initial,
        &mut foreign_backing,
        LEDGER_LIMITS,
    )
    .unwrap();
    drop(foreign);
    drop(foreign_backing);
    manager
        .configure_source(id(4), id(1), source(80, 10000))
        .unwrap();
    assert!(prepare(&mut manager, id(1), peer).is_none());
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert!(manager.fenced_rooms().is_empty());
    assert_eq!(
        manager.metadata.initial_target(id(1), peer).unwrap(),
        Some(initial)
    );
    assert!(manager
        .peer_request(peer::Request::Head {
            room: fixture.room.room_id()
        })
        .is_ok());
    fixture
        .room
        .send([91; 16], "source refusal does not revoke native custody", 1)
        .unwrap();

    let mut other = fixture.remote(81, 2);
    let other_peer = source_id(&source(81, 10000)).unwrap();
    manager
        .configure_source(id(5), id(1), source(81, 10000))
        .unwrap();
    for _ in 0..3 {
        exchange(&mut manager, &mut fixture.room, other_peer, &mut other);
    }
    assert_eq!(verified(&manager, other_peer).coverage, Coverage::Complete);
    assert_eq!(manager.status(id(1)).unwrap()["state"], "ready");
    assert!(manager.fenced_rooms().is_empty());
}

#[test]
fn wrong_authentication_truncation_and_changed_source_epochs_never_claim_coverage() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 3);
    let peer = source_id(&source(80, 10000)).unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    let request = prepare(&mut manager, id(1), peer).unwrap();
    queue(
        &mut manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: [9; 32],
            reply: peer::Reply::Genesis(fixture.room.genesis().encode()),
        }),
    );
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert!(manager
        .metadata
        .initial_target(id(1), peer)
        .unwrap()
        .is_none());
    manager
        .configure_source(id(3), id(1), source(80, 10000))
        .unwrap();
    for _ in 0..2 {
        exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    }
    let request = prepare(&mut manager, id(1), peer).unwrap();
    queue(
        &mut manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply: peer::Reply::Page(None),
        }),
    );
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert_eq!(verified(&manager, peer).coverage, Coverage::Pending);
    assert_eq!(verified(&manager, peer).progress.records, 0);
    assert!(!manager.runtime[&id(1)].sources[&peer].blocked);
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    let complete = verified(&manager, peer);
    assert_eq!(complete.coverage, Coverage::Complete);
    let request = prepare(&mut manager, id(1), peer).unwrap();
    assert!(matches!(request, peer::Request::Head { .. }));
    queue(
        &mut manager,
        id(1),
        peer,
        request,
        Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply: peer::Reply::Head(Checkpoint {
                epoch: [42; 32],
                ..complete.target
            }),
        }),
    );
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert!(manager.runtime[&id(1)].sources[&peer].blocked);
    assert_eq!(verified(&manager, peer), complete);
    assert_eq!(manager.status(id(1)).unwrap()["state"], "ready");
}

#[test]
fn obsolete_completion_cannot_initialize_a_newly_configured_source() {
    let mut fixture = Fixture::new();
    let mut remote = fixture.remote(80, 1);
    let peer = source_id(&source(80, 10000)).unwrap();
    let mut manager = fixture.published();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    exchange(&mut manager, &mut fixture.room, peer, &mut remote);
    let old = Completed {
        slot: id(1),
        peer,
        selection: id(2),
        request: peer::Request::Head {
            room: fixture.room.room_id(),
        },
        outcome: Ok(peer::AuthenticatedReply {
            source: peer.0,
            reply: peer::Reply::Head(remote.checkpoint().unwrap()),
        }),
        observation: None,
    };
    manager
        .configure_source(id(3), id(1), source(80, 10001))
        .unwrap();
    prepare(&mut manager, id(1), peer).unwrap();
    manager.completed.push_back(old);
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert!(manager
        .metadata
        .initial_target(id(1), peer)
        .unwrap()
        .is_none());
    assert!(manager.runtime[&id(1)].sources[&peer].status.is_none());
}

#[test]
fn native_mismatch_and_room_directory_replacement_require_explicit_reopen() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let room = fixture.room.room_id();
    let mut other = RoomSession::create(
        fixture.account.clone(),
        fixture.root.path().join("other"),
        limits(),
    )
    .unwrap();
    assert!(manager.tick_room(id(1), &mut other, None).is_err());
    let native_failure = manager.fenced[&id(1)];
    manager.close_room(id(1));
    assert_eq!(manager.fenced[&id(1)], native_failure);
    assert_eq!(manager.fenced_rooms(), vec![id(1)]);
    assert!(manager.tick_room(id(1), &mut fixture.room, None).is_err());
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }),
        Err(peer::PeerError::Unavailable)
    );
    manager.reopen_room(id(1), &mut fixture.room).unwrap();
    assert!(manager.peer_request(peer::Request::Head { room }).is_ok());
    let path = manager.path(id(1));
    let preserved = path.with_extension("preserved");
    fs::rename(&path, &preserved).unwrap();
    Directory::create(&path).unwrap();
    assert!(manager.tick_room(id(1), &mut fixture.room, None).is_err());
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }),
        Err(peer::PeerError::Unavailable)
    );
    assert!(manager.reopen_room(id(1), &mut fixture.room).is_err());
    assert!(!path.join("replica").exists());
    assert!(preserved.join("replica").exists());
}

struct PendingRead(Arc<AtomicUsize>);
impl Future for PendingRead {
    type Output = std::result::Result<peer::ObservedReply, peer::PeerError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
impl Drop for PendingRead {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn reconfigure_disable_and_manager_drop_cancel_owned_futures_without_detaching() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let peer = source_id(&source(80, 10000)).unwrap();
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let flight = |selection| Flight {
        slot: id(1),
        peer,
        selection,
        request: peer::Request::Head {
            room: fixture.room.room_id(),
        },
        future: Box::pin(PendingRead(dropped.clone())),
    };
    manager.flights.push(flight(id(2)));
    manager
        .configure_source(id(3), id(1), source(80, 10001))
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    manager.flights.push(flight(id(3)));
    manager
        .configure_source(id(2), id(1), source(80, 10000))
        .unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    manager.disable_source(id(4), id(1), peer).unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    manager.flights.push(flight(id(3)));
    drop(manager);
    assert_eq!(dropped.load(Ordering::SeqCst), 3);
}

#[test]
fn explicit_native_reopen_releases_old_handles_and_global_invalidation_stays_closed() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let room = fixture.room.room_id();
    let source = source(80, 10000);
    let peer = source_id(&source).unwrap();
    manager
        .configure_source(id(2), id(1), source.clone())
        .unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    manager.flights.push(Flight {
        slot: id(1),
        peer,
        selection: id(2),
        request: peer::Request::Head { room },
        future: Box::pin(PendingRead(dropped.clone())),
    });
    let checkpoint = manager
        .runtime
        .get_mut(&id(1))
        .unwrap()
        .replica
        .checkpoint()
        .unwrap();
    manager.close_room(id(1));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(manager.runtime.is_empty());
    assert!(manager.next_room().is_none());
    assert!(manager.tick_room(id(1), &mut fixture.room, None).is_err());
    drop(fixture.room);
    fixture.room = RoomSession::open(
        fixture.account.clone(),
        fixture.root.path().join("room"),
        room,
    )
    .unwrap();
    manager.reopen_room(id(1), &mut fixture.room).unwrap();
    assert_eq!(
        manager.metadata.slot(id(1)).unwrap().selected[&peer].source,
        source
    );
    assert_eq!(
        manager
            .runtime
            .get_mut(&id(1))
            .unwrap()
            .replica
            .checkpoint()
            .unwrap(),
        checkpoint
    );
    manager.flights.push(Flight {
        slot: id(1),
        peer,
        selection: id(2),
        request: peer::Request::Head { room },
        future: Box::pin(PendingRead(dropped.clone())),
    });
    manager.invalidate();
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert!(manager.runtime.is_empty());
    assert!(manager.check().is_err());
    assert!(manager.reopen_room(id(1), &mut fixture.room).is_err());
    assert_eq!(
        manager.peer_request(peer::Request::Head { room }),
        Err(peer::PeerError::Unavailable)
    );
    drop(manager);
    let mut manager = fixture.open();
    manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    assert_eq!(
        manager
            .runtime
            .get_mut(&id(1))
            .unwrap()
            .replica
            .checkpoint()
            .unwrap(),
        checkpoint
    );
}

#[test]
fn replacing_global_metadata_cancels_only_manager_work_and_never_creates_state() {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let room = fixture.room.room_id();
    let dropped = Arc::new(AtomicUsize::new(0));
    manager.flights.push(Flight {
        slot: id(1),
        peer: Hex([9; 32]),
        selection: id(2),
        request: peer::Request::Head { room },
        future: Box::pin(PendingRead(dropped.clone())),
    });
    let path = fixture.path().join("metadata");
    let preserved = fixture.path().join("metadata-preserved");
    fs::rename(&path, &preserved).unwrap();
    Directory::create(&path).unwrap();
    assert!(manager.check().is_err());
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(manager.runtime.is_empty());
    assert!(manager.next_room().is_none());
    assert!(!path.join("FORMAT").exists());
    fixture
        .room
        .send([5; 16], "unrelated native custody is still usable", 1)
        .unwrap();
    drop(manager);
    assert!(PublicSync::open(&fixture.path(), fixture.account_id(), local_id()).is_err());
    assert!(preserved.join("FORMAT").exists());
}

async fn endpoint(key: [u8; 32]) -> Endpoint {
    peer::endpoint_builder()
        .secret_key(SecretKey::from_bytes(&key))
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn global_admission_and_maintenance_are_fair_independently_of_completions() {
    let mut fixture = Fixture::new();
    let endpoint = endpoint(LOCAL_KEY).await;
    let mut manager = fixture.published();
    let mut rooms = Vec::new();
    for number in 1..=6 {
        if number != 1 {
            let mut room = RoomSession::create(
                fixture.account.clone(),
                fixture.root.path().join(format!("room-{number}")),
                limits(),
            )
            .unwrap();
            manager.publish(id(number), id(number), &mut room).unwrap();
            rooms.push(room);
        }
        manager
            .configure_source(id(number + 20), id(number), source(80, 10000))
            .unwrap();
    }
    for _ in 0..MAX_FLIGHTS {
        manager.schedule_one(&endpoint).unwrap();
    }
    assert_eq!(
        manager
            .flights
            .iter()
            .map(|flight| flight.slot)
            .collect::<Vec<_>>(),
        (1..=4).map(id).collect::<Vec<_>>()
    );
    manager.schedule_one(&endpoint).unwrap();
    assert_eq!(manager.flights.len(), MAX_FLIGHTS);
    // A fast early room frees a permit; the fifth room gets it, then the sixth.
    manager.flights.remove(0);
    manager.schedule_one(&endpoint).unwrap();
    assert_eq!(manager.flights.last().unwrap().slot, id(5));
    manager.flights.remove(0);
    manager.schedule_one(&endpoint).unwrap();
    assert_eq!(manager.flights.last().unwrap().slot, id(6));
    assert_eq!(
        (0..12)
            .map(|_| manager.next_room().unwrap())
            .collect::<Vec<_>>(),
        (1..=6).chain(1..=6).map(id).collect::<Vec<_>>()
    );
    manager.flights[0].future = Box::pin(async { Err(peer::PeerError::Unavailable) });
    let mut cx = Context::from_waker(Waker::noop());
    assert!(manager.poll_network(&mut cx).is_ready());
    assert_eq!(manager.flights.len() + manager.completed.len(), MAX_FLIGHTS);
    manager.schedule_one(&endpoint).unwrap();
    assert_eq!(manager.flights.len() + manager.completed.len(), MAX_FLIGHTS);
    drop(manager);
    endpoint.close().await;
    drop(rooms);
}

#[tokio::test]
async fn source_rotation_is_fair_and_disabled_peers_do_not_consume_admission() {
    let mut fixture = Fixture::new();
    let endpoint = endpoint(LOCAL_KEY).await;
    let mut manager = fixture.published();
    let mut peers = Vec::new();
    for number in 80..83 {
        peers.push(source_id(&source(number, 10000)).unwrap());
        manager
            .configure_source(id(number), id(1), source(number, 10000))
            .unwrap();
    }
    peers.sort();
    let mut observed = Vec::new();
    for _ in 0..6 {
        manager.schedule_one(&endpoint).unwrap();
        observed.push(manager.flights.pop().unwrap().peer);
    }
    assert_eq!(
        observed,
        peers
            .iter()
            .chain(peers.iter())
            .copied()
            .collect::<Vec<_>>()
    );
    manager.disable_source(id(99), id(1), peers[0]).unwrap();
    for _ in 0..4 {
        manager.schedule_one(&endpoint).unwrap();
        assert_ne!(manager.flights.pop().unwrap().peer, peers[0]);
    }
    drop(manager);
    endpoint.close().await;
}

#[derive(Clone)]
struct Host {
    replica: Arc<Mutex<Replica>>,
    genesis: PinnedGenesis,
}
impl peer::Handler for Host {
    async fn handle(
        &self,
        _authenticated_peer: [u8; 32],
        request: peer::Request,
    ) -> std::result::Result<peer::Reply, peer::PeerError> {
        if request.room() != self.genesis.id() {
            return Err(peer::PeerError::Scope);
        }
        let mut replica = self.replica.lock().unwrap();
        Ok(answer(&request, &mut replica, &self.genesis))
    }
}

#[tokio::test]
async fn real_loopback_reads_complete_one_source_and_retained_signed_frames_reach_native() {
    let mut fixture = Fixture::new();
    let client_endpoint = endpoint(LOCAL_KEY).await;
    let server_endpoint = endpoint([80; 32]).await;
    let remote = fixture.remote(80, 11);
    let host = Host {
        replica: Arc::new(Mutex::new(remote)),
        genesis: fixture.room.genesis().clone(),
    };
    let target = host.replica.lock().unwrap().checkpoint().unwrap();
    let configured = network::Source {
        endpoint_id: server_endpoint.id().to_string(),
        relay_url: None,
        addresses: server_endpoint.addr().ip_addrs().copied().collect(),
    };
    let remote_id = source_id(&configured).unwrap();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(peer::serve(server_endpoint.clone(), host.clone(), stopped));
    let mut manager = fixture.published();
    manager.configure_source(id(2), id(1), configured).unwrap();
    manager
        .tick_room(id(1), &mut fixture.room, Some(&client_endpoint))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let slot = std::future::poll_fn(|cx| manager.poll_network(cx)).await;
            manager
                .tick_room(slot, &mut fixture.room, Some(&client_endpoint))
                .unwrap();
            if manager.runtime[&id(1)].sources[&remote_id]
                .status
                .is_some_and(|status| status.coverage == Coverage::Complete)
            {
                break;
            }
        }
    })
    .await
    .expect("bounded loopback completion");
    assert_eq!(verified(&manager, remote_id).target, target);
    for _ in 0..30 {
        manager.tick_room(id(1), &mut fixture.room, None).unwrap();
    }
    let native = fixture.room.replicated_records(0, 32).unwrap();
    let source_page = host
        .replica
        .lock()
        .unwrap()
        .page(target, 0, 32)
        .unwrap()
        .unwrap();
    for frame in source_page.frames {
        assert!(native
            .records
            .iter()
            .any(|record| record.bytes == frame.bytes));
    }
    drop(manager);
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    client_endpoint.close().await;
    server_endpoint.close().await;
}

#[hegel::test(test_cases = 64, suppress_health_check = [HealthCheck::TooSlow])]
fn interleaved_configuration_retries_reopen_and_native_growth_preserve_current_selection(
    tc: hegel::TestCase,
) {
    let mut fixture = Fixture::new();
    let mut manager = fixture.published();
    let peer = source_id(&source(80, 10000)).unwrap();
    let mut history: Vec<(u8, bool)> = Vec::new();
    let mut current: Option<u8> = None;
    let mut next_operation = 2u8;
    let mut next_message = 1u8;
    let steps = tc.draw(
        hegel::generators::integers::<usize>()
            .min_value(8)
            .max_value(24),
    );
    for _ in 0..steps {
        let command = tc.draw(hegel::generators::integers::<u8>().max_value(5));
        match command {
            0 | 1 => {
                let operation = next_operation;
                next_operation += 1;
                let enabled = command == 0;
                if enabled {
                    manager
                        .configure_source(
                            id(operation),
                            id(1),
                            source(80, 10000 + operation as u16),
                        )
                        .unwrap();
                    current = Some(operation);
                } else {
                    manager.disable_source(id(operation), id(1), peer).unwrap();
                    current = None;
                }
                history.push((operation, enabled));
            }
            2 | 3 if !history.is_empty() => {
                let selected =
                    tc.draw(hegel::generators::integers::<usize>().max_value(history.len() - 1));
                let (operation, originally_enabled) = history[selected];
                let enabled = if command == 2 {
                    originally_enabled
                } else {
                    !originally_enabled
                };
                let result = if enabled {
                    manager.configure_source(
                        id(operation),
                        id(1),
                        source(80, 10000 + operation as u16),
                    )
                } else {
                    manager.disable_source(id(operation), id(1), peer)
                };
                assert_eq!(result.is_ok(), command == 2);
            }
            4 => {
                drop(manager);
                manager = fixture.open();
            }
            5 => {
                fixture
                    .room
                    .send(
                        [next_message; 16],
                        &format!("local {next_message}"),
                        next_message as u64,
                    )
                    .unwrap();
                next_message += 1;
                manager.tick_room(id(1), &mut fixture.room, None).unwrap();
            }
            _ => {}
        }
        let selected = &manager.metadata.slot(id(1)).unwrap().selected;
        assert_eq!(selected.len(), usize::from(current.is_some()));
        assert_eq!(
            selected.get(&peer).map(|selected| selected.operation),
            current.map(id)
        );
        manager.check().unwrap();
    }
}
