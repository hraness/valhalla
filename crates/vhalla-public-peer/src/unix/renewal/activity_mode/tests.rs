use super::*;
use crate::unix::tests::Fixture;
use vhalla_room_activity::RoomScope;
use vhalla_room_activity_store::{Limits, Store};
use vhalla_rooms::RoomGenesisId;

fn fixture() -> (Fixture, PathBuf, Config, ActivityConfig) {
    let fixture = Fixture::new();
    let state = fixture.dir.join("publisher");
    let mut config = fixture.config.clone();
    config.advertisement_file = state.join(ADVERTISEMENT);
    let loaded = Peer::load(&config).unwrap();
    let bootstrap = Bootstrap::decode(&loaded.raw, config.bootstrap_pin).unwrap();
    let client = CertifiedClient::new(bootstrap, config.bootstrap_pin).unwrap();
    let limits = Limits {
        max_events: 100,
        max_history_bytes: 1_000_000,
    };
    let mut rooms = Vec::new();
    for id in [5, 6] {
        let room = RoomGenesisId::from_bytes([id; 32]);
        let directory = fixture.dir.join(format!("activity-{id}"));
        let scope = RoomScope {
            network: loaded.network,
            realm: client.registry().realm(),
            directory: client.registry().directory(),
            room,
        };
        drop(Store::create(&directory, scope, limits).unwrap());
        rooms.push(ActivityRoomConfig {
            room,
            directory,
            limits,
        });
    }
    (fixture, state, config, ActivityConfig { rooms })
}
fn files(state: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(state)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}
fn assert_publish(peer: &ManagedPeer, sequence: u64) {
    assert_eq!(peer.advertisement_sequence().unwrap(), sequence);
    let ad = peer.current_public_advertisement().unwrap();
    assert_eq!(
        ad.unverified_claims().capabilities,
        capabilities(true).unwrap()
    );
    assert!(peer.peer.activity.lock().unwrap().is_some());
}
#[test]
fn activity_mode_is_explicit_immutable_and_order_independent() {
    let (_fixture, state, config, mut activity) = fixture();
    let peer = ManagedPeer::create_with_activity(config.clone(), &state, activity.clone()).unwrap();
    assert_publish(&peer, 1);
    let marker = fs::read(state.join(MODE)).unwrap();
    drop(peer);
    let before = files(&state);
    assert!(ManagedPeer::open(config.clone(), &state).is_err());
    assert!(Peer::open(config.clone()).is_err());
    assert_eq!(files(&state), before);
    activity.rooms.reverse();
    let peer = ManagedPeer::open_with_activity(config, &state, activity).unwrap();
    assert_publish(&peer, 2);
    assert_eq!(fs::read(state.join(MODE)).unwrap(), marker);
}
#[test]
fn activity_mode_never_migrates_read_state_or_creates_missing_stores() {
    let (_fixture, state, config, mut activity) = fixture();
    drop(ManagedPeer::create(config.clone(), &state).unwrap());
    let before = files(&state);
    assert!(ManagedPeer::open_with_activity(config.clone(), &state, activity.clone()).is_err());
    assert_eq!(files(&state), before);
    let new_state = state.with_file_name("new-publisher");
    let mut new_config = config;
    new_config.advertisement_file = new_state.join(ADVERTISEMENT);
    activity.rooms[0].directory = new_state.with_file_name("missing-store");
    assert!(ManagedPeer::create_with_activity(new_config, &new_state, activity.clone()).is_err());
    assert!(!new_state.exists());
    assert!(!activity.rooms[0].directory.exists());
}
#[test]
fn changed_mode_configuration_is_refused_before_store_open_or_temp_recovery() {
    let (_fixture, state, config, activity) = fixture();
    drop(ManagedPeer::create_with_activity(config.clone(), &state, activity.clone()).unwrap());
    scratch(&state, "sequence.tmp", &[]);
    let before = files(&state);
    for variant in 0..5 {
        let mut changed = activity.clone();
        match variant {
            0 => changed.rooms[0].room = RoomGenesisId::from_bytes([99; 32]),
            1 => changed.rooms[0].directory = state.join("foreign"),
            2 => changed.rooms[0].limits.max_events += 1,
            3 => changed.rooms[0].limits.max_history_bytes += 1,
            4 => changed.rooms.push(changed.rooms[0].clone()),
            _ => unreachable!(),
        }
        assert!(ManagedPeer::open_with_activity(config.clone(), &state, changed).is_err());
        assert_eq!(files(&state), before);
    }
}
#[test]
fn corrupt_or_missing_mode_preserves_every_artifact() {
    for variant in 0..4 {
        let (_fixture, state, config, activity) = fixture();
        drop(ManagedPeer::create_with_activity(config.clone(), &state, activity.clone()).unwrap());
        let marker = fs::read(state.join(MODE)).unwrap();
        match variant {
            0 => fs::write(state.join(MODE), []).unwrap(),
            1 => fs::write(state.join(MODE), &marker[..marker.len() / 2]).unwrap(),
            2 => {
                let mut raw = marker;
                raw[5] ^= 1;
                fs::write(state.join(MODE), raw).unwrap();
            }
            3 => fs::remove_file(state.join(MODE)).unwrap(),
            _ => unreachable!(),
        }
        let before = files(&state);
        assert!(ManagedPeer::open_with_activity(config.clone(), &state, activity).is_err());
        assert!(ManagedPeer::open(config, &state).is_err());
        assert_eq!(files(&state), before);
    }
}
#[test]
fn mode_mutation_poisoning_stops_publication_without_overwriting_evidence() {
    let (_fixture, state, config, activity) = fixture();
    let peer = ManagedPeer::create_with_activity(config, &state, activity).unwrap();
    fs::write(state.join(MODE), b"retain-corrupt-mode").unwrap();
    let before = files(&state);
    assert!(peer.renew().is_err());
    assert!(peer.renew().is_err());
    assert!(peer.current_public_advertisement().is_err());
    assert_eq!(files(&state), before);
}
#[test]
fn every_publish_mode_fault_preserves_monotone_recovery_and_capability() {
    for fault in [
        Fault::ReserveCreated,
        Fault::ReservePartial,
        Fault::ReserveFileSync,
        Fault::ReserveRename,
        Fault::ReserveDirSync,
        Fault::AdvertisementCreated,
        Fault::AdvertisementPartial,
        Fault::AdvertisementFileSync,
        Fault::AdvertisementRename,
        Fault::AdvertisementDirSync,
    ] {
        let (_fixture, state, config, activity) = fixture();
        let peer =
            ManagedPeer::create_with_activity(config.clone(), &state, activity.clone()).unwrap();
        let clock = peer.publisher.lock().unwrap().reservation.issued;
        assert!(
            peer.renew_at(clock, false, Some(fault)).is_err(),
            "{fault:?}"
        );
        assert!(peer.current_public_advertisement().is_err());
        assert!(peer.renew().is_err());
        drop(peer);
        let peer = ManagedPeer::open_with_activity(config, &state, activity).unwrap();
        let next = if matches!(fault, Fault::ReserveCreated | Fault::ReservePartial) {
            2
        } else {
            3
        };
        assert_publish(&peer, next);
        assert!(!state.join("sequence.tmp").exists());
        assert!(!state.join("advertisement.tmp").exists());
    }
}
#[test]
fn publish_partial_advertisement_uses_exact_mode_and_preserves_wrong_capability() {
    let (_fixture, state, config, activity) = fixture();
    let mode = config_digest(&activity).unwrap();
    let peer = ManagedPeer::create_with_activity(config, &state, activity).unwrap();
    let clock = peer.publisher.lock().unwrap().reservation.issued;
    assert!(peer
        .renew_at(clock, false, Some(Fault::ReserveDirSync))
        .is_err());
    let scope = peer.publisher.lock().unwrap().scope.clone();
    let reserved = Reservation {
        sequence: 2,
        issued: clock,
    };
    let proposed = peer
        .peer
        .identity
        .sign_public_advertisement(
            scope
                .unsigned_ad(reserved, capabilities(true).unwrap())
                .unwrap(),
        )
        .unwrap()
        .encode();
    let read_only = peer
        .peer
        .identity
        .sign_public_advertisement(scope.unsigned_ad(reserved, Capabilities::READ).unwrap())
        .unwrap()
        .encode();
    drop(peer);
    let before = files(&state);
    for cut in 0..proposed.len() {
        scratch(&state, "advertisement.tmp", &proposed[..cut]);
        let reopened = Publisher::open_mode(&state, scope.clone(), clock, Some(mode)).unwrap();
        assert_eq!(reopened.reservation, reserved, "cut {cut}");
        assert_eq!(files(&state), before);
        drop(reopened);
    }
    for raw in [&read_only[..read_only.len() - 64], read_only.as_slice()] {
        scratch(&state, "advertisement.tmp", raw);
        let retained = files(&state);
        assert!(Publisher::open_mode(&state, scope.clone(), clock, Some(mode)).is_err());
        assert_eq!(files(&state), retained);
        fs::remove_file(state.join("advertisement.tmp")).unwrap();
    }
}

fn scratch(state: &Path, name: &str, raw: &[u8]) {
    let mut file = custody::create_private_file(&state.join(name)).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
