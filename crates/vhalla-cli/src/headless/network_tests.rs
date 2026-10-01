use super::*;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

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
fn source_fixture() -> Source {
    Source {
        endpoint_id: SecretKey::from_bytes(&[2; 32]).public().to_string(),
        relay_url: None,
        addresses: vec!["127.0.0.1:1234".parse().unwrap()],
    }
}
fn vector(name: &str) -> Vec<u8> {
    include_str!("../../../../vectors/direct-room-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn genesis() -> PinnedGenesis {
    SignedGenesis::decode(&vector("genesis_signed"))
        .unwrap()
        .verify_pin(RoomId::from_bytes(vector("genesis_id").try_into().unwrap()))
        .unwrap()
}

#[test]
fn transport_identity_reopens_without_replacement_and_missing_or_foreign_keys_refuse() {
    let temp = Temp::new();
    let identity = Identity::create_new(&temp.home).unwrap();
    let id = identity.id();
    let original = fs::read(temp.home.join("peer.key")).unwrap();
    assert!(Identity::create_new(&temp.home).is_err());
    assert!(fs::read(temp.home.join("peer.key")).unwrap() == original);
    drop(identity);
    assert_eq!(Identity::open(&temp.home).unwrap().id(), id);
    let other = Temp::new();
    assert_ne!(Identity::create_new(&other.home).unwrap().id(), id);
    let missing = Temp::new();
    assert!(Identity::open(&missing.home).is_err());
    assert!(!missing.home.join("peer.key").exists());
    for bytes in [
        vec![0; KEY_BYTES],
        b"VHDPKEY1".iter().copied().chain([0; 32]).collect(),
        vec![1; KEY_BYTES + 1],
    ] {
        fs::write(temp.home.join("peer.key"), &bytes).unwrap();
        assert!(Identity::open(&temp.home).is_err());
        assert!(fs::read(temp.home.join("peer.key")).unwrap() == bytes);
    }
}

#[test]
fn key_or_directory_replacement_and_in_place_edits_close_the_live_identity() {
    for change in 0..4 {
        let temp = Temp::new();
        let identity = Identity::create_new(&temp.home).unwrap();
        let path = temp.home.join("peer.key");
        let original = fs::read(&path).unwrap();
        match change {
            0 => {
                fs::rename(&path, temp.root.path().join("retained.key")).unwrap();
                let mut file = custody::create_private_file(&path).unwrap();
                file.write_all(&original).unwrap();
            }
            1 => {
                let mut changed = original.clone();
                changed[39] ^= 1;
                fs::write(&path, changed).unwrap();
            }
            2 => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => {
                let retained = temp.root.path().join("retained-home");
                fs::rename(&temp.home, &retained).unwrap();
                symlink(&retained, &temp.home).unwrap();
            }
        }
        assert!(identity.check().is_err());
        if change == 1 {
            fs::write(&path, &original).unwrap();
            assert!(identity.check().is_err());
        }
    }
}

#[test]
fn public_links_authenticate_genesis_and_validate_route_before_network_access() {
    let genesis = genesis();
    let link = RoomLink::new(&genesis, source_fixture()).unwrap();
    let encoded = link.encode().unwrap();
    let parsed = RoomLink::parse(&encoded).unwrap();
    assert_eq!(parsed.validate().unwrap(), genesis);
    assert_eq!(parsed.encode().unwrap(), encoded);
    let mut value = serde_json::to_value(&link).unwrap();
    let encode = |value: &serde_json::Value| {
        format!(
            "{LINK_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
        )
    };
    value["pin"] = json!(Hex([3; 32]));
    assert!(RoomLink::parse(&encode(&value)).is_err());
    value = serde_json::to_value(&link).unwrap();
    let mut altered = genesis.encode();
    *altered.last_mut().unwrap() ^= 1;
    value["genesis"] = json!(URL_SAFE_NO_PAD.encode(altered));
    assert!(RoomLink::parse(&encode(&value)).is_err());
    value = serde_json::to_value(&link).unwrap();
    value["admin"] = json!(true);
    assert!(RoomLink::parse(&encode(&value)).is_err());
    for bad in [
        format!("{encoded}="),
        encoded.replace("/1/", "/2/"),
        format!("{LINK_PREFIX}{}", "x".repeat(MAX_LINK_BYTES)),
    ] {
        assert!(RoomLink::parse(&bad).is_err());
    }
}

#[test]
fn routing_hints_refuse_ambiguous_destinations_and_never_grant_authority() {
    let valid = source_fixture();
    for mut bad in [
        Source {
            addresses: vec![],
            ..valid.clone()
        },
        Source {
            addresses: vec!["0.0.0.0:3".parse().unwrap()],
            ..valid.clone()
        },
        Source {
            addresses: vec!["127.0.0.1:0".parse().unwrap()],
            ..valid.clone()
        },
        Source {
            addresses: vec![valid.addresses[0]; 2],
            ..valid.clone()
        },
    ] {
        assert!(address(&bad).is_err());
        bad.addresses = valid.addresses.clone();
        assert!(address(&bad).is_ok());
    }
    for url in [
        "http://relay.example/",
        "https://user@relay.example/",
        "https://relay.example/path",
        "https://relay.example/?q=1",
        "https://relay.example/#fragment",
    ] {
        assert!(relay_url(url).is_err());
    }
    assert!(relay_url("https://relay.example/").is_ok());
}

#[test]
fn listen_defaults_are_stable_and_invalid_routes_refuse_before_startup() {
    let default = Listen::default();
    assert_eq!(default.bind, "0.0.0.0:48888".parse().unwrap());
    assert_eq!(default.relay_url, None);
    assert!(!default.relay_only);
    default.validate().unwrap();
    for bind in [
        "224.0.0.1:48888",
        "255.255.255.255:48888",
        "169.254.1.1:48888",
        "[ff02::1]:48888",
        "[fe80::1]:48888",
        "[::ffff:127.0.0.1]:48888",
        "[::1%1]:48888",
    ] {
        assert!(Listen {
            bind: bind.parse().unwrap(),
            ..default.clone()
        }
        .validate()
        .is_err());
    }
    for relay in [
        "http://relay.example/",
        "https://user:secret@relay.example/",
    ] {
        assert!(Listen {
            relay_url: Some(relay.into()),
            ..default.clone()
        }
        .validate()
        .is_err());
    }
}

#[test]
fn relay_only_requires_an_explicit_valid_relay_and_old_configs_remain_direct_capable() {
    let old: Listen = serde_json::from_value(json!({
        "bind": "127.0.0.1:0",
        "relay_url": null,
    }))
    .unwrap();
    assert!(!old.relay_only);
    old.validate().unwrap();
    let mut selected = Listen {
        relay_only: true,
        ..old
    };
    assert!(selected.validate().is_err());
    selected.relay_url = Some("http://relay.example/".into());
    assert!(selected.validate().is_err());
    selected.relay_url = Some("https://relay.example/".into());
    selected.validate().unwrap();
    let encoded = serde_json::to_value(&selected).unwrap();
    assert_eq!(encoded["relay_only"], true);
    assert!(
        serde_json::from_value::<Listen>(encoded)
            .unwrap()
            .relay_only
    );
}

#[tokio::test]
async fn restoring_key_bytes_does_not_reopen_a_refused_live_identity() {
    let temp = Temp::new();
    let identity = Identity::create_new(&temp.home).unwrap();
    let path = temp.home.join("peer.key");
    let original = fs::read(&path).unwrap();
    let mut changed = original.clone();
    changed[39] ^= 1;
    fs::write(&path, changed).unwrap();
    assert!(identity.check().is_err());
    fs::write(&path, original).unwrap();
    assert!(identity
        .bind(&Listen {
            bind: "127.0.0.1:0".parse().unwrap(),
            relay_url: None,
            relay_only: false,
        })
        .await
        .is_err());
}

#[tokio::test]
async fn listener_reuses_only_its_transport_key_and_exposes_usable_direct_hints() {
    let temp = Temp::new();
    let identity = Identity::create_new(&temp.home).unwrap();
    let listen = Listen {
        bind: "127.0.0.1:0".parse().unwrap(),
        relay_url: None,
        relay_only: false,
    };
    let endpoint = identity.bind(&listen).await.unwrap();
    assert_eq!(*endpoint.id().as_bytes(), identity.id().0);
    let selected = source(&endpoint).unwrap();
    assert_eq!(selected.endpoint_id, identity.id().to_string());
    assert_eq!(selected.relay_url, None);
    assert_eq!(address(&selected).unwrap().id, endpoint.id());
    endpoint.close().await;
    drop(endpoint);
    let id = identity.id();
    drop(identity);
    let reopened = Identity::open(&temp.home).unwrap();
    let endpoint = reopened.bind(&listen).await.unwrap();
    assert_eq!(*endpoint.id().as_bytes(), id.0);
    endpoint.close().await;
}
