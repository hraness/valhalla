use super::*;
use crate::headless::catalog::Hex;
use crate::private_rooms::agent_delivery::Driver;
use std::{
    fs,
    io::Write,
    os::unix::fs::{symlink, PermissionsExt},
};
use tempfile::TempDir;
use vhalla_private_kernel::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

fn key(value: u8) -> Key {
    Key::from_bytes(
        *iroh::SecretKey::from_bytes(&[value; 32])
            .public()
            .as_bytes(),
    )
    .unwrap()
}
fn context() -> Context {
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: key(3),
        device: key(4),
    }
}
fn write(path: &Path, bytes: &[u8]) {
    let mut file = custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn hash(bytes: &[u8]) -> Hash {
    Hex(Sha256::digest(bytes).into())
}

struct Fixture {
    _temp: TempDir,
    base: PathBuf,
    profile: PathBuf,
    state: PathBuf,
    value: Value,
    bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let base = temp.path().canonicalize().unwrap();
        custody::open_private_directory(&base).unwrap();
        let parent = base.join("profiles");
        custody::create_private_directory(&parent).unwrap();
        let profile = parent.join("delivery.json");
        let state = base.join("queue");
        write(&base.join("token"), Hex([7; 32]).to_string().as_bytes());
        let context = context();
        let value = json!({
            "version": 4,
            "context": {"room": Hex(*context.scope.room.as_bytes()), "anchor": Hex(*context.scope.anchor.as_bytes()),
                "account": Hex(*context.account.as_bytes()), "device": Hex(*context.device.as_bytes())},
            "namespace": Hex([9; 32]),
            "transport": {"kind": "iroh", "endpoint": {
                "endpoint_id": iroh::SecretKey::from_bytes(&[8; 32]).public().to_string(),
                "relay_url": null, "addresses": ["127.0.0.1:9"] }},
            "token": base.join("token"), "state": state,
            "max_jobs": 8, "max_bytes": 1048576, "max_attempts": 1,
            "initial_backoff_secs": 1, "max_backoff_secs": 30, "emit_acceptance": false,
        });
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        write(&profile, &bytes);
        Self {
            _temp: temp,
            base,
            profile,
            state,
            value,
            bytes,
        }
    }
    fn hash(&self) -> Hash {
        hash(&self.bytes)
    }
    fn replace(&mut self, value: Value) {
        fs::rename(&self.profile, self.profile.with_extension("previous")).unwrap();
        self.value = value;
        self.bytes = serde_json::to_vec_pretty(&self.value).unwrap();
        write(&self.profile, &self.bytes);
    }
    fn tls(&mut self, version: u64, address: &str) {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["setup.invalid".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let ca = self.base.join("ca.der");
        write(&ca, certificate.der());
        let mut value = self.value.clone();
        value["version"] = json!(version);
        if version == 4 {
            value["transport"] =
                json!({"kind": "tls", "addr": address, "tls_name": "setup.invalid", "ca": ca});
        } else {
            value.as_object_mut().unwrap().remove("transport");
            value["addr"] = json!(address);
            value["tls_name"] = json!("setup.invalid");
            value["ca"] = json!(ca);
        }
        self.replace(value);
    }
    fn assert_openable(&self) {
        let driver = Driver::open_polling_bound(&self.profile, context(), self.hash().0).unwrap();
        driver
            .check_bound_profile(&self.profile, self.hash().0)
            .unwrap();
    }
}

#[test]
fn current_v4_setup_creates_complete_queues_without_rewriting_or_returning_secrets() {
    let fixture = Fixture::new();
    let owner = Owner::current().unwrap();
    let original = custody::open_private_file(&fixture.profile, owner, PROFILE_BYTES).unwrap();
    let result = initialize(&fixture.profile, fixture.hash(), context()).unwrap();
    assert_eq!(
        result,
        json!({"profile_hash": fixture.hash(), "initialized": true})
    );
    assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);
    let current = custody::open_private_file(&fixture.profile, owner, PROFILE_BYTES).unwrap();
    assert!(custody::same_open_file(&original, &current).unwrap());
    for name in [
        "lock",
        "jobs",
        "scan",
        "applied",
        "binding",
        "controls",
        "controls.enabled",
    ] {
        assert!(
            fixture.state.join(name).exists(),
            "missing initialized {name}"
        );
    }
    fixture.assert_openable();
    assert!(!fixture
        .profile
        .with_file_name("delivery.json.controls-upgrade-tmp")
        .exists());
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    fixture.assert_openable();
}

#[test]
fn wrong_hash_and_wrong_native_context_have_no_queue_effects() {
    let fixture = Fixture::new();
    assert_eq!(
        initialize(&fixture.profile, Hex([5; 32]), context())
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(!fixture.state.exists());
    assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);
    // The lower-level initializer also hashes what it parses, independent of
    // the outer guard. It cannot treat a caller's earlier observation as proof.
    assert_eq!(
        agent_delivery::initialize_bound(&fixture.profile, context(), [5; 32]),
        Err(agent_delivery::InitializeBoundError::Refused)
    );
    let other = Context {
        device: key(6),
        ..context()
    };
    assert!(initialize(&fixture.profile, fixture.hash(), other).is_err());
    assert!(!fixture.state.exists());
    assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);
}

#[test]
fn transient_profile_aba_cannot_change_the_config_actually_initialized() {
    let fixture = Fixture::new();
    let original = fixture.profile.with_extension("original");
    let foreign = fixture.profile.with_extension("foreign");
    let mut changed = fixture.value.clone();
    let foreign_state = fixture.base.join("foreign-queue");
    changed["state"] = json!(foreign_state);
    let changed = serde_json::to_vec(&changed).unwrap();
    assert!(
        initialize_with(&fixture.profile, fixture.hash(), context(), |at| {
            match at {
                Boundary::Selected => {
                    fs::rename(&fixture.profile, &original).unwrap();
                    write(&fixture.profile, &changed);
                }
                Boundary::Initialized => {
                    fs::rename(&fixture.profile, &foreign).unwrap();
                    fs::rename(&original, &fixture.profile).unwrap();
                }
            }
            Ok(())
        })
        .is_err()
    );
    assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);
    assert_eq!(fs::read(&foreign).unwrap(), changed);
    assert!(!fixture.state.exists());
    assert!(!foreign_state.exists());
    // After refusal, the untouched original selection can still be explicitly
    // initialized; the rejected transient profile consumed no queue authority.
    initialize(&fixture.profile, fixture.hash(), context()).unwrap();
    fixture.assert_openable();
}

#[test]
fn same_byte_profile_replacement_after_setup_refuses_success_and_preserves_created_state() {
    let fixture = Fixture::new();
    assert!(
        initialize_with(&fixture.profile, fixture.hash(), context(), |at| {
            if at == Boundary::Initialized {
                fs::rename(
                    &fixture.profile,
                    fixture.profile.with_extension("preserved"),
                )
                .unwrap();
                write(&fixture.profile, &fixture.bytes);
            }
            Ok(())
        })
        .is_err()
    );
    assert!(fixture.state.join("jobs").exists());
    let binding = fs::read(fixture.state.join("binding")).unwrap();
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert_eq!(fs::read(fixture.state.join("binding")).unwrap(), binding);
    fixture.assert_openable();
}

#[test]
fn parent_replacement_is_refused_even_when_the_original_file_inode_is_preserved() {
    let fixture = Fixture::new();
    let parent = fixture.profile.parent().unwrap();
    let saved = fixture.base.join("old-profiles");
    assert!(
        initialize_with(&fixture.profile, fixture.hash(), context(), |at| {
            if at == Boundary::Initialized {
                fs::rename(parent, &saved).unwrap();
                custody::create_private_directory(parent).unwrap();
                fs::rename(saved.join("delivery.json"), &fixture.profile).unwrap();
            }
            Ok(())
        })
        .is_err()
    );
    assert!(fixture.state.join("jobs").exists());
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    fixture.assert_openable();
}

#[test]
fn preexisting_and_missing_initialized_components_are_preserved_without_repair() {
    let fixture = Fixture::new();
    custody::create_private_directory(&fixture.state).unwrap();
    let sentinel = fixture.state.join("partial-evidence");
    write(&sentinel, b"retained initialization evidence");
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"retained initialization evidence"
    );
    assert!(!fixture.state.join("jobs").exists());

    let fixture = Fixture::new();
    initialize(&fixture.profile, fixture.hash(), context()).unwrap();
    fs::rename(
        fixture.state.join("controls"),
        fixture.base.join("preserved-controls"),
    )
    .unwrap();
    let binding = fs::read(fixture.state.join("binding")).unwrap();
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert!(!fixture.state.join("controls").exists());
    assert_eq!(fs::read(fixture.state.join("binding")).unwrap(), binding);
    assert!(Driver::open_polling_bound(&fixture.profile, context(), fixture.hash().0).is_err());
}

#[test]
fn legacy_setup_is_refused_while_standalone_initialization_retains_its_upgrade_behavior() {
    for version in [1, 2] {
        let mut fixture = Fixture::new();
        fixture.tls(version, "127.0.0.1:9");
        let error = initialize(&fixture.profile, fixture.hash(), context()).unwrap_err();
        assert_eq!(error.code, ErrorCode::Usage);
        assert!(!fixture.state.exists());
        assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);
        agent_delivery::initialize(&fixture.profile, context()).unwrap();
        let initialized = fs::read(&fixture.profile).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&initialized).unwrap()["version"],
            2
        );
        let driver =
            Driver::open_polling_bound(&fixture.profile, context(), hash(&initialized).0).unwrap();
        driver
            .check_bound_profile(&fixture.profile, hash(&initialized).0)
            .unwrap();
    }
}

#[test]
fn numeric_tls_setup_is_local_and_named_tls_is_an_explicit_usage_refusal() {
    let mut fixture = Fixture::new();
    fixture.tls(4, "127.0.0.1:9");
    initialize(&fixture.profile, fixture.hash(), context()).unwrap();
    fixture.assert_openable();
    assert_eq!(fs::read(&fixture.profile).unwrap(), fixture.bytes);

    let mut fixture = Fixture::new();
    fixture.tls(4, "must-not-resolve.invalid:443");
    let error = initialize(&fixture.profile, fixture.hash(), context()).unwrap_err();
    assert_eq!(error.code, ErrorCode::Usage);
    assert!(serde_json::to_string(&error)
        .unwrap()
        .contains("numeric TLS"));
    assert!(!fixture.state.exists());
}

#[test]
fn profile_permissions_links_and_noncanonical_queue_parents_are_refused() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.profile, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert!(!fixture.state.exists());

    let fixture = Fixture::new();
    fs::set_permissions(
        fixture.profile.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert!(!fixture.state.exists());

    let fixture = Fixture::new();
    let link = fixture.profile.with_extension("symlink");
    symlink(&fixture.profile, &link).unwrap();
    assert!(initialize(&link, fixture.hash(), context()).is_err());
    let hardlink = fixture.profile.with_extension("hardlink");
    fs::hard_link(&fixture.profile, hardlink).unwrap();
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert!(!fixture.state.exists());

    let mut fixture = Fixture::new();
    let alias = fixture.base.join("alias");
    symlink(&fixture.base, &alias).unwrap();
    let mut value = fixture.value.clone();
    value["state"] = json!(alias.join("queue"));
    fixture.replace(value);
    assert!(initialize(&fixture.profile, fixture.hash(), context()).is_err());
    assert!(!fixture.state.exists());
}
