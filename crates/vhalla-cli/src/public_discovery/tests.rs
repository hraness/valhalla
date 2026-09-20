use super::*;
use std::fs;
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_public_client::{Validator, ValidatorActivation};
use vhalla_public_protocol::{AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION};
use vhalla_rooms::{registry::DirectoryPolicy, DirectoryId};
use vhalla_rooms_consensus::Genesis;
use vhalla_social::archive::{Archive, Limits};

struct Home {
    dir: PathBuf,
    pin: [u8; 32],
    network: [u8; 32],
    seed: PathBuf,
}
impl Home {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vhalla-discovery-cli-{}-{}",
            std::process::id(),
            hex(&nonce().unwrap())
        ));
        fs::create_dir(&dir).unwrap();
        let identity = Identity::create_new(dir.join("key")).unwrap();
        let realm = RealmId(77);
        let limits = Limits::default();
        let bootstrap = Bootstrap::from_genesis(
            Genesis {
                directory: DirectoryId::from_bytes([8; 32]),
                realm,
                policy: DirectoryPolicy {
                    base_cost: 1,
                    window_seconds: 86400,
                    max_in_window: 8,
                    support_epoch_seconds: 86400,
                    max_lifetime_rooms: 16,
                },
                eligible: vec![],
                limits,
                archive: Archive::new(realm, limits).unwrap(),
            },
            vec![ValidatorActivation {
                from: 1,
                validators: vec![Validator {
                    public_key: identity.public_key(),
                    power: 1,
                }],
            }],
        )
        .unwrap();
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        fs::write(dir.join("bootstrap"), bootstrap.encode()).unwrap();
        let at = now().unwrap();
        let ad = identity
            .sign_public_advertisement(
                UnsignedAdvertisement::new(AdvertisementClaims {
                    network,
                    application_key: identity.public_key(),
                    sequence: 7,
                    issued_at: at,
                    expires_at: at + 3600,
                    protocol: PROTOCOL_VERSION,
                    capabilities: Capabilities::READ,
                    endpoints: vec![
                        Endpoint::parse("https://seed.vhalla.dev:443/vhalla/v1").unwrap()
                    ],
                })
                .unwrap(),
            )
            .unwrap();
        let seed = dir.join("seed");
        fs::write(&seed, ad.encode()).unwrap();
        Self {
            dir,
            pin,
            network,
            seed,
        }
    }
    fn args(&self) -> Vec<OsString> {
        vec![
            "public".into(),
            "discovery-serve".into(),
            self.dir.join("bootstrap").into(),
            hex(&self.pin).into(),
            self.dir.join("key").into(),
            self.dir.join("journal").into(),
            self.dir.join("publisher").into(),
            "https://peer.vhalla.dev:443/vhalla/v1".into(),
            "https://app.vhalla.dev".into(),
            self.dir.join("discovery").into(),
        ]
    }
    fn with_seed(&self) -> Vec<OsString> {
        let mut args = self.args();
        args.extend([
            "--seed".into(),
            self.seed.clone().into(),
            "https://seed.vhalla.dev:443/vhalla/v1".into(),
        ]);
        args
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn discovery_cli_parses_only_explicit_bounded_routes_without_creating_state() {
    let home = Home::new();
    let options = parse(&home.args()).unwrap();
    assert_eq!(options.network, home.network);
    assert!(options.seeds.is_empty());
    assert!(!options.create);
    assert!(!options.discovery.create_new);
    let options = parse(&home.with_seed()).unwrap();
    assert_eq!(options.seeds.len(), 1);
    assert_eq!(options.seeds[0].floor.sequence(), 7);
    assert!(!home.dir.join("publisher").exists());
    assert!(!home.dir.join("discovery").exists());
    for extras in [
        vec!["--solve-attempts", "0"],
        vec!["--solve-attempts", "16777217"],
        vec!["--solve-attempts", "01"],
        vec!["--listen", "0.0.0.0:9790"],
        vec!["--new-state", "--new-state"],
    ] {
        let mut args = home.args();
        args.extend(extras.into_iter().map(OsString::from));
        assert!(parse(&args).is_err());
    }
    let mut duplicate = home.with_seed();
    duplicate.extend([
        "--seed".into(),
        home.seed.clone().into(),
        "https://seed.vhalla.dev:443/vhalla/v1".into(),
    ]);
    assert!(parse(&duplicate).is_err());
}

#[test]
fn discovery_cli_wrong_pin_route_signature_and_symlink_are_refused() {
    let home = Home::new();
    let mut args = home.with_seed();
    args[3] = hex(&[9; 32]).into();
    assert!(parse(&args).is_err());
    let mut args = home.with_seed();
    *args.last_mut().unwrap() = "https://other.vhalla.dev:443/vhalla/v1".into();
    assert!(parse(&args).is_err());
    let link = home.dir.join("linked-seed");
    std::os::unix::fs::symlink(&home.seed, &link).unwrap();
    let mut args = home.with_seed();
    args[11] = link.into();
    assert!(parse(&args).is_err());
    let mut raw = fs::read(&home.seed).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    fs::write(&home.seed, raw).unwrap();
    assert!(parse(&home.with_seed()).is_err());
    assert!(!home.dir.join("publisher").exists());
    assert!(!home.dir.join("discovery").exists());
}
