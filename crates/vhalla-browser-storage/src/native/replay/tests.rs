use super::*;
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicU64, Ordering};

fn stage(home: &Home, raw: &[u8]) {
    let mut file = custody::create_private_file(&home.profile().join("STATE.tmp")).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}
fn bootstrap(directory: u8) -> Bootstrap {
    // Small, canonical empty signed-evidence genesis. The real decoder checks
    // this independent fixture; no application or certificate verifier is faked.
    let realm = 17u128.to_be_bytes();
    let mut raw = b"VHPB\x01".to_vec();
    raw.extend_from_slice(&realm);
    raw.extend_from_slice(&[directory; 32]);
    raw.extend_from_slice(&1u64.to_be_bytes());
    raw.extend_from_slice(&60u64.to_be_bytes());
    raw.extend_from_slice(&1u16.to_be_bytes());
    raw.extend_from_slice(&60u64.to_be_bytes());
    raw.extend_from_slice(&1u32.to_be_bytes());
    for limit in [1024u32, 128, 128, 64, 32, 128, 8] {
        raw.extend_from_slice(&limit.to_be_bytes());
    }
    raw.extend_from_slice(&0u16.to_be_bytes());
    raw.push(1);
    raw.extend_from_slice(&1u64.to_be_bytes());
    raw.push(1);
    raw.extend_from_slice(&SigningKey::from_bytes(&[83; 32]).verifying_key().to_bytes());
    raw.extend_from_slice(&1u64.to_be_bytes());
    raw.extend_from_slice(&28u32.to_be_bytes());
    raw.extend_from_slice(b"VHSA\0\0\0\x01");
    raw.extend_from_slice(&realm);
    raw.extend_from_slice(&0u32.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(b"vhalla/public-bootstrap/v1\0");
    hash.update(&raw);
    Bootstrap::decode(&raw, hash.finalize().into()).unwrap()
}
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vhalla-replay-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn profile(&self) -> PathBuf {
        self.0.join("profile")
    }
    fn create(&self) -> NativeReplay {
        let b = bootstrap(1);
        NativeReplay::create_new(self.profile(), b.clone(), b.pin()).unwrap()
    }
    fn open(&self) -> Result<NativeReplay, Error> {
        let b = bootstrap(1);
        NativeReplay::open(self.profile(), b.clone(), b.pin())
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn replay_profile_create_open_lock_scope_and_no_reset() {
    let home = Home::new();
    let profile = home.create();
    assert!(home.open().is_err());
    let original = fs::read(home.profile().join("STATE")).unwrap();
    let head = profile.client().checkpoint_head();
    drop(profile);
    let other = bootstrap(2);
    assert!(matches!(
        NativeReplay::open(home.profile(), other.clone(), other.pin()),
        Err(Error::WrongScope)
    ));
    assert_eq!(fs::read(home.profile().join("STATE")).unwrap(), original);
    let profile = home.open().unwrap();
    assert_eq!(profile.client().checkpoint_head(), head);
    drop(profile);
    assert!(NativeReplay::create_new(home.profile(), bootstrap(1), bootstrap(1).pin()).is_err());
}

#[test]
fn replay_profile_zero_partial_full_rename_faults_recover_exact_old_or_new() {
    for point in [
        Point::Created,
        Point::Partial,
        Point::Written,
        Point::Synced,
        Point::Renamed,
        Point::DirectorySynced,
    ] {
        let home = Home::new();
        let mut profile = home.create();
        let head = profile.client().checkpoint_head();
        profile.require_anchor(head).unwrap();
        profile.fault = Some(point);
        assert_eq!(profile.checkpoint(), Err(Error::Storage));
        assert!(profile.needs_reopen());
        assert_eq!(profile.checkpoint(), Err(Error::NeedsReopen));
        drop(profile);
        let mut profile = home.open().unwrap();
        assert_eq!(profile.client().checkpoint_head(), head);
        let old = matches!(point, Point::Created | Point::Partial);
        assert_eq!(profile.generation(), u64::from(!old));
        assert_eq!(
            profile.client().retained_anchor(),
            if old { None } else { Some((head, true)) }
        );
        assert!(!home.profile().join("STATE.tmp").exists());
        profile.require_anchor(head).unwrap();
        profile.checkpoint().unwrap();
        assert_eq!(profile.generation(), 1); // exact clean retry does not create more history
    }
}

#[test]
fn replay_profile_initial_scratch_completes_without_removing_sole_prefix() {
    for prefix in [0usize, 1, 17, 112, 120, 200, usize::MAX] {
        let home = Home::new();
        drop(home.create());
        let original = fs::read(home.profile().join("STATE")).unwrap();
        fs::rename(
            home.profile().join("STATE"),
            home.profile().join("STATE.tmp"),
        )
        .unwrap();
        fs::write(
            home.profile().join("STATE.tmp"),
            &original[..prefix.min(original.len())],
        )
        .unwrap();
        let profile = home.open().unwrap();
        assert_eq!(profile.generation(), 0);
        assert_eq!(fs::read(home.profile().join("STATE")).unwrap(), original);
        assert!(!home.profile().join("STATE.tmp").exists());
    }
}

#[test]
fn replay_profile_preserves_corrupt_authority_and_unknown_initial_scratch() {
    let home = Home::new();
    drop(home.create());
    let mut damaged = fs::read(home.profile().join("STATE")).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(home.profile().join("STATE"), &damaged).unwrap();
    stage(&home, &[]);
    assert!(home.open().is_err());
    assert_eq!(fs::read(home.profile().join("STATE")).unwrap(), damaged);
    assert!(home.profile().join("STATE.tmp").exists());
    fs::remove_file(home.profile().join("STATE")).unwrap();
    fs::write(home.profile().join("STATE.tmp"), [255]).unwrap();
    assert!(home.open().is_err());
    assert_eq!(fs::read(home.profile().join("STATE.tmp")).unwrap(), [255]);
    fs::remove_file(home.profile().join("STATE.tmp")).unwrap();
    assert!(matches!(home.open(), Err(Error::RecoveryRequired)));
}

#[test]
fn replay_profile_wrong_partial_scope_length_and_stale_cas_preserve_bytes() {
    for corrupt_at in [8usize, 16, 48, 80, 112] {
        let home = Home::new();
        let mut profile = home.create();
        let old = profile.raw.clone();
        let head = profile.client().checkpoint_head();
        profile.require_anchor(head).unwrap();
        let next = profile.client.checkpoint_image().unwrap().seal(
            &profile.key,
            1,
            Sha256::digest(&old).into(),
        );
        drop(profile);
        let mut prefix = next[..corrupt_at + 1].to_vec();
        prefix[corrupt_at] = 255;
        stage(&home, &prefix);
        assert!(home.open().is_err());
        assert_eq!(fs::read(home.profile().join("STATE.tmp")).unwrap(), prefix);
        assert_eq!(fs::read(home.profile().join("STATE")).unwrap(), old);
    }
    let home = Home::new();
    let mut profile = home.create();
    let old = profile.raw.clone();
    let head = profile.client().checkpoint_head();
    profile.require_anchor(head).unwrap();
    profile.checkpoint().unwrap();
    fs::write(home.profile().join("STATE"), &old).unwrap();
    assert_eq!(profile.checkpoint(), Err(Error::Stale));
    assert!(profile.needs_reopen());
    assert_eq!(fs::read(home.profile().join("STATE")).unwrap(), old);
}

#[test]
fn replay_profile_future_anchor_survives_without_becoming_permission() {
    let home = Home::new();
    let mut profile = home.create();
    let mut frontier = profile.client().frontier();
    frontier.height = 20;
    let anchor = CheckpointHead::new(frontier, [20; 32]).unwrap();
    profile.require_anchor(anchor).unwrap();
    profile.checkpoint().unwrap();
    drop(profile);
    let profile = home.open().unwrap();
    assert!(!profile.client().anchor_matched());
    assert_eq!(profile.client().retained_anchor(), Some((anchor, false)));
    assert_eq!(profile.client().frontier().height, 0);
}

#[test]
fn replay_profile_state_read_and_clean_sync_failure_require_reopen() {
    let home = Home::new();
    let mut profile = home.create();
    profile.fault = Some(Point::CleanSync);
    assert_eq!(profile.checkpoint(), Err(Error::Storage));
    assert!(profile.needs_reopen());
    assert_eq!(profile.checkpoint(), Err(Error::NeedsReopen));
    drop(profile);
    let mut profile = home.open().unwrap();
    fs::rename(
        home.profile().join("STATE"),
        home.profile().join("saved-state"),
    )
    .unwrap();
    assert!(profile.checkpoint().is_err());
    assert!(profile.needs_reopen());
    assert_eq!(profile.checkpoint(), Err(Error::NeedsReopen));
    drop(profile);
    fs::rename(
        home.profile().join("saved-state"),
        home.profile().join("STATE"),
    )
    .unwrap();
    assert!(home.open().is_ok());
}
