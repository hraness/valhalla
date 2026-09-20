use super::*;
use crate::native::disk::Point;
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use vhalla_public_protocol::{AdvertisementClaims, UnsignedAdvertisement, PROTOCOL_VERSION};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "vhalla-native-peer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("session")
    }
    fn create(&self) -> NativePeerSession {
        NativePeerSession::create_new(
            self.path(),
            scope(),
            peer(),
            route(),
            &ad(7, 1000, 1100, 3, false),
            1000,
        )
        .unwrap()
    }
    fn open(&self) -> NativePeerSession {
        NativePeerSession::open(self.path(), scope(), peer(), &route()).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scope() -> HistoryScope {
    HistoryScope::new([7; 32], [8; 32])
}
fn peer() -> [u8; 32] {
    SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()
}
fn route() -> Endpoint {
    Endpoint::parse("https://peer.vhalla.dev:443/vhalla/v1").unwrap()
}
fn ad(
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
    capabilities: u32,
    changed_route: bool,
) -> Vec<u8> {
    let claims = AdvertisementClaims {
        network: scope().network(),
        application_key: peer(),
        sequence,
        issued_at,
        expires_at,
        protocol: PROTOCOL_VERSION,
        capabilities: Capabilities::from_bits(capabilities).unwrap(),
        endpoints: vec![if changed_route {
            Endpoint::parse("https://new.vhalla.dev:443/vhalla/v1").unwrap()
        } else {
            route()
        }],
    };
    UnsignedAdvertisement::new(claims)
        .unwrap()
        .sign_with_key(&SigningKey::from_bytes(&[3; 32]))
        .unwrap()
        .encode()
}
#[test]
fn peer_session_explicit_creation_strong_open_lock_and_private_files() {
    let home = Home::new();
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    assert!(!home.path().exists());
    let session = home.create();
    assert!(NativePeerSession::create_new(
        home.path(),
        scope(),
        peer(),
        route(),
        &ad(7, 1000, 1100, 3, false),
        1000
    )
    .is_err());
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    drop(session);
    assert!(NativePeerSession::open(
        home.path(),
        HistoryScope::new([7; 32], [9; 32]),
        peer(),
        &route()
    )
    .is_err());
    assert!(NativePeerSession::open(home.path(), scope(), [99; 32], &route()).is_err());
    assert!(NativePeerSession::open(
        home.path(),
        scope(),
        peer(),
        &Endpoint::parse("https://other.vhalla.dev:443/vhalla/v1").unwrap()
    )
    .is_err());
    assert_eq!(home.open().selection().unwrap().peer(), peer());
    assert_eq!(
        fs::metadata(home.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for entry in fs::read_dir(home.path()).unwrap() {
        assert_eq!(
            entry.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn peer_session_initial_selection_requires_fresh_read_and_exact_route() {
    for raw in [
        ad(1, 900, 1000, 3, false),
        ad(1, 1000, 1100, 2, false),
        ad(1, 1000, 1100, 1, true),
    ] {
        let home = Home::new();
        assert!(
            NativePeerSession::create_new(home.path(), scope(), peer(), route(), &raw, 1000)
                .is_err()
        );
        assert!(!home.path().exists());
    }
}
#[test]
fn peer_session_expired_floor_survives_restart_and_blocks_downgrade() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    let old = session.checkpoint_clock(&old, 1100).unwrap();
    assert!(session
        .observe(&old, &old.advertisement().encode(), 1100)
        .is_err());
    drop(session);
    let mut session = home.open();
    let expired = session.selection().unwrap();
    assert_eq!(
        expired
            .advertisement()
            .restore_sequence_anchor(scope().network())
            .unwrap()
            .sequence(),
        7
    );
    assert!(session
        .observe(&expired, &ad(6, 1100, 1200, 3, false), 1100)
        .is_err());
    let next = session
        .observe(&expired, &ad(8, 1100, 1200, 3, false), 1100)
        .unwrap();
    assert_eq!(next.advertisement().unverified_claims().sequence, 8);
}
#[test]
fn peer_session_exact_retry_and_sequence_conflicts_do_not_rewrite_floor() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    assert_eq!(
        session
            .observe(&old, &old.advertisement().encode(), 1000)
            .unwrap(),
        old
    );
    assert!(session
        .observe(&old, &ad(7, 1000, 1100, 1, false), 1000)
        .is_err());
    let advanced = session.checkpoint_clock(&old, 1001).unwrap();
    assert!(session.checkpoint_clock(&old, 1002).is_err());
    assert!(session
        .observe(&old, &ad(8, 1000, 1100, 3, false), 1002)
        .is_err());
    assert_eq!(session.selection().unwrap(), advanced);
}
#[test]
fn peer_session_clock_floor_and_skew_boundaries_are_durable() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    assert!(session.checkpoint_clock(&old, 999).is_err());
    assert!(session
        .observe(&old, &ad(8, 1301, 1400, 3, false), 1000)
        .is_err());
    let next = session
        .observe(&old, &ad(8, 1300, 1400, 3, false), 1000)
        .unwrap();
    let next = session.checkpoint_clock(&next, 1300).unwrap();
    assert_eq!(session.checkpoint_clock(&next, 1300).unwrap(), next);
    drop(session);
    let mut session = home.open();
    let current = session.selection().unwrap();
    assert!(session.checkpoint_clock(&current, 1299).is_err());
    assert!(session
        .observe(&current, &ad(9, 1200, 1400, 3, false), 1299)
        .is_err());
    assert_eq!(session.selection().unwrap().clock_floor(), 1300);
}
#[test]
fn peer_session_new_signed_withdrawal_is_retained_before_usability_checks() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    let withdrawn = session
        .observe(&old, &ad(8, 1000, 1100, 4, true), 1001)
        .unwrap();
    assert_eq!(withdrawn.endpoint(), &route());
    let claims = withdrawn.advertisement().unverified_claims();
    assert!(!claims.capabilities.contains(Capabilities::READ));
    assert!(!claims.capabilities.contains(Capabilities::PUBLISH));
    assert!(!claims.endpoints.contains(withdrawn.endpoint()));
    drop(session);
    let mut session = home.open();
    let current = session.selection().unwrap();
    assert!(session
        .observe(&current, &old.advertisement().encode(), 1002)
        .is_err());
    assert_eq!(session.selection().unwrap(), current);
}
#[test]
fn peer_session_faults_from_empty_scratch_through_cleanup_reconcile_before_use() {
    for point in [
        Point::IntentCreated,
        Point::IntentPartial,
        Point::IntentWritten,
        Point::IntentStageSynced,
        Point::IntentRenamed,
        Point::IntentSynced,
        Point::StateSynced,
        Point::StateRenamed,
        Point::IntentRemoved,
    ] {
        let home = Home::new();
        let mut session = home.create();
        let old = session.selection().unwrap();
        let next_ad = ad(8, 1000, 1100, 1, true);
        session.disk.fault = Some(point);
        assert!(
            matches!(
                session.observe(&old, &next_ad, 1001),
                Err(PublishError::ReopenRequired(_))
            ),
            "{point:?}"
        );
        assert!(session.needs_reopen());
        assert!(session.selection().is_err());
        drop(session);
        let mut session = home.open();
        let recovered = session.selection().unwrap();
        let incomplete = matches!(point, Point::IntentCreated | Point::IntentPartial);
        assert_eq!(
            recovered.advertisement().unverified_claims().sequence,
            if incomplete { 7 } else { 8 },
            "{point:?}"
        );
        assert_eq!(
            recovered.clock_floor(),
            if incomplete { 1000 } else { 1001 }
        );
        let accepted = session.observe(&recovered, &next_ad, 1001).unwrap();
        assert_eq!(accepted.advertisement().unverified_claims().sequence, 8);
        assert!(!home.path().join("INTENT").exists());
        assert!(!home.path().join("INTENT.tmp").exists());
        if point == Point::StateRenamed {
            let syncs = session.disk.syncs.borrow();
            assert!(
                syncs.iter().position(|s| s == "INTENT").unwrap()
                    < syncs.iter().position(|s| s == "STATE").unwrap()
            );
        }
    }
}
#[test]
fn peer_session_wrong_scope_never_cleans_scratch_and_final_partial_intent_is_preserved() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    session.disk.fault = Some(Point::IntentCreated);
    assert!(session.checkpoint_clock(&old, 1001).is_err());
    drop(session);
    assert_eq!(
        fs::read(home.path().join("INTENT.tmp")).unwrap(),
        Vec::<u8>::new()
    );
    let state = fs::read(home.path().join("STATE")).unwrap();
    assert!(NativePeerSession::open(
        home.path(),
        HistoryScope::new([7; 32], [9; 32]),
        peer(),
        &route()
    )
    .is_err());
    assert!(home.path().join("INTENT.tmp").exists());
    assert_eq!(fs::read(home.path().join("STATE")).unwrap(), state);
    fs::rename(home.path().join("INTENT.tmp"), home.path().join("INTENT")).unwrap();
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    assert_eq!(
        fs::read(home.path().join("INTENT")).unwrap(),
        Vec::<u8>::new()
    );
}
#[test]
fn peer_session_complete_corrupt_scratch_and_post_intent_effects_are_preserved() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    session.disk.fault = Some(Point::IntentWritten);
    assert!(session.checkpoint_clock(&old, 1001).is_err());
    drop(session);
    let path = home.path().join("INTENT.tmp");
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    session.disk.fault = Some(Point::IntentCreated);
    assert!(session.checkpoint_clock(&old, 1001).is_err());
    session
        .disk
        .create_file("STATE.tmp", b"unexpected effect")
        .unwrap();
    drop(session);
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    assert!(home.path().join("INTENT.tmp").exists());
}
#[test]
fn peer_session_malformed_oversized_and_foreign_ads_do_not_mutate_state() {
    let home = Home::new();
    let mut session = home.create();
    let old = session.selection().unwrap();
    let mut tampered = ad(8, 1000, 1100, 3, false);
    *tampered.last_mut().unwrap() ^= 1;
    for raw in [vec![], vec![0; MAX_ADVERTISEMENT_BYTES + 1], tampered] {
        assert!(session.observe(&old, &raw, 1001).is_err());
        assert_eq!(session.selection().unwrap(), old);
    }
    let key = SigningKey::from_bytes(&[4; 32]);
    let mut claims = old.advertisement().unverified_claims().clone();
    claims.application_key = key.verifying_key().to_bytes();
    claims.sequence = 8;
    let foreign = UnsignedAdvertisement::new(claims)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .encode();
    assert!(session.observe(&old, &foreign, 1001).is_err());
    assert_eq!(session.selection().unwrap(), old);
}

#[test]
fn peer_session_truncated_stale_or_foreign_before_state_is_never_discarded() {
    for foreign in [false, true] {
        let home = Home::new();
        let mut session = home.create();
        let mut before = session.selection().unwrap();
        if foreign {
            before.scope = HistoryScope::new([7; 32], [99; 32]);
        } else {
            before.generation += 1;
        }
        let end = 16 + before.encode().len() + 1;
        let intent = Intent {
            before,
            change: Change::Clock(1001),
        };
        let raw = intent.encode()[..end].to_vec();
        session.disk.create_file("INTENT.tmp", &raw).unwrap();
        drop(session);
        assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
        assert_eq!(fs::read(home.path().join("INTENT.tmp")).unwrap(), raw);
    }
}

#[test]
fn peer_session_invalid_available_change_framing_is_not_treated_as_incomplete() {
    for case in 0..4 {
        let home = Home::new();
        let mut session = home.create();
        let before = session.selection().unwrap();
        let base = 16 + before.encode().len();
        let mut raw = Intent {
            before,
            change: Change::Clock(1001),
        }
        .encode();
        match case {
            0 => {
                raw[base] = 255;
                let size = raw.len() as u32 + 1;
                raw[8..12].copy_from_slice(&size.to_be_bytes());
            }
            1 => {
                let size = raw.len() as u32 + 1;
                raw[8..12].copy_from_slice(&size.to_be_bytes());
            }
            2 => {
                raw[8..12].copy_from_slice(&100u32.to_be_bytes());
                raw.truncate(20);
            }
            3 => {
                raw[base + 1..base + 9].copy_from_slice(&999u64.to_be_bytes());
                raw.pop();
            }
            _ => unreachable!(),
        }
        session.disk.create_file("INTENT.tmp", &raw).unwrap();
        drop(session);
        assert!(
            NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err(),
            "case{case}"
        );
        assert_eq!(fs::read(home.path().join("INTENT.tmp")).unwrap(), raw);
    }
    let home = Home::new();
    let mut session = home.create();
    let before = session.selection().unwrap();
    let length_at = 16 + before.encode().len() + 1 + 8;
    let mut raw = Intent {
        before,
        change: Change::Observe(decode_ad(&ad(8, 1000, 1100, 3, false)).unwrap(), 1001),
    }
    .encode();
    raw[length_at..length_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    raw.pop();
    session.disk.create_file("INTENT.tmp", &raw).unwrap();
    drop(session);
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    assert_eq!(fs::read(home.path().join("INTENT.tmp")).unwrap(), raw);
}

#[test]
fn peer_session_drop_releases_custody_even_with_inherited_description() {
    let home = Home::new();
    let session = home.create();
    // Like a pre-exec fork, this retains the same open file description.
    let inherited = session._lock.try_clone().unwrap();
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    drop(session);
    let reopened = home.open();
    // Closing the stale reference must not unlock the new owner's description.
    drop(inherited);
    assert!(NativePeerSession::open(home.path(), scope(), peer(), &route()).is_err());
    drop(reopened);
    let _final_owner = home.open();
}
