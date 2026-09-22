use super::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use vhalla_journal::BundleParts;
use vhalla_rooms::DirectoryId;
use vhalla_rooms_consensus::{fixture, Genesis};
use vhalla_rooms_node::{Address, PublicKey};

fn keys() -> Vec<SigningKey> {
    (101..=104)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect()
}

fn activation(from: u64, keys: &[SigningKey]) -> ValidatorActivation {
    ValidatorActivation {
        from,
        validators: keys
            .iter()
            .map(|key| Validator {
                public_key: key.verifying_key().to_bytes(),
                power: 1,
            })
            .collect(),
    }
}

fn bootstrap(genesis: Genesis) -> Bootstrap {
    Bootstrap::from_genesis(genesis, vec![activation(1, &keys())]).unwrap()
}

fn client(bootstrap: Bootstrap) -> CertifiedClient {
    let pin = bootstrap.pin();
    CertifiedClient::new(bootstrap, pin).unwrap()
}

fn certificate(height: u64, value: [u8; 32], signers: &[SigningKey]) -> Vec<u8> {
    let round = 0u32;
    let mut raw = b"VC2".to_vec();
    raw.extend_from_slice(&height.to_be_bytes());
    raw.extend_from_slice(&round.to_be_bytes());
    raw.extend_from_slice(&value);
    raw.extend_from_slice(&(signers.len() as u16).to_be_bytes());
    for key in signers {
        let public = PublicKey::from_bytes(key.verifying_key().to_bytes()).unwrap();
        let address = Address::from_public_key(&public).into_inner();
        // Independent fixture construction of the documented RV1 precommit.
        // The production VC2 consumer reconstructs and verifies this message.
        let mut vote = b"RV1".to_vec();
        vote.push(1);
        vote.extend_from_slice(&height.to_be_bytes());
        vote.extend_from_slice(&round.to_be_bytes());
        vote.push(1);
        vote.extend_from_slice(&value);
        vote.extend_from_slice(&address);
        raw.extend_from_slice(&address);
        raw.extend_from_slice(&key.sign(&vote).to_bytes());
    }
    raw
}

fn next(batch: &Batch) -> Frontier {
    Frontier {
        height: batch.parent.height + 1,
        value: batch.value_id(),
        registry: batch.result_registry,
        social: batch.result_social,
        control: batch.result_control,
        time: batch.time,
    }
}

fn bundle(batch: &Batch, policy: &vhalla_rooms::registry::DirectoryPolicy) -> Bundle {
    let next = next(batch);
    Bundle::new(BundleParts {
        certificate: certificate(next.height, batch.value_id(), &keys()[..3]),
        predecessor: batch.parent.commitment(),
        next: next.commitment(),
        batch: batch.encode(),
        value: batch.value_id().to_vec(),
        configuration: policy.id().as_bytes().to_vec(),
        control_record: next.control.to_vec(),
        debit_marker: next.value.to_vec(),
        height: next.height,
    })
    .unwrap()
}

fn parts(bundle: &Bundle) -> BundleParts {
    BundleParts {
        certificate: bundle.field(0).unwrap().to_vec(),
        predecessor: bundle.predecessor(),
        next: bundle.next(),
        batch: bundle.field(3).unwrap().to_vec(),
        value: bundle.field(4).unwrap().to_vec(),
        configuration: bundle.field(5).unwrap().to_vec(),
        control_record: bundle.field(6).unwrap().to_vec(),
        debit_marker: bundle.field(7).unwrap().to_vec(),
        height: bundle.height(),
    }
}

fn trusted_pin(raw: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"vhalla/public-bootstrap/v1\0");
    hash.update(raw);
    hash.finalize().into()
}

fn assert_prepare_error(client: &CertifiedClient, raw: &[u8], expected: Error) {
    let before = client.frontier();
    assert_eq!(
        client.prepare(client.network_id(), raw).err(),
        Some(expected)
    );
    assert_eq!(client.frontier(), before);
}

#[test]
fn signed_quorum_replay_stages_then_installs_real_directory_state() {
    let plan = fixture::plan(2, 2, 4);
    let boot = bootstrap(plan.genesis.clone());
    let mut replica = client(boot.clone());
    let original = replica.frontier();
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let candidate = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    assert_eq!(replica.frontier(), original);
    assert_eq!(
        replica
            .registry()
            .search("room", 8, 64)
            .unwrap()
            .rooms
            .len(),
        0
    );
    assert_eq!(candidate.network_id(), boot.network_id());
    assert_eq!(candidate.bootstrap_pin(), boot.pin());
    assert_eq!(candidate.base_frontier(), original);
    assert_eq!(candidate.bundle_id(), first.id());
    assert_eq!(candidate.bundle_bytes(), first.bytes());
    let stored_bytes = candidate.bundle_bytes().to_vec();
    let stored_frontier = candidate.next_frontier();
    // This in-memory test represents the caller's successful publication, not
    // evidence of actual browser or filesystem durability.
    replica.commit_after_persist(candidate).unwrap();
    assert_eq!(replica.frontier(), stored_frontier);
    assert_eq!(replica.frontier().height, 1);
    assert_eq!(
        replica
            .registry()
            .search("room", 8, 64)
            .unwrap()
            .rooms
            .len(),
        1
    );
    assert_eq!(stored_bytes, first.bytes());
    assert!(!replica.archive().is_empty());
}

#[test]
fn failed_or_cancelled_storage_never_advances_memory() {
    let plan = fixture::plan(1, 1, 4);
    let replica = client(bootstrap(plan.genesis.clone()));
    let before = replica.frontier();
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let cancelled = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    drop(cancelled);
    assert_eq!(replica.frontier(), before);
    assert!(replica.prepare(replica.network_id(), first.bytes()).is_ok());
}

#[test]
fn multi_peer_duplicate_reordered_delivery_and_restart_recover_same_frontier() {
    let plan = fixture::plan(3, 3, 4);
    let boot = bootstrap(plan.genesis.clone());
    let mut replica = client(boot.clone());
    let bundles: Vec<_> = plan
        .batches
        .values()
        .map(|batch| bundle(batch, &plan.genesis.policy))
        .collect();
    assert_prepare_error(&replica, bundles[1].bytes(), Error::Height);
    let mut retained = Vec::new();
    for (index, delivered) in bundles.iter().enumerate() {
        let candidate = replica
            .prepare(replica.network_id(), delivered.bytes())
            .unwrap();
        retained.push(candidate.bundle_bytes().to_vec());
        replica.commit_after_persist(candidate).unwrap();
        // A second peer can supply a different valid quorum for the same batch.
        let mut duplicate = parts(delivered);
        duplicate.certificate = certificate(
            (index + 1) as u64,
            plan.batches[&((index + 1) as u64)].value_id(),
            &keys()[1..],
        );
        assert_prepare_error(
            &replica,
            Bundle::new(duplicate).unwrap().bytes(),
            Error::Height,
        );
    }
    let mut reopened = client(boot);
    for raw in &retained {
        let candidate = reopened.prepare(reopened.network_id(), raw).unwrap();
        reopened.commit_after_persist(candidate).unwrap();
    }
    assert_eq!(reopened.frontier(), replica.frontier());
    assert_eq!(
        reopened
            .registry()
            .search("room", 8, 64)
            .unwrap()
            .rooms
            .len(),
        3
    );
}

#[test]
fn wrong_network_pin_quorum_signature_and_value_are_rejected() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis.clone());
    assert_eq!(
        CertifiedClient::new(boot.clone(), [0; 32]).err(),
        Some(Error::BootstrapPin)
    );
    let replica = client(boot);
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    assert_eq!(
        replica.prepare([0; 32], first.bytes()).err(),
        Some(Error::Network)
    );
    let mut bad = parts(&first);
    bad.certificate = certificate(1, plan.batches[&1].value_id(), &keys()[..2]);
    assert_prepare_error(
        &replica,
        Bundle::new(bad).unwrap().bytes(),
        Error::Certificate,
    );
    let mut bad = parts(&first);
    let last = bad.certificate.len() - 1;
    bad.certificate[last] ^= 1;
    assert_prepare_error(
        &replica,
        Bundle::new(bad).unwrap().bytes(),
        Error::Certificate,
    );
    let mut bad = parts(&first);
    bad.certificate = certificate(1, [9; 32], &keys()[..3]);
    assert_prepare_error(
        &replica,
        Bundle::new(bad).unwrap().bytes(),
        Error::Certificate,
    );
    let mut bad = parts(&first);
    bad.value[0] ^= 1;
    assert_prepare_error(
        &replica,
        Bundle::new(bad).unwrap().bytes(),
        Error::Certificate,
    );
    let mut bad = parts(&first);
    let signers = keys();
    bad.certificate = certificate(
        1,
        plan.batches[&1].value_id(),
        &[signers[0].clone(), signers[0].clone(), signers[1].clone()],
    );
    assert_prepare_error(
        &replica,
        Bundle::new(bad).unwrap().bytes(),
        Error::Certificate,
    );
}

#[test]
fn signed_wrong_height_parent_result_and_every_bundle_annotation_are_rejected() {
    let plan = fixture::plan(1, 1, 4);
    let replica = client(bootstrap(plan.genesis.clone()));
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let mut bad = parts(&first);
    bad.height = 2;
    bad.certificate = certificate(2, plan.batches[&1].value_id(), &keys()[..3]);
    assert_prepare_error(&replica, Bundle::new(bad).unwrap().bytes(), Error::Height);
    let mut bad_batch = plan.batches[&1].clone();
    bad_batch.parent.value[0] ^= 1;
    assert_prepare_error(
        &replica,
        bundle(&bad_batch, &plan.genesis.policy).bytes(),
        Error::Frontier,
    );
    let mut bad_batch = plan.batches[&1].clone();
    bad_batch.result_registry[0] ^= 1;
    assert_prepare_error(
        &replica,
        bundle(&bad_batch, &plan.genesis.policy).bytes(),
        Error::Replay,
    );
    for field in [1, 2, 5, 6, 7] {
        let mut bad = parts(&first);
        let expected = match field {
            1 => {
                bad.predecessor[0] ^= 1;
                Error::Frontier
            }
            2 => {
                bad.next[0] ^= 1;
                Error::Frontier
            }
            5 => {
                bad.configuration[0] ^= 1;
                Error::BundleFields
            }
            6 => {
                bad.control_record[0] ^= 1;
                Error::BundleFields
            }
            _ => {
                bad.debit_marker[0] ^= 1;
                Error::BundleFields
            }
        };
        assert_prepare_error(&replica, Bundle::new(bad).unwrap().bytes(), expected);
    }
}

#[test]
fn malformed_trailing_and_wide_lengths_never_create_a_candidate() {
    let plan = fixture::plan(1, 1, 4);
    let replica = client(bootstrap(plan.genesis.clone()));
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    for end in [0, 3, 4, 11, first.len() - 1] {
        assert_prepare_error(&replica, &first.bytes()[..end], Error::Encoding);
    }
    let mut trailing = first.bytes().to_vec();
    trailing.push(0);
    assert_prepare_error(&replica, &trailing, Error::Encoding);
    let mut wide = first.bytes().to_vec();
    let actual = u64::from_le_bytes(wide[4..12].try_into().unwrap());
    wide[4..12].copy_from_slice(&(actual + (1u64 << 32)).to_le_bytes());
    // On every supported word size, wide foreign lengths either fail decoding
    // or fail the exact canonical producer-byte comparison.
    assert!(replica.prepare(replica.network_id(), &wide).is_err());
    assert_prepare_error(&replica, &vec![0; MAX_BUNDLE_BYTES + 1], Error::Bounds);
}

#[test]
fn stale_candidate_cannot_install_after_advance_or_trust_configuration_change() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis.clone());
    let mut replica = client(boot.clone());
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let winner = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    let stale = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    replica.commit_after_persist(winner).unwrap();
    let after = replica.frontier();
    assert_eq!(
        replica.commit_after_persist(stale),
        Err(Error::StaleCandidate)
    );
    assert_eq!(replica.frontier(), after);

    let original = client(boot);
    let candidate = original
        .prepare(original.network_id(), first.bytes())
        .unwrap();
    let updated = Bootstrap::from_genesis(
        plan.genesis.clone(),
        vec![activation(1, &keys()), activation(10, &keys())],
    )
    .unwrap();
    let mut different_config = client(updated);
    assert_eq!(different_config.network_id(), original.network_id());
    assert_ne!(different_config.bootstrap_pin(), original.bootstrap_pin());
    assert_eq!(
        different_config.commit_after_persist(candidate),
        Err(Error::StaleCandidate)
    );

    let candidate = original
        .prepare(original.network_id(), first.bytes())
        .unwrap();
    let mut foreign_genesis = plan.genesis;
    foreign_genesis.directory = DirectoryId::from_bytes([8; 32]);
    let mut foreign = client(bootstrap(foreign_genesis));
    assert_eq!(
        foreign.commit_after_persist(candidate),
        Err(Error::StaleCandidate)
    );
    assert_eq!(foreign.frontier().height, 0);
}

#[test]
fn bootstrap_roundtrip_preserves_full_genesis_and_origin_ignores_only_future_sets() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis.clone());
    let raw = boot.encode();
    assert!(raw.len() <= MAX_BOOTSTRAP_BYTES);
    assert_eq!(trusted_pin(&raw), boot.pin());
    let decoded = Bootstrap::decode(&raw, boot.pin()).unwrap();
    assert_eq!(decoded.encode(), raw);
    assert_eq!(decoded.network_id(), boot.network_id());
    assert_eq!(
        decoded.genesis().archive.root(),
        plan.genesis.archive.root()
    );
    assert_eq!(client(decoded).frontier(), client(boot.clone()).frontier());

    let mut reversed = activation(1, &keys());
    reversed.validators.reverse();
    let mut equivalent_genesis = plan.genesis.clone();
    equivalent_genesis.eligible.reverse();
    let equivalent = Bootstrap::from_genesis(equivalent_genesis, vec![reversed]).unwrap();
    assert_eq!(equivalent.pin(), boot.pin());

    let changed_keys: Vec<_> = (111..=114)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let extension = Bootstrap::from_genesis(
        plan.genesis.clone(),
        vec![activation(1, &keys()), activation(10, &changed_keys)],
    )
    .unwrap();
    assert_eq!(extension.network_id(), boot.network_id());
    assert_ne!(extension.pin(), boot.pin());
    let changed_initial =
        Bootstrap::from_genesis(plan.genesis, vec![activation(1, &changed_keys)]).unwrap();
    assert_ne!(changed_initial.network_id(), boot.network_id());
}

#[test]
fn changing_genesis_evidence_configuration_or_archive_context_changes_or_rejects_pin() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis.clone());
    let mut changed = plan.genesis.clone();
    fixture::owner(&mut changed.archive, 20);
    let changed = bootstrap(changed);
    assert_ne!(changed.pin(), boot.pin());
    assert_ne!(changed.network_id(), boot.network_id());
    let mut changed = plan.genesis.clone();
    changed.policy.base_cost += 1;
    assert_ne!(bootstrap(changed).network_id(), boot.network_id());
    let mut mismatched = plan.genesis.clone();
    mismatched.realm = vhalla_core::RealmId(123);
    assert_eq!(
        Bootstrap::from_genesis(mismatched, vec![activation(1, &keys())]).err(),
        Some(Error::Bootstrap)
    );
    let mut mismatched = plan.genesis;
    mismatched.limits.records += 1;
    assert_eq!(
        Bootstrap::from_genesis(mismatched, vec![activation(1, &keys())]).err(),
        Some(Error::Bootstrap)
    );
}

#[test]
fn bootstrap_checks_independent_pin_before_admitting_hostile_snapshot() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis);
    let raw = boot.encode();
    let mut tampered = raw.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        Bootstrap::decode(&tampered, boot.pin()).err(),
        Some(Error::BootstrapPin)
    );
    // Even an explicitly pinned malformed snapshot remains structurally invalid.
    assert_eq!(
        Bootstrap::decode(&tampered, trusted_pin(&tampered)).err(),
        Some(Error::Bootstrap)
    );
    for end in [0, 4, 5, 111, 112, raw.len() - 1] {
        assert!(Bootstrap::decode(&raw[..end], trusted_pin(&raw[..end])).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(
        Bootstrap::decode(&trailing, trusted_pin(&trailing)).err(),
        Some(Error::Encoding)
    );
    let mut version = raw;
    version[4] = 2;
    assert_eq!(
        Bootstrap::decode(&version, trusted_pin(&version)).err(),
        Some(Error::Encoding)
    );
}

#[test]
fn bootstrap_rejects_noncanonical_wire_order_even_under_matching_content_pin() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis);
    let mut raw = boot.encode();
    // Four eligible owners follow the fixed 111-byte configuration header.
    assert_eq!(u16::from_be_bytes(raw[111..113].try_into().unwrap()), 4);
    for i in 0..32 {
        raw.swap(113 + i, 145 + i);
    }
    assert_eq!(
        Bootstrap::decode(&raw, trusted_pin(&raw)).err(),
        Some(Error::Encoding)
    );
    let mut raw = boot.encode();
    let activation_count = 113 + 4 * 32;
    raw[activation_count] = 65;
    assert_eq!(
        Bootstrap::decode(&raw, trusted_pin(&raw)).err(),
        Some(Error::Bounds)
    );
}

#[test]
fn validator_identity_power_and_schedule_bounds_are_checked_before_engine_construction() {
    let plan = fixture::plan(1, 1, 4);
    for power in [0, u64::MAX, u64::MAX / 3 + 1] {
        let mut set = activation(1, &keys());
        set.validators[0].power = power;
        assert_eq!(
            Bootstrap::from_genesis(plan.genesis.clone(), vec![set]).err(),
            Some(Error::Validators)
        );
    }
    for conflicting in [false, true] {
        let mut set = activation(1, &keys());
        let mut duplicate = set.validators[0].clone();
        if conflicting {
            duplicate.power = 2;
        }
        set.validators.insert(2, duplicate);
        assert_eq!(
            Bootstrap::from_genesis(plan.genesis.clone(), vec![set]).err(),
            Some(Error::Validators)
        );
    }
    let mut weak = activation(1, &keys());
    weak.validators[0].public_key = [0; 32];
    assert_eq!(
        Bootstrap::from_genesis(plan.genesis.clone(), vec![weak]).err(),
        Some(Error::Validators)
    );
    for from in [0, 2, u64::MAX] {
        assert_eq!(
            Bootstrap::from_genesis(plan.genesis.clone(), vec![activation(from, &keys())]).err(),
            Some(Error::Validators)
        );
    }
    assert_eq!(
        Bootstrap::from_genesis(
            plan.genesis.clone(),
            vec![activation(1, &keys()), activation(1, &keys())]
        )
        .err(),
        Some(Error::Validators)
    );
    assert_eq!(
        Bootstrap::from_genesis(plan.genesis.clone(), Vec::new()).err(),
        Some(Error::Bounds)
    );
    let mut too_many = activation(1, &keys());
    too_many.validators = vec![too_many.validators[0].clone(); MAX_VALIDATORS + 1];
    assert_eq!(
        Bootstrap::from_genesis(plan.genesis.clone(), vec![too_many]).err(),
        Some(Error::Bounds)
    );
    assert_eq!(
        Bootstrap::from_genesis(
            plan.genesis,
            vec![activation(1, &keys()); MAX_VALIDATOR_SETS + 1]
        )
        .err(),
        Some(Error::Bounds)
    );
}

#[test]
fn maximum_schedule_and_validator_count_are_bounded_and_roundtrip() {
    let genesis = Genesis {
        directory: DirectoryId::from_bytes([3; 32]),
        realm: vhalla_core::RealmId(1),
        policy: fixture::policy(),
        eligible: Vec::new(),
        limits: fixture::limits(),
        archive: Archive::new(vhalla_core::RealmId(1), fixture::limits()).unwrap(),
    };
    let many_keys: Vec<_> = (1..=64)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let schedule = (1..=64).map(|from| activation(from, &many_keys)).collect();
    let boot = Bootstrap::from_genesis(genesis, schedule).unwrap();
    assert!(boot.encode().len() <= MAX_BOOTSTRAP_BYTES);
    assert_eq!(
        Bootstrap::decode(&boot.encode(), boot.pin()).unwrap().pin(),
        boot.pin()
    );
}

#[test]
fn rotation_uses_the_pinned_active_set_at_each_exact_height() {
    let plan = fixture::plan(2, 2, 4);
    let new_keys: Vec<_> = (111..=114)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let boot = Bootstrap::from_genesis(
        plan.genesis.clone(),
        vec![activation(1, &keys()), activation(2, &new_keys)],
    )
    .unwrap();
    let mut replica = client(boot);
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let candidate = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    replica.commit_after_persist(candidate).unwrap();
    let second = bundle(&plan.batches[&2], &plan.genesis.policy);
    assert_prepare_error(&replica, second.bytes(), Error::Certificate);
    let mut rotated = parts(&second);
    rotated.certificate = certificate(2, plan.batches[&2].value_id(), &new_keys[..3]);
    let rotated = Bundle::new(rotated).unwrap();
    let candidate = replica
        .prepare(replica.network_id(), rotated.bytes())
        .unwrap();
    replica.commit_after_persist(candidate).unwrap();
    assert_eq!(replica.frontier().height, 2);
}

fn checkpoint_resign(raw: &mut [u8], key: &[u8; 32]) {
    use hmac::{Hmac, Mac};
    let split = raw.len() - 32;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(b"vhalla/local-certified-checkpoint/v1\0");
    mac.update(&raw[..split]);
    raw[split..].copy_from_slice(&mac.finalize().into_bytes());
}

#[test]
fn checkpoint_restores_exact_state_and_matched_ancestry_then_continues() {
    use crate::checkpoint::AuthenticatedCheckpoint;
    let plan = fixture::plan(3, 3, 4);
    let boot = bootstrap(plan.genesis.clone());
    let mut replica = client(boot.clone());
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let candidate = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    replica.commit_after_persist(candidate).unwrap();
    let anchor = replica.checkpoint_head();
    replica.require_anchor(anchor).unwrap();
    let second = bundle(&plan.batches[&2], &plan.genesis.policy);
    let candidate = replica
        .prepare(replica.network_id(), second.bytes())
        .unwrap();
    replica.commit_after_persist(candidate).unwrap();
    let raw = replica
        .checkpoint_image()
        .unwrap()
        .seal(&[71; 32], 12, [14; 32]);
    let authenticated =
        AuthenticatedCheckpoint::open(&raw, &[71; 32], boot.network_id(), boot.pin()).unwrap();
    assert_eq!(authenticated.generation(), 12);
    assert_eq!(authenticated.previous(), [14; 32]);
    let mut restored = authenticated.restore(boot.clone(), boot.pin()).unwrap();
    assert_eq!(restored.checkpoint_head(), replica.checkpoint_head());
    assert_eq!(restored.archive().snapshot(), replica.archive().snapshot());
    assert_eq!(
        restored.registry().snapshot(),
        replica.registry().snapshot()
    );
    assert_eq!(restored.retained_anchor(), Some((anchor, true)));
    restored.require_anchor(anchor).unwrap();
    let third = bundle(&plan.batches[&3], &plan.genesis.policy);
    let candidate = restored
        .prepare(restored.network_id(), third.bytes())
        .unwrap();
    restored.commit_after_persist(candidate).unwrap();
    assert_eq!(restored.frontier(), next(&plan.batches[&3]));
    let wrong = checkpoint::CheckpointHead::new(anchor.frontier(), [72; 32]).unwrap();
    assert_eq!(restored.require_anchor(wrong), Err(Error::Anchor));
}

#[test]
fn checkpoint_anchor_rejects_before_persist_and_binds_candidate_revision() {
    let plan = fixture::plan(1, 1, 4);
    let boot = bootstrap(plan.genesis.clone());
    let first = bundle(&plan.batches[&1], &plan.genesis.policy);
    let mut replica = client(boot.clone());
    let wrong = checkpoint::CheckpointHead::new(next(&plan.batches[&1]), [42; 32]).unwrap();
    replica.require_anchor(wrong).unwrap();
    assert_prepare_error(&replica, first.bytes(), Error::Anchor);
    assert!(!replica.anchor_matched());
    let mut replica = client(boot);
    let before = replica.checkpoint_head();
    let candidate = replica
        .prepare(replica.network_id(), first.bytes())
        .unwrap();
    replica.require_anchor(before).unwrap();
    assert_eq!(
        replica.commit_after_persist(candidate),
        Err(Error::StaleCandidate)
    );
    assert_eq!(replica.checkpoint_head(), before);
}

#[test]
fn checkpoint_authentication_scope_and_bounds_precede_restore() {
    use crate::checkpoint::{AuthenticatedCheckpoint, CHECKPOINT_HEADER_BYTES};
    let boot = bootstrap(fixture::scenario(1, 1).genesis);
    let replica = client(boot.clone());
    let key = [52; 32];
    let raw = replica.checkpoint_image().unwrap().seal(&key, 0, [0; 32]);
    for at in [8, 16, 48, 80, CHECKPOINT_HEADER_BYTES + 8, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[at] ^= 1;
        assert!(AuthenticatedCheckpoint::open(&bad, &key, boot.network_id(), boot.pin()).is_err());
    }
    assert!(AuthenticatedCheckpoint::open(&raw, &[53; 32], boot.network_id(), boot.pin()).is_err());
    assert!(AuthenticatedCheckpoint::open(&raw, &key, [1; 32], boot.pin()).is_err());
    assert!(AuthenticatedCheckpoint::open(&raw, &key, boot.network_id(), [1; 32]).is_err());
    let mut bad = raw.clone();
    bad[112..120].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        AuthenticatedCheckpoint::open(&bad, &key, boot.network_id(), boot.pin()),
        Err(Error::Bounds)
    ));
    assert!(AuthenticatedCheckpoint::open(
        &raw[..raw.len() - 1],
        &key,
        boot.network_id(),
        boot.pin()
    )
    .is_err());
    let mut bad = raw;
    bad.push(0);
    assert!(AuthenticatedCheckpoint::open(&bad, &key, boot.network_id(), boot.pin()).is_err());
}

#[test]
fn checkpoint_checked_restore_rejects_forged_genesis_and_noncanonical_registry() {
    use crate::checkpoint::{AuthenticatedCheckpoint, CHECKPOINT_HEADER_BYTES};
    let boot = bootstrap(fixture::plan(3, 3, 4).genesis);
    let replica = client(boot.clone());
    let key = [61; 32];
    let raw = replica.checkpoint_image().unwrap().seal(&key, 0, [0; 32]);
    let mut bad = raw.clone();
    bad[CHECKPOINT_HEADER_BYTES + 8] ^= 1;
    checkpoint_resign(&mut bad, &key);
    let token = AuthenticatedCheckpoint::open(&bad, &key, boot.network_id(), boot.pin()).unwrap();
    assert!(matches!(
        token.restore(boot.clone(), boot.pin()),
        Err(Error::Checkpoint)
    ));

    // Registry restore normalizes eligibility ordering. Its resulting semantic
    // digest is still correct, so canonical equality is a necessary extra guard.
    let length_at = CHECKPOINT_HEADER_BYTES + 176 + 1;
    let len = u32::from_be_bytes(raw[length_at..length_at + 4].try_into().unwrap()) as usize;
    let start = length_at + 4;
    let mut bad = raw;
    let registry = &mut bad[start..start + len];
    let count = u32::from_be_bytes(registry[102..106].try_into().unwrap());
    assert!(count >= 2);
    for index in 0..32 {
        registry.swap(106 + index, 138 + index);
    }
    let mut hash = Sha256::new();
    hash.update(b"vhalla/rooms/registry-snapshot/v1\0");
    hash.update(&registry[8..len - 32]);
    registry[len - 32..].copy_from_slice(&hash.finalize());
    assert_eq!(
        Registry::restore(registry).unwrap().digest(),
        replica.registry().digest()
    );
    checkpoint_resign(&mut bad, &key);
    let token = AuthenticatedCheckpoint::open(&bad, &key, boot.network_id(), boot.pin()).unwrap();
    assert!(matches!(
        token.restore(boot.clone(), boot.pin()),
        Err(Error::Checkpoint)
    ));
}

#[test]
fn checkpoint_scratch_classifier_preserves_impossible_prefixes() {
    use crate::checkpoint::{incomplete_successor, CHECKPOINT_HEADER_BYTES};
    let boot = bootstrap(fixture::scenario(1, 1).genesis);
    let replica = client(boot.clone());
    let raw = replica
        .checkpoint_image()
        .unwrap()
        .seal(&[88; 32], 1, [9; 32]);
    for prefix in 0..raw.len() {
        assert_eq!(
            incomplete_successor(&raw[..prefix], boot.network_id(), boot.pin(), 1, [9; 32]),
            Ok(true),
            "prefix {prefix}"
        );
    }
    assert_eq!(
        incomplete_successor(&raw, boot.network_id(), boot.pin(), 1, [9; 32]),
        Ok(false)
    );
    for at in [
        112,
        CHECKPOINT_HEADER_BYTES + 176,
        CHECKPOINT_HEADER_BYTES + 177,
    ] {
        let mut bad = raw[..at + 1].to_vec();
        bad[at] = 255;
        assert!(incomplete_successor(&bad, boot.network_id(), boot.pin(), 1, [9; 32]).is_err());
    }
    assert!(incomplete_successor(&raw[..17], boot.network_id(), boot.pin(), 2, [9; 32]).is_err());
}
