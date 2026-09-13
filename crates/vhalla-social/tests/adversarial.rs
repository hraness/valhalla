//! Independently constructed signed cross-boundary regressions.
use ed25519_dalek::SigningKey;
use vhalla_core::RealmId;
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    control::ControlView,
    *,
};

fn sign(body: Body, key: &SigningKey, ack: Option<&SigningKey>) -> SignedRecord {
    let primary = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(k) => primary.countersign(k).unwrap(),
        None => primary.finish().unwrap(),
    }
}
fn ingest(archive: &mut Archive, record: &SignedRecord) -> Result<archive::IngestReceipt, Error> {
    archive.ingest(
        &record.encode(),
        &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
    )
}

#[test]
fn authenticated_revocation_cannot_be_lost_to_an_exhausted_control_quota() {
    let realm = RealmId(91);
    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let agent_key = SigningKey::from_bytes(&[2; 32]);
    let root = sign(
        Body::OwnerGenesis {
            controller: owner_key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [1; 32],
        },
        &owner_key,
        None,
    );
    let owner = OwnerId::from_bytes(*root.id().as_bytes());
    let agent_root = sign(
        Body::AgentGenesis {
            owner,
            control: root.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [2; 32],
        },
        &owner_key,
        Some(&agent_key),
    );
    let agent = AgentId::from_bytes(*agent_root.id().as_bytes());
    let grant = sign(
        Body::Control {
            owner,
            previous: root.id(),
            action: ControlAction::Grant {
                agent,
                realm,
                rights: Rights::ALL,
                expires_at: 1000,
                nonce: [3; 32],
            },
        },
        &owner_key,
        None,
    );
    let revoke = sign(
        Body::Control {
            owner,
            previous: grant.id(),
            action: ControlAction::Revoke {
                grant: grant.id(),
                accepted: References::default(),
            },
        },
        &owner_key,
        None,
    );
    let limits = Limits {
        records: 16,
        control_reserve: 4,
        data_per_owner: 4,
        data_per_writer: 4,
        control_per_owner: 1,
        pending: 4,
        pending_per_signer: 2,
    };
    let mut archive = Archive::new(realm, limits).unwrap();
    for record in [&root, &agent_root, &grant] {
        ingest(&mut archive, record).unwrap();
    }
    // Eligibility must close before a retained set consumes its last ability
    // to accept a terminal control. This is independent of arrival history.
    assert!(
        !ControlView::new(&archive, 1).agent(agent).unwrap().active(),
        "a fully consumed control quota still exposes live authority"
    );
    let result = ingest(&mut archive, &revoke);
    assert!(
        !ControlView::new(&archive, 1).agent(agent).unwrap().active(),
        "observed authenticated revocation left the old grant active after {result:?}"
    );
}

#[test]
fn pending_data_reclassification_cannot_veto_a_valid_revocation() {
    let realm = RealmId(92);
    let owner_key = SigningKey::from_bytes(&[3; 32]);
    let agent_key = SigningKey::from_bytes(&[4; 32]);
    let root = sign(
        Body::OwnerGenesis {
            controller: owner_key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [3; 32],
        },
        &owner_key,
        None,
    );
    let owner = OwnerId::from_bytes(*root.id().as_bytes());
    let agent_root = sign(
        Body::AgentGenesis {
            owner,
            control: root.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [4; 32],
        },
        &owner_key,
        Some(&agent_key),
    );
    let agent = AgentId::from_bytes(*agent_root.id().as_bytes());
    let grant = sign(
        Body::Control {
            owner,
            previous: root.id(),
            action: ControlAction::Grant {
                agent,
                realm,
                rights: Rights::ALL,
                expires_at: 1000,
                nonce: [5; 32],
            },
        },
        &owner_key,
        None,
    );
    let revoke = sign(
        Body::Control {
            owner,
            previous: grant.id(),
            action: ControlAction::Revoke {
                grant: grant.id(),
                accepted: References::default(),
            },
        },
        &owner_key,
        None,
    );
    let staged = sign(
        Body::Social {
            actor: Actor::Owner {
                owner,
                control: revoke.id(),
            },
            realm,
            sequence: 0,
            previous: None,
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new("post after withheld revocation").unwrap(),
                reply: None,
                quote: None,
            },
        },
        &owner_key,
        None,
    );
    let limits = Limits {
        records: 16,
        control_reserve: 4,
        data_per_owner: 2,
        data_per_writer: 2,
        control_per_owner: 4,
        pending: 4,
        pending_per_signer: 2,
    };
    let mut archive = Archive::new(realm, limits).unwrap();
    for record in [&root, &agent_root, &grant] {
        ingest(&mut archive, record).unwrap();
    }
    // Earlier full-key affiliation may reject this ordinary data immediately;
    // otherwise its already retained footprint cannot veto the revealing control.
    let staged_result = ingest(&mut archive, &staged);
    assert!(staged_result.is_ok() || staged_result == Err(Error::Capacity));
    let result = ingest(&mut archive, &revoke);
    assert!(
        !ControlView::new(&archive, 1).agent(agent).unwrap().active(),
        "reclassification vetoed revocation despite free control quota: {result:?}"
    );
}
