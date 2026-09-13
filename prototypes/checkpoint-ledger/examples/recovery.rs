//! In-memory demonstration; fixed signing keys are public test fixtures only.
use ed25519_dalek::SigningKey;
use valhalla_checkpoint_ledger_prototype::{certificate_realm, CertifiedLedger, Error};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

fn certificate(model: &CertifiedLedger, keys: &[SigningKey]) -> Vec<u8> {
    let statement = model.propose_tip().expect("nonempty history");
    let approvals = keys
        .iter()
        .map(|key| Approval::sign(key, statement.clone()).expect("bounded claim"))
        .collect();
    wire::encode(&CheckpointProof {
        statement,
        approvals,
    })
    .expect("canonical certificate")
}

fn main() {
    let realm = RealmId(42);
    let epoch = Epoch(7);
    let keys = [
        SigningKey::from_bytes(&[1; 32]),
        SigningKey::from_bytes(&[2; 32]),
    ];
    let trust = TrustConfig::new(
        certificate_realm(realm),
        epoch.0,
        keys.iter().map(SigningKey::verifying_key),
        2,
        2,
        4096,
    )
    .unwrap();
    let mut model = CertifiedLedger::new(realm, epoch, trust.clone(), 8).unwrap();
    model
        .append(Event::new(
            None,
            realm,
            epoch,
            PeerId(1),
            Sequence(1),
            b"room opened".to_vec(),
        ))
        .unwrap();
    let old_certificate = certificate(&model, &keys);
    model.admit(&old_certificate).unwrap();
    let old_snapshot = model.snapshot();

    model
        .append(Event::new(
            model.head(),
            realm,
            epoch,
            PeerId(1),
            Sequence(2),
            b"game move recorded".to_vec(),
        ))
        .unwrap();
    let latest_certificate = certificate(&model, &keys);
    let anchor = model.admit(&latest_certificate).unwrap().recovery_anchor();
    let recovered = CertifiedLedger::recover(
        &model.snapshot(),
        &latest_certificate,
        &anchor,
        trust.clone(),
        8,
    )
    .unwrap();
    assert_eq!(
        recovered.accepted().unwrap().checkpoint(),
        anchor.checkpoint()
    );
    println!(
        "recovered {} events at certified height {}",
        recovered.event_count(),
        anchor.checkpoint().height
    );

    assert!(matches!(
        CertifiedLedger::recover(&old_snapshot, &old_certificate, &anchor, trust, 8),
        Err(Error::AnchorMismatch)
    ));
    println!("rejected an older valid certificate against the separately retained anchor");
    println!("in-memory reference only: no durable store, consensus, or host authority");
}
