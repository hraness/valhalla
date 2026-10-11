//! Deterministic two-store *protocol model*, not a protected commit adapter.
//! Candidate pins come from real certified `PreparedCommit`s, but the journal's
//! checked-data marker abstracts re-reading and verifying the actual bundle.
//! No test here establishes host isolation, physical fsync, or live availability.
use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use valhalla_checkpoint_ledger_prototype::persistence::{BundleId, Pin, PreparedCommit};
use valhalla_checkpoint_ledger_prototype::{certificate_realm, CertifiedLedger};
use valhalla_checkpoint_proof_prototype::{wire, Approval, CheckpointProof, TrustConfig};
use vhalla_core::{Epoch, PeerId, RealmId, Sequence};
use vhalla_ledger::Event;

fn trust() -> TrustConfig {
    TrustConfig::new(
        certificate_realm(RealmId(1)),
        7,
        [1, 2]
            .map(|n| SigningKey::from_bytes(&[n; 32]))
            .iter()
            .map(SigningKey::verifying_key),
        2,
        2,
        4096,
    )
    .unwrap()
}

fn append_and_certify(model: &mut CertifiedLedger, payload: &[u8]) -> Vec<u8> {
    model
        .append(Event::new(
            model.head(),
            RealmId(1),
            Epoch(7),
            PeerId(2),
            Sequence(model.event_count() as u64 + 1),
            payload.to_vec(),
        ))
        .unwrap();
    let statement = model.propose_tip().unwrap();
    let approvals = [1, 2]
        .map(|n| SigningKey::from_bytes(&[n; 32]))
        .iter()
        .map(|key| Approval::sign(key, statement.clone()).unwrap())
        .collect();
    let certificate = wire::encode(&CheckpointProof {
        statement,
        approvals,
    })
    .unwrap();
    model.admit(&certificate).unwrap();
    certificate
}

#[derive(Clone)]
struct Candidate {
    expected: Pin,
    next: Pin,
}

fn fixtures() -> (Pin, Candidate, Candidate) {
    let mut model = CertifiedLedger::new(RealmId(1), Epoch(7), trust(), 64).unwrap();
    let cert = append_and_certify(&mut model, b"first");
    let base = PreparedCommit::prepare(&model, &cert, None)
        .unwrap()
        .pin()
        .clone();
    let mut fork = CertifiedLedger::new(RealmId(1), Epoch(7), trust(), 64).unwrap();
    let first = append_and_certify(&mut fork, b"first");
    assert_eq!(
        PreparedCommit::prepare(&fork, &first, None).unwrap().pin(),
        &base
    );
    let cert = append_and_certify(&mut model, b"second");
    let next = PreparedCommit::prepare(&model, &cert, Some(&base))
        .unwrap()
        .pin()
        .clone();
    let cert = append_and_certify(&mut fork, b"competing second");
    let other = PreparedCommit::prepare(&fork, &cert, Some(&base))
        .unwrap()
        .pin()
        .clone();
    assert_ne!(next, other);
    (
        base.clone(),
        Candidate {
            expected: base.clone(),
            next,
        },
        Candidate {
            expected: base,
            next: other,
        },
    )
}

// The journal stands for retained, exact, independently reverified certified
// bundle bytes and the predecessor-bound intent. Its marker is NOT those bytes.
// Removing it simulates lost/corrupt data; the witness cannot reconstruct it.
#[derive(Clone, Default)]
struct Local {
    visible_pin: Option<Pin>,
    durable_pin: Option<Pin>,
    visible_journal: BTreeMap<BundleId, Candidate>,
    durable_journal: BTreeMap<BundleId, Candidate>,
}

#[derive(Clone)]
struct Witness {
    visible: Pin,
    durable: Pin,
    fence: u64,
    unavailable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Writer {
    owner: bool,
    fence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Unavailable,
    Unauthorized,
    Conflict,
    IncompleteLocal,
    MissingCertifiedData,
}

impl Witness {
    fn read(&self, writer: Writer) -> Result<&Pin, Refusal> {
        if self.unavailable {
            return Err(Refusal::Unavailable);
        }
        if !writer.owner || writer.fence != self.fence {
            return Err(Refusal::Unauthorized);
        }
        Ok(&self.durable)
    }

    // The independently controlled host authenticates the owner and fencing
    // epoch and serializes an exact full-pin CAS. A successful response means
    // the new witness record is durable, not just visible.
    fn cas_visible(&mut self, writer: Writer, candidate: &Candidate) -> Result<(), Refusal> {
        let current = self.read(writer)?;
        if current != &candidate.expected
            || candidate.next.generation()
                != current
                    .generation()
                    .checked_add(1)
                    .ok_or(Refusal::Conflict)?
            || candidate.next.checkpoint().realm != current.checkpoint().realm
            || candidate.next.checkpoint().epoch != current.checkpoint().epoch
            || candidate.next.trust_digest() != current.trust_digest()
            || candidate.next.checkpoint().height <= current.checkpoint().height
        {
            return Err(Refusal::Conflict);
        }
        self.visible = candidate.next.clone();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Cut {
    BeforeJournalSync,
    JournalSynced,
    LocalPinVisible,
    LocalPinSynced,
    WitnessVisible,
    WitnessSyncedAckLost, // witness CAS succeeded; its response was lost
}

// No interrupted attempt returns a commit acknowledgement, even when the
// witness advanced but the reply was lost.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Interrupted,
}

struct Model {
    local: Local,
    witness: Witness, // separate trust domain: local crash/rollback cannot edit it
}

impl Model {
    fn new(base: Pin) -> Self {
        let mut journal = BTreeMap::new();
        // Bootstrap is assumed explicitly provisioned, certified and synced in
        // BOTH stores. The model does not infer an empty witness is safe.
        journal.insert(
            base.bundle(),
            Candidate {
                expected: base.clone(),
                next: base.clone(),
            },
        );
        Self {
            local: Local {
                visible_pin: Some(base.clone()),
                durable_pin: Some(base.clone()),
                visible_journal: journal.clone(),
                durable_journal: journal,
            },
            witness: Witness {
                visible: base.clone(),
                durable: base,
                fence: 1,
                unavailable: false,
            },
        }
    }

    fn owner(&self) -> Writer {
        Writer {
            owner: true,
            fence: self.witness.fence,
        }
    }

    fn has_exact_data(&self, pin: &Pin) -> bool {
        self.local
            .durable_journal
            .get(&pin.bundle())
            .is_some_and(|record| record.next == *pin)
    }

    // A protected recovery read is never the legacy `load` fallback. In a real
    // adapter, `has_exact_data` MUST instead reverify the snapshot, certificate,
    // trust policy and complete pinned checkpoint against exact durable bytes.
    fn recover(&self, writer: Writer) -> Result<Pin, Refusal> {
        let expected = self.witness.read(writer)?;
        if self.local.durable_pin.as_ref() != Some(expected) {
            return Err(Refusal::IncompleteLocal);
        }
        if !self.has_exact_data(expected) {
            return Err(Refusal::MissingCertifiedData);
        }
        Ok(expected.clone())
    }

    // Local journal and pin publication must both be durable before even
    // attempting the remote CAS. All intermediate states return no ack.
    fn attempt(
        &mut self,
        writer: Writer,
        candidate: &Candidate,
        cut: Cut,
    ) -> Result<Attempt, Refusal> {
        if self.recover(writer)? != candidate.expected {
            return Err(Refusal::Conflict);
        }
        self.local
            .visible_journal
            .insert(candidate.next.bundle(), candidate.clone());
        if matches!(cut, Cut::BeforeJournalSync) {
            return Ok(Attempt::Interrupted);
        }
        self.local.durable_journal = self.local.visible_journal.clone();
        if matches!(cut, Cut::JournalSynced) {
            return Ok(Attempt::Interrupted);
        }
        // Full local CAS against the durable pin; a second writer from the
        // same predecessor must lose even if it has a valid certificate.
        if self.local.durable_pin.as_ref() != Some(&candidate.expected) {
            return Err(Refusal::Conflict);
        }
        self.local.visible_pin = Some(candidate.next.clone());
        if matches!(cut, Cut::LocalPinVisible) {
            return Ok(Attempt::Interrupted);
        }
        self.local.durable_pin = self.local.visible_pin.clone();
        if matches!(cut, Cut::LocalPinSynced) {
            return Ok(Attempt::Interrupted);
        }
        self.witness.cas_visible(writer, candidate)?;
        if matches!(cut, Cut::WitnessVisible) {
            return Ok(Attempt::Interrupted);
        }
        self.witness.durable = self.witness.visible.clone();
        // Return is still uncertain if the ack is dropped after durable CAS.
        if matches!(cut, Cut::WitnessSyncedAckLost) {
            return Ok(Attempt::Interrupted);
        }
        unreachable!()
    }

    fn crash(&mut self) {
        self.local.visible_pin = self.local.durable_pin.clone();
        self.local.visible_journal = self.local.durable_journal.clone();
        self.witness.visible = self.witness.durable.clone();
    }

    // Fenced, idempotent reconciliation of *one* exact certified candidate.
    // A witness ahead, a different winner, lost data or outage never licenses
    // rollback, fallback, or an acknowledgement of a merely visible write.
    fn reconcile(&mut self, writer: Writer, candidate: &Candidate) -> Result<Pin, Refusal> {
        let witnessed = self.witness.read(writer)?.clone();
        if self.local.durable_pin.as_ref() != Some(&candidate.next)
            || !self.has_exact_data(&candidate.next)
        {
            return Err(Refusal::IncompleteLocal);
        }
        if witnessed == candidate.expected {
            self.witness.cas_visible(writer, candidate)?;
            self.witness.durable = self.witness.visible.clone();
        } else if witnessed != candidate.next {
            return Err(Refusal::Conflict);
        }
        // Recheck after CAS before ack: real adapters must hold a fenced local
        // writer lock/lease through this check and the response.
        if self.witness.read(writer)? != &candidate.next
            || self.local.durable_pin.as_ref() != Some(&candidate.next)
            || !self.has_exact_data(&candidate.next)
        {
            return Err(Refusal::IncompleteLocal);
        }
        Ok(candidate.next.clone())
    }
}

#[test]
fn every_crash_and_lost_ack_cut_fences_until_both_stores_are_durable() {
    let (base, candidate, _) = fixtures();
    for cut in [
        Cut::BeforeJournalSync,
        Cut::JournalSynced,
        Cut::LocalPinVisible,
        Cut::LocalPinSynced,
        Cut::WitnessVisible,
        Cut::WitnessSyncedAckLost,
    ] {
        let mut model = Model::new(base.clone());
        let owner = model.owner();
        assert_eq!(
            model.attempt(owner, &candidate, cut),
            Ok(Attempt::Interrupted)
        );
        assert_eq!(
            model.witness.durable,
            if matches!(cut, Cut::WitnessSyncedAckLost) {
                candidate.next.clone()
            } else {
                base.clone()
            }
        );
        model.crash();
        if matches!(
            cut,
            Cut::BeforeJournalSync | Cut::JournalSynced | Cut::LocalPinVisible
        ) {
            assert_eq!(model.recover(owner), Ok(base.clone()));
            assert_eq!(
                model.reconcile(owner, &candidate),
                Err(Refusal::IncompleteLocal)
            );
            model
                .attempt(owner, &candidate, Cut::WitnessSyncedAckLost)
                .unwrap();
            model.crash();
        } else if matches!(cut, Cut::WitnessSyncedAckLost) {
            // A lost response does not undo durable success. Read may observe
            // the target, but acknowledgement still requires reconciliation.
            assert_eq!(model.recover(owner), Ok(candidate.next.clone()));
        } else {
            assert!(model.recover(owner).is_err()); // no older frontier returned
        }
        assert_eq!(
            model.reconcile(owner, &candidate),
            Ok(candidate.next.clone())
        );
        assert_eq!(model.recover(owner), Ok(candidate.next.clone()));
        assert_eq!(model.witness.durable, candidate.next);
    }
}

#[test]
fn rollback_loss_and_outage_never_fall_back_or_reconstruct_from_the_witness() {
    let (base, candidate, _) = fixtures();
    let mut model = Model::new(base.clone());
    let owner = model.owner();
    model
        .attempt(owner, &candidate, Cut::WitnessSyncedAckLost)
        .unwrap();
    assert_eq!(
        model.reconcile(owner, &candidate),
        Ok(candidate.next.clone())
    );
    model.witness.unavailable = true;
    assert_eq!(model.recover(owner), Err(Refusal::Unavailable));
    assert_eq!(
        model.reconcile(owner, &candidate),
        Err(Refusal::Unavailable)
    );
    model.witness.unavailable = false;
    model.local.durable_pin = Some(base.clone());
    model
        .local
        .durable_journal
        .retain(|id, _| *id == base.bundle());
    model.crash(); // coordinated rollback of every local byte
    assert_eq!(model.recover(owner), Err(Refusal::IncompleteLocal));
    assert_eq!(
        model.reconcile(owner, &candidate),
        Err(Refusal::IncompleteLocal)
    );
    assert_eq!(model.witness.durable, candidate.next);
    // Even a matching local pin without its certified payload cannot recover.
    model.local.durable_pin = Some(candidate.next.clone());
    assert_eq!(model.recover(owner), Err(Refusal::MissingCertifiedData));
    // Only externally restored, exactly checked candidate data can repair it;
    // this insertion is an explicit test fixture, not witness reconstruction.
    model
        .local
        .durable_journal
        .insert(candidate.next.bundle(), candidate.clone());
    assert_eq!(model.recover(owner), Ok(candidate.next));
}

#[test]
fn authenticated_full_pin_cas_rejects_stale_fence_forks_and_racing_writers() {
    let (base, candidate, fork) = fixtures();
    let mut model = Model::new(base.clone());
    let owner = model.owner();
    let intruder = Writer {
        owner: false,
        fence: owner.fence,
    };
    assert_eq!(model.recover(intruder), Err(Refusal::Unauthorized));
    assert_eq!(
        model.witness.cas_visible(intruder, &candidate),
        Err(Refusal::Unauthorized)
    );
    model.witness.fence += 1; // independent host fence rotation
    assert_eq!(
        model.attempt(owner, &candidate, Cut::LocalPinSynced),
        Err(Refusal::Unauthorized)
    );
    let owner = model.owner();
    model
        .attempt(owner, &candidate, Cut::LocalPinSynced)
        .unwrap();
    assert_eq!(model.recover(owner), Err(Refusal::IncompleteLocal));
    assert_eq!(
        model.attempt(owner, &fork, Cut::LocalPinSynced),
        Err(Refusal::IncompleteLocal)
    );
    assert_eq!(
        model.reconcile(owner, &candidate),
        Ok(candidate.next.clone())
    );
    assert_eq!(
        model.witness.cas_visible(owner, &fork),
        Err(Refusal::Conflict)
    );
    assert_eq!(model.witness.durable, candidate.next);
    assert_eq!(model.witness.durable.generation(), base.generation() + 1);
}
