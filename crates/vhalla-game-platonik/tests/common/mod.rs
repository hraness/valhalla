//! Shared drivers: signing helpers, an honest host's seal derivation, and a
//! live manifest over a converted Platonik fixture.
#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use vhalla_core::{Epoch, RealmId, RoomId, Sequence};
use vhalla_game_platonik::ids::{CheckpointHash, GameEventDigest, RulesetId, SessionKey};
use vhalla_game_platonik::manifest::{
    GameManifest, GameSlot, MissingMember, SessionKind, SessionLimits, SlotRole,
    VerificationAllowance, MAX_ARTIFACT_BYTES,
};
use vhalla_game_platonik::oracle::convert::Converted;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::{Receiver, ReceiverPolicy};
use vhalla_game_platonik::record::{GameRecord, RecordKind};
use vhalla_game_platonik::session::{Session, INPUT_ENCODED_BYTES};
use vhalla_game_platonik::wire::{
    encode_game_event, encode_settlement, EventBody, GameEvent, Settlement,
};
use vhalla_witness::codec;
use vhalla_witness::hash::ProgramHash;
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::platform::WorkAllowance;

pub const REALM: RealmId = RealmId(3);
pub const ROOM: RoomId = RoomId(4);

pub struct Signer {
    pub key: SigningKey,
    pub sequence: u64,
}

impl Signer {
    pub fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            sequence: 0,
        }
    }
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    pub fn unsigned(&self, session: SessionKey, epoch: Epoch, body: EventBody) -> GameEvent {
        GameEvent {
            session,
            epoch,
            author: self.public(),
            sequence: Sequence(self.sequence + 1),
            parents: Vec::new(),
            body,
        }
    }
    pub fn sign(&mut self, event: GameEvent) -> (GameRecord, GameEventDigest) {
        self.sequence += 1;
        let digest = event.digest();
        let record = GameRecord::sign(
            RecordKind::Event,
            event.session,
            encode_game_event(&event),
            &self.key,
        )
        .unwrap();
        (record, digest)
    }
    pub fn event(
        &mut self,
        session: SessionKey,
        epoch: Epoch,
        body: EventBody,
    ) -> (GameRecord, GameEventDigest) {
        let event = self.unsigned(session, epoch, body);
        self.sign(event)
    }
    /// An honest host's seal: plan, derive through a scratch receiver, sign.
    pub fn seal(
        &mut self,
        session: &Session,
        segment: u8,
        through_tick: u32,
        order: Vec<GameEventDigest>,
    ) -> (GameRecord, CheckpointHash) {
        let draft = self.unsigned(
            session.key(),
            session.epoch(),
            EventBody::Seal {
                segment,
                through_tick,
                order: order.clone(),
                checkpoint: CheckpointHash([0; 32]),
            },
        );
        let plan = session.plan_seal(&draft).unwrap();
        let mut scratch = Receiver::new(PlatonikV1, policy());
        let checkpoint = scratch.derive(session, &plan).unwrap().hash();
        let event = self.unsigned(
            session.key(),
            session.epoch(),
            EventBody::Seal {
                segment,
                through_tick,
                order,
                checkpoint,
            },
        );
        let (record, _) = self.sign(event);
        (record, checkpoint)
    }
    /// A host-signed settlement record.
    pub fn settlement(&self, session: SessionKey, settlement: &Settlement) -> GameRecord {
        GameRecord::sign(
            RecordKind::Settlement,
            session,
            encode_settlement(settlement),
            &self.key,
        )
        .unwrap()
    }
    /// Advances the sequence without signing, for a fork twin.
    pub fn twin(&self) -> Self {
        Self {
            key: self.key.clone(),
            sequence: self.sequence.saturating_sub(1),
        }
    }
}

pub fn policy() -> ReceiverPolicy {
    ReceiverPolicy {
        max_replays: 64,
        max_work: u64::MAX,
        max_steps: u64::MAX,
    }
}

/// A live manifest over a converted single-case fixture: every cell an open
/// slot, `max_events` as given, the world digest of the open template.
pub fn live_manifest(
    converted: &Converted,
    publisher: [u8; 32],
    max_events: u32,
    missing_member: MissingMember,
    fallback: Option<ProgramHash>,
) -> (GameManifest, TaskManifest) {
    let mut template = TaskManifest {
        world: converted.task.world.clone(),
        slots: converted
            .programs
            .iter()
            .map(|(cell, _)| ProgramSlot {
                cell: *cell,
                fixed: None,
            })
            .collect(),
        cases: {
            let mut case = converted.task.cases[0].clone();
            case.seed = 0;
            case.events.clear();
            vec![case]
        },
        contract: WorkContract {
            useful_floor: 0,
            total_ceiling: converted.task.cases[0].fuel,
            require_passed: false,
        },
    };
    let template_len = codec::encode_manifest(&template).len() as u64;
    template.cases[0].loading_work = template_len + u64::from(max_events) * INPUT_ENCODED_BYTES;
    let valid = ValidManifest::validate(template.clone()).unwrap();
    let manifest = GameManifest {
        ruleset: RulesetId::V1,
        world: valid.hash(),
        slots: converted
            .programs
            .iter()
            .map(|(cell, _)| GameSlot {
                cell: *cell,
                role: SlotRole::Open { fallback },
            })
            .collect(),
        contract: template.contract,
        loading_work: vec![template.cases[0].loading_work],
        artifacts: Vec::new(),
        limits: SessionLimits {
            max_events,
            max_segments: 8,
            replay: WorkAllowance {
                max_total: valid.fuel_total(),
            },
            verification: VerificationAllowance {
                max_replays: 64,
                max_work: u64::MAX,
                max_event_bytes: 64 * 24_576,
                max_artifact_bytes: MAX_ARTIFACT_BYTES,
            },
            missing_member,
            kind: SessionKind::Live,
        },
        publisher,
    };
    (manifest, template)
}

/// The passing flag of a plain witness run of `task` with `candidate`.
pub fn passed_by_plain_run(
    task: &TaskManifest,
    candidate: Vec<(u16, vhalla_witness::model::Program)>,
) -> bool {
    let valid = ValidManifest::validate(task.clone()).unwrap();
    let assignment = valid.assign(candidate).unwrap();
    let program = ProgramHash::of(&codec::encode_assignment(&assignment));
    #[allow(clippy::disallowed_methods)]
    let cap = vhalla_witness::platform::RunCapability::mint(
        valid.hash(),
        program,
        WorkAllowance {
            max_total: valid.fuel_total(),
        },
        vhalla_witness::platform::RunRole::Replay,
    );
    vhalla_witness::platform::run(&valid, &assignment, cap)
        .unwrap()
        .passed()
}
