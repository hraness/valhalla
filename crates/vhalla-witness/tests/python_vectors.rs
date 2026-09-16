//! The independent Python oracle at `/vectors/witness-v1.json`: hand-authored
//! values encoded with `struct` and `hashlib`, asserted here byte for byte.

use std::fs;
use std::path::Path;

use vhalla_witness::codec;
use vhalla_witness::hash::{ManifestHash, OutputHash, ProgramHash, ReceiptHash};
use vhalla_witness::manifest::{ProgramSlot, TaskManifest, ValidManifest, WorkContract};
use vhalla_witness::model::{
    Action, Condition, Direction, MemoryWrite, Program, Relative, Rule, Slot,
};
use vhalla_witness::platform::ClaimedReceipt;
use vhalla_witness::vectors::{hex, unhex};
use vhalla_witness::world::{Beacon, CaseSpec, CellBody, Point, Source, Spark, WorldSpec};

/// The oracle file is a flat JSON object of strings and integers.
pub fn field(json: &str, key: &str) -> String {
    let needle = format!("\"{key}\": ");
    let start = json.find(&needle).unwrap_or_else(|| panic!("{key}")) + needle.len();
    let rest = &json[start..];
    let end = rest.find([',', '\n']).unwrap();
    rest[..end].trim().trim_matches('"').to_string()
}

fn oracle() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/witness-v1.json"))
        .unwrap()
}

fn program() -> Program {
    let slot = |index| Slot::new(index).unwrap();
    Program::new(vec![
        Rule::new(
            vec![
                Condition::Carrying { value: false },
                Condition::AtSource { value: true },
            ],
            Action::Pickup,
            None,
        )
        .unwrap(),
        Rule::new(
            vec![
                Condition::Carrying { value: true },
                Condition::AtBeacon { value: true },
            ],
            Action::Drop,
            Some(MemoryWrite::new(slot(0), 1)),
        )
        .unwrap(),
        Rule::new(
            vec![Condition::Blocked {
                direction: Relative::Forward,
                value: false,
            }],
            Action::Move {
                direction: Relative::Forward,
            },
            None,
        )
        .unwrap(),
        Rule::new(
            vec![],
            Action::Turn {
                direction: Relative::Left,
            },
            None,
        )
        .unwrap(),
    ])
    .unwrap()
}

fn manifest(loading_work: u64) -> TaskManifest {
    TaskManifest {
        world: WorldSpec {
            width: 5,
            height: 3,
            walls: vec![Point { x: 2, y: 0 }, Point { x: 2, y: 2 }],
            sources: vec![Source {
                id: 10,
                position: Point { x: 0, y: 1 },
                sparks: vec![Spark { id: 1, bit: true }, Spark { id: 2, bit: false }],
            }],
            depots: vec![],
            beacons: vec![Beacon {
                id: 20,
                position: Point { x: 4, y: 1 },
                accepts: true,
                initial_charge: 10,
                drain_every: 8,
                drain_amount: 1,
                spark_charge: 4,
                required_deliveries: 1,
            }],
            valves: vec![],
            cells: vec![CellBody {
                id: 1,
                position: Point { x: 0, y: 1 },
                heading: Direction::East,
                mobile: true,
                memory: [0; 4],
            }],
            links: vec![],
        },
        slots: vec![ProgramSlot {
            cell: 1,
            fixed: None,
        }],
        cases: vec![CaseSpec {
            seed: 7,
            ticks: 16,
            fuel: 4000,
            activation_fuel: 64,
            events: vec![],
            loading_work,
        }],
        contract: WorkContract {
            useful_floor: 1,
            total_ceiling: 4000,
            require_passed: false,
        },
    }
}

#[test]
fn python_program_candidate_manifest_and_receipt_match_byte_for_byte() {
    let json = oracle();
    let program = program();
    assert_eq!(
        hex(&codec::encode_program(&program)),
        field(&json, "program_hex")
    );
    let candidate = vec![(1_u16, program)];
    let candidate_bytes = codec::encode_candidate(&candidate);
    assert_eq!(hex(&candidate_bytes), field(&json, "candidate_hex"));
    assert_eq!(
        hex(&ProgramHash::of(&candidate_bytes).0),
        field(&json, "program_hash_hex")
    );

    let loading_work: u64 = field(&json, "manifest_loading_work").parse().unwrap();
    let manifest = manifest(loading_work);
    let manifest_bytes = codec::encode_manifest(&manifest);
    assert_eq!(manifest_bytes.len() as u64, loading_work);
    assert_eq!(hex(&manifest_bytes), field(&json, "manifest_hex"));
    let valid = ValidManifest::validate(manifest).unwrap();
    assert_eq!(hex(&valid.hash().0), field(&json, "manifest_hash_hex"));
    let assignment = valid.assign(candidate).unwrap();
    assert_eq!(
        ProgramHash::of(&codec::encode_assignment(&assignment)).0,
        ProgramHash::of(&candidate_bytes).0,
        "a single open slot: the assignment is the candidate"
    );

    let claimed = ClaimedReceipt {
        challenge_id: core::array::from_fn(|index| index as u8),
        subject_key: [9; 32],
        manifest: ManifestHash([1; 32]),
        program: ProgramHash([2; 32]),
        output: OutputHash([3; 32]),
        useful: 5,
        total: 123_456_789,
        passed: true,
        case_count: 1,
    };
    let receipt_bytes = claimed.encode();
    assert_eq!(hex(&receipt_bytes), field(&json, "receipt_hex"));
    assert_eq!(
        hex(&ReceiptHash::of(&receipt_bytes).0),
        field(&json, "receipt_hash_hex")
    );
    assert_eq!(
        ClaimedReceipt::decode(&unhex(&field(&json, "receipt_hex")).unwrap()).unwrap(),
        claimed
    );
}
