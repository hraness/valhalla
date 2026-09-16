//! Codec laws over the committed corpus and over generated programs, and
//! malformed-byte rejection.

mod common;

use proptest::prelude::*;
use vhalla_witness::codec::{
    self, CodecError, Field, MAX_ASSIGNMENT_BYTES, MAX_MANIFEST_BYTES, MAX_PROGRAM_BYTES,
};
use vhalla_witness::model::{
    Action, BitSource, Condition, Direction, MemoryWrite, Port, Program, Relative, Rule, Slot,
    ValveId,
};
use vhalla_witness::platform::ClaimedReceipt;

#[test]
fn corpus_manifests_and_candidates_satisfy_both_laws() {
    for (path, vector) in common::vectors() {
        let label = path.display();
        assert!(vector.manifest.len() <= MAX_MANIFEST_BYTES);
        let manifest = codec::decode_manifest(&vector.manifest).unwrap();
        assert_eq!(
            codec::encode_manifest(&manifest),
            vector.manifest,
            "{label}: manifest"
        );
        let again = codec::decode_manifest(&codec::encode_manifest(&manifest)).unwrap();
        assert_eq!(again, manifest, "{label}: manifest twice");
        assert!(vector.assignment.len() <= MAX_ASSIGNMENT_BYTES);
        let candidate = codec::decode_candidate(&vector.assignment).unwrap();
        assert_eq!(
            codec::encode_candidate(&candidate),
            vector.assignment,
            "{label}: candidate"
        );
        for (_, program) in &candidate {
            let raw = codec::encode_program(program);
            assert!(raw.len() <= MAX_PROGRAM_BYTES);
            assert_eq!(
                &codec::decode_program(&raw).unwrap(),
                program,
                "{label}: program"
            );
        }
        for slot in &manifest.slots {
            if let Some(program) = &slot.fixed {
                let raw = codec::encode_program(program);
                assert_eq!(
                    &codec::decode_program(&raw).unwrap(),
                    program,
                    "{label}: fixed"
                );
            }
        }
    }
}

#[test]
fn decoders_reject_malformed_bytes_with_stable_errors() {
    let vector = common::vector("fixture-opening-normal");
    let raw = vector.assignment.clone();
    assert!(matches!(
        codec::decode_candidate(&raw[..raw.len() - 1]),
        Err(CodecError::Truncated { .. })
    ));
    let mut extra = raw.clone();
    extra.push(0);
    assert_eq!(
        codec::decode_candidate(&extra),
        Err(CodecError::TrailingBytes { count: 1 })
    );
    let mut version = raw.clone();
    version[0] = 2;
    assert_eq!(
        codec::decode_candidate(&version),
        Err(CodecError::UnsupportedVersion { found: 2 })
    );
    let mut language = raw.clone();
    language[1] = 2;
    assert_eq!(
        codec::decode_candidate(&language),
        Err(CodecError::UnsupportedLanguage { found: 2 })
    );
    assert!(matches!(
        codec::decode_candidate(&vec![0_u8; MAX_ASSIGNMENT_BYTES + 1]),
        Err(CodecError::TooLarge { .. })
    ));
    let mut count = raw.clone();
    count[2] = 200;
    assert_eq!(
        codec::decode_candidate(&count),
        Err(CodecError::Bound {
            field: Field::Count
        })
    );
    let manifest = vector.manifest.clone();
    let mut truncated = manifest.clone();
    truncated.truncate(manifest.len() / 2);
    assert!(matches!(
        codec::decode_manifest(&truncated),
        Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
        ClaimedReceipt::decode(&[1, 1, 0]),
        Err(CodecError::Truncated { .. })
    ));
}

fn slot() -> impl Strategy<Value = Slot> {
    (0_u8..4).prop_map(|index| Slot::new(index).unwrap())
}

fn port() -> impl Strategy<Value = Port> {
    (0_u8..4).prop_map(|index| Port::new(index).unwrap())
}

fn relative() -> impl Strategy<Value = Relative> {
    prop_oneof![
        Just(Relative::Forward),
        Just(Relative::Left),
        Just(Relative::Right),
        Just(Relative::Back)
    ]
}

fn direction() -> impl Strategy<Value = Direction> {
    prop_oneof![
        Just(Direction::North),
        Just(Direction::East),
        Just(Direction::South),
        Just(Direction::West)
    ]
}

fn condition() -> impl Strategy<Value = Condition> {
    prop_oneof![
        any::<bool>().prop_map(|value| Condition::Carrying { value }),
        any::<bool>().prop_map(|value| Condition::AtSource { value }),
        any::<bool>().prop_map(|value| Condition::AtDepot { value }),
        any::<bool>().prop_map(|value| Condition::AtBeacon { value }),
        any::<bool>().prop_map(|value| Condition::AtReceiver { value }),
        (relative(), any::<bool>())
            .prop_map(|(direction, value)| Condition::Blocked { direction, value }),
        (port(), any::<bool>()).prop_map(|(port, value)| Condition::HasMessage { port, value }),
        (port(), any::<bool>()).prop_map(|(port, value)| Condition::MessageBit { port, value }),
        (slot(), any::<u8>()).prop_map(|(slot, value)| Condition::Memory { slot, value }),
        direction().prop_map(|direction| Condition::Heading { direction }),
    ]
}

fn bit_source() -> impl Strategy<Value = BitSource> {
    prop_oneof![
        any::<bool>().prop_map(|value| BitSource::Constant { value }),
        slot().prop_map(|slot| BitSource::Memory { slot }),
        port().prop_map(|port| BitSource::Message { port }),
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        relative().prop_map(|direction| Action::Move { direction }),
        relative().prop_map(|direction| Action::Turn { direction }),
        Just(Action::Pickup),
        Just(Action::Drop),
        Just(Action::Wait),
        (slot(), any::<u8>()).prop_map(|(slot, value)| Action::WriteMemory { slot, value }),
        (port(), slot()).prop_map(|(port, slot)| Action::TakeMessage { port, slot }),
        (port(), bit_source()).prop_map(|(port, bit)| Action::Send { port, bit }),
        (any::<u16>(), bit_source()).prop_map(|(valve, bit)| Action::Route {
            valve: ValveId::new(valve),
            bit
        }),
    ]
}

fn rule() -> impl Strategy<Value = Rule> {
    (
        prop::collection::vec(condition(), 0..=8),
        action(),
        prop::option::of(
            (slot(), any::<u8>()).prop_map(|(slot, value)| MemoryWrite::new(slot, value)),
        ),
    )
        .prop_map(|(when, action, remember)| Rule::new(when, action, remember).unwrap())
}

fn program() -> impl Strategy<Value = Program> {
    prop::collection::vec(rule(), 1..=32).prop_map(|rules| Program::new(rules).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn generated_programs_satisfy_both_laws(program in program()) {
        let raw = codec::encode_program(&program);
        prop_assert!(raw.len() <= MAX_PROGRAM_BYTES);
        let back = codec::decode_program(&raw).unwrap();
        prop_assert_eq!(&back, &program);
        prop_assert_eq!(codec::encode_program(&back), raw);
    }

    #[test]
    fn generated_candidates_satisfy_both_laws(programs in prop::collection::vec(program(), 1..=16)) {
        let candidate: Vec<(u16, Program)> = programs
            .into_iter()
            .enumerate()
            .map(|(index, program)| (index as u16 * 3, program))
            .collect();
        let raw = codec::encode_candidate(&candidate);
        prop_assert!(raw.len() <= MAX_ASSIGNMENT_BYTES);
        let back = codec::decode_candidate(&raw).unwrap();
        prop_assert_eq!(&back, &candidate);
        prop_assert_eq!(codec::encode_candidate(&back), raw);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = codec::decode_program(&bytes);
        let _ = codec::decode_candidate(&bytes);
        let _ = codec::decode_manifest(&bytes);
        let _ = codec::decode_output(&bytes);
        let _ = ClaimedReceipt::decode(&bytes);
    }
}
