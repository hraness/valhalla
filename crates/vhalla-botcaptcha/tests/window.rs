//! The one-use window against a map model under random accept, replay,
//! equivocate, and prune schedules.

use std::collections::BTreeMap;

use proptest::prelude::*;
use vhalla_botcaptcha::window::{OneUseWindow, WindowError, MAX_OPEN_CHALLENGES};

#[derive(Clone, Debug)]
enum Op {
    Consume {
        scope: u8,
        response: u8,
        expires_at: u64,
    },
    Prune {
        now: u64,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (any::<u8>(), 0_u8..3, 0_u64..100).prop_map(|(scope, response, expires_at)| Op::Consume { scope, response, expires_at }),
        1 => (0_u64..100).prop_map(|now| Op::Prune { now }),
    ]
}

fn key(byte: u8) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[0] = byte;
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn window_matches_the_model(ops in prop::collection::vec(op(), 1..200)) {
        let mut window = OneUseWindow::new();
        let mut model: BTreeMap<[u8; 32], ([u8; 32], u64)> = BTreeMap::new();
        for op in ops {
            match op {
                Op::Consume { scope, response, expires_at } => {
                    let expected = match model.get(&key(scope)) {
                        Some((stored, _)) if *stored == key(response) => Err(WindowError::Replay),
                        Some(_) => Err(WindowError::Equivocation),
                        None if model.len() >= MAX_OPEN_CHALLENGES => Err(WindowError::Capacity),
                        None => {
                            model.insert(key(scope), (key(response), expires_at));
                            Ok(())
                        }
                    };
                    prop_assert_eq!(window.consume(key(scope), key(response), expires_at), expected);
                }
                Op::Prune { now } => {
                    model.retain(|_, (_, expires_at)| *expires_at >= now);
                    window.prune(now);
                }
            }
            prop_assert_eq!(window.len(), model.len());
            for (scope, (response, _)) in &model {
                prop_assert_eq!(window.consumed(scope), Some(*response));
            }
        }
    }
}

#[test]
fn prune_never_removes_an_unexpired_entry() {
    let mut window = OneUseWindow::new();
    window.consume(key(1), key(1), 10).unwrap();
    window.consume(key(2), key(2), 20).unwrap();
    window.prune(10);
    assert_eq!(window.len(), 2, "expires_at == now is still open");
    window.prune(11);
    assert_eq!(window.len(), 1);
    assert_eq!(window.consumed(&key(2)), Some(key(2)));
    assert_eq!(
        window.consume(key(1), key(3), 30),
        Ok(()),
        "a pruned scope can be reused only by a fresh unexpired challenge"
    );
}
