//! Spike 4: pause, member replacement, and resume reproduce the plain run's
//! result across an epoch bump, over every fixture with random seal ticks.

mod common;

use common::{live_manifest, policy, Signer, REALM, ROOM};
use vhalla_core::Epoch;
use vhalla_game_platonik::engine::GameEngine;
use vhalla_game_platonik::ids::RulesetId;
use vhalla_game_platonik::manifest::MissingMember;
use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::platonik::PlatonikV1;
use vhalla_game_platonik::receiver::Receiver;
use vhalla_game_platonik::session::{bind_commit, derive_seed, seed_commitment, Session, State};
use vhalla_game_platonik::wire::{Authority, EventBody, Player, SessionOpen};
use vhalla_witness::codec;
use vhalla_witness::hash::ProgramHash;
use vhalla_witness::manifest::ValidManifest;
use vhalla_witness::platform::{ReceiptBinding, WorkAllowance};
use vhalla_witness::world::{Event, EventKind};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

#[test]
fn replace_at_a_seal_boundary_reproduces_the_full_run_on_every_fixture() {
    let mut rng = Rng(0x5eed_0004);
    let mut sessions = 0;
    let mut epochs_bumped = 0;
    for name in platonik_core::fixtures::names() {
        let converted = convert(&platonik_core::fixtures::experiment(name).unwrap()).unwrap();
        for _seed in 0..3 {
            let mut host = Signer::new(1);
            let mut players: Vec<Signer> = (0..converted.programs.len())
                .map(|i| Signer::new(10 + i as u8))
                .collect();
            let mut successor = Signer::new(200);
            let (manifest, template) =
                live_manifest(&converted, [11; 32], 64, MissingMember::Pause, None);
            let host_salt = [7; 32];
            let open = SessionOpen {
                realm: REALM,
                room: ROOM,
                manifest: manifest.hash(),
                ruleset: RulesetId::V1,
                seed_commitment: seed_commitment(&host_salt, manifest.world),
                authority: Authority::Host { key: host.public() },
                players: {
                    let mut list: Vec<Player> = converted
                        .programs
                        .iter()
                        .enumerate()
                        .map(|(i, (cell, _))| Player {
                            key: players[i].public(),
                            slots: vec![*cell],
                        })
                        .collect();
                    list.sort_by_key(|p| p.key);
                    list
                },
                epoch: Epoch(0),
                nonce: [5; 32],
            };
            // Re-map players by sorted key order to their slots.
            let mut session = Session::open(manifest, open, REALM).unwrap();
            let mut receiver = Receiver::new(PlatonikV1, policy());
            let key = session.key();
            let owners = session.slot_owners().clone();
            let mut order = Vec::new();
            let mut salts = Vec::new();
            let mut commits = Vec::new();
            for (i, (cell, program)) in converted.programs.iter().enumerate() {
                let salt = [(20 + i) as u8; 32];
                salts.push(salt);
                let commit = bind_commit(key, *cell, program, &salt);
                commits.push((*cell, commit));
                let owner = owners[cell];
                let signer = players.iter_mut().find(|p| p.public() == owner).unwrap();
                let (record, digest) = signer.event(
                    key,
                    Epoch(0),
                    EventBody::BindCommit {
                        slot: *cell,
                        commit,
                    },
                );
                receiver.admit(&mut session, &record, 1).unwrap();
                order.push(digest);
            }
            commits.sort_by_key(|(slot, _)| *slot);
            let (close, close_digest) = host.event(key, Epoch(0), EventBody::BindClose { commits });
            receiver.admit(&mut session, &close, 1).unwrap();
            order.push(close_digest);
            for (i, (cell, program)) in converted.programs.iter().enumerate() {
                let owner = owners[cell];
                let signer = players.iter_mut().find(|p| p.public() == owner).unwrap();
                let (record, digest) = signer.event(
                    key,
                    Epoch(0),
                    EventBody::BindReveal {
                        slot: *cell,
                        program: program.clone(),
                        salt: salts[i],
                    },
                );
                receiver.admit(&mut session, &record, 1).unwrap();
                order.push(digest);
            }
            let mut task = template.clone();
            task.cases[0].seed = derive_seed(&host_salt, &salts, 0);
            let (reveal, reveal_digest) = host.event(
                key,
                Epoch(0),
                EventBody::Reveal {
                    task: task.clone(),
                    host_salt,
                },
            );
            receiver.admit(&mut session, &reveal, 1).unwrap();
            order.push(reveal_digest);
            let ticks = task.cases[0].ticks;
            // Random increasing seal ticks ending at the horizon, with one
            // replace at a random non-final seal.
            let seal_count = 2 + rng.below(3) as u32;
            let mut ticks_at: Vec<u32> = (0..seal_count - 1)
                .map(|_| 1 + rng.below(u64::from(ticks - 1)) as u32)
                .collect();
            ticks_at.push(ticks);
            ticks_at.sort_unstable();
            ticks_at.dedup();
            let replace_at = rng.below((ticks_at.len() - 1) as u64) as usize;
            let replaced_slot =
                converted.programs[rng.below(converted.programs.len() as u64) as usize].0;
            let mut all_inputs: Vec<Event> = Vec::new();
            let mut last_tick = 0;
            let mut epoch = Epoch(0);
            for (index, &through) in ticks_at.iter().enumerate() {
                // A couple of inputs from the slot's current owner in (last, through].
                if through > last_tick + 1 && index < ticks_at.len() - 1 {
                    for _ in 0..rng.below(3) {
                        let tick =
                            last_tick + 1 + rng.below(u64::from(through - last_tick - 1)) as u32;
                        let owners = session.slot_owners().clone();
                        let (cell, owner) = owners.iter().next().map(|(c, o)| (*c, *o)).unwrap();
                        let signer = if owner == successor.public() {
                            &mut successor
                        } else {
                            players.iter_mut().find(|p| p.public() == owner).unwrap()
                        };
                        let (record, digest) = signer.event(
                            key,
                            epoch,
                            EventBody::Input {
                                case: 0,
                                tick,
                                kind: EventKind::ClearMemory { cell },
                            },
                        );
                        if receiver.admit(&mut session, &record, 1).is_ok() {
                            order.push(digest);
                            all_inputs.push(Event {
                                tick,
                                event: EventKind::ClearMemory { cell },
                            });
                        }
                    }
                }
                if index == replace_at {
                    let old = session.slot_owners()[&replaced_slot];
                    let (record, digest) = host.event(
                        key,
                        epoch,
                        EventBody::Replace {
                            slot: replaced_slot,
                            old,
                            new: successor.public(),
                        },
                    );
                    receiver.admit(&mut session, &record, 1).unwrap();
                    order.push(digest);
                }
                let (seal, _) =
                    host.seal(&session, index as u8, through, std::mem::take(&mut order));
                let verified = receiver.admit(&mut session, &seal, 1).unwrap().unwrap();
                assert_eq!(verified.is_final(), index == ticks_at.len() - 1, "{name}");
                if index == replace_at {
                    epochs_bumped += 1;
                    epoch = Epoch(epoch.0 + 1);
                    assert_eq!(session.epoch(), epoch, "{name}: epoch bumped");
                    host.sequence = 0;
                }
                last_tick = through;
            }
            assert_eq!(session.state(), State::Finished, "{name}");
            // The plain run of the same task with every admitted input in
            // admission order must produce the same receipt the session did.
            let (final_task, candidate, through) = session.final_plan().cloned().unwrap();
            let mut expected = task.clone();
            expected.cases[0].events = all_inputs;
            assert_eq!(
                final_task.cases[0].events, expected.cases[0].events,
                "{name}: admitted inputs in order"
            );
            let valid = ValidManifest::validate(final_task).unwrap();
            let assignment = valid.assign(candidate.clone()).unwrap();
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
            let plain = vhalla_witness::platform::run(&valid, &assignment, cap).unwrap();
            let evidence = PlatonikV1
                .replay(
                    session.world(),
                    &valid,
                    candidate,
                    WorkAllowance {
                        max_total: valid.fuel_total(),
                    },
                    through,
                    ReceiptBinding {
                        challenge_id: key.0,
                        subject_key: host.public(),
                    },
                )
                .unwrap();
            assert_eq!(
                evidence.receipt.output(),
                plain.output_hash(),
                "{name}: session receipt equals the plain run"
            );
            assert_eq!(evidence.passed, plain.passed(), "{name}");
            sessions += 1;
        }
    }
    println!("spike 4: {sessions} sessions, {epochs_bumped} epoch bumps, every result equal to the plain run");
    assert_eq!(epochs_bumped, sessions);
}
