//! Generated selected-source schedules checked against an executable model.
//!
//! Each case draws a source history that mixes minimum- and maximum-size
//! records and events from unlisted authors, then an interleaved schedule of
//! honest pages, held and stale tokens, replayed or skipped ranges, damaged,
//! cross-room and non-owner frames, valid substitutions, checkpoint extensions,
//! restarts that replay the retained prefix with a new pagination, and discards
//! that start over from zero. The model recomputes the rolling digest
//! independently of the crate. After every step the receiver must agree with
//! it: refusals leave progress and the target unchanged, honest pages and
//! extensions are never refused, and coverage is complete only after the exact
//! target history has been committed.

use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use hegel::generators as gs;
use hegel::TestCase;
use sha2::{Digest, Sha256};
use vhalla_direct_room::{
    Error as RoomError, EventClaims, EventId, GenesisClaims, PinnedGenesis, PolicyClaims, SealHead,
    Text, UnsignedEvent, UnsignedGenesis, UnsignedPolicy, MAX_POLICY_BYTES, MAX_TEXT_BYTES,
    MAX_WRITERS,
};
use vhalla_direct_sync::*;

const SOURCE: [u8; 32] = [7; 32];
const EPOCH: [u8; 32] = [8; 32];
/// Long enough that a complete transfer needs more than one full page.
const MAX_HISTORY: usize = MAX_PAGE_FRAMES + 16;

/// A claimed frame type and its exact signed bytes.
type Record = (FrameKind, Vec<u8>);

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> [u8; 32] {
    static KEYS: OnceLock<Vec<[u8; 32]>> = OnceLock::new();
    KEYS.get_or_init(|| {
        (1..=MAX_WRITERS as u8)
            .map(|n| key(n).verifying_key().to_bytes())
            .collect()
    })[usize::from(n) - 1]
}
/// A fresh room owned by key 1 that lists key 2 as its other writer.
fn new_room() -> PinnedGenesis {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("room nonce entropy");
    let owner = public(1);
    let mut writers = vec![owner, public(2)];
    writers.sort_unstable();
    let signed = UnsignedGenesis::new(GenesisClaims {
        owner,
        nonce,
        writers,
    })
    .unwrap()
    .sign_with_key(&key(1))
    .unwrap();
    let id = signed.id();
    signed.verify_pin(id).unwrap()
}
/// An event whose text has exactly `length` bytes; `serial` separates equal
/// sizes. Author 2 is a listed writer. Author 3 is not, and sync keeps it.
fn event(room: &PinnedGenesis, author: u8, length: usize, serial: u64) -> Record {
    let signed = UnsignedEvent::new(EventClaims {
        room: room.id(),
        policy: room.id().initial_policy(),
        author: public(author),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: serial,
        text: Text::new(&"x".repeat(length)).unwrap(),
    })
    .unwrap()
    .sign_with_key(&key(author))
    .unwrap();
    (FrameKind::Event, signed.encode())
}
/// An owner policy listing `writers` keys and sealing `heads` author terminals.
fn policy(room: &PinnedGenesis, writers: u8, heads: u8, revision: u64) -> Record {
    let mut keys: Vec<_> = (1..=writers).map(public).collect();
    keys.sort_unstable();
    let mut sealed_heads: Vec<_> = (1..=heads)
        .map(|n| SealHead {
            author: public(n),
            sequence: 1,
            event: EventId::from_bytes([n; 32]),
        })
        .collect();
    sealed_heads.sort_unstable_by_key(|head| head.author);
    let signed = UnsignedPolicy::new(PolicyClaims {
        room: room.id(),
        owner: public(1),
        revision,
        previous: room.id().initial_policy(),
        writers: keys,
        sealed_heads,
    })
    .unwrap()
    .sign_with_key(&key(1))
    .unwrap();
    (FrameKind::Policy, signed.encode())
}
/// A correctly signed policy whose signer is not the pinned owner.
fn impostor(room: &PinnedGenesis) -> Record {
    let signed = UnsignedPolicy::new(PolicyClaims {
        room: room.id(),
        owner: public(3),
        revision: 1,
        previous: room.id().initial_policy(),
        writers: vec![public(3)],
        sealed_heads: vec![],
    })
    .unwrap()
    .sign_with_key(&key(3))
    .unwrap();
    (FrameKind::Policy, signed.encode())
}
/// A record of minimum, maximum or intermediate encoded size.
fn draw_record(tc: &TestCase, room: &PinnedGenesis, serial: u64) -> Record {
    if tc.draw(gs::booleans()) {
        let author = tc.draw(gs::integers::<u8>().min_value(2).max_value(3));
        let length = match tc.draw(gs::integers::<u8>().max_value(2)) {
            0 => 1,
            1 => MAX_TEXT_BYTES,
            _ => tc.draw(gs::integers::<usize>().min_value(2).max_value(96)),
        };
        event(room, author, length, serial)
    } else {
        let (writers, heads) = match tc.draw(gs::integers::<u8>().max_value(2)) {
            0 => (1, 0),
            1 => (MAX_WRITERS as u8, MAX_WRITERS as u8),
            _ => (
                tc.draw(gs::integers::<u8>().min_value(1).max_value(4)),
                tc.draw(gs::integers::<u8>().max_value(4)),
            ),
        };
        policy(room, writers, heads, serial + 1)
    }
}
fn draw_count(tc: &TestCase, available: usize) -> usize {
    tc.draw(
        gs::integers::<usize>()
            .min_value(1)
            .max_value(available.min(MAX_PAGE_FRAMES)),
    )
}
fn frame(record: &Record) -> Frame<'_> {
    Frame {
        kind: record.0,
        bytes: &record.1,
    }
}
fn frames(records: &[Record]) -> Vec<Frame<'_>> {
    records.iter().map(frame).collect()
}
fn page<'a>(checkpoint: Checkpoint, first: u64, last: u64, frames: &'a [Frame<'a>]) -> Page<'a> {
    Page {
        checkpoint_id: checkpoint.id(),
        first,
        last,
        frames,
    }
}
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// A prepared token with the progress and target it was prepared against.
struct Held {
    token: PreparedPage,
    base: Progress,
    target: usize,
    records: Vec<Record>,
}

struct Model {
    room: PinnedGenesis,
    /// The selected source's complete history.
    history: Vec<Record>,
    /// `checkpoints[k - 1]` freezes the first `k` history records.
    checkpoints: Vec<Checkpoint>,
    /// Record count of the receiver's current target.
    target: usize,
    /// Records the receiver has committed, possibly a wrong but valid prefix.
    committed: Vec<Record>,
    progress: Progress,
}
impl Model {
    fn seed(room: &PinnedGenesis) -> Progress {
        Progress {
            records: 0,
            bytes: 0,
            digest: sha256(&[
                b"vhalla/direct-sync/source/v1\0",
                &SOURCE,
                room.id().as_bytes(),
                &EPOCH,
            ]),
        }
    }
    fn advance(progress: Progress, (kind, bytes): &Record) -> Progress {
        let records = progress.records + 1;
        Progress {
            records,
            bytes: progress.bytes + bytes.len() as u64,
            digest: sha256(&[
                b"vhalla/direct-sync/frame/v1\0",
                &progress.digest,
                &records.to_be_bytes(),
                &[*kind as u8],
                &(bytes.len() as u64).to_be_bytes(),
                &sha256(&[bytes.as_slice()]),
            ]),
        }
    }
    fn current(&self) -> Checkpoint {
        self.checkpoints[self.target - 1]
    }
    fn honest(&self, records: &[Record]) -> bool {
        self.history.starts_with(records)
    }
    fn complete(&self) -> bool {
        self.committed.len() == self.target && self.honest(&self.committed)
    }
    fn commit(&mut self, records: Vec<Record>) {
        for record in &records {
            self.progress = Self::advance(self.progress, record);
        }
        self.committed.extend(records);
    }
    fn check(&self, receiver: &Receiver) {
        assert_eq!(receiver.target(), self.current());
        assert_eq!(receiver.progress(), self.progress);
        let complete = self.complete();
        assert_eq!(
            receiver.coverage(),
            if complete {
                Coverage::Complete
            } else {
                Coverage::Pending
            }
        );
        assert_eq!(
            receiver.finish(),
            if complete {
                Ok(self.current())
            } else {
                Err(Error::Truncated)
            }
        );
    }
    /// A checkpoint that a complete receiver must refuse, with the refusal:
    /// a rollback, another epoch, another source or a same-count fork.
    fn changed(&self, tc: &TestCase, variant: u8) -> ([u8; 32], Checkpoint, Error) {
        let current = self.current();
        let later = self.checkpoints[tc.draw(
            gs::integers::<usize>()
                .min_value(self.target)
                .max_value(self.checkpoints.len()),
        ) - 1];
        match variant {
            1 if self.target > 1 => {
                let earlier = tc.draw(gs::integers::<usize>().max_value(self.target - 2));
                (SOURCE, self.checkpoints[earlier], Error::Rollback)
            }
            2 => (
                SOURCE,
                Checkpoint {
                    epoch: [9; 32],
                    ..later
                },
                Error::Epoch,
            ),
            3 => ([6; 32], later, Error::Source),
            _ => {
                let mut digest = current.digest;
                digest[tc.draw(gs::integers::<usize>().max_value(31))] ^= 1;
                (SOURCE, Checkpoint { digest, ..current }, Error::Fork)
            }
        }
    }
}

/// Offer valid records at the receiver's next position. An honest prefix must
/// be accepted. A wrong prefix may stay pending but can never reach the target.
/// Returns whether the page was accepted.
fn offer(
    model: &mut Model,
    receiver: &mut Receiver,
    held: &mut Vec<Held>,
    records: Vec<Record>,
    hold: bool,
) -> bool {
    let first = model.committed.len() as u64 + 1;
    let last = model.committed.len() as u64 + records.len() as u64;
    let inputs = frames(&records);
    let result = receiver.prepare_page(page(model.current(), first, last, &inputs));
    model.check(receiver);
    let mut candidate = model.committed.clone();
    candidate.extend(records.iter().cloned());
    let honest = model.honest(&candidate);
    let next = records.iter().fold(model.progress, Model::advance);
    let prepared = match result {
        Ok(prepared) => prepared,
        Err(error) => {
            assert!(!honest, "an honest page was refused: {error:?}");
            assert_eq!(error, Error::Digest);
            return false;
        }
    };
    assert!(
        honest || (last < model.target as u64 && next.bytes <= model.current().bytes),
        "a wrong prefix was accepted at the target or over its byte total"
    );
    assert_eq!(
        (prepared.first(), prepared.last(), prepared.progress()),
        (first, last, next)
    );
    assert!(prepared
        .frames()
        .iter()
        .zip(&records)
        .all(|(verified, (kind, bytes))| verified.kind() == *kind && verified.encode() == *bytes));
    if hold {
        held.push(Held {
            token: prepared,
            base: model.progress,
            target: model.target,
            records,
        });
    } else {
        receiver.commit_after_persist(prepared).unwrap();
        model.commit(records);
    }
    true
}

/// Require a refusal that leaves the receiver unchanged.
fn refuse(model: &Model, receiver: &Receiver, input: Page<'_>) -> Error {
    let error = receiver
        .prepare_page(input)
        .expect_err("an invalid page was accepted");
    model.check(receiver);
    error
}

/// Offer honest pages until the target is reached or a page is refused.
fn drain(tc: &TestCase, model: &mut Model, receiver: &mut Receiver, held: &mut Vec<Held>) {
    while model.committed.len() < model.target {
        let next = model.committed.len();
        let records = model.history[next..next + draw_count(tc, model.target - next)].to_vec();
        let accepted = offer(model, receiver, held, records, false);
        model.check(receiver);
        if !accepted {
            break;
        }
    }
}

#[hegel::test(test_cases = 64)]
fn generated_schedules_match_the_receiver_model(tc: TestCase) {
    let room = new_room();
    let foreign = new_room();
    let pool_size = tc.draw(gs::integers::<u64>().min_value(1).max_value(6));
    let pool: Vec<Record> = (0..pool_size)
        .map(|serial| draw_record(&tc, &room, serial))
        .collect();
    let mut history = vec![(FrameKind::Genesis, room.encode())];
    for _ in 0..tc.draw(gs::integers::<usize>().max_value(MAX_HISTORY - 1)) {
        history.push(pool[tc.draw(gs::integers::<usize>().max_value(pool.len() - 1))].clone());
    }
    // The source accumulator and the independent model agree on every prefix.
    let mut source = SourceAccumulator::new(SOURCE, room.clone(), EPOCH).unwrap();
    let mut expected = Model::seed(&room);
    let mut checkpoints = vec![];
    for record in &history {
        source.push(frame(record)).unwrap();
        expected = Model::advance(expected, record);
        let checkpoint = source.checkpoint().unwrap();
        assert_eq!(
            (checkpoint.records, checkpoint.bytes, checkpoint.digest),
            (expected.records, expected.bytes, expected.digest)
        );
        checkpoints.push(checkpoint);
    }
    let target = tc.draw(
        gs::integers::<usize>()
            .min_value(1)
            .max_value(history.len()),
    );
    let mut receiver =
        Receiver::begin(room.clone(), SOURCE, SOURCE, checkpoints[target - 1]).unwrap();
    let mut model = Model {
        progress: Model::seed(&room),
        room,
        history,
        checkpoints,
        target,
        committed: vec![],
    };
    model.check(&receiver);
    let mut held: Vec<Held> = vec![];
    for _ in 0..tc.draw(gs::integers::<usize>().min_value(1).max_value(32)) {
        let next = model.committed.len();
        let remaining = model.target - next;
        match tc.draw(gs::integers::<u8>().max_value(8)) {
            // An honest page from the source history.
            0 if remaining > 0 => {
                let count = draw_count(&tc, remaining);
                let records = model.history[next..next + count].to_vec();
                let hold = tc.draw(gs::booleans());
                offer(&mut model, &mut receiver, &mut held, records, hold);
            }
            // A valid record substituted after the genesis: reorder, repeat or fork.
            1 if remaining > 0 => {
                let count = draw_count(&tc, remaining);
                let mut records = model.history[next..next + count].to_vec();
                let lowest = usize::from(next == 0);
                if lowest < count {
                    let index = tc.draw(
                        gs::integers::<usize>()
                            .min_value(lowest)
                            .max_value(count - 1),
                    );
                    records[index] = if model.history.len() > 1 && tc.draw(gs::booleans()) {
                        let at = tc.draw(
                            gs::integers::<usize>()
                                .min_value(1)
                                .max_value(model.history.len() - 1),
                        );
                        model.history[at].clone()
                    } else {
                        pool[tc.draw(gs::integers::<usize>().max_value(pool.len() - 1))].clone()
                    };
                }
                let hold = tc.draw(gs::booleans());
                offer(&mut model, &mut receiver, &mut held, records, hold);
            }
            // One damaged, retyped, oversize, cross-room or non-owner frame.
            2 if remaining > 0 => {
                let count = draw_count(&tc, remaining);
                let mut records = model.history[next..next + count].to_vec();
                let index = tc.draw(gs::integers::<usize>().max_value(count - 1));
                let genesis = next + index == 0;
                let (kind, bytes) = &mut records[index];
                // The refusal for damage whose outcome does not depend on decoding.
                let expected = match tc.draw(gs::integers::<u8>().max_value(6)) {
                    0 => {
                        let at = tc.draw(gs::integers::<usize>().max_value(bytes.len() - 1));
                        bytes[at] ^= 1 << tc.draw(gs::integers::<u8>().max_value(7));
                        None
                    }
                    1 => {
                        bytes.truncate(tc.draw(gs::integers::<usize>().max_value(bytes.len() - 1)));
                        bytes.is_empty().then_some(Error::Bounds)
                    }
                    2 => {
                        bytes.push(tc.draw(gs::integers::<u8>()));
                        None
                    }
                    3 => {
                        *kind = match *kind {
                            FrameKind::Genesis => FrameKind::Policy,
                            FrameKind::Policy => FrameKind::Event,
                            FrameKind::Event => FrameKind::Genesis,
                        };
                        None
                    }
                    4 => {
                        *bytes = match *kind {
                            FrameKind::Genesis => foreign.encode(),
                            FrameKind::Policy => policy(&foreign, 1, 0, 1).1,
                            FrameKind::Event => event(&foreign, 2, 1, 0).1,
                        };
                        Some(if genesis {
                            Error::Protocol(RoomError::Scope)
                        } else {
                            Error::Room
                        })
                    }
                    5 => {
                        (*kind, *bytes) = impostor(&model.room);
                        Some(if genesis {
                            Error::Sequence
                        } else {
                            Error::Protocol(RoomError::Owner)
                        })
                    }
                    _ => {
                        bytes.resize(MAX_POLICY_BYTES + 1, 0);
                        Some(Error::Bounds)
                    }
                };
                let inputs = frames(&records);
                let first = next as u64 + 1;
                let error = refuse(
                    &model,
                    &receiver,
                    page(model.current(), first, first + count as u64 - 1, &inputs),
                );
                // After an honest prefix, the damaged frame itself is what is refused.
                if model.honest(&model.committed) {
                    assert_ne!(error, Error::Digest);
                    if let Some(expected) = expected {
                        assert_eq!(error, expected);
                    }
                }
            }
            // Honest bytes at a replayed, skipped, misnumbered or out-of-range position.
            3 => {
                let (next, target) = (next as u64, model.target as u64);
                let first = match tc.draw(gs::integers::<u8>().max_value(2)) {
                    0 if next > 0 => tc.draw(gs::integers::<u64>().min_value(1).max_value(next)),
                    1 => tc.draw(
                        gs::integers::<u64>()
                            .min_value(next + 2)
                            .max_value(target + 2),
                    ),
                    _ => next + 1,
                };
                let count = tc.draw(
                    gs::integers::<u64>()
                        .min_value(1)
                        .max_value(MAX_PAGE_FRAMES as u64),
                );
                let mut last = first + count - 1;
                if first == next + 1 && last <= target {
                    last = if count == 1 || tc.draw(gs::booleans()) {
                        last + 1
                    } else {
                        last - 1
                    };
                }
                let size = model.history.len() as u64;
                let records: Vec<Record> = (0..count)
                    .map(|offset| model.history[((first - 1 + offset) % size) as usize].clone())
                    .collect();
                let inputs = frames(&records);
                assert_eq!(
                    refuse(
                        &model,
                        &receiver,
                        page(model.current(), first, last, &inputs)
                    ),
                    Error::Sequence
                );
            }
            // Another checkpoint, an empty page or an oversize page.
            4 => {
                let one = frames(&model.history[..1]);
                let many = [one[0]; MAX_PAGE_FRAMES + 1];
                let first = next as u64 + 1;
                let mut input = page(model.current(), first, first, &one);
                let error = match tc.draw(gs::integers::<u8>().max_value(2)) {
                    0 => {
                        let other =
                            tc.draw(gs::integers::<usize>().max_value(model.checkpoints.len() - 1));
                        if other + 1 == model.target {
                            input.checkpoint_id[tc.draw(gs::integers::<usize>().max_value(31))] ^=
                                1;
                        } else {
                            input.checkpoint_id = model.checkpoints[other].id();
                        }
                        Error::Checkpoint
                    }
                    1 => {
                        input.frames = &[];
                        input.last = next as u64;
                        Error::Bounds
                    }
                    _ => {
                        input.frames = &many;
                        input.last = first + many.len() as u64 - 1;
                        Error::Bounds
                    }
                };
                assert_eq!(refuse(&model, &receiver, input), error);
            }
            // Commit a held token: only an unchanged base and target accept it.
            5 if !held.is_empty() => {
                let index = tc.draw(gs::integers::<usize>().max_value(held.len() - 1));
                let Held {
                    token,
                    base,
                    target,
                    records,
                } = held.swap_remove(index);
                if base == model.progress && target == model.target {
                    receiver.commit_after_persist(token).unwrap();
                    model.commit(records);
                } else {
                    assert_eq!(receiver.commit_after_persist(token), Err(Error::StaleBase));
                }
            }
            // Extend to a later checkpoint of the same source, or a refused variant.
            6 => {
                if model.complete() {
                    match tc.draw(gs::integers::<u8>().max_value(4)) {
                        0 => {
                            let later = tc.draw(
                                gs::integers::<usize>()
                                    .min_value(model.target)
                                    .max_value(model.checkpoints.len()),
                            );
                            receiver
                                .extend(SOURCE, model.checkpoints[later - 1])
                                .unwrap();
                            model.target = later;
                        }
                        variant => {
                            let (source, checkpoint, error) = model.changed(&tc, variant);
                            assert_eq!(receiver.extend(source, checkpoint), Err(error));
                        }
                    }
                } else {
                    let any = model.checkpoints
                        [tc.draw(gs::integers::<usize>().max_value(model.checkpoints.len() - 1))];
                    assert_eq!(receiver.extend(SOURCE, any), Err(Error::Pending));
                }
            }
            // Discard the receiver and start over from zero for the same target.
            7 => {
                receiver =
                    Receiver::begin(model.room.clone(), SOURCE, SOURCE, model.current()).unwrap();
                model.committed.clear();
                model.progress = Model::seed(&model.room);
            }
            // Restart: replay the retained prefix into a fresh receiver with a new pagination.
            _ => {
                let current = model.current();
                let mut fresh =
                    Receiver::begin(model.room.clone(), SOURCE, SOURCE, current).unwrap();
                let mut position = 0;
                while position < model.committed.len() {
                    let count = draw_count(&tc, model.committed.len() - position);
                    let inputs = frames(&model.committed[position..position + count]);
                    let first = position as u64 + 1;
                    let step = fresh
                        .prepare_page(page(current, first, first + count as u64 - 1, &inputs))
                        .unwrap();
                    fresh.commit_after_persist(step).unwrap();
                    position += count;
                }
                receiver = fresh;
            }
        }
        model.check(&receiver);
    }
    // An honest prefix always completes; a wrong prefix never can.
    let honest = model.honest(&model.committed);
    drain(&tc, &mut model, &mut receiver, &mut held);
    assert_eq!(model.complete(), honest);
    if honest {
        // A complete receiver refuses changed identity or history and keeps its
        // state, then continues to the end of the same source's history.
        for variant in 1..=4 {
            let (source, checkpoint, error) = model.changed(&tc, variant);
            assert_eq!(receiver.extend(source, checkpoint), Err(error));
            model.check(&receiver);
        }
        receiver
            .extend(SOURCE, *model.checkpoints.last().unwrap())
            .unwrap();
        model.target = model.checkpoints.len();
        drain(&tc, &mut model, &mut receiver, &mut held);
        assert!(model.complete());
    }
}
