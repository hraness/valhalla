//! Generative crash and uncertain-commit coverage of message custody under
//! Hegel's interleaved draw model.
//!
//! This is the implementation-level analogue of the `private-delivery`
//! verification suite: each step draws an operation — send, deliver, or
//! reopen — and a storage fault point for it: refuse before commit,
//! commit then report uncertainty, or commit then hang so the dropped
//! future stands in for a process crash mid-publication (`begin` already
//! latches `needs_reopen` before the first backend await, so an abandoned
//! future is exactly the modeled crash). A shadow model tracks admitted
//! wires and predicts custody:
//!
//! * no received body was ever fabricated — every inbox record came from a
//!   committed send in the opposite direction,
//! * each admitted wire occupies exactly one inbox position, and exact
//!   retries return that same position,
//! * reopen always succeeds and committed outbox contents match the
//!   records the backend actually applied, including sends whose commit
//!   report was uncertain,
//! * a faulted operation leaves `needs_reopen` set until reopen.
//!
//! `recovery_hegel.rs` in vhalla-ledger is the reference for the
//! draw-inside-the-loop style.

use super::*;
use hegel::{generators as gs, TestCase};
use std::{
    future::Future,
    task::{Context as TaskContext, Poll},
};

/// Direction 0: owner → member. Direction 1: member → owner.
struct Shadow {
    /// Committed outbox wires and bodies per direction.
    sent: [Vec<(Vec<u8>, Vec<u8>)>; 2],
    /// Highest outbox sequence observed, counting confidential entries.
    outbox_head: [u64; 2],
    /// Wire bytes → committed inbox sequence, per receiving direction.
    delivered: [BTreeMap<Vec<u8>, u64>; 2],
    /// Bodies recorded per attempted send, keyed by operation id, so a
    /// commit discovered only at reopen still resolves to its body.
    pending_body: BTreeMap<OperationId, Vec<u8>>,
    /// Operations handed out so far.
    ops: u64,
}

impl Shadow {
    fn new() -> Self {
        Self {
            sent: [Vec::new(), Vec::new()],
            outbox_head: [0, 0],
            delivered: [BTreeMap::new(), BTreeMap::new()],
            pending_body: BTreeMap::new(),
            // op(1) is already committed by the join handshake on both
            // disks; reusing it with a different request must conflict.
            ops: 1,
        }
    }
}

fn side(pair: &mut Pair, dir: usize) -> (&mut Kernel<Memory>, &Memory, &StorageKey) {
    if dir == 0 {
        (&mut pair.owner, &pair.owner_disk, &pair.owner_key)
    } else {
        (&mut pair.member, &pair.member_disk, &pair.member_key)
    }
}

/// Poll a future once; returns `true` when it completed. A `false` result
/// models a crash mid-operation — the caller drops the future and must
/// reopen, matching `begin`'s custody latch.
fn ran<F: Future>(f: F) -> bool {
    futures::pin_mut!(f);
    let waker = futures::task::noop_waker();
    let mut cx = TaskContext::from_waker(&waker);
    matches!(f.as_mut().poll(&mut cx), Poll::Ready(_))
}

/// Reopen a kernel and drain its committed outbox/inbox into the shadow
/// model, so sends and receives whose commit report was uncertain are
/// still accounted — the reopen is the source of truth, not the return.
async fn resync(
    kernel: &mut Kernel<Memory>,
    disk: &Memory,
    key: &StorageKey,
    shadow: &mut Shadow,
    dir: usize,
) {
    let context = kernel.status().context;
    *kernel = Kernel::open(disk.clone(), key, context).await.unwrap();
    // A committed send is any outbox artifact past the shadow's frontier;
    // its operation id resolves the body the driver attempted to send.
    let mut after = shadow.outbox_head[dir];
    loop {
        let page = kernel.outbox(after, MAX_PAGE_RECORDS).await.unwrap();
        for entry in page.records {
            assert_eq!(entry.sequence(), after + 1);
            if let Some(artifact) = entry.artifact() {
                // Only application wires are deliverable to `receive`;
                // join artifacts (key packages, invitations) are not.
                if artifact.kind() == OutboxKind::Application {
                    let body = shadow
                        .pending_body
                        .get(&artifact.operation())
                        .cloned()
                        .unwrap_or_default();
                    shadow.sent[dir].push((artifact.bytes().to_vec(), body));
                }
            }
            after = entry.sequence();
        }
        shadow.outbox_head[dir] = after;
        match page.next {
            Some(next) => after = next,
            None => break,
        }
    }
    // A committed receive lands exactly once; its body must be a body
    // committed in the opposite direction or the model is wrong.
    let mut after = shadow.delivered[dir].len() as u64;
    loop {
        let page = kernel.inbox(after, MAX_PAGE_RECORDS).await.unwrap();
        for message in page.records {
            let wire = shadow.sent[1 - dir]
                .iter()
                .find(|(_, body)| *body == *message.body())
                .map(|(wire, _)| wire.clone())
                .expect("inbox body was never sent");
            let prior = shadow.delivered[dir].insert(wire, message.sequence());
            assert!(prior.is_none(), "wire committed to two inbox positions");
        }
        match page.next {
            Some(next) => after = next,
            None => break,
        }
    }
}

#[hegel::test(test_cases = 64)]
fn crashes_and_uncertain_commits_preserve_message_custody(tc: TestCase) {
    block_on(async {
        let mut pair = joined().await;
        let mut shadow = Shadow::new();
        resync(
            &mut pair.owner,
            &pair.owner_disk,
            &pair.owner_key,
            &mut shadow,
            0,
        )
        .await;
        resync(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_key,
            &mut shadow,
            1,
        )
        .await;
        let steps = tc.draw(gs::integers::<usize>().max_value(31));
        for _ in 0..steps {
            pair.now += 1 + tc.draw(gs::integers::<u64>().max_value(2));
            let now = pair.now;
            let dir = tc.draw(gs::booleans()) as usize;
            let fault = match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=5 => Fault::None,
                6..=7 => Fault::Before,
                8 => Fault::After,
                _ => Fault::HangAfter,
            };
            let (kernel, disk, key) = side(&mut pair, dir);
            // A latched reopen is mandatory; any new operation must fail
            // until the exact backend is reopened.
            if kernel.needs_reopen() {
                assert!(kernel.prepare_message(b"probe").is_err());
                resync(kernel, disk, key, &mut shadow, dir).await;
            }
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                // Send an application message, possibly into a fault.
                0..=3 => {
                    shadow.ops += 1;
                    let operation = op(shadow.ops);
                    let body = format!("m{:05}", shadow.ops).into_bytes();
                    shadow.pending_body.insert(operation, body.clone());
                    disk.fault(fault);
                    match fault {
                        Fault::HangAfter => {
                            assert!(!ran(kernel.test_send(operation, &body, now)));
                            resync(kernel, disk, key, &mut shadow, dir).await;
                        }
                        Fault::None => {
                            let outbox =
                                kernel.test_send(operation, &body, now).await.unwrap();
                            assert_eq!(outbox.kind(), OutboxKind::Application);
                            assert_eq!(outbox.operation(), operation);
                            assert_eq!(outbox.sequence(), shadow.outbox_head[dir] + 1);
                            shadow.outbox_head[dir] = outbox.sequence();
                            shadow.sent[dir].push((outbox.bytes().to_vec(), body));
                        }
                        _ => {
                            assert!(kernel.test_send(operation, &body, now).await.is_err());
                            assert!(kernel.needs_reopen());
                            resync(kernel, disk, key, &mut shadow, dir).await;
                        }
                    }
                }
                // Deliver a committed wire — sometimes a replay or a
                // corrupted frame — into an optional storage fault.
                4..=7 => {
                    let incoming = &shadow.sent[1 - dir];
                    if incoming.is_empty() {
                        continue;
                    }
                    let i = tc.draw(gs::integers::<usize>().max_value(incoming.len() - 1));
                    let (wire, body) = incoming[i].clone();
                    let mut tampered = wire.clone();
                    let corrupt = tc.draw(gs::booleans());
                    if corrupt {
                        let b = tc.draw(gs::integers::<usize>().max_value(tampered.len() - 1));
                        tampered[b] ^= 1;
                    }
                    let frame = if corrupt { &tampered } else { &wire };
                    let retained = !corrupt && shadow.delivered[dir].contains_key(&wire);
                    disk.fault(fault);
                    if corrupt || retained {
                        // Corruption and duplicate deliveries resolve before
                        // the publish point, so no armed fault can fire.
                        let result = kernel.receive(frame, now).await;
                        if corrupt {
                            assert!(result.is_err());
                        } else {
                            let message = result.unwrap();
                            assert_eq!(message.sequence(), shadow.delivered[dir][&wire]);
                        }
                        continue;
                    }
                    match fault {
                        Fault::HangAfter => {
                            assert!(!ran(kernel.receive(frame, now)));
                            resync(kernel, disk, key, &mut shadow, dir).await;
                        }
                        Fault::None => {
                            let message = kernel.receive(frame, now).await.unwrap();
                            assert_eq!(message.body(), body.as_slice());
                            match shadow.delivered[dir].insert(wire.clone(), message.sequence()) {
                                None => {}
                                Some(seq) => assert_eq!(seq, message.sequence()),
                            }
                        }
                        _ => {
                            assert!(kernel.receive(frame, now).await.is_err());
                            assert!(kernel.needs_reopen());
                            resync(kernel, disk, key, &mut shadow, dir).await;
                        }
                    }
                }
                _ => {
                    resync(kernel, disk, key, &mut shadow, dir).await;
                }
            }
        }
        resync(
            &mut pair.owner,
            &pair.owner_disk,
            &pair.owner_key,
            &mut shadow,
            0,
        )
        .await;
        resync(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_key,
            &mut shadow,
            1,
        )
        .await;
    });
}
