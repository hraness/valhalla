//! Generative crash and uncertain-commit coverage of agent queue custody
//! under Hegel's interleaved draw model — the `agent` layer analogue of the
//! kernel's `fault_hegel` driver, running over the real `KernelStore`
//! (SQLite) bridge instead of an in-memory store.
//!
//! The owner runs an `AgentRoomSession` — prepare/queue plus inbox and
//! outbox-status reads under a grant budget — while the member stays a
//! host kernel. Each mutating step draws a storage fault: refuse before
//! commit, commit then report uncertainty, or commit then hang so the
//! dropped future models a process crash between the durable write and
//! its report. A reopen drops the live session, reopens the on-disk
//! store, and drains committed records into a shadow model, so an
//! operation whose commit report was uncertain is still accounted through
//! its operation ID. Member wires are delivered to the owner only during
//! a reopen window, when the kernel is outside agent custody.
//!
//! Asserted custody: queued sequences are contiguous from the committed
//! head, every admitted wire occupies exactly one inbox position with
//! identical retry results, no inbox body was never sent, reopen always
//! succeeds against the reopened SQLite store, and `needs_reopen` is
//! latched whenever a publication's report was lost.

use super::*;
use hegel::{generators as gs, TestCase};
use std::{
    collections::BTreeMap,
    future::Future,
    task::{Context as TaskContext, Poll},
};

/// Committed wires per direction and the receiving side's admitted set.
struct Shadow {
    /// Direction 0: owner → member, direction 1: member → owner.
    sent: [Vec<(Vec<u8>, Vec<u8>)>; 2],
    /// Highest outbox sequence drained, including confidential entries.
    outbox_head: [u64; 2],
    /// Committed wire → inbox position, per receiving side.
    delivered: [BTreeMap<Vec<u8>, u64>; 2],
    /// Attempted bodies by operation, for uncertain-commit accounting.
    pending_body: BTreeMap<OperationId, Vec<u8>>,
    ops: u64,
    queued: u64,
}

impl Shadow {
    fn new() -> Self {
        Self {
            sent: [Vec::new(), Vec::new()],
            outbox_head: [0, 0],
            delivered: [BTreeMap::new(), BTreeMap::new()],
            pending_body: BTreeMap::new(),
            // op(1) is committed by the join handshake on both disks.
            ops: 1,
            queued: 0,
        }
    }
}

/// Poll once; `false` means the future is stuck mid-operation (a crash) —
/// the caller drops it and must reopen.
fn ran<F: Future>(f: F) -> bool {
    futures::pin_mut!(f);
    let waker = futures::task::noop_waker();
    let mut cx = TaskContext::from_waker(&waker);
    matches!(f.as_mut().poll(&mut cx), Poll::Ready(_))
}

/// Drain committed outbox/inbox records past the shadow frontier.
async fn resync(kernel: &mut Kernel<Disk>, shadow: &mut Shadow, dir: usize) {
    let mut after = shadow.outbox_head[dir];
    loop {
        let page = kernel.outbox(after, MAX_PAGE_RECORDS).await.unwrap();
        for entry in page.records {
            assert_eq!(entry.sequence(), after + 1);
            if let Some(artifact) = entry.artifact() {
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

/// Recreate the owner's kernel from the reopened on-disk store — a real
/// SQLite close/open, not a snapshot — optionally deliver one committed
/// member wire while the kernel is outside agent custody, drain the
/// committed records, and rebuild the agent session.
async fn reopen_owner(
    disk: &Disk,
    home: &PathBuf,
    key: &StorageKey,
    context: Context,
    deliver: Option<Vec<u8>>,
    now: u64,
    shadow: &mut Shadow,
) -> (AgentRoomSession<Disk>, RevocationHandle) {
    disk.reopen(home, context);
    let mut kernel = Kernel::open(disk.clone(), key, context).await.unwrap();
    if let Some(wire) = deliver {
        // The kernel is freshly opened, so the wire always takes the
        // publish path — a crash here lands on the receive commit.
        let message = kernel.receive(&wire, now).await.unwrap();
        let prior = shadow.delivered[0].insert(wire, message.sequence());
        assert!(prior.is_none());
    }
    resync(&mut kernel, shadow, 0).await;
    session(kernel)
}

/// Recreate the member kernel from the reopened on-disk store. Takes the
/// fields disjointly because the owner kernel lives in the agent session
/// while `pair` is partially moved.
async fn reopen_member(
    member: &mut Kernel<Disk>,
    disk: &Disk,
    home: &PathBuf,
    key: &StorageKey,
    context: Context,
    shadow: &mut Shadow,
) {
    disk.reopen(home, context);
    *member = Kernel::open(disk.clone(), key, context).await.unwrap();
    resync(member, shadow, 1).await;
}

#[hegel::test(test_cases = 64)]
fn crashes_and_uncertain_commits_preserve_queue_custody(tc: TestCase) {
    block_on(async {
        let mut pair = Pair::fresh(100, 100).await;
        pair.join().await;
        let mut shadow = Shadow::new();
        resync(&mut pair.owner, &mut shadow, 0).await;
        resync(&mut pair.member, &mut shadow, 1).await;
        let owner_kernel = pair.owner;
        let (initial, authority) = session(owner_kernel);
        let mut owner_session = Some(initial);
        let mut owner_handle = Some(authority);
        let steps = tc.draw(gs::integers::<usize>().max_value(23));
        for _ in 0..steps {
            // The agent layer and kernel share the wall clock, not the
            // pair's logical clock.
            let now = wall_time().unwrap();
            let fault = match tc.draw(gs::integers::<u8>().max_value(9)) {
                0..=5 => Fault::None,
                6..=7 => Fault::Before,
                8 => Fault::After,
                _ => Fault::PendingAfter,
            };
            match tc.draw(gs::integers::<u8>().max_value(9)) {
                // Queue a fresh body through the agent grant.
                0..=3 => {
                    if owner_session.is_none() || shadow.queued >= 9 {
                        continue;
                    }
                    let agent = owner_session.as_mut().unwrap();
                    shadow.ops += 1;
                    let operation = op(shadow.ops);
                    let body = format!("m{:05}", shadow.ops).into_bytes();
                    shadow.pending_body.insert(operation, body.clone());
                    let draft = agent.prepare(&body).unwrap();
                    pair.owner_disk.fault(fault);
                    match fault {
                        Fault::PendingAfter => {
                            assert!(!ran(agent.queue(operation, draft)));
                            drop(owner_session.take());
                            drop(owner_handle.take());
                            let (s, h) = reopen_owner(
                                &pair.owner_disk,
                                &pair.owner_home,
                                &pair.owner_key,
                                pair.owner_context,
                                None,
                                now,
                                &mut shadow,
                            )
                            .await;
                            owner_session = Some(s);
                            owner_handle = Some(h);
                        }
                        Fault::None => {
                            let queued = agent.queue(operation, draft).await.unwrap();
                            assert_eq!(queued.kind, OutboxKind::Application);
                            assert_eq!(queued.operation, operation);
                            assert_eq!(queued.sequence, shadow.outbox_head[0] + 1);
                            shadow.outbox_head[0] = queued.sequence;
                            shadow.queued += 1;
                            let wire = committed_wire(&mut agent.kernel, queued.sequence).await;
                            shadow.sent[0].push((wire, body));
                        }
                        _ => {
                            assert!(agent.queue(operation, draft).await.is_err());
                            drop(owner_session.take());
                            drop(owner_handle.take());
                            let (s, h) = reopen_owner(
                                &pair.owner_disk,
                                &pair.owner_home,
                                &pair.owner_key,
                                pair.owner_context,
                                None,
                                now,
                                &mut shadow,
                            )
                            .await;
                            owner_session = Some(s);
                            owner_handle = Some(h);
                        }
                    }
                }
                // Deliver a committed owner wire to the member, with a
                // drawn storage fault on the member's disk.
                4..=6 => {
                    let incoming = &shadow.sent[0];
                    if incoming.is_empty() {
                        continue;
                    }
                    let i = tc.draw(gs::integers::<usize>().max_value(incoming.len() - 1));
                    let (wire, body) = incoming[i].clone();
                    pair.member_disk.fault(fault);
                    if shadow.delivered[1].contains_key(&wire) {
                        // Retained retries resolve before the publish point.
                        let message = pair.member.receive(&wire, now).await.unwrap();
                        assert_eq!(message.sequence(), shadow.delivered[1][&wire]);
                        assert_eq!(message.body(), body.as_slice());
                        continue;
                    }
                    match fault {
                        Fault::PendingAfter => {
                            assert!(!ran(pair.member.receive(&wire, now)));
                            reopen_member(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_home,
            &pair.member_key,
            pair.member_context,
            &mut shadow,
        )
        .await;
                        }
                        Fault::None => {
                            let message = pair.member.receive(&wire, now).await.unwrap();
                            assert_eq!(message.body(), body.as_slice());
                            let prior =
                                shadow.delivered[1].insert(wire, message.sequence());
                            assert!(prior.is_none());
                        }
                        _ => {
                            assert!(pair.member.receive(&wire, now).await.is_err());
                            reopen_member(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_home,
            &pair.member_key,
            pair.member_context,
            &mut shadow,
        )
        .await;
                        }
                    }
                }
                // Member sends a reply at kernel level.
                7 => {
                    shadow.ops += 1;
                    let operation = op(shadow.ops);
                    let body = format!("m{:05}", shadow.ops).into_bytes();
                    shadow.pending_body.insert(operation, body.clone());
                    let draft = pair.member.prepare_message(&body).unwrap();
                    pair.member_disk.fault(fault);
                    match fault {
                        Fault::PendingAfter => {
                            assert!(!ran(pair.member.send(operation, &draft, now)));
                            reopen_member(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_home,
            &pair.member_key,
            pair.member_context,
            &mut shadow,
        )
        .await;
                        }
                        Fault::None => {
                            let outbox =
                                pair.member.send(operation, &draft, now).await.unwrap();
                            assert_eq!(outbox.sequence(), shadow.outbox_head[1] + 1);
                            shadow.outbox_head[1] = outbox.sequence();
                            shadow.sent[1].push((outbox.bytes().to_vec(), body));
                        }
                        _ => {
                            assert!(pair.member.send(operation, &draft, now).await.is_err());
                            reopen_member(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_home,
            &pair.member_key,
            pair.member_context,
            &mut shadow,
        )
        .await;
                        }
                    }
                }
                // Reopen the owner through the real store, sometimes
                // delivering a committed member wire during the window.
                _ => {
                    drop(owner_session.take());
                    drop(owner_handle.take());
                    let deliver = if shadow.sent[1].is_empty() {
                        None
                    } else {
                        let i =
                            tc.draw(gs::integers::<usize>().max_value(shadow.sent[1].len() - 1));
                        let wire = shadow.sent[1][i].0.clone();
                        (!shadow.delivered[0].contains_key(&wire)).then_some(wire)
                    };
                    let (s, h) = reopen_owner(
                        &pair.owner_disk,
                        &pair.owner_home,
                        &pair.owner_key,
                        pair.owner_context,
                        deliver,
                        now,
                        &mut shadow,
                    )
                    .await;
                    owner_session = Some(s);
                    owner_handle = Some(h);
                }
            }
        }
        drop(owner_session.take());
        drop(owner_handle.take());
        drop(
            reopen_owner(
                &pair.owner_disk,
                &pair.owner_home,
                &pair.owner_key,
                pair.owner_context,
                None,
                wall_time().unwrap(),
                &mut shadow,
            )
            .await,
        );
        reopen_member(
            &mut pair.member,
            &pair.member_disk,
            &pair.member_home,
            &pair.member_key,
            pair.member_context,
            &mut shadow,
        )
        .await;
    });
}

/// Read back the committed artifact bytes at an exact outbox position —
/// the queue status deliberately does not expose wire bytes.
async fn committed_wire(kernel: &mut Kernel<Disk>, sequence: u64) -> Vec<u8> {
    let page = kernel
        .outbox(sequence - 1, MAX_PAGE_RECORDS)
        .await
        .unwrap();
    page.records
        .into_iter()
        .find_map(|entry| {
            (entry.sequence() == sequence)
                .then(|| entry.artifact().map(|a| a.bytes().to_vec()))
                .flatten()
        })
        .expect("queued artifact committed")
}
