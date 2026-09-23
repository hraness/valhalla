//! Production correspondence for `verify/rooms-held-reply`.
//!
//! These schedules drive the actual host loop and oneshots, not a second Rust
//! implementation of the model. They exercise successful operating-host paths;
//! permanent storage/network failure and host termination are outside liveness.
use super::*;
use tokio::sync::{mpsc, oneshot};

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum Schedule {
    Deadline,
    LateSubmit,
    FullMetadata,
}

async fn exercise(schedule: Schedule) {
    let (keys, set) = validators(1);
    let mut app = test_app("formal-held-reply", &keys[0], &set);
    let home = app.store.parent().unwrap().to_path_buf();
    let cleanup = Cleanup(home.parent().unwrap().to_path_buf());
    let store = app.store.clone();
    let batch = batch_plan(1).remove(&1).unwrap();
    let id = RoomValueId(batch.value_id());
    let round = Round::new(MAX_SEEN_RECORDS_PER_HEIGHT as u32);
    let tombstone = app.tombstone(1, round);
    if matches!(schedule, Schedule::FullMetadata) {
        // The admission boundary is full; disk-full behavior and full retained
        // metadata persistence are tested separately in `seen_tests`.
        app.seen.insert(
            1,
            (0..MAX_SEEN_RECORDS_PER_HEIGHT)
                .map(|i| SeenProposal {
                    round: Round::new(i as u32),
                    pol_round: Round::Nil,
                    proposer: app.address,
                    value_id: id,
                })
                .collect(),
        );
    }
    let (messages, consensus) = mpsc::channel(2);
    let (network, mut network_rx) = mpsc::channel(1);
    let (requests, _requests_rx) = mpsc::channel(1);
    let (net_requests, _net_requests_rx) = mpsc::channel(1);
    let mut channels: Channels<RoomContext> = Channels {
        consensus,
        network,
        requests,
        net_requests,
        events: Default::default(),
    };
    let (submissions, mut submission_rx) = mpsc::channel(1);
    let driver = async move {
        let (reply, mut answer) = oneshot::channel::<LocallyProposedValue<RoomContext>>();
        messages
            .send(AppMsg::GetValue {
                height: Height::new(1),
                round,
                timeout: if matches!(schedule, Schedule::Deadline) {
                    Duration::ZERO
                } else {
                    Duration::from_secs(60)
                },
                reply,
            })
            .await
            .unwrap();

        if !matches!(schedule, Schedule::Deadline) {
            // A host-loop barrier confirms GetValue was consumed before the
            // late submission. This diagnostic message is not a substitute
            // for deadline polling: the Deadline schedule sends nothing else
            // until the GetValue reply arrives.
            let (reply, barrier) = oneshot::channel();
            messages
                .send(AppMsg::ConsensusReady { reply })
                .await
                .unwrap();
            barrier.await.unwrap();
            assert!(matches!(
                answer.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            submissions.send(batch).await.unwrap();
        }

        let answered = (&mut answer)
            .await
            .expect("held oneshot must not be dropped");
        assert_eq!(answered.height, Height::new(1));
        assert_eq!(answered.round, round);
        if matches!(schedule, Schedule::LateSubmit) {
            assert_eq!(answered.value.id, id);
            let (retained, seen) = load_store(&store);
            // This observes custody when the receiver resumes. The existing
            // `seen_failed_preparation_cannot_release_direct_or_held_reply`
            // regression forces persistence failure and separately rejects
            // sending before the synchronous preparation call.
            assert!(
                retained.contains_key(&id),
                "batch retained at reply observation"
            );
            assert!(
                seen[&1]
                    .iter()
                    .any(|entry| entry.value_id == id && entry.round == round),
                "exact recovery metadata retained at reply observation"
            );
            // Deliberately do not drain network before the reply: a single
            // channel slot backpressures the paced multipart publication.
            let mut parts = Vec::new();
            loop {
                let NetworkMsg::PublishProposalPart(message) = network_rx.recv().await.unwrap();
                match message.content {
                    StreamContent::Data(part) => parts.push(part),
                    StreamContent::Fin => break,
                }
            }
            assert!(!parts.is_empty(), "live proposal is published after reply");
        } else {
            assert_eq!(answered.value.id, tombstone.id);
            assert!(answered.value.bytes.is_empty());
        }

        // The simulated sequential connector can only issue its next request
        // after the held reply. Deadline-only and capacity refusal must both
        // let it continue, with no network consumer needed for tombstones.
        let (reply, next) = oneshot::channel();
        messages
            .send(AppMsg::ConsensusReady { reply })
            .await
            .unwrap();
        assert_eq!(next.await.unwrap().0, Height::new(1));
        assert!(
            matches!(network_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "tombstones must stay off the network; live stream must be complete"
        );
        drop(messages);
        drop(submissions);
    };
    // Dropping these borrowed futures on failure cancels all test work; there
    // are no detached host tasks or listeners left after the timeout.
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(run(&mut app, &mut channels, &mut submission_rx), driver);
    })
    .await
    .expect("host reply and subsequent connector request must resolve");
    assert!(app.held_replies.is_empty());
    drop(app);
    drop(cleanup);
}

#[tokio::test]
async fn deadline_unparks_connector_without_another_message() {
    exercise(Schedule::Deadline).await;
}

#[tokio::test]
async fn late_submit_is_durable_before_reply_and_network_drain() {
    exercise(Schedule::LateSubmit).await;
}

#[tokio::test]
async fn full_metadata_answers_locally_without_publishing() {
    exercise(Schedule::FullMetadata).await;
}
