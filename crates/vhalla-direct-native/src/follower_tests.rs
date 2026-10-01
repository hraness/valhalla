use super::*;
use hegel::HealthCheck;
use std::{fs, path::PathBuf};
use tempfile::TempDir;
use vhalla_direct_room::{
    EventClaims, EventId, GenesisClaims, Text, UnsignedEvent, UnsignedGenesis,
};
use vhalla_direct_sync::SourceAccumulator;
use vhalla_identity::Identity;

const REMOTE: [u8; 32] = [61; 32];
const REMOTE_EPOCH: [u8; 32] = [62; 32];
const LOCAL: [u8; 32] = [63; 32];

#[test]
fn initial_target_stays_exact_after_extension_and_reopen() {
    let fixture = Fixture::new(3);
    let mut backing = fixture.backing(limits());
    let mut follower = fixture.create(&mut backing, 1, limits());
    let first = fixture.target(1);
    assert_eq!(follower.initial_target(&mut backing).unwrap(), first);
    fixture
        .receive(&mut follower, &mut backing, first, 0, 1)
        .unwrap();
    follower
        .extend(REMOTE, fixture.target(3), &mut backing)
        .unwrap();
    assert_eq!(follower.initial_target(&mut backing).unwrap(), first);
    assert_eq!(
        follower.status(&mut backing).unwrap().target,
        fixture.target(3)
    );
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    assert_eq!(follower.initial_target(&mut backing).unwrap(), first);
    assert_eq!(
        follower.status(&mut backing).unwrap().target,
        fixture.target(3)
    );
}

struct Fixture {
    root: TempDir,
    genesis: PinnedGenesis,
    frames: Vec<ReplicaFrame>,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let root = TempDir::new().unwrap();
        let owner = Identity::create_new(root.path().join("owner")).unwrap();
        let author = Identity::create_new(root.path().join("author")).unwrap();
        let signed = owner
            .sign_direct_genesis(
                UnsignedGenesis::new(GenesisClaims {
                    owner: owner.public_key(),
                    nonce: [64; 32],
                    writers: vec![owner.public_key()],
                })
                .unwrap(),
            )
            .unwrap();
        let genesis = signed.clone().verify_pin(signed.id()).unwrap();
        let mut frames = vec![ReplicaFrame {
            kind: FrameKind::Genesis,
            bytes: genesis.encode(),
        }];
        for number in 1..count {
            // Valid unadmitted, conflicting events are retained as evidence;
            // selected-source coverage does not turn them into admitted messages.
            let signed = author
                .sign_direct_event(
                    UnsignedEvent::new(EventClaims {
                        room: genesis.id(),
                        policy: genesis.id().initial_policy(),
                        author: author.public_key(),
                        sequence: 1,
                        previous: EventId::ZERO,
                        created_at: number as u64,
                        text: Text::new(&format!("source frame {number}")).unwrap(),
                    })
                    .unwrap(),
                )
                .unwrap();
            frames.push(ReplicaFrame {
                kind: FrameKind::Event,
                bytes: signed.encode(),
            });
        }
        Self {
            root,
            genesis,
            frames,
        }
    }

    fn path(&self) -> PathBuf {
        self.root.path().join("follower")
    }
    fn backing_path(&self) -> PathBuf {
        self.root.path().join("replica")
    }

    fn backing(&self, limits: Limits) -> Replica {
        Replica::create_new(self.backing_path(), self.genesis.clone(), LOCAL, limits).unwrap()
    }

    fn target(&self, count: usize) -> Checkpoint {
        let mut source =
            SourceAccumulator::new(REMOTE, self.genesis.clone(), REMOTE_EPOCH).unwrap();
        for frame in &self.frames[..count] {
            source.push(frame.as_frame()).unwrap();
        }
        source.checkpoint().unwrap()
    }

    fn create(&self, backing: &mut Replica, count: usize, limits: Limits) -> Follower {
        Follower::create_new(
            self.path(),
            self.genesis.clone(),
            REMOTE,
            REMOTE,
            self.target(count),
            backing,
            limits,
        )
        .unwrap()
    }

    fn open(&self, backing: &mut Replica) -> Follower {
        Follower::open(self.path(), self.genesis.clone(), REMOTE, backing).unwrap()
    }

    fn receive(
        &self,
        follower: &mut Follower,
        backing: &mut Replica,
        target: Checkpoint,
        start: usize,
        end: usize,
    ) -> FollowerResult<FollowerOutcome> {
        let frames: Vec<_> = self.frames[start..end]
            .iter()
            .map(ReplicaFrame::as_frame)
            .collect();
        follower.receive(
            REMOTE,
            Page {
                checkpoint_id: target.id(),
                first: start as u64 + 1,
                last: end as u64,
                frames: &frames,
            },
            backing,
        )
    }

    fn refs(&self, target: Checkpoint, start: usize, end: usize) -> References {
        let frames: Vec<_> = self.frames[start..end]
            .iter()
            .map(ReplicaFrame::as_frame)
            .collect();
        References::from_page(Page {
            checkpoint_id: target.id(),
            first: start as u64 + 1,
            last: end as u64,
            frames: &frames,
        })
        .unwrap()
    }
}

fn limits() -> Limits {
    Limits {
        max_records: 1_000,
        max_record_bytes: 1024 * 1024,
    }
}

fn append_all(backing: &mut Replica, frames: &[ReplicaFrame]) {
    for chunk in frames.chunks(8) {
        let frames: Vec<_> = chunk.iter().map(ReplicaFrame::as_frame).collect();
        backing.append(&frames).unwrap();
    }
}

fn copy_directory(from: &Path, to: &Path) {
    vhalla_custody::create_private_directory(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
    }
}

#[test]
fn partial_progress_exact_retries_extensions_and_reopen_preserve_source_order() {
    let fixture = Fixture::new(46);
    let mut backing = fixture.backing(limits());
    let mut follower = fixture.create(&mut backing, 41, limits());
    let first = fixture.target(41);
    let zero = follower.status(&mut backing).unwrap();
    assert_eq!(zero.progress.records, 0);
    assert_eq!(zero.coverage, Coverage::Pending);
    let page = fixture
        .receive(&mut follower, &mut backing, first, 0, 32)
        .unwrap();
    assert_eq!(page.status.progress.records, 32);
    assert_eq!(page.status.coverage, Coverage::Pending);
    assert!(!page.exact_retry);
    let saved = follower.accounting(&mut backing).unwrap();
    let replica = backing.checkpoint().unwrap();
    assert!(
        fixture
            .receive(&mut follower, &mut backing, first, 0, 32)
            .unwrap()
            .exact_retry
    );
    assert_eq!(follower.accounting(&mut backing).unwrap(), saved);
    assert_eq!(backing.checkpoint().unwrap(), replica);
    assert!(fixture
        .receive(&mut follower, &mut backing, first, 0, 16)
        .is_err());
    assert_eq!(
        follower.extend(REMOTE, fixture.target(46), &mut backing),
        Err(vhalla_direct_sync::Error::Pending.into())
    );
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    assert_eq!(follower.status(&mut backing).unwrap(), page.status);
    let finished = fixture
        .receive(&mut follower, &mut backing, first, 32, 41)
        .unwrap();
    assert_eq!(finished.status.coverage, Coverage::Complete);
    let next = fixture.target(46);
    assert_eq!(
        follower
            .extend(REMOTE, next, &mut backing)
            .unwrap()
            .coverage,
        Coverage::Pending
    );
    // An old exact retry acknowledges that page, but does not complete the new target.
    let retry = fixture
        .receive(&mut follower, &mut backing, first, 0, 32)
        .unwrap();
    assert!(retry.exact_retry);
    assert_eq!(retry.status.target, next);
    assert_eq!(retry.status.coverage, Coverage::Pending);
    fixture
        .receive(&mut follower, &mut backing, next, 41, 46)
        .unwrap();
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    let complete = follower.status(&mut backing).unwrap();
    assert_eq!(complete.target, next);
    assert_eq!(complete.progress.records, next.records);
    assert_eq!(complete.progress.bytes, next.bytes);
    assert_eq!(complete.progress.digest, next.digest);
    assert_eq!(complete.coverage, Coverage::Complete);
}

#[test]
fn two_sources_share_signed_bodies_without_sharing_order_or_checkpoint_authority() {
    let fixture = Fixture::new(8);
    let mut backing = fixture.backing(limits());
    let mut first = fixture.create(&mut backing, 8, limits());
    fixture
        .receive(&mut first, &mut backing, fixture.target(8), 0, 8)
        .unwrap();
    let retained = backing.accounting().unwrap();
    let source = [65; 32];
    let mut reversed = fixture.frames.clone();
    reversed[1..].reverse();
    let mut accumulator =
        SourceAccumulator::new(source, fixture.genesis.clone(), [66; 32]).unwrap();
    for frame in &reversed {
        accumulator.push(frame.as_frame()).unwrap();
    }
    let target = accumulator.checkpoint().unwrap();
    let path = fixture.root.path().join("second-source");
    let mut second = Follower::create_new(
        &path,
        fixture.genesis.clone(),
        source,
        source,
        target,
        &mut backing,
        limits(),
    )
    .unwrap();
    let frames: Vec<_> = reversed.iter().map(ReplicaFrame::as_frame).collect();
    second
        .receive(
            source,
            Page {
                checkpoint_id: target.id(),
                first: 1,
                last: 8,
                frames: &frames,
            },
            &mut backing,
        )
        .unwrap();
    assert_eq!(backing.accounting().unwrap(), retained);
    assert_ne!(
        first.status(&mut backing).unwrap().target.digest,
        second.status(&mut backing).unwrap().target.digest
    );
    drop(second);
    assert_eq!(
        Follower::open(path, fixture.genesis.clone(), source, &mut backing)
            .unwrap()
            .status(&mut backing)
            .unwrap()
            .coverage,
        Coverage::Complete
    );
    for frame in &fixture.frames {
        let hash = Sha256::digest(&frame.bytes).into();
        assert_eq!(backing.lookup(frame.kind, hash).unwrap().unwrap(), *frame);
    }
    assert!(backing
        .lookup(FrameKind::Event, [67; 32])
        .unwrap()
        .is_none());
    assert!(backing.lookup(FrameKind::Event, [0; 32]).is_err());
}

#[test]
fn invalid_sources_pages_signatures_and_terminal_hashes_make_no_publication() {
    let fixture = Fixture::new(5);
    let mut backing = fixture.backing(limits());
    let mut follower = fixture.create(&mut backing, 5, limits());
    let target = fixture.target(5);
    let ledger = follower.accounting(&mut backing).unwrap();
    let retained = backing.accounting().unwrap();
    let frames: Vec<_> = fixture.frames.iter().map(ReplicaFrame::as_frame).collect();
    let valid = Page {
        checkpoint_id: target.id(),
        first: 1,
        last: 5,
        frames: &frames,
    };
    assert_eq!(
        follower.receive([68; 32], valid, &mut backing),
        Err(vhalla_direct_sync::Error::Source.into())
    );
    assert!(follower
        .receive(
            REMOTE,
            Page {
                checkpoint_id: [69; 32],
                ..valid
            },
            &mut backing
        )
        .is_err());
    assert!(follower
        .receive(
            REMOTE,
            Page {
                first: 2,
                last: 6,
                ..valid
            },
            &mut backing
        )
        .is_err());
    assert!(follower
        .receive(REMOTE, Page { last: 4, ..valid }, &mut backing)
        .is_err());
    let mut altered = fixture.frames.clone();
    *altered[2].bytes.last_mut().unwrap() ^= 1;
    let altered: Vec<_> = altered.iter().map(ReplicaFrame::as_frame).collect();
    assert!(follower
        .receive(
            REMOTE,
            Page {
                frames: &altered,
                ..valid
            },
            &mut backing
        )
        .is_err());
    let mut reordered = fixture.frames.clone();
    reordered.swap(2, 3);
    let reordered: Vec<_> = reordered.iter().map(ReplicaFrame::as_frame).collect();
    assert_eq!(
        follower.receive(
            REMOTE,
            Page {
                frames: &reordered,
                ..valid
            },
            &mut backing
        ),
        Err(vhalla_direct_sync::Error::Digest.into())
    );
    assert_eq!(follower.accounting(&mut backing).unwrap(), ledger);
    assert_eq!(backing.accounting().unwrap(), retained);
    assert_eq!(follower.status(&mut backing).unwrap().progress.records, 0);
    fixture
        .receive(&mut follower, &mut backing, target, 0, 5)
        .unwrap();
}

#[test]
fn authenticated_but_wrong_partial_prefix_never_becomes_complete_or_resets() {
    let fixture = Fixture::new(5);
    let mut backing = fixture.backing(limits());
    let mut follower = fixture.create(&mut backing, 5, limits());
    let target = fixture.target(5);
    let frames = [fixture.frames[0].as_frame(), fixture.frames[2].as_frame()];
    follower
        .receive(
            REMOTE,
            Page {
                checkpoint_id: target.id(),
                first: 1,
                last: 2,
                frames: &frames,
            },
            &mut backing,
        )
        .unwrap();
    assert_eq!(
        follower.status(&mut backing).unwrap().coverage,
        Coverage::Pending
    );
    assert!(fixture
        .receive(&mut follower, &mut backing, target, 2, 5)
        .is_err());
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    assert_eq!(follower.status(&mut backing).unwrap().progress.records, 2);
    assert_eq!(
        follower.status(&mut backing).unwrap().coverage,
        Coverage::Pending
    );
    assert!(fixture
        .receive(&mut follower, &mut backing, target, 0, 2)
        .is_err());
}

#[test]
fn faults_between_backing_and_progress_reconcile_exactly_after_reopen() {
    for point in [
        PublicationPoint::AfterBackingBatch,
        PublicationPoint::BeforePublish,
        PublicationPoint::AfterPublish,
    ] {
        let fixture = Fixture::new(21);
        let mut backing = fixture.backing(limits());
        let mut follower = fixture.create(&mut backing, 21, limits());
        let target = fixture.target(21);
        follower.fault = Some(point);
        assert_eq!(
            fixture.receive(&mut follower, &mut backing, target, 0, 21),
            Err(uncertain())
        );
        assert_eq!(follower.status(&mut backing), Err(uncertain()));
        assert_eq!(
            fixture.receive(&mut follower, &mut backing, target, 0, 21),
            Err(uncertain())
        );
        assert_eq!(
            backing.checkpoint().unwrap().records,
            if point == PublicationPoint::AfterBackingBatch {
                8
            } else {
                21
            }
        );
        drop(follower);
        let mut follower = fixture.open(&mut backing);
        assert_eq!(
            follower.status(&mut backing).unwrap().progress.records,
            if point == PublicationPoint::AfterPublish {
                21
            } else {
                0
            }
        );
        let result = fixture
            .receive(&mut follower, &mut backing, target, 0, 21)
            .unwrap();
        assert_eq!(result.exact_retry, point == PublicationPoint::AfterPublish);
        assert_eq!(result.status.coverage, Coverage::Complete);
        assert_eq!(follower.accounting(&mut backing).unwrap().records, 2);
        assert_eq!(backing.checkpoint().unwrap().records, 21);
    }
}

#[test]
fn source_epoch_rollbacks_forks_and_extension_faults_preserve_prior_evidence() {
    let fixture = Fixture::new(5);
    let mut backing = fixture.backing(limits());
    let mut follower = fixture.create(&mut backing, 3, limits());
    let initial = fixture.target(3);
    fixture
        .receive(&mut follower, &mut backing, initial, 0, 3)
        .unwrap();
    let before = follower.accounting(&mut backing).unwrap();
    for (target, expected) in [
        (
            Checkpoint {
                epoch: [70; 32],
                ..fixture.target(5)
            },
            vhalla_direct_sync::Error::Epoch,
        ),
        (
            Checkpoint {
                digest: [71; 32],
                ..initial
            },
            vhalla_direct_sync::Error::Fork,
        ),
        (fixture.target(2), vhalla_direct_sync::Error::Rollback),
        (
            Checkpoint {
                source: [72; 32],
                ..fixture.target(5)
            },
            vhalla_direct_sync::Error::Source,
        ),
        (
            Checkpoint {
                room: RoomId::from_bytes([73; 32]),
                ..fixture.target(5)
            },
            vhalla_direct_sync::Error::Room,
        ),
    ] {
        assert_eq!(
            follower.extend(REMOTE, target, &mut backing),
            Err(expected.into())
        );
    }
    assert_eq!(follower.accounting(&mut backing).unwrap(), before);
    follower.fault = Some(PublicationPoint::BeforePublish);
    assert_eq!(
        follower.extend(REMOTE, fixture.target(5), &mut backing),
        Err(uncertain())
    );
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    assert_eq!(follower.status(&mut backing).unwrap().target, initial);
    follower.fault = Some(PublicationPoint::AfterPublish);
    assert_eq!(
        follower.extend(REMOTE, fixture.target(5), &mut backing),
        Err(uncertain())
    );
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    let pending = follower.status(&mut backing).unwrap();
    assert_eq!(pending.target, fixture.target(5));
    assert_eq!(pending.progress.records, 3);
    assert_eq!(pending.coverage, Coverage::Pending);
    assert_eq!(
        follower
            .extend(REMOTE, fixture.target(5), &mut backing)
            .unwrap(),
        pending
    );
}

#[test]
fn replaced_or_rolled_back_backing_cannot_inherit_verified_progress() {
    let fixture = Fixture::new(7);
    let backing = fixture.backing(limits());
    drop(backing);
    let rollback_path = fixture.root.path().join("old-replica");
    copy_directory(&fixture.backing_path(), &rollback_path);
    let mut backing =
        Replica::open(fixture.backing_path(), fixture.genesis.clone(), LOCAL).unwrap();
    let mut follower = fixture.create(&mut backing, 7, limits());
    fixture
        .receive(&mut follower, &mut backing, fixture.target(7), 0, 7)
        .unwrap();
    let mut replacement = Replica::create_new(
        fixture.root.path().join("new-replica"),
        fixture.genesis.clone(),
        LOCAL,
        limits(),
    )
    .unwrap();
    assert_eq!(
        follower.status(&mut replacement),
        Err(FollowerError::Backing)
    );
    assert_eq!(follower.status(&mut backing), Err(uncertain()));
    drop(follower);
    assert!(matches!(
        Follower::open(
            fixture.path(),
            fixture.genesis.clone(),
            REMOTE,
            &mut replacement
        ),
        Err(FollowerError::Backing)
    ));
    let mut rollback = Replica::open(rollback_path, fixture.genesis.clone(), LOCAL).unwrap();
    assert_eq!(
        backing.checkpoint().unwrap().epoch,
        rollback.checkpoint().unwrap().epoch
    );
    assert!(matches!(
        Follower::open(
            fixture.path(),
            fixture.genesis.clone(),
            REMOTE,
            &mut rollback
        ),
        Err(FollowerError::Backing)
    ));
    let mut reopened = fixture.open(&mut backing);
    assert_eq!(reopened.status(&mut rollback), Err(FollowerError::Backing));
    assert_eq!(reopened.status(&mut backing), Err(uncertain()));
    drop(reopened);

    // Even a coherently lowered image floor cannot weaken the fresh proof
    // established by replay against all actual current backing frames.
    let target = fixture.target(7);
    let saved = Saved {
        backing: Backing::from_checkpoint(rollback.checkpoint().unwrap()),
        target,
        progress: Progress {
            records: target.records,
            bytes: target.bytes,
            digest: target.digest,
        },
        events: 2,
        bytes: 0,
    };
    let lowered_path = fixture.root.path().join("lowered-floor");
    let refs = fixture.refs(target, 0, 7);
    install_ledger(
        &lowered_path,
        saved,
        vec![
            target_record(target).unwrap(),
            Record::new(page_key(1), &refs.encode()).unwrap(),
        ],
    );
    let mut lowered =
        Follower::open(lowered_path, fixture.genesis.clone(), REMOTE, &mut backing).unwrap();
    assert_eq!(
        lowered.status(&mut backing).unwrap().backing_floor.records,
        7
    );
    assert_eq!(lowered.status(&mut rollback), Err(FollowerError::Backing));
    assert_eq!(
        fixture
            .open(&mut backing)
            .status(&mut backing)
            .unwrap()
            .coverage,
        Coverage::Complete
    );
}

fn install_ledger(path: &Path, mut saved: Saved, records: Vec<Record>) {
    let mut store = Store::create_new(
        path,
        context(saved.target.room, saved.target.source).unwrap(),
        limits(),
    )
    .unwrap();
    let mut previous = None;
    saved.events = 0;
    saved.bytes = 0;
    for record in records {
        saved.events += 1;
        saved.bytes += record.as_bytes().len() as u64;
        let image = encode_image(saved);
        store
            .publish(previous.as_deref(), &image, &[record])
            .unwrap();
        previous = Some(image);
    }
}

#[test]
fn forged_refs_targets_progress_and_missing_images_are_refused_without_repair() {
    let fixture = Fixture::new(5);
    let mut backing = fixture.backing(limits());
    append_all(&mut backing, &fixture.frames);
    let target = fixture.target(5);
    let template = Saved {
        backing: Backing::from_checkpoint(backing.checkpoint().unwrap()),
        target,
        progress: Progress {
            records: target.records,
            bytes: target.bytes,
            digest: target.digest,
        },
        events: 2,
        bytes: 0,
    };
    for case in 0..7 {
        let mut saved = template;
        let mut refs = fixture.refs(target, 0, 5);
        let mut recorded_target = target;
        match case {
            0 => refs.frames[2].hash = [74; 32],
            1 => refs.frames.swap(2, 3),
            2 => refs.checkpoint = [75; 32],
            3 => saved.progress.digest = [76; 32],
            4 => saved.target.epoch = [77; 32],
            5 => {
                recorded_target.digest = [78; 32];
                saved.target = recorded_target;
                refs.checkpoint = recorded_target.id();
            }
            6 => {
                refs.first = 2;
                refs.last = 6;
            }
            _ => unreachable!(),
        }
        let path = fixture.root.path().join(format!("forged-{case}"));
        install_ledger(
            &path,
            saved,
            vec![
                target_record(recorded_target).unwrap(),
                Record::new(page_key(refs.first), &refs.encode()).unwrap(),
            ],
        );
        assert!(Follower::open(&path, fixture.genesis.clone(), REMOTE, &mut backing).is_err());
        assert!(path.join("FORMAT").exists());
    }
    let path = fixture.root.path().join("missing-image");
    drop(Store::create_new(&path, context(target.room, REMOTE).unwrap(), limits()).unwrap());
    assert!(Follower::open(&path, fixture.genesis.clone(), REMOTE, &mut backing).is_err());
    assert!(path.join("FORMAT").exists());
}

#[test]
fn definite_ledger_quota_refusal_and_partial_backing_quota_have_distinct_recovery() {
    let fixture = Fixture::new(20);
    let mut backing = fixture.backing(Limits {
        max_records: 8,
        ..limits()
    });
    let mut follower = fixture.create(
        &mut backing,
        20,
        Limits {
            max_records: 1,
            ..limits()
        },
    );
    let target = fixture.target(20);
    let initial = follower.status(&mut backing).unwrap();
    assert_eq!(
        fixture.receive(&mut follower, &mut backing, target, 0, 20),
        Err(vhalla_direct_store::Error::Refused.into())
    );
    assert_eq!(follower.status(&mut backing).unwrap(), initial);
    assert_eq!(backing.checkpoint().unwrap().records, 1);
    let before = follower.accounting(&mut backing).unwrap();
    let expanded = follower.expand_limits(limits(), &mut backing).unwrap();
    assert_eq!(expanded.generation, before.generation);
    assert_eq!(expanded.records, before.records);
    assert!(follower
        .expand_limits(
            Limits {
                max_records: 1,
                ..limits()
            },
            &mut backing
        )
        .is_err());
    assert_eq!(follower.status(&mut backing).unwrap(), initial);
    assert_eq!(
        fixture.receive(&mut follower, &mut backing, target, 0, 20),
        Err(FollowerError::Replica(ReplicaError::Store(
            vhalla_direct_store::Error::Refused
        )))
    );
    assert_eq!(backing.checkpoint().unwrap().records, 8);
    assert_eq!(follower.status(&mut backing), Err(uncertain()));
    drop(follower);
    let mut follower = fixture.open(&mut backing);
    let reopened = follower.status(&mut backing).unwrap();
    assert_eq!(reopened.progress, initial.progress);
    assert_eq!(reopened.target, initial.target);
    assert_eq!(reopened.coverage, initial.coverage);
    assert_eq!(reopened.backing_floor.records, 8);
    backing.expand_limits(limits()).unwrap();
    assert_eq!(
        fixture
            .receive(&mut follower, &mut backing, target, 0, 20)
            .unwrap()
            .status
            .coverage,
        Coverage::Complete
    );
}

#[test]
fn creation_scope_lock_and_changed_live_image_are_checked() {
    let fixture = Fixture::new(3);
    let mut backing = fixture.backing(limits());
    let target = fixture.target(3);
    let absent = fixture.root.path().join("invalid");
    assert!(Follower::create_new(
        &absent,
        fixture.genesis.clone(),
        REMOTE,
        [79; 32],
        target,
        &mut backing,
        limits()
    )
    .is_err());
    assert!(!absent.exists());
    assert!(Follower::create_new(
        &absent,
        fixture.genesis.clone(),
        REMOTE,
        REMOTE,
        target,
        &mut backing,
        Limits {
            max_records: 0,
            ..limits()
        }
    )
    .is_err());
    assert!(!absent.exists());
    let mut follower = fixture.create(&mut backing, 3, limits());
    assert!(Follower::open(
        fixture.path(),
        fixture.genesis.clone(),
        REMOTE,
        &mut backing
    )
    .is_err());
    let mut changed = follower.saved;
    changed.progress.records = 1;
    follower
        .store
        .publish(Some(&follower.image), &encode_image(changed), &[])
        .unwrap();
    assert_eq!(follower.status(&mut backing), Err(corrupt()));
    assert_eq!(follower.status(&mut backing), Err(uncertain()));
    drop(follower);
    assert!(Follower::open(
        fixture.path(),
        fixture.genesis.clone(),
        REMOTE,
        &mut backing
    )
    .is_err());
    assert!(fixture.path().join("FORMAT").exists());
}

#[hegel::test(test_cases=64,suppress_health_check=[HealthCheck::TooSlow])]
fn interleaved_pages_retries_reopen_extensions_and_uncertainty(tc: hegel::TestCase) {
    let fixture = Fixture::new(24);
    let mut backing = fixture.backing(limits());
    let mut target_count = 8usize;
    let mut follower = fixture.create(&mut backing, target_count, limits());
    let mut position = 0usize;
    let mut last: Option<(Checkpoint, usize, usize)> = None;
    let steps = tc.draw(
        hegel::generators::integers::<usize>()
            .min_value(5)
            .max_value(16),
    );
    let mut ledger_limits = limits();
    for _ in 0..steps {
        let action = tc.draw(hegel::generators::integers::<u8>().max_value(6));
        let target = fixture.target(target_count);
        match action {
            0 if position < target_count => {
                let count = tc.draw(
                    hegel::generators::integers::<usize>()
                        .min_value(1)
                        .max_value(4),
                );
                let end = (position + count).min(target_count);
                fixture
                    .receive(&mut follower, &mut backing, target, position, end)
                    .unwrap();
                last = Some((target, position, end));
                position = end;
            }
            1 => {
                if let Some((target, start, end)) = last {
                    let before = follower.accounting(&mut backing).unwrap();
                    assert!(
                        fixture
                            .receive(&mut follower, &mut backing, target, start, end)
                            .unwrap()
                            .exact_retry
                    );
                    assert_eq!(follower.accounting(&mut backing).unwrap(), before);
                }
            }
            2 => {
                drop(follower);
                follower = fixture.open(&mut backing);
            }
            3 => {
                ledger_limits.max_records += 1;
                let status = follower.status(&mut backing).unwrap();
                follower.expand_limits(ledger_limits, &mut backing).unwrap();
                assert_eq!(follower.status(&mut backing).unwrap(), status);
            }
            4 if position < target_count => {
                let end = (position + 3).min(target_count);
                let after = tc.draw(hegel::generators::booleans());
                follower.fault = Some(if after {
                    PublicationPoint::AfterPublish
                } else {
                    PublicationPoint::BeforePublish
                });
                assert_eq!(
                    fixture.receive(&mut follower, &mut backing, target, position, end),
                    Err(uncertain())
                );
                drop(follower);
                follower = fixture.open(&mut backing);
                if after {
                    last = Some((target, position, end));
                    position = end;
                }
            }
            5 if position == target_count && target_count < 24 => {
                target_count = (target_count + 3).min(24);
                follower
                    .extend(REMOTE, fixture.target(target_count), &mut backing)
                    .unwrap();
            }
            _ => {
                let frames = [fixture.frames[0].as_frame()];
                assert!(follower
                    .receive(
                        [80; 32],
                        Page {
                            checkpoint_id: target.id(),
                            first: 1,
                            last: 1,
                            frames: &frames
                        },
                        &mut backing
                    )
                    .is_err());
            }
        }
        let status = follower.status(&mut backing).unwrap();
        assert_eq!(status.progress.records, position as u64);
        assert_eq!(status.target, fixture.target(target_count));
        assert_eq!(
            status.coverage,
            if position == target_count {
                Coverage::Complete
            } else {
                Coverage::Pending
            }
        );
    }
    drop(follower);
    assert_eq!(
        fixture
            .open(&mut backing)
            .status(&mut backing)
            .unwrap()
            .progress
            .records,
        position as u64
    );
}
