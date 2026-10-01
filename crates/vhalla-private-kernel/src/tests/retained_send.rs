use super::*;
use std::cell::Cell;

#[test]
fn exact_send_lookup_survives_epoch_change_removal_and_reopen_without_writes() {
    block_on(async {
        let mut pair = joined().await;
        let owner_binding = pair.owner.status();
        let member_binding = pair.member.status();
        let owner_sent = pair
            .owner
            .test_send(op(50), b"owner original", pair.now)
            .await
            .unwrap();
        let member_sent = pair
            .member
            .test_send(op(50), b"member original", pair.now)
            .await
            .unwrap();
        let removal = pair
            .owner
            .remove(op(51), member_binding.context.device, pair.now)
            .await
            .unwrap();
        pair.member
            .apply_control(removal.bytes(), pair.now)
            .await
            .unwrap();
        assert_ne!(pair.owner.status().epoch, owner_binding.epoch);
        assert_ne!(pair.owner.status().roster, owner_binding.roster);
        assert_eq!(pair.member.status().phase, Phase::Removed);
        pair.reopen_owner().await;
        pair.reopen_member().await;
        let owner_before = pair.owner_disk.snapshot();
        let member_before = pair.member_disk.snapshot();
        let owner = pair
            .owner
            .retained_send(
                op(50),
                owner_binding.epoch,
                owner_binding.roster,
                b"owner original",
            )
            .await
            .unwrap()
            .unwrap();
        let member = pair
            .member
            .retained_send(
                op(50),
                member_binding.epoch,
                member_binding.roster,
                b"member original",
            )
            .await
            .unwrap()
            .unwrap();
        for (retained, original) in [(&owner, &owner_sent), (&member, &member_sent)] {
            assert_eq!(retained.operation(), original.operation());
            assert_eq!(retained.sequence(), original.sequence());
            assert_eq!(retained.kind(), original.kind());
            assert_eq!(retained.bytes(), original.bytes());
        }
        assert!(pair.owner_disk.snapshot() == owner_before);
        assert!(pair.member_disk.snapshot() == member_before);
        assert!(pair
            .member
            .prepare_message(b"no renewed authority")
            .is_err());
    });
}

#[test]
fn lookup_refuses_changed_intent_and_non_application_operations_without_spending_ids() {
    block_on(async {
        let mut pair = joined().await;
        let binding = pair.owner.status();
        pair.owner
            .test_send(op(50), b"original", pair.now)
            .await
            .unwrap();
        let before = pair.owner_disk.snapshot();
        let mut other_roster = binding.roster;
        other_roster[0] ^= 1;
        for (operation, epoch, roster, body) in [
            (op(50), binding.epoch, binding.roster, b"changed".as_slice()),
            (
                op(50),
                binding.epoch + 1,
                binding.roster,
                b"original".as_slice(),
            ),
            (op(50), binding.epoch, other_roster, b"original".as_slice()),
            // The existing invitation uses this ID; it must not become a send.
            (op(1), binding.epoch, binding.roster, b"original".as_slice()),
        ] {
            assert!(matches!(
                pair.owner
                    .retained_send(operation, epoch, roster, body)
                    .await,
                Err(Error::Conflict)
            ));
            assert!(!pair.owner.needs_reopen());
        }
        assert!(pair
            .owner
            .retained_send(op(51), binding.epoch, binding.roster, b"new")
            .await
            .unwrap()
            .is_none());
        for body in [Vec::new(), vec![0; MAX_BODY_BYTES + 1]] {
            assert!(matches!(
                pair.owner
                    .retained_send(op(51), binding.epoch, binding.roster, &body)
                    .await,
                Err(Error::Bounds)
            ));
        }
        assert!(pair.owner_disk.snapshot() == before);
        let sent = pair
            .owner
            .test_send(op(51), b"new", pair.now)
            .await
            .unwrap();
        assert_eq!(
            pair.member
                .receive(sent.bytes(), pair.now)
                .await
                .unwrap()
                .body(),
            b"new"
        );
    });
}

#[test]
fn missing_or_tampered_published_lookup_never_becomes_an_absent_operation() {
    block_on(async {
        for (lookup, remove) in [(true, true), (false, true), (true, false), (false, false)] {
            let mut pair = joined().await;
            let binding = pair.owner.status();
            let sent = pair
                .owner
                .test_send(op(50), b"retained evidence", pair.now)
                .await
                .unwrap();
            let record_key = if lookup {
                RecordKey::Operation(op(50))
            } else {
                RecordKey::Outbox(sent.sequence())
            };
            {
                let mut disk = pair.owner_disk.0.borrow_mut();
                if remove {
                    disk.records.remove(&record_key);
                } else {
                    let record = disk.records.get(&record_key).unwrap();
                    let mut bytes = record.as_bytes().to_vec();
                    *bytes.last_mut().unwrap() ^= 1;
                    disk.records.insert(
                        record_key,
                        StoredRecord::from_bytes(record_key, &bytes).unwrap(),
                    );
                }
            }
            let damaged = pair.owner_disk.snapshot();
            assert!(pair
                .owner
                .retained_send(op(50), binding.epoch, binding.roster, b"retained evidence")
                .await
                .is_err());
            assert!(pair.owner_disk.snapshot() == damaged);
        }
    });
}

#[test]
fn lookup_rechecks_the_authoritative_image_before_returning_a_known_send() {
    block_on(async {
        let mut pair = joined().await;
        let binding = pair.owner.status();
        pair.owner
            .test_send(op(50), b"retained", pair.now)
            .await
            .unwrap();
        let mut stale = Kernel::open(pair.owner_disk.clone(), &pair.owner_key, binding.context)
            .await
            .unwrap();
        pair.owner
            .test_send(op(51), b"advanced", pair.now)
            .await
            .unwrap();
        let before = pair.owner_disk.snapshot();
        assert!(matches!(
            stale
                .retained_send(op(50), binding.epoch, binding.roster, b"retained")
                .await,
            Err(Error::Conflict)
        ));
        assert!(stale.needs_reopen());
        assert!(pair.owner_disk.snapshot() == before);
    });
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReadFault {
    None,
    WaitLoad,
    WaitOperation,
    WaitOutbox,
    UncertainLoad,
    UncertainOperation,
}

struct ReadProbe {
    inner: Memory,
    fault: Rc<Cell<ReadFault>>,
}
impl Store for ReadProbe {
    async fn load(&mut self, context: Context) -> std::result::Result<Option<Image>, StoreError> {
        match self.fault.get() {
            ReadFault::WaitLoad => std::future::pending().await,
            ReadFault::UncertainLoad => Err(StoreError::Uncertain),
            _ => self.inner.load(context).await,
        }
    }
    async fn read(
        &mut self,
        context: Context,
        key: RecordKey,
    ) -> std::result::Result<Option<StoredRecord>, StoreError> {
        match (self.fault.get(), key) {
            (ReadFault::WaitOperation, RecordKey::Operation(_))
            | (ReadFault::WaitOutbox, RecordKey::Outbox(_)) => std::future::pending().await,
            (ReadFault::UncertainOperation, RecordKey::Operation(_)) => Err(StoreError::Uncertain),
            _ => self.inner.read(context, key).await,
        }
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> std::result::Result<(), StoreError> {
        self.inner.publish(context, expected, next, records).await
    }
}

#[test]
fn cancelling_a_read_does_not_fence_kernel_or_change_retained_state() {
    block_on(async {
        for interrupted in [
            ReadFault::WaitLoad,
            ReadFault::WaitOperation,
            ReadFault::WaitOutbox,
        ] {
            let mut pair = joined().await;
            let binding = pair.owner.status();
            let sent = pair
                .owner
                .test_send(op(50), b"retained", pair.now)
                .await
                .unwrap();
            let before = pair.owner_disk.snapshot();
            let fault = Rc::new(Cell::new(ReadFault::None));
            let mut kernel = Kernel::open(
                ReadProbe {
                    inner: pair.owner_disk.clone(),
                    fault: fault.clone(),
                },
                &pair.owner_key,
                binding.context,
            )
            .await
            .unwrap();
            fault.set(interrupted);
            {
                let pending =
                    kernel.retained_send(op(50), binding.epoch, binding.roster, b"retained");
                futures::pin_mut!(pending);
                assert!(futures::poll!(pending).is_pending());
            }
            fault.set(ReadFault::None);
            assert!(!kernel.needs_reopen());
            assert!(pair.owner_disk.snapshot() == before);
            assert_eq!(
                kernel
                    .retained_send(op(50), binding.epoch, binding.roster, b"retained")
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes(),
                sent.bytes()
            );
            assert!(pair.owner_disk.snapshot() == before);
            let draft = kernel.prepare_message(b"still writable").unwrap();
            let next = kernel.send(op(51), &draft, pair.now).await.unwrap();
            assert_eq!(
                pair.member
                    .receive(next.bytes(), pair.now)
                    .await
                    .unwrap()
                    .body(),
                b"still writable"
            );
        }
    });
}

#[test]
fn read_uncertainty_refuses_output_and_explicit_reopen_recovers_exact_send() {
    block_on(async {
        for failure in [ReadFault::UncertainLoad, ReadFault::UncertainOperation] {
            let mut pair = joined().await;
            let binding = pair.owner.status();
            let sent = pair
                .owner
                .test_send(op(50), b"retained", pair.now)
                .await
                .unwrap();
            let before = pair.owner_disk.snapshot();
            let fault = Rc::new(Cell::new(ReadFault::None));
            let mut kernel = Kernel::open(
                ReadProbe {
                    inner: pair.owner_disk.clone(),
                    fault: fault.clone(),
                },
                &pair.owner_key,
                binding.context,
            )
            .await
            .unwrap();
            fault.set(failure);
            assert!(matches!(
                kernel
                    .retained_send(op(50), binding.epoch, binding.roster, b"retained")
                    .await,
                Err(Error::NeedsReopen)
            ));
            assert!(pair.owner_disk.snapshot() == before);
            drop(kernel);
            pair.reopen_owner().await;
            assert_eq!(
                pair.owner
                    .retained_send(op(50), binding.epoch, binding.roster, b"retained")
                    .await
                    .unwrap()
                    .unwrap()
                    .bytes(),
                sent.bytes()
            );
            assert!(pair.owner_disk.snapshot() == before);
        }
    });
}
