//! Interleaved three-device delivery over a positional mailbox (C1/C9).
//! Messages and owner controls are emitted into one ordered mailbox; each
//! device delivers from its own cursor. Refusals must stay typed, leave no
//! effects, and never latch the session.
use super::*;
use hegel::{generators as gs, TestCase};

enum Item {
    Control {
        targets: [bool; 3],
        bytes: Vec<u8>,
    },
    Message {
        emitter: usize,
        wire: Vec<u8>,
        body: Vec<u8>,
    },
}

struct World {
    pair: Pair,
    third: Kernel<Memory>,
    third_disk: Memory,
    mailbox: Vec<Item>,
    cursors: [usize; 3],
    operation: u64,
}

impl World {
    fn device(&mut self, index: usize) -> &mut Kernel<Memory> {
        match index {
            0 => &mut self.pair.owner,
            1 => &mut self.pair.member,
            _ => &mut self.third,
        }
    }
    fn disk(&self, index: usize) -> &Memory {
        match index {
            0 => &self.pair.owner_disk,
            1 => &self.pair.member_disk,
            _ => &self.third_disk,
        }
    }
    fn operation(&mut self) -> OperationId {
        self.operation += 1;
        op(self.operation)
    }
    async fn send(&mut self, emitter: usize, body: Vec<u8>) {
        let operation = self.operation();
        let now = self.pair.now;
        let sent = self
            .device(emitter)
            .test_send(operation, &body, now)
            .await
            .unwrap();
        self.mailbox.push(Item::Message {
            emitter,
            wire: sent.bytes().to_vec(),
            body,
        });
    }
    async fn renew(&mut self) {
        let floor = self.pair.owner.status().control_floor;
        // Each renewal must extend the owner's enrollment expiry.
        let horizon = self.pair.now + 7200 + 3600 * self.operation;
        let enrollment = renewal(&self.pair, Validity::new(self.pair.now, horizon).unwrap());
        let operation = self.operation();
        self.pair
            .owner
            .renew_owner(operation, enrollment, self.pair.now)
            .await
            .unwrap();
        let page = self.pair.owner.encrypted_controls(floor, 1).await.unwrap();
        assert_eq!(page.records.len(), 1);
        self.mailbox.push(Item::Control {
            targets: [false, true, true],
            bytes: page.records[0].bytes().to_vec(),
        });
    }
    async fn deliver(&mut self, receiver: usize) {
        let mut index = self.cursors[receiver];
        loop {
            let Some(item) = self.mailbox.get(index) else {
                self.cursors[receiver] = self.mailbox.len();
                return;
            };
            let deliver = match item {
                Item::Control { targets, .. } => targets[receiver],
                Item::Message { emitter, .. } => *emitter != receiver,
            };
            if deliver {
                break;
            }
            index += 1;
        }
        let now = self.pair.now;
        let disk = self.disk(receiver).clone();
        let before = disk.snapshot();
        let terminal = match self.mailbox.get(index).unwrap() {
            Item::Control { bytes, .. } => {
                let bytes = bytes.clone();
                let kernel = self.device(receiver);
                match kernel.apply_control(&bytes, now).await {
                    Ok(_) => true,
                    Err(error) => {
                        assert!(!kernel.needs_reopen());
                        assert!(disk.snapshot() == before);
                        match error {
                            // Per-receiver order cannot produce a real gap,
                            // but a transient gap must stay unlatched too.
                            Error::ControlGap => false,
                            other => panic!("unexpected control refusal: {other:?}"),
                        }
                    }
                }
            }
            Item::Message { wire, body, .. } => {
                let wire = wire.clone();
                let body = body.clone();
                let kernel = self.device(receiver);
                match kernel.receive(&wire, now).await {
                    Ok(received) => {
                        assert_eq!(received.body(), body.as_slice());
                        true
                    }
                    Err(error) => {
                        assert!(!kernel.needs_reopen());
                        assert!(disk.snapshot() == before);
                        match error {
                            // Terminal for this item: the receiver keeps going.
                            Error::StaleEpoch | Error::RatchetGap { past: true } => true,
                            // Transient: apply the pending control first, retry.
                            Error::FutureEpoch
                            | Error::ControlGap
                            | Error::RatchetGap { past: false } => false,
                            other => panic!("unexpected receive refusal: {other:?}"),
                        }
                    }
                }
            }
        };
        self.cursors[receiver] = if terminal { index + 1 } else { index };
    }
}

#[hegel::test(test_cases = 64)]
fn interleaved_controls_and_messages_stay_typed_and_unlatched(tc: TestCase) {
    block_on(async {
        let mut pair = joined().await;
        let (mut third, third_disk, _) = pending_device(&pair, &account()).await;
        let join_control = add_device(&mut pair, &mut third, 10).await;
        let mut world = World {
            pair,
            third,
            third_disk,
            mailbox: vec![Item::Control {
                // The owner holds it; the join already carried it for `third`.
                targets: [false, true, false],
                bytes: join_control,
            }],
            cursors: [0; 3],
            operation: 20,
        };
        let steps = tc.draw(gs::integers::<usize>().max_value(23)) + 1;
        for _ in 0..steps {
            match tc.draw(gs::integers::<u8>().max_value(3)) {
                0 => world.send(0, b"owner".to_vec()).await,
                1 => {
                    let member = tc.draw(gs::integers::<u8>().max_value(1)) as usize + 1;
                    world.send(member, b"member".to_vec()).await
                }
                2 => world.renew().await,
                _ => {
                    let receiver = tc.draw(gs::integers::<u8>().max_value(2)) as usize;
                    world.deliver(receiver).await;
                }
            }
        }
    });
}
