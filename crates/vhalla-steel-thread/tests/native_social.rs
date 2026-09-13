#![cfg(unix)]

//! A real native transport steel thread for the social evidence boundary.
//!
//! The QUIC adapter authenticates a short-lived application session. The
//! receiver still treats its body as inert bytes and performs social record
//! verification and bounded archive admission independently.

use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_native::{send_message, Event, Listener, Route};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, RecordState, View},
    *,
};

const REALM: RealmId = RealmId(45);

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn public(n: u8) -> [u8; 32] {
    key(n).verifying_key().to_bytes()
}

fn signed(body: Body) -> SignedRecord {
    UnsignedRecord::new(public(11), body)
        .unwrap()
        .sign_with_key(&key(11))
        .unwrap()
        .finish()
        .unwrap()
}

fn evidence() -> (Vec<SignedRecord>, OwnerId, RecordId) {
    let root = signed(Body::OwnerGenesis {
        controller: public(11),
        recovery: None,
        nonce: [17; 32],
    });
    let owner = OwnerId::from_bytes(*root.id().as_bytes());
    let post = signed(Body::Social {
        actor: Actor::Owner {
            owner,
            control: root.id(),
        },
        realm: REALM,
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new("native social evidence").unwrap(),
            reply: None,
            quote: None,
        },
    });
    let id = post.id();
    let seal = signed(Body::Control {
        owner,
        previous: root.id(),
        action: ControlAction::Seal {
            realm: REALM,
            heads: References::sorted(vec![id]).unwrap(),
        },
    });
    (vec![root, post, seal], owner, id)
}

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-steel-native-social-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn identity_path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_transport_delivers_only_independently_verified_social_evidence() {
    let temp = Temp::new();
    let sender_path = temp.identity_path("sender");
    let receiver_path = temp.identity_path("receiver");
    let sender = Identity::create_new(&sender_path).unwrap();
    let sender_key = sender.public_key();
    assert_ne!(sender_key, public(11));
    drop(sender);
    let receiver = Identity::create_new(&receiver_path).unwrap();
    let receiver_key = receiver.public_key();
    let mut listener = Listener::bind(receiver, sender_key).await.unwrap();
    let route = listener.route().clone();
    let (records, owner, post) = evidence();
    let mut forged = records[1].encode();
    assert_eq!(
        forged.last(),
        Some(&0),
        "post must have no acknowledgement proof"
    );
    let signature_byte = forged.len() - 2;
    forged[signature_byte] ^= 1;
    let bodies = [
        records[0].encode(),
        records[1].encode(),
        records[0].encode(),
        records[2].encode(),
        forged,
    ];
    let total = bodies.len();
    let expected = records.iter().map(SignedRecord::encode).collect::<Vec<_>>();
    let server = async move {
        let mut archive = Archive::new(REALM, Limits::default()).unwrap();
        let mut inserted = 0;
        let mut duplicates = 0;
        let mut invalid = 0;
        let mut messages = 0;
        let mut disconnected = 0;
        while messages < total || disconnected < total {
            match listener.next().await.expect("native listener failed") {
                Event::Joined(_) => {}
                Event::Message(message) => {
                    // The outer signer is the forwarding app, never the social owner.
                    assert_eq!(message.signer_key(), &sender_key);
                    let before = (archive.root(), archive.len());
                    let mut budget = Budget::new(1, MAX_RECORD_BYTES).unwrap();
                    match archive.ingest(message.envelope().body(), &mut budget) {
                        Ok(receipt) if receipt.inserted => inserted += 1,
                        Ok(_) => duplicates += 1,
                        Err(vhalla_social::Error::Signature) => {
                            assert_eq!((archive.root(), archive.len()), before);
                            invalid += 1;
                        }
                        Err(error) => panic!("unexpected inner social error: {error:?}"),
                    }
                    messages += 1;
                }
                Event::Rejected(error) => panic!("unexpected native rejection: {error:?}"),
                Event::Disconnected => disconnected += 1,
            }
        }
        (archive, inserted, duplicates, invalid)
    };
    let client = async move {
        for body in bodies {
            let identity = Identity::open(&sender_path).unwrap();
            let delivery = send_message(identity, receiver_key, route.clone(), &body).await?;
            assert_eq!(*delivery.acknowledgment().signer_key(), receiver_key);
            assert_ne!(delivery.digest(), &[0; 32]);
        }
        Ok::<(), vhalla_native::Error>(())
    };
    let ((archive, inserted, duplicates, invalid), client_result) =
        tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(server, client)
        })
        .await
        .expect("native social steel thread timed out");
    client_result.expect("native client failed");

    assert_eq!((inserted, duplicates, invalid), (3, 1, 1));
    assert_eq!(archive.len(), 3);
    let eligibility = Eligibility::default();
    let view = View::new(&archive, 0, &eligibility);
    assert_eq!(view.state(post), Some(RecordState::Committed));
    assert_eq!(view.post(post).unwrap().attribution.owner, owner);
    assert!(archive.get(records[2].id()).is_some());
    assert!(expected.iter().all(|raw| raw.len() <= MAX_RECORD_BYTES));
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex value has odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
            let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
            ((high << 4) | low) as u8
        })
        .collect()
}

fn publish(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)
}

fn child_paths(temp: &Temp, generation: usize) -> (PathBuf, PathBuf) {
    (
        temp.identity_path(&format!("route-{generation}")),
        temp.identity_path(&format!("evidence-{generation}")),
    )
}

fn spawn_receiver(
    receiver_path: &Path,
    sender_key: [u8; 32],
    route_path: &Path,
    evidence_path: &Path,
    expected_messages: usize,
) -> Child {
    let executable = std::env::current_exe().expect("current test executable");
    Command::new(executable)
        .arg("--ignored")
        .arg("--exact")
        .arg("child_receiver")
        .arg("--nocapture")
        .env("VHALLA_CHILD_RECEIVER", receiver_path)
        .env("VHALLA_CHILD_SENDER_KEY", hex_encode(&sender_key))
        .env("VHALLA_CHILD_ROUTE", route_path)
        .env("VHALLA_CHILD_EVIDENCE", evidence_path)
        .env("VHALLA_CHILD_MESSAGES", expected_messages.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn native receiver child")
}

async fn wait_for_route(path: &Path) -> Route {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(raw) = fs::read_to_string(path) {
            let mut lines = raw.lines();
            let (Some(address), Some(expiry)) = (lines.next(), lines.next()) else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            let Ok(expires_at) = expiry.parse::<u64>() else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            if let Ok(route) = Route::parse(address, expires_at) {
                return route;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "receiver child did not publish a route"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_child(mut child: Child, evidence_path: &Path) -> String {
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .expect("join receiver child wait")
        .expect("wait receiver child");
    assert!(status.success(), "receiver child exited with {status}");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(raw) = fs::read_to_string(evidence_path) {
                return raw;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("receiver child did not publish evidence")
}

fn ingest_child_evidence(
    archive: &mut Archive,
    raw: &str,
    sender_key: [u8; 32],
) -> (usize, usize, usize) {
    let mut lines = raw.lines();
    let expected_sender = hex_encode(&sender_key);
    assert_eq!(lines.next(), Some(expected_sender.as_str()));
    let mut inserted = 0;
    let mut duplicates = 0;
    let mut invalid = 0;
    for line in lines {
        let body = hex_decode(line);
        let before = (archive.root(), archive.len());
        let mut budget = Budget::new(1, MAX_RECORD_BYTES).unwrap();
        match archive.ingest(&body, &mut budget) {
            Ok(receipt) if receipt.inserted => inserted += 1,
            Ok(_) => duplicates += 1,
            Err(vhalla_social::Error::Signature) => {
                assert_eq!((archive.root(), archive.len()), before);
                invalid += 1;
            }
            Err(error) => panic!("unexpected inner social error: {error:?}"),
        }
    }
    (inserted, duplicates, invalid)
}

/// Child-process helper for `native_transport_restarts_without_conflating_outer_and_inner_keys`.
/// It is invoked by the parent test with `--ignored --exact`; normal test runs never execute it.
#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn child_receiver() {
    let Some(receiver_path) = std::env::var_os("VHALLA_CHILD_RECEIVER") else {
        return;
    };
    let sender_key =
        hex_decode(&std::env::var("VHALLA_CHILD_SENDER_KEY").expect("child sender key"));
    let sender_key: [u8; 32] = sender_key.try_into().expect("sender key length");
    let route_path =
        PathBuf::from(std::env::var_os("VHALLA_CHILD_ROUTE").expect("child route path"));
    let evidence_path =
        PathBuf::from(std::env::var_os("VHALLA_CHILD_EVIDENCE").expect("child evidence path"));
    let expected_messages = std::env::var("VHALLA_CHILD_MESSAGES")
        .expect("child message count")
        .parse::<usize>()
        .expect("child message count integer");
    let receiver = Identity::open(receiver_path).expect("open receiver identity");
    let receiver_key = receiver.public_key();
    let mut listener = Listener::bind(receiver, sender_key)
        .await
        .expect("bind child receiver");
    let route = listener.route().clone();
    publish(
        &route_path,
        format!(
            "{}\n{}\n{}\n",
            route.address(),
            route.expires_at(),
            hex_encode(&receiver_key)
        ),
    )
    .expect("publish child route");

    let mut evidence = vec![hex_encode(&sender_key)];
    let mut messages = 0;
    while messages < expected_messages {
        match listener.next().await.expect("child listener failed") {
            Event::Joined(_) | Event::Disconnected => {}
            Event::Message(message) => {
                assert_eq!(message.signer_key(), &sender_key);
                evidence.push(hex_encode(message.envelope().body()));
                messages += 1;
            }
            Event::Rejected(error) => panic!("unexpected child rejection: {error:?}"),
        }
    }
    // `Listener::next` queues the acknowledgment before yielding Message, but
    // the child must keep polling until the final client connection closes so
    // that the response actually leaves this process before exit.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(
                listener.next().await.expect("child listener failed"),
                Event::Disconnected
            ) {
                break;
            }
        }
    })
    .await
    .expect("final child connection did not close after acknowledgment");
    publish(&evidence_path, evidence.join("\n") + "\n").expect("publish child evidence");
}

#[tokio::test(flavor = "current_thread")]
async fn native_transport_restarts_without_conflating_outer_and_inner_keys() {
    let temp = Temp::new();
    let sender_path = temp.identity_path("sender");
    let receiver_path = temp.identity_path("receiver");
    let sender = Identity::create_new(&sender_path).unwrap();
    let sender_key = sender.public_key();
    drop(sender);
    let receiver = Identity::create_new(&receiver_path).unwrap();
    let receiver_key = receiver.public_key();
    drop(receiver);
    let (records, owner, post) = evidence();
    let forged = {
        let mut raw = records[1].encode();
        let signature_byte = raw.len() - 2;
        raw[signature_byte] ^= 1;
        raw
    };

    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let (route1_path, evidence1_path) = child_paths(&temp, 1);
    let child1 = spawn_receiver(&receiver_path, sender_key, &route1_path, &evidence1_path, 3);
    let route1 = wait_for_route(&route1_path).await;
    for record in &records {
        let identity = Identity::open(&sender_path).unwrap();
        let delivery = send_message(identity, receiver_key, route1.clone(), &record.encode())
            .await
            .expect("send first receiver evidence");
        assert_eq!(*delivery.acknowledgment().signer_key(), receiver_key);
    }
    let raw1 = wait_for_child(child1, &evidence1_path).await;
    assert_eq!(raw1.lines().count(), 4);
    assert_eq!(
        ingest_child_evidence(&mut archive, &raw1, sender_key),
        (3, 0, 0)
    );
    assert_eq!(archive.len(), 3);

    // Restart the listener process with the same identity. Its app key remains
    // stable, while the new route/session is independent of the first process.
    let (route2_path, evidence2_path) = child_paths(&temp, 2);
    let child2 = spawn_receiver(&receiver_path, sender_key, &route2_path, &evidence2_path, 2);
    let route2 = wait_for_route(&route2_path).await;
    let identity = Identity::open(&sender_path).unwrap();
    let delivery = send_message(identity, receiver_key, route2.clone(), &records[0].encode())
        .await
        .expect("send duplicate after receiver restart");
    assert_eq!(*delivery.acknowledgment().signer_key(), receiver_key);
    let identity = Identity::open(&sender_path).unwrap();
    let delivery = send_message(identity, receiver_key, route2, &forged)
        .await
        .expect("send forged inner evidence after receiver restart");
    assert_eq!(*delivery.acknowledgment().signer_key(), receiver_key);
    let raw2 = wait_for_child(child2, &evidence2_path).await;
    let route1_receiver_key = fs::read_to_string(&route1_path)
        .unwrap()
        .lines()
        .nth(2)
        .unwrap()
        .to_owned();
    let route2_receiver_key = fs::read_to_string(&route2_path)
        .unwrap()
        .lines()
        .nth(2)
        .unwrap()
        .to_owned();
    assert_eq!(route1_receiver_key, route2_receiver_key);
    assert_eq!(
        ingest_child_evidence(&mut archive, &raw2, sender_key),
        (0, 1, 1)
    );
    assert_eq!(archive.len(), 3);
    let eligibility = Eligibility::default();
    let view = View::new(&archive, 0, &eligibility);
    assert_eq!(view.state(post), Some(RecordState::Committed));
    assert_eq!(view.post(post).unwrap().attribution.owner, owner);
}
