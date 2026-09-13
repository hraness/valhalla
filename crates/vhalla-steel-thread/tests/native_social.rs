#![cfg(unix)]

//! A real native transport steel thread for the social evidence boundary.
//!
//! The QUIC adapter authenticates a short-lived application session. The
//! receiver still treats its body as inert bytes and performs social record
//! verification and bounded archive admission independently.

use ed25519_dalek::SigningKey;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};
use vhalla_core::RealmId;
use vhalla_identity::Identity;
use vhalla_native::{send_message, Event, Listener};
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
