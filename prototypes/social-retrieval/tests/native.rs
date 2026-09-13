#![cfg(unix)]
#![forbid(unsafe_code)]
//! Real loopback QUIC sessions; no synthetic VerifiedEnvelope constructor.
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use vhalla_core::{Epoch, RealmId, RoomId};
use vhalla_crypto::VerifiedEnvelope;
use vhalla_discovery::{DiscoveryState, Filters, Query};
use vhalla_identity::Identity;
use vhalla_native::{send_message, Event, Listener};
use vhalla_retrieval::{ChannelScope, Error, Provider, Request, Round};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, RecordState, View},
    *,
};

const REALM: RealmId = RealmId(53);
fn channel() -> ChannelScope {
    ChannelScope {
        realm: RealmId(1),
        room: RoomId(2),
        epoch: Epoch(1),
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-retrieval-native-{:032x}",
            u128::from_be_bytes(nonce)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn create(path: &Path) -> [u8; 32] {
    Identity::create_new(path).unwrap().public_key()
}

async fn transfer(sender: &Path, receiver: &Path, body: &[u8]) -> VerifiedEnvelope {
    let sender = Identity::open(sender).unwrap();
    let receiver = Identity::open(receiver).unwrap();
    let sender_pin = sender.public_key();
    let receiver_pin = receiver.public_key();
    let mut listener = Listener::bind(receiver, sender_pin).await.unwrap();
    let send = send_message(sender, receiver_pin, listener.route().clone(), body);
    tokio::pin!(send);
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut received = None;
        loop {
            tokio::select! {
                result = &mut send => {
                    let delivery = result.unwrap();
                    assert_eq!(*delivery.acknowledgment().signer_key(), receiver_pin);
                    return received.expect("signed message observed before its acknowledgment");
                },
                event = listener.next() => match event.unwrap() {
                    Event::Message(message) => { assert!(received.is_none()); assert_eq!(*message.signer_key(), sender_pin); received = Some(*message); },
                    Event::Joined(_) => {},
                    Event::Rejected(error) => panic!("unexpected paired transport rejection: {error}"),
                    Event::Disconnected => {},
                }
            }
        }
    }).await.expect("bounded paired exchange")
}
fn signed(key: &SigningKey, body: Body, ack: Option<&SigningKey>) -> SignedRecord {
    let draft = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap();
    match ack {
        Some(ack) => draft.countersign(ack).unwrap(),
        None => draft.finish().unwrap(),
    }
}
fn add(archive: &mut Archive, record: &SignedRecord) {
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
}
struct Corpus {
    archive: Archive,
    owner: OwnerId,
    actor: Actor,
    owner_key: SigningKey,
    agent_key: SigningKey,
    seal: RecordId,
    reference: PostRef,
    genesis: SignedRecord,
}
fn corpus() -> Corpus {
    let owner_key = SigningKey::from_bytes(&[21; 32]);
    let agent_key = SigningKey::from_bytes(&[22; 32]);
    let genesis = signed(
        &owner_key,
        Body::OwnerGenesis {
            controller: owner_key.verifying_key().to_bytes(),
            recovery: None,
            nonce: [21; 32],
        },
        None,
    );
    let owner = OwnerId::from_bytes(*genesis.id().as_bytes());
    let agent = signed(
        &owner_key,
        Body::AgentGenesis {
            owner,
            control: genesis.id(),
            key: agent_key.verifying_key().to_bytes(),
            nonce: [22; 32],
        },
        Some(&agent_key),
    );
    let grant = signed(
        &owner_key,
        Body::Control {
            owner,
            previous: genesis.id(),
            action: ControlAction::Grant {
                agent: AgentId::from_bytes(*agent.id().as_bytes()),
                realm: REALM,
                rights: Rights::ALL,
                expires_at: u64::MAX,
                nonce: [23; 32],
            },
        },
        None,
    );
    let actor = Actor::Agent {
        owner,
        agent: AgentId::from_bytes(*agent.id().as_bytes()),
        grant: grant.id(),
    };
    let post = signed(
        &agent_key,
        Body::Social {
            actor,
            realm: REALM,
            sequence: 0,
            previous: None,
            operation: Operation::PostFaceted {
                placement: Placement::Profile,
                content: FacetedText::new(
                    Text::new("rust #Rust café").unwrap(),
                    vec![Facet {
                        start: 5,
                        end: 10,
                        kind: FacetKind::Tag(CanonicalTag::new("rust").unwrap()),
                    }],
                )
                .unwrap(),
                reply: None,
                quote: None,
            },
        },
        None,
    );
    let reference = PostRef {
        post: post.id(),
        revision: post.id(),
    };
    let seal = signed(
        &owner_key,
        Body::Control {
            owner,
            previous: grant.id(),
            action: ControlAction::Seal {
                realm: REALM,
                heads: References::sorted(vec![post.id()]).unwrap(),
            },
        },
        None,
    );
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    for record in [&genesis, &agent, &grant, &post, &seal] {
        add(&mut archive, record);
    }
    Corpus {
        archive,
        owner,
        actor,
        owner_key,
        agent_key,
        seal: seal.id(),
        reference,
        genesis,
    }
}
// Corrupt a valid encoded response's exact hint and one complete signed record,
// then send those malicious bytes inside a legitimately authenticated channel.
fn poison(mut response: Vec<u8>) -> Vec<u8> {
    assert_eq!(&response[..8], b"VHRTR\0\0\x01");
    let hints = usize::from(u16::from_be_bytes(response[59..61].try_into().unwrap()));
    assert_eq!(hints, 1);
    response[61..125].fill(0xff);
    let count_at = 61 + hints * 64;
    assert!(u16::from_be_bytes(response[count_at..count_at + 2].try_into().unwrap()) > 0);
    let len_at = count_at + 2;
    let len = usize::from(u16::from_be_bytes(
        response[len_at..len_at + 2].try_into().unwrap(),
    ));
    response[len_at + 2 + len - 2] ^= 1;
    response
}

#[tokio::test(flavor = "current_thread")]
async fn paired_native_retrieval_hydrates_filters_rejects_poison_and_applies_late_controls() {
    let temp = Temp::new();
    let requester_path = temp.0.join("requester");
    let provider_path = temp.0.join("provider");
    let requester_pin = create(&requester_path);
    let provider_pin = create(&provider_path);
    let mut corpus = corpus();
    let mut local = Archive::new(REALM, Limits::default()).unwrap();
    add(&mut local, &corpus.genesis);
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).unwrap();
    let request = Request::new(
        nonce,
        REALM,
        Query::parse("rust").unwrap(),
        Some(CanonicalTag::new("rust").unwrap()),
        vec![corpus.genesis.id()],
    )
    .unwrap();
    let received = transfer(&requester_path, &provider_path, &request.encode()).await;
    assert!(Request::from_message(&received, provider_pin, channel(), now()).is_err());
    assert!(Request::from_message(
        &received,
        requester_pin,
        ChannelScope {
            room: RoomId(99),
            ..channel()
        },
        now()
    )
    .is_err());
    let decoded = Request::from_message(&received, requester_pin, channel(), now()).unwrap();
    let mut provider = Provider::new(decoded);
    let mut round = Round::new(request.clone(), vec![provider_pin], channel()).unwrap();
    let response = provider.next(&corpus.archive, corpus.owner, now()).unwrap();
    assert_eq!(response.hints(), &[corpus.reference]);
    let response = transfer(&provider_path, &requester_path, &poison(response.encode())).await;
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 1;
    let mut foreign = Round::new(
        Request::new(
            wrong_nonce,
            REALM,
            Query::parse("rust").unwrap(),
            None,
            vec![],
        )
        .unwrap(),
        vec![provider_pin],
        channel(),
    )
    .unwrap();
    let before = local.snapshot();
    assert_eq!(
        foreign.receive(&response, &mut local, now()),
        Err(Error::Context)
    );
    assert_eq!(local.snapshot(), before);
    round.receive(&response, &mut local, now()).unwrap();
    assert!(round.stats(provider_pin).unwrap().failures > 0);
    assert!(round
        .candidates(
            &local,
            now(),
            corpus.owner,
            &DiscoveryState::new([0; 32]),
            Filters::default()
        )
        .unwrap()
        .references
        .is_empty());
    for _ in 0..2 {
        let response = provider.next(&corpus.archive, corpus.owner, now()).unwrap();
        let received = transfer(&provider_path, &requester_path, &response.encode()).await;
        round.receive(&received, &mut local, now()).unwrap();
    }
    let state = DiscoveryState::new([0; 32]);
    let found = round
        .candidates(&local, now(), corpus.owner, &state, Filters::default())
        .unwrap();
    assert_eq!(found.references, vec![corpus.reference]);
    assert!(!found.network_complete);
    assert_eq!(found.unresolved, 1);
    let filtered = round
        .candidates(
            &local,
            now(),
            corpus.owner,
            &state,
            Filters {
                owner: Some(OwnerId::from_bytes([0; 32])),
                ..Filters::default()
            },
        )
        .unwrap();
    assert!(filtered.references.is_empty());
    assert!(round.stats(provider_pin).unwrap().duplicates > 0);

    let provisional = signed(
        &corpus.agent_key,
        Body::Social {
            actor: corpus.actor,
            realm: REALM,
            sequence: 1,
            previous: Some(corpus.reference.post),
            operation: Operation::Post {
                placement: Placement::Profile,
                text: Text::new("rust provisional").unwrap(),
                reply: None,
                quote: None,
            },
        },
        None,
    );
    add(&mut corpus.archive, &provisional);
    for _ in 0..2 {
        let response = provider.next(&corpus.archive, corpus.owner, now()).unwrap();
        let received = transfer(&provider_path, &requester_path, &response.encode()).await;
        round.receive(&received, &mut local, now()).unwrap();
    }
    let eligibility = Eligibility::default();
    assert_eq!(
        View::new(&local, now(), &eligibility).state(provisional.id()),
        Some(RecordState::Provisional)
    );
    let Actor::Agent { grant, .. } = corpus.actor else {
        unreachable!()
    };
    let revoke = signed(
        &corpus.owner_key,
        Body::Control {
            owner: corpus.owner,
            previous: corpus.seal,
            action: ControlAction::Revoke {
                grant,
                accepted: References::sorted(vec![]).unwrap(),
            },
        },
        None,
    );
    add(&mut corpus.archive, &revoke);
    for _ in 0..3 {
        let response = provider.next(&corpus.archive, corpus.owner, now()).unwrap();
        let received = transfer(&provider_path, &requester_path, &response.encode()).await;
        round.receive(&received, &mut local, now()).unwrap();
    }
    assert_eq!(
        View::new(&local, now(), &eligibility).state(provisional.id()),
        Some(RecordState::Rejected)
    );
    assert_eq!(
        round
            .candidates(&local, now(), corpus.owner, &state, Filters::default())
            .unwrap()
            .references,
        vec![corpus.reference]
    );
    assert!(
        local.get(provisional.id()).is_some(),
        "late control never erases retained evidence"
    );
}
