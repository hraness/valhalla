//! Canonical portable codec and real signed-registry admission regressions.
#[path = "../../vhalla-rooms/tests/common/mod.rs"]
mod common;

use ed25519_dalek::{Signer, SigningKey};
use vhalla_core::RealmId;
use vhalla_room_activity::{
    AdmissionContext, AuthorChain, Content, Error, EventClaims, EventId, RoomScope, SignedEvent,
    Text, UnsignedEvent, VerifiedEvent, MAX_EVENT_BYTES, MAX_TEXT_BYTES,
};
use vhalla_rooms::{
    Applied, Description, DirectoryId, Registry, RoomGenesisId, RoomRecordId, RoomUpdate,
    UpdateAction,
};
use vhalla_social::{archive::Archive, control::ControlView};

const NETWORK: [u8; 32] = [7; 32];

fn author() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn raw_scope() -> RoomScope {
    RoomScope {
        network: NETWORK,
        realm: common::REALM,
        directory: common::DIRECTORY,
        room: RoomGenesisId::from_bytes([8; 32]),
    }
}
fn claims(scope: RoomScope, policy: RoomRecordId) -> EventClaims {
    EventClaims {
        scope,
        policy,
        author: author().verifying_key().to_bytes(),
        sequence: 1,
        previous: EventId::ZERO,
        created_at: 1234,
        content: Content::Text(Text::new("hello").unwrap()),
    }
}
fn signed(claims: EventClaims) -> SignedEvent {
    UnsignedEvent::new(claims)
        .unwrap()
        .sign_with_key(&author())
        .unwrap()
}
fn verified(claims: EventClaims) -> VerifiedEvent {
    signed(claims).verify().unwrap()
}
fn from_hex(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(core::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn canonical_frame_and_content_id_match_frozen_external_vector() {
    // RFC 8032 test-key seed; the content-ID vector was independently computed
    // from the documented wire bytes using Python hashlib.sha256.
    let seed = from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let key = SigningKey::from_bytes(&seed.try_into().unwrap());
    let mut body = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    body.author = key.verifying_key().to_bytes();
    let unsigned = UnsignedEvent::new(body).unwrap();
    assert_eq!(
        unsigned.id().as_bytes().as_slice(),
        from_hex("80f9c9ce61dbf528ecef5e5d547fdb6ac8ad42a4889a5cdeef0e214d66aca06e")
    );
    let expected = from_hex("564852410107070707070707070707070707070707070707070707070707070707070707070000000000000000000000000000004d050505050505050505050505050505050505050505050505050505050505050508080808080808080808080808080808080808080808080808080808080808080909090909090909090909090909090909090909090909090909090909090909d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a0000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000004d200000568656c6c6f");
    let event = unsigned.sign_with_key(&key).unwrap();
    let raw = event.encode();
    assert_eq!(&raw[..raw.len() - 64], expected);
    let decoded = SignedEvent::decode(&raw).unwrap();
    assert_eq!(decoded.encode(), raw);
    assert_eq!(decoded.verify().unwrap().id(), event.id());
}

#[test]
fn text_is_byte_bounded_and_never_normalized() {
    assert_eq!(Text::new(""), Err(Error::Bounds));
    assert!(Text::new(&"a".repeat(MAX_TEXT_BYTES)).is_ok());
    assert_eq!(
        Text::new(&"a".repeat(MAX_TEXT_BYTES + 1)),
        Err(Error::Bounds)
    );
    assert!(Text::new(&"é".repeat(MAX_TEXT_BYTES / 2)).is_ok());
    assert_eq!(
        Text::new(&"é".repeat(MAX_TEXT_BYTES / 2 + 1)),
        Err(Error::Bounds)
    );
    for text in ["\r", "\0", "\u{7f}", "\u{85}"] {
        assert_eq!(Text::new(text), Err(Error::Encoding));
    }
    assert_eq!(Text::new("line\n\ttab").unwrap().as_str(), "line\n\ttab");
    let mut body = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    body.content = Content::Text(Text::new("é").unwrap());
    let composed = verified(body.clone());
    body.content = Content::Text(Text::new("e\u{301}").unwrap());
    let decomposed = verified(body);
    assert_ne!(composed.id(), decomposed.id());
    assert!(composed.conflicts_with(&decomposed));
}

#[test]
fn maximum_frame_roundtrips_and_all_noncanonical_shapes_refuse() {
    let mut body = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    body.content = Content::Text(Text::new(&"x".repeat(MAX_TEXT_BYTES)).unwrap());
    let raw = signed(body).encode();
    assert_eq!(raw.len(), MAX_EVENT_BYTES);
    assert_eq!(
        SignedEvent::decode(&raw)
            .unwrap()
            .verify()
            .unwrap()
            .encode(),
        raw
    );
    let mut over = raw.clone();
    over.push(0);
    assert_eq!(SignedEvent::decode(&over), Err(Error::Bounds));
    let raw = signed(claims(raw_scope(), RoomRecordId::from_bytes([9; 32]))).encode();
    for end in 0..raw.len() {
        assert!(
            SignedEvent::decode(&raw[..end]).is_err(),
            "accepted truncation {end}"
        );
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(SignedEvent::decode(&trailing), Err(Error::Encoding));
    for (index, byte, expected) in [
        (4, 2, Error::Protocol),      // version
        (229, 1, Error::Protocol),    // content kind
        (232, 0xff, Error::Encoding), // UTF-8
        (232, 0, Error::Encoding),    // forbidden control
    ] {
        let mut altered = raw.clone();
        altered[index] = byte;
        assert_eq!(SignedEvent::decode(&altered), Err(expected));
    }
    for length in [0u16, 4097] {
        let mut altered = raw.clone();
        altered[230..232].copy_from_slice(&length.to_be_bytes());
        assert_eq!(SignedEvent::decode(&altered), Err(Error::Bounds));
    }
}

#[test]
fn every_frame_byte_and_signing_domain_are_authenticated() {
    let body = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    let raw = signed(body.clone()).encode();
    for index in 0..raw.len() {
        let mut altered = raw.clone();
        altered[index] ^= 1;
        assert!(
            SignedEvent::decode(&altered)
                .and_then(SignedEvent::verify)
                .is_err(),
            "accepted changed byte {index}"
        );
    }
    let unsigned = UnsignedEvent::new(body).unwrap();
    let wrong_domain = author().sign(unsigned.id().as_bytes()).to_bytes();
    assert_eq!(
        unsigned.clone().attach_signature(wrong_domain),
        Err(Error::Signature)
    );
    let wrong = SigningKey::from_bytes(&[43; 32]);
    assert_eq!(unsigned.sign_with_key(&wrong), Err(Error::Signer));
    let mut altered = raw;
    let last = altered.len() - 1;
    altered[last] ^= 1;
    // Decoding can succeed but does not construct VerifiedEvent.
    assert_eq!(
        SignedEvent::decode(&altered).unwrap().verify(),
        Err(Error::Signature)
    );
}

#[test]
fn weak_keys_and_impossible_chain_shapes_refuse_before_signing() {
    let original = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    for weak in [[0u8; 32], {
        let mut bytes = [0; 32];
        bytes[0] = 1;
        bytes
    }] {
        let mut body = original.clone();
        body.author = weak;
        assert_eq!(UnsignedEvent::new(body), Err(Error::Key));
        assert!(matches!(
            AuthorChain::new(raw_scope(), weak),
            Err(Error::Key)
        ));
    }
    for (sequence, previous) in [
        (0, EventId::ZERO),
        (1, EventId::from_bytes([1; 32])),
        (2, EventId::ZERO),
    ] {
        let mut body = original.clone();
        body.sequence = sequence;
        body.previous = previous;
        assert_eq!(UnsignedEvent::new(body), Err(Error::Sequence));
    }
    let mut body = original;
    body.scope.network = [0; 32];
    assert_eq!(UnsignedEvent::new(body), Err(Error::Scope));
}

struct Fixture {
    archive: Archive,
    creator: common::Owner,
    registry: Registry,
    scope: RoomScope,
    room_head: RoomRecordId,
}
impl Fixture {
    fn new() -> Self {
        let mut archive = Archive::new(common::REALM, common::limits()).unwrap();
        let creator = common::beneficiary(&mut archive, 4);
        let (mut pool, mut registry) = common::sources(&mut archive, 90, 1);
        let head = common::grant_create(&mut registry, &archive, &creator, 100);
        common::award_one(&mut registry, &mut archive, &mut pool[0], &creator, 200);
        let create = common::creation(&creator, head, head, "activity-room", 1, 1, 13);
        let Applied::Created(genesis) =
            common::apply(&mut registry, &archive, &create, 300).unwrap()
        else {
            panic!("expected new room")
        };
        Self {
            archive,
            creator,
            registry,
            scope: RoomScope {
                room: genesis,
                ..raw_scope()
            },
            room_head: create.id(),
        }
    }
    fn update(&mut self, action: UpdateAction) -> RoomRecordId {
        let record = RoomUpdate {
            directory: self.scope.directory,
            realm: self.scope.realm,
            genesis: self.scope.room,
            previous: self.room_head,
            owner: self.creator.id,
            social_control: self.creator.head,
            controller_key: self.creator.key.verifying_key().to_bytes(),
            expires_at: common::EXPIRES,
            nonce: *self.room_head.as_bytes(),
            action,
        }
        .sign_with_key(&self.creator.key)
        .unwrap()
        .verify()
        .unwrap();
        assert_eq!(
            self.registry
                .apply(&record, &ControlView::new(&self.archive, 400), 400),
            Ok(Applied::Updated(record.id()))
        );
        self.room_head = record.id();
        record.id()
    }
    fn policy(&mut self, enabled: bool) -> RoomRecordId {
        self.update(UpdateAction::SetPublicActivityPolicy {
            network: NETWORK,
            enabled,
        })
    }
    fn context(&self) -> AdmissionContext<'_> {
        AdmissionContext::new(NETWORK, &self.registry).unwrap()
    }
    fn chain(&self) -> AuthorChain {
        AuthorChain::new(self.scope, author().verifying_key().to_bytes()).unwrap()
    }
}

#[test]
fn authentic_bytes_need_explicit_current_policy_and_exact_scope() {
    let mut f = Fixture::new();
    let mut chain = f.chain();
    let closed = verified(claims(f.scope, f.room_head));
    assert_eq!(
        chain.prepare_next(closed, &f.context()).unwrap_err(),
        Error::Policy
    );
    let open = f.policy(true);
    let body = claims(f.scope, open);
    // A fresh unrelated application key can post only because the owner
    // explicitly opened this exact network policy. No social owner is minted.
    assert_ne!(body.author, f.creator.key.verifying_key().to_bytes());
    let mut wrong = body.clone();
    wrong.policy = RoomRecordId::from_bytes([99; 32]);
    assert_eq!(
        chain
            .prepare_next(verified(wrong), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    for scope in [
        RoomScope {
            network: [8; 32],
            ..f.scope
        },
        RoomScope {
            realm: RealmId(78),
            ..f.scope
        },
        RoomScope {
            directory: DirectoryId::from_bytes([6; 32]),
            ..f.scope
        },
        RoomScope {
            room: RoomGenesisId::from_bytes([9; 32]),
            ..f.scope
        },
    ] {
        let foreign = verified(claims(scope, open));
        assert_eq!(
            chain
                .prepare_next(foreign.clone(), &f.context())
                .unwrap_err(),
            Error::Scope
        );
        let alternate = AuthorChain::new(scope, body.author).unwrap();
        let expected = if scope.room != f.scope.room {
            Error::UnknownRoom
        } else {
            Error::Scope
        };
        assert_eq!(
            alternate.prepare_next(foreign, &f.context()).unwrap_err(),
            expected
        );
    }
    let wrong_key = SigningKey::from_bytes(&[43; 32]);
    let mut wrong = body.clone();
    wrong.author = wrong_key.verifying_key().to_bytes();
    let foreign = UnsignedEvent::new(wrong)
        .unwrap()
        .sign_with_key(&wrong_key)
        .unwrap()
        .verify()
        .unwrap();
    assert_eq!(
        chain.prepare_next(foreign, &f.context()).unwrap_err(),
        Error::Author
    );
    assert!(chain.position().is_none());
    let candidate = chain.prepare_next(verified(body), &f.context()).unwrap();
    let receipt = chain.commit_after_persist(candidate, &f.context()).unwrap();
    assert_eq!(receipt.position().sequence(), 1);
}

#[test]
fn prepare_is_nondurable_and_commit_compares_both_chain_and_registry_bases() {
    let mut f = Fixture::new();
    let open = f.policy(true);
    let event = verified(claims(f.scope, open));
    let mut chain = f.chain();
    let abandoned = chain.prepare_next(event.clone(), &f.context()).unwrap();
    assert!(abandoned.base().is_none());
    assert!(chain.position().is_none());
    drop(abandoned); // failed durable transaction: no floor advance
    let candidate = chain.prepare_next(event.clone(), &f.context()).unwrap();
    let racing = chain.prepare_next(event.clone(), &f.context()).unwrap();
    assert_eq!(candidate.next().id(), event.id());
    assert_eq!(candidate.registry_digest(), f.context().registry_digest());
    let receipt = chain.commit_after_persist(candidate, &f.context()).unwrap();
    assert_eq!(
        chain
            .commit_after_persist(racing, &f.context())
            .unwrap_err(),
        Error::StaleBase
    );
    assert_eq!(
        AuthorChain::from_receipt(&receipt).position(),
        chain.position()
    );

    let mut another = f.chain();
    let candidate = another.prepare_next(event.clone(), &f.context()).unwrap();
    let wrong_context = AdmissionContext::new([8; 32], &f.registry).unwrap();
    assert_eq!(
        another
            .commit_after_persist(candidate, &wrong_context)
            .unwrap_err(),
        Error::StalePolicy
    );
    assert!(another.position().is_none());
    let candidate = another.prepare_next(event, &f.context()).unwrap();
    // Even a non-policy room update changes the transaction's evaluated view.
    f.update(UpdateAction::Describe(
        Description::new("new description").unwrap(),
    ));
    assert_eq!(
        another
            .commit_after_persist(candidate, &f.context())
            .unwrap_err(),
        Error::StalePolicy
    );
    assert!(another.position().is_none());
}

#[test]
fn fork_gap_duplicate_and_historical_replay_never_replace_chain_head() {
    let mut f = Fixture::new();
    let open = f.policy(true);
    let first = verified(claims(f.scope, open));
    let mut chain = f.chain();
    let mut second_claims = claims(f.scope, open);
    second_claims.sequence = 2;
    second_claims.previous = first.id();
    let second = verified(second_claims.clone());
    assert_eq!(
        chain
            .prepare_next(second.clone(), &f.context())
            .unwrap_err(),
        Error::Gap
    );
    let candidate = chain.prepare_next(first.clone(), &f.context()).unwrap();
    chain.commit_after_persist(candidate, &f.context()).unwrap();
    let head = chain.position();
    assert_eq!(
        chain.prepare_next(first.clone(), &f.context()).unwrap_err(),
        Error::Duplicate
    );
    let mut competitor = claims(f.scope, open);
    competitor.content = Content::Text(Text::new("different authentic first event").unwrap());
    let fork = verified(competitor);
    assert!(first.conflicts_with(&fork));
    assert_eq!(
        chain.prepare_next(fork.clone(), &f.context()).unwrap_err(),
        Error::Fork
    );
    second_claims.previous = fork.id();
    assert_eq!(
        chain
            .prepare_next(verified(second_claims.clone()), &f.context())
            .unwrap_err(),
        Error::Fork
    );
    second_claims.sequence = 3;
    assert_eq!(
        chain
            .prepare_next(verified(second_claims), &f.context())
            .unwrap_err(),
        Error::Gap
    );
    assert_eq!(chain.position(), head);
    let candidate = chain.prepare_next(second, &f.context()).unwrap();
    chain.commit_after_persist(candidate, &f.context()).unwrap();
    let head = chain.position();
    assert_eq!(
        chain.prepare_next(fork.clone(), &f.context()).unwrap_err(),
        Error::Replay
    );
    assert_eq!(chain.position(), head);
    // The bounded head refuses old data; retained signed history distinguishes
    // a historical duplicate from actual equivocation without arrival ordering.
    assert!(first.conflicts_with(&fork));
}

#[test]
fn revocation_and_reopening_preserve_chain_identity_and_historical_receipts() {
    let mut f = Fixture::new();
    let open = f.policy(true);
    let mut chain = f.chain();
    let candidate = chain
        .prepare_next(verified(claims(f.scope, open)), &f.context())
        .unwrap();
    let receipt = chain.commit_after_persist(candidate, &f.context()).unwrap();
    let mut next = claims(f.scope, open);
    next.sequence = 2;
    next.previous = receipt.event().id();
    let pending = chain
        .prepare_next(verified(next.clone()), &f.context())
        .unwrap();
    f.policy(false);
    assert_eq!(
        chain
            .commit_after_persist(pending, &f.context())
            .unwrap_err(),
        Error::StalePolicy
    );
    assert_eq!(
        chain
            .prepare_next(verified(next.clone()), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    // A historical signature/receipt remains readable, not currently authorized.
    assert!(SignedEvent::decode(&receipt.event().encode())
        .unwrap()
        .verify()
        .is_ok());
    assert_eq!(chain.position(), Some(receipt.position()));
    let reopened = f.policy(true);
    assert_eq!(
        chain
            .prepare_next(verified(next.clone()), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    next.policy = reopened;
    let candidate = chain.prepare_next(verified(next), &f.context()).unwrap();
    let second = chain.commit_after_persist(candidate, &f.context()).unwrap();
    assert_eq!(second.position().sequence(), 2);
    let mut archived = claims(f.scope, reopened);
    archived.sequence = 3;
    archived.previous = second.event().id();
    f.update(UpdateAction::Archive);
    assert_eq!(
        chain
            .prepare_next(verified(archived), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    assert_eq!(chain.position(), Some(second.position()));
}

#[test]
fn trusted_local_restore_preserves_revoked_history_without_new_admission() {
    let mut f = Fixture::new();
    let open = f.policy(true);
    let mut chain = f.chain();
    let pending = chain
        .prepare_next(verified(claims(f.scope, open)), &f.context())
        .unwrap();
    let receipt = chain.commit_after_persist(pending, &f.context()).unwrap();
    // This fixture retains the exact bytes whose local durable publication was
    // reported. A real store must pin them to its own admission log/head index.
    let retained = receipt.event().encode();
    f.policy(false);
    let head = SignedEvent::decode(&retained).unwrap().verify().unwrap();
    let author = head.claims().author;
    assert_eq!(
        AuthorChain::restore_local_admitted_head(
            RoomScope {
                realm: RealmId(78),
                ..f.scope
            },
            author,
            head.clone()
        )
        .unwrap_err(),
        Error::Scope
    );
    assert_eq!(
        AuthorChain::restore_local_admitted_head(
            f.scope,
            SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
            head.clone()
        )
        .unwrap_err(),
        Error::Author
    );
    let mut restored = AuthorChain::restore_local_admitted_head(f.scope, author, head).unwrap();
    assert_eq!(restored.position(), chain.position());
    let mut next = claims(f.scope, open);
    next.sequence = 2;
    next.previous = receipt.event().id();
    assert_eq!(
        restored
            .prepare_next(verified(next.clone()), &f.context())
            .unwrap_err(),
        Error::Policy
    );
    next.policy = f.policy(true);
    let pending = restored.prepare_next(verified(next), &f.context()).unwrap();
    let second = restored
        .commit_after_persist(pending, &f.context())
        .unwrap();
    assert_eq!(second.position().sequence(), 2);
}

#[test]
fn unsigned_reservations_roundtrip_exactly_without_placeholder_signatures() {
    let original =
        UnsignedEvent::new(claims(raw_scope(), RoomRecordId::from_bytes([9; 32]))).unwrap();
    let raw = original.encode();
    let restored = UnsignedEvent::decode(&raw).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.signing_bytes(), original.signing_bytes());
    let signed = restored.sign_with_key(&author()).unwrap();
    assert_eq!(&signed.encode()[..raw.len()], raw);
    assert_eq!(signed.id(), original.id());
    assert!(SignedEvent::decode(&raw).is_err());
    assert!(UnsignedEvent::decode(&signed.encode()).is_err());
    for end in 0..raw.len() {
        assert!(UnsignedEvent::decode(&raw[..end]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(UnsignedEvent::decode(&trailing), Err(Error::Encoding));
    let mut max = claims(raw_scope(), RoomRecordId::from_bytes([9; 32]));
    max.content = Content::Text(Text::new(&"x".repeat(MAX_TEXT_BYTES)).unwrap());
    let max = UnsignedEvent::new(max).unwrap().encode();
    assert_eq!(max.len(), vhalla_room_activity::MAX_UNSIGNED_BYTES);
    assert_eq!(UnsignedEvent::decode(&max).unwrap().encode(), max);
    let mut over = max;
    over.push(0);
    assert_eq!(UnsignedEvent::decode(&over), Err(Error::Bounds));
    for (index, value, expected) in [
        (4, 2, Error::Protocol),
        (229, 1, Error::Protocol),
        (232, 0, Error::Encoding),
    ] {
        let mut altered = raw.clone();
        altered[index] = value;
        assert_eq!(UnsignedEvent::decode(&altered), Err(expected));
    }
    let mut weak = raw;
    weak[149..181].fill(0);
    assert_eq!(UnsignedEvent::decode(&weak), Err(Error::Key));
}

mod continuity;
