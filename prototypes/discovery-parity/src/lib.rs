#![forbid(unsafe_code)]
//! Executed native/WASM semantic parity fixture; no transport or storage adapter.
use ed25519_dalek::SigningKey;
use vhalla_attention::{
    Attention, AttentionPolicy, NotificationSnapshot, ReadState, ReaderScope, Reason,
};
use vhalla_core::{RealmId, RoomId};
use vhalla_discovery::{
    Budget as QueryBudget, Change, DiscoverySnapshot, DiscoveryState, FeedMode, Filters, Page,
    Query, Visibility,
};
use vhalla_social::{
    archive::{Archive, Budget, Limits},
    view::{Eligibility, View},
    *,
};

const REALM: RealmId = RealmId(73);
const NOW: u64 = 10;
struct Author {
    key: SigningKey,
    owner: OwnerId,
    control: RecordId,
    sequence: u64,
    previous: Option<RecordId>,
}
fn admit(archive: &mut Archive, record: SignedRecord) -> RecordId {
    let id = record.id();
    archive
        .ingest(
            &record.encode(),
            &mut Budget::new(1, MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap();
    id
}
fn sign(key: &SigningKey, body: Body) -> SignedRecord {
    UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap()
        .finish()
        .unwrap()
}
impl Author {
    fn new(archive: &mut Archive, seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let control = admit(
            archive,
            sign(
                &key,
                Body::OwnerGenesis {
                    controller: key.verifying_key().to_bytes(),
                    recovery: None,
                    nonce: [seed; 32],
                },
            ),
        );
        Self {
            key,
            owner: OwnerId::from_bytes(*control.as_bytes()),
            control,
            sequence: 0,
            previous: None,
        }
    }
    fn emit(&mut self, archive: &mut Archive, operation: Operation) -> RecordId {
        let id = admit(
            archive,
            sign(
                &self.key,
                Body::Social {
                    actor: Actor::Owner {
                        owner: self.owner,
                        control: self.control,
                    },
                    realm: REALM,
                    sequence: self.sequence,
                    previous: self.previous,
                    operation,
                },
            ),
        );
        self.previous = Some(id);
        self.sequence += 1;
        id
    }
    fn seal(&mut self, archive: &mut Archive) {
        self.control = admit(
            archive,
            sign(
                &self.key,
                Body::Control {
                    owner: self.owner,
                    previous: self.control,
                    action: ControlAction::Seal {
                        realm: REALM,
                        heads: References::sorted(self.previous.into_iter().collect()).unwrap(),
                    },
                },
            ),
        );
        // Owner writer identity includes its exact control basis. A new sealed
        // control basis starts its own writer chain; old sealed history persists.
        self.sequence = 0;
        self.previous = None;
    }
}
fn mention(recipient: OwnerId, tag: &str, suffix: &str) -> FacetedText {
    let text = format!("💠 @b #{tag} café {suffix}");
    FacetedText::new(
        Text::new(&text).unwrap(),
        vec![
            Facet {
                start: 5,
                end: 7,
                kind: FacetKind::Mention(MentionTarget::Owner(recipient)),
            },
            Facet {
                start: 8,
                end: (9 + tag.len()) as u16,
                kind: FacetKind::Tag(CanonicalTag::new(tag).unwrap()),
            },
        ],
    )
    .unwrap()
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend(bytes);
}
fn number(out: &mut Vec<u8>, value: usize) {
    out.extend((value as u64).to_be_bytes());
}
fn page_bytes(out: &mut Vec<u8>, page: &Page<'_>) {
    number(out, page.hits.len());
    number(out, page.matches);
    out.extend([
        u8::from(page.coverage.corpus_complete),
        u8::from(page.coverage.history_complete),
        u8::from(page.coverage.query_complete),
    ]);
    for value in [
        page.coverage.retained_records,
        page.coverage.documents,
        page.coverage.examined,
        page.coverage.bytes,
        page.coverage.steps,
    ] {
        number(out, value);
    }
    for hit in &page.hits {
        out.extend(hit.reference.post.as_bytes());
        out.extend(hit.reference.revision.as_bytes());
        out.extend(hit.owner.as_bytes());
        out.extend(hit.root.as_bytes());
        blob(out, hit.text.as_bytes());
        number(out, hit.facets.len());
        for facet in hit.facets {
            out.extend(facet.start.to_be_bytes());
            out.extend(facet.end.to_be_bytes());
            match &facet.kind {
                FacetKind::Mention(MentionTarget::Owner(id)) => {
                    out.push(0);
                    out.extend(id.as_bytes());
                }
                FacetKind::Mention(MentionTarget::Agent(id)) => {
                    out.push(1);
                    out.extend(id.as_bytes());
                }
                FacetKind::Tag(tag) => {
                    out.push(2);
                    blob(out, tag.as_str().as_bytes());
                }
            }
        }
        for score in hit.why {
            out.extend(score.to_be_bytes());
        }
        out.extend(hit.first_observed.unwrap_or(0).to_be_bytes());
    }
}
fn inbox_bytes(out: &mut Vec<u8>, snapshot: &NotificationSnapshot) {
    let counts = snapshot.counts();
    for n in [
        snapshot.entries().len(),
        counts.unread_updates,
        counts.unknown_updates,
        counts.unread_groups,
        counts.unknown_groups,
    ] {
        number(out, n);
    }
    out.extend(snapshot.basis().digest);
    for entry in snapshot.entries() {
        out.extend(entry.id());
        out.extend(entry.update.event.as_bytes());
        out.push(match entry.read {
            ReadState::Unread => 0,
            ReadState::Read => 1,
            ReadState::Unknown => 2,
        });
        out.push(match entry.priority {
            None => 0,
            Some(ReadState::Unread) => 1,
            Some(ReadState::Read) => 2,
            Some(ReadState::Unknown) => 3,
        });
    }
}
/// Fixed fixture runs all assertions on each platform and returns canonical bytes.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen::prelude::wasm_bindgen)]
pub fn fixture_bytes() -> Vec<u8> {
    let mut archive = Archive::new(REALM, Limits::default()).unwrap();
    let mut author = Author::new(&mut archive, 11);
    let mut reader = Author::new(&mut archive, 12);
    let original = author.emit(
        &mut archive,
        Operation::PostFaceted {
            placement: Placement::Profile,
            content: mention(reader.owner, "Rust", "\u{202e}<inert>"),
            reply: None,
            quote: None,
        },
    );
    author.emit(
        &mut archive,
        Operation::Post {
            placement: Placement::Channel(RoomId(77)),
            text: Text::new(&"a".repeat(MAX_TEXT_BYTES)).unwrap(),
            reply: None,
            quote: None,
        },
    );
    author.seal(&mut archive);
    reader.emit(
        &mut archive,
        Operation::Follow {
            target: author.owner,
            following: true,
            supersedes: References::default(),
        },
    );
    reader.seal(&mut archive);
    let scope = ReaderScope::new(&archive, NOW, reader.owner, None, [1; 32], [2; 32]).unwrap();
    let mut state = DiscoveryState::new(scope.digest());
    let policy = AttentionPolicy::new(vec![author.owner], vec![], vec![], false).unwrap();
    let attention = Attention::new(scope);
    let eligibility = Eligibility::default();
    let mut out = b"VHDP\0\0\0\x01".to_vec();
    blob(&mut out, &archive.snapshot());
    let acknowledged;
    let mut stale;
    let observed;
    {
        let view = View::new(&archive, NOW, &eligibility);
        assert!(view.matches_archive(&archive));
        state.observe(&view).unwrap();
        observed = state.ordinal(original).unwrap();
        state
            .apply(Change::Interest {
                tag: "rust".into(),
                delta: 2,
            })
            .unwrap();
        state
            .feedback(
                &view,
                PostRef {
                    post: original,
                    revision: original,
                },
                1,
            )
            .unwrap();
        let snapshot =
            DiscoverySnapshot::new(&archive, &view, reader.owner, &state, Visibility::Committed)
                .unwrap();
        let filter = Filters {
            tag: Some("rust".into()),
            mention: Some(MentionTarget::Owner(reader.owner)),
            ..Filters::default()
        };
        let hits = snapshot
            .search(
                &Query::parse("RUST café").unwrap(),
                &filter,
                QueryBudget::default(),
                64,
            )
            .unwrap();
        assert_eq!(hits.hits.len(), 1);
        assert_eq!(
            hits.hits[0].reference,
            PostRef {
                post: original,
                revision: original
            }
        );
        assert_eq!(hits.hits[0].facets.len(), 2);
        page_bytes(&mut out, &hits);
        let hydrated = snapshot
            .search_references(
                &Query::parse("RUST café").unwrap(),
                &filter,
                QueryBudget::default(),
                &[hits.hits[0].reference],
            )
            .unwrap();
        assert_eq!(hydrated.matches, 1);
        assert_eq!(hydrated.hits[0].reference, hits.hits[0].reference);
        page_bytes(&mut out, &hydrated);
        let no_unicode_fold = snapshot
            .search(
                &Query::parse("CAFÉ").unwrap(),
                &Filters::default(),
                QueryBudget::default(),
                64,
            )
            .unwrap();
        assert!(no_unicode_fold.hits.is_empty());
        assert!(no_unicode_fold.coverage.query_complete);
        page_bytes(&mut out, &no_unicode_fold);
        let following = snapshot
            .feed(FeedMode::Following, QueryBudget::default(), 64)
            .unwrap();
        assert_eq!(following.hits.len(), 2);
        page_bytes(&mut out, &following);
        let discover = snapshot
            .feed(FeedMode::Discover, QueryBudget::default(), 64)
            .unwrap();
        assert_eq!(discover.hits.len(), 2);
        assert_eq!(discover.hits[0].reference.post, original);
        assert!(discover.hits[0].why[2] > 0);
        page_bytes(&mut out, &discover);
        assert_eq!(snapshot.boards(64).unwrap().len(), 1);
        let exhausted = snapshot
            .search(
                &Query::parse(&("a".repeat(95) + "b")).unwrap(),
                &Filters::default(),
                QueryBudget {
                    documents: 10,
                    bytes: 10000,
                    steps: 1500,
                },
                64,
            )
            .unwrap();
        assert!(exhausted.hits.is_empty());
        assert!(!exhausted.coverage.query_complete);
        page_bytes(&mut out, &exhausted);
        assert!(Query::parse("\"unterminated").is_err());
        stale = snapshot
            .cursor(
                Query::parse("rust").unwrap(),
                Filters::default(),
                None,
                QueryBudget::default(),
            )
            .unwrap();
        let inbox = attention
            .notifications(&archive, NOW, &policy, 0, 64)
            .unwrap();
        assert_eq!(inbox.entries().len(), 1);
        assert_eq!(inbox.entries()[0].update.group.reason, Reason::Mention);
        assert_eq!(inbox.counts().unread_groups, 1);
        inbox_bytes(&mut out, &inbox);
        acknowledged = attention.acknowledge(&inbox, &archive).unwrap();
        let read = acknowledged
            .notifications(&archive, NOW, &policy, 0, 64)
            .unwrap();
        assert_eq!(read.counts().unread_updates, 0);
        inbox_bytes(&mut out, &read);
        state
            .mark_seen(
                &view,
                PostRef {
                    post: original,
                    revision: original,
                },
            )
            .unwrap();
    }
    // Reject a byte offset inside a multibyte scalar and malformed wire UTF-8.
    assert!(FacetedText::new(
        Text::new("💠").unwrap(),
        vec![Facet {
            start: 1,
            end: 3,
            kind: FacetKind::Mention(MentionTarget::Owner(reader.owner))
        }]
    )
    .is_err());
    let mut malformed = archive.get(original).unwrap().encode();
    let accent = malformed
        .windows(2)
        .position(|bytes| bytes == [0xc3, 0xa9])
        .unwrap();
    malformed[accent] = 0xff;
    assert!(SignedRecord::decode(&malformed).is_err());
    let revision = author.emit(
        &mut archive,
        Operation::ReviseFaceted {
            post: original,
            content: mention(reader.owner, "Wasm", "edited"),
            supersedes: References::sorted(vec![original]).unwrap(),
        },
    );
    author.seal(&mut archive);
    {
        let view = View::new(&archive, NOW + 1, &eligibility);
        state.observe(&view).unwrap();
        assert_eq!(state.ordinal(original), Some(observed));
        assert!(matches!(
            stale.page(&archive, &view, &state, 64),
            Err(vhalla_discovery::Error::Stale)
        ));
        let snapshot =
            DiscoverySnapshot::new(&archive, &view, reader.owner, &state, Visibility::Committed)
                .unwrap();
        let old = snapshot
            .search(
                &Query::parse("").unwrap(),
                &Filters {
                    tag: Some("rust".into()),
                    ..Filters::default()
                },
                QueryBudget::default(),
                64,
            )
            .unwrap();
        assert!(old.hits.is_empty());
        let stale_hint = snapshot
            .search_references(
                &Query::parse("").unwrap(),
                &Filters::default(),
                QueryBudget::default(),
                &[PostRef {
                    post: original,
                    revision: original,
                }],
            )
            .unwrap();
        assert!(stale_hint.hits.is_empty());
        assert!(stale_hint.coverage.query_complete);
        page_bytes(&mut out, &stale_hint);
        let current = snapshot
            .search(
                &Query::parse("edited").unwrap(),
                &Filters {
                    tag: Some("wasm".into()),
                    ..Filters::default()
                },
                QueryBudget::default(),
                64,
            )
            .unwrap();
        assert_eq!(current.hits.len(), 1);
        assert_eq!(current.hits[0].reference.revision, revision);
        page_bytes(&mut out, &current);
        let inbox = acknowledged
            .notifications(&archive, NOW + 1, &policy, 0, 64)
            .unwrap();
        assert_eq!(inbox.entries().len(), 1);
        assert_eq!(inbox.counts().unread_groups, 0);
        assert_eq!(inbox.counts().unread_updates, 1);
        assert_eq!(inbox.entries()[0].update.event, revision);
        inbox_bytes(&mut out, &inbox);
        // An old exact read receipt cannot mark edited content read.
        let roundtrip = Attention::decode(&acknowledged.encode(), scope).unwrap();
        assert_eq!(
            roundtrip
                .notifications(&archive, NOW + 1, &policy, 0, 64)
                .unwrap()
                .counts()
                .unread_updates,
            1
        );
    }
    let encoded = state.encode();
    assert_eq!(
        DiscoveryState::decode(&encoded, scope.digest())
            .unwrap()
            .encode(),
        encoded
    );
    blob(&mut out, &encoded);
    blob(&mut out, &acknowledged.encode());
    blob(&mut out, &archive.snapshot());
    let copy = Archive::from_snapshot(REALM, Limits::default(), &archive.snapshot()).unwrap();
    assert_eq!(copy.root(), archive.root());
    let wire = archive.get(revision).unwrap().encode();
    let verified = SignedRecord::decode(&wire).unwrap().verify().unwrap();
    assert_eq!(verified.id(), revision);
    blob(&mut out, &wire);
    assert!(out.len() < 32000);
    out
}
#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_signed_discovery_and_attention_fixture() {
        let first = super::fixture_bytes();
        assert_eq!(first, super::fixture_bytes());
        assert!(first.starts_with(b"VHDP\0\0\0\x01"));
    }
}
