use ed25519_dalek::SigningKey;
use vhalla_core::RealmId;
use vhalla_social::{
    Actor, Body, Operation, OwnerId, Placement, RecordId, References, Text, UnsignedRecord,
};
use vhalla_social_facets_spike::*;
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let body = Body::Social {
        actor: Actor::Owner {
            owner: OwnerId::from_bytes([1; 32]),
            control: RecordId::from_bytes([2; 32]),
        },
        realm: RealmId(7),
        sequence: 0,
        previous: None,
        operation: Operation::Post {
            placement: Placement::Profile,
            text: Text::new("@alice #Rust").unwrap(),
            reply: None,
            quote: None,
        },
    };
    let facets = vec![
        Facet {
            start: 0,
            end: 6,
            kind: Kind::Mention(Target::Owner(OwnerId::from_bytes([3; 32]))),
        },
        Facet {
            start: 7,
            end: 12,
            kind: Kind::Tag("rust".into()),
        },
    ];
    for (name, encoding) in [
        ("faceted-post-v1", Encoding::NewOpcodesV1),
        ("faceted-post-v2", Encoding::EnvelopeV2),
    ] {
        let raw = sign_revision(&key, body.clone(), facets.clone(), encoding).unwrap();
        println!(
            "{name} {} {}",
            hex(verify_revision(&raw).unwrap().id().as_bytes()),
            hex(&raw)
        );
    }
    let original = verify_revision(
        &sign_revision(&key, body.clone(), facets.clone(), Encoding::NewOpcodesV1).unwrap(),
    )
    .unwrap()
    .id();
    let mut revision_body = body.clone();
    if let Body::Social {
        sequence,
        previous,
        operation,
        ..
    } = &mut revision_body
    {
        *sequence = 1;
        *previous = Some(original);
        *operation = Operation::Revise {
            post: original,
            text: Text::new("#Wasm").unwrap(),
            supersedes: References::sorted(vec![original]).unwrap(),
        };
    }
    let raw = sign_revision(
        &key,
        revision_body,
        vec![Facet {
            start: 0,
            end: 5,
            kind: Kind::Tag("wasm".into()),
        }],
        Encoding::NewOpcodesV1,
    )
    .unwrap();
    println!(
        "faceted-revision-v1 {} {}",
        hex(verify_revision(&raw).unwrap().id().as_bytes()),
        hex(&raw)
    );
    let legacy = UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap()
        .finish()
        .unwrap();
    println!(
        "legacy-post-v1 {} {}",
        hex(legacy.id().as_bytes()),
        hex(&legacy.encode())
    );
}
