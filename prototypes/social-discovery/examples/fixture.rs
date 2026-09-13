#![allow(dead_code)]
use ed25519_dalek::SigningKey;
use vhalla_core::{RealmId, RoomId};
use vhalla_social::{
    archive::{Archive, Limits},
    *,
};

pub const REALM: RealmId = RealmId(7);

pub fn limits() -> Limits {
    Limits {
        records: 4096,
        control_reserve: 64,
        data_per_owner: 63,
        data_per_writer: 63,
        control_per_owner: 1,
        pending: 256,
        pending_per_signer: 64,
    }
}
fn signed(key: &SigningKey, body: Body) -> SignedRecord {
    UnsignedRecord::new(key.verifying_key().to_bytes(), body)
        .unwrap()
        .sign_with_key(key)
        .unwrap()
        .finish()
        .unwrap()
}

/// Every 64 records is one independent owner, 62 posts, and an accepting Seal.
/// This is a real signed archive at the selected hard cap, not 4,096 extra posts.
pub fn corpus(count: usize, text_bytes: usize) -> Vec<u8> {
    assert!(count > 0 && count <= 4096 && count.is_multiple_of(64));
    let mut records = Vec::new();
    for owner_index in 0..count / 64 {
        let key = SigningKey::from_bytes(&[(owner_index + 1) as u8; 32]);
        let genesis = signed(
            &key,
            Body::OwnerGenesis {
                controller: key.verifying_key().to_bytes(),
                recovery: None,
                nonce: [(owner_index + 1) as u8; 32],
            },
        );
        let control = genesis.id();
        let owner = OwnerId::from_bytes(*control.as_bytes());
        records.push(genesis);
        let mut previous = None;
        for i in 0..62 {
            let prefix = format!("owner {owner_index} record {i} Rust WASM café proof budget ");
            let body = if text_bytes <= prefix.len() {
                prefix
            } else {
                let fill: String = (0..text_bytes - prefix.len())
                    .map(|j| {
                        // Deterministic varied ASCII is deliberately less compressible
                        // in trigrams than repeating filler; this is not random entropy.
                        char::from(b'a' + ((j * 17 + j / 31 + i * 13) % 26) as u8)
                    })
                    .collect();
                prefix + &fill
            };
            let record = signed(
                &key,
                Body::Social {
                    actor: Actor::Owner { owner, control },
                    realm: REALM,
                    sequence: i as u64,
                    previous,
                    operation: Operation::Post {
                        placement: Placement::Channel(RoomId((i % 4) as u128)),
                        text: Text::new(&body).unwrap(),
                        reply: None,
                        quote: None,
                    },
                },
            );
            previous = Some(record.id());
            records.push(record);
        }
        records.push(signed(
            &key,
            Body::Control {
                owner,
                previous: control,
                action: ControlAction::Seal {
                    realm: REALM,
                    heads: References::new(vec![previous.unwrap()]).unwrap(),
                },
            },
        ));
    }
    records.sort_by_key(SignedRecord::id);
    let mut out = b"VHSA\0\0\0\x01".to_vec();
    out.extend_from_slice(&REALM.0.to_be_bytes());
    out.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for r in records {
        let bytes = r.encode();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
    }
    out
}
pub fn archive(count: usize, text_bytes: usize) -> Archive {
    Archive::from_snapshot(REALM, limits(), &corpus(count, text_bytes)).unwrap()
}
fn main() {}
