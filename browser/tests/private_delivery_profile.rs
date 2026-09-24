//! Shipping profile selection, exercised without a JS or network mock.
#![cfg(feature = "private-rooms")]
#[path = "../src/private/delivery_profile.rs"]
mod profile;

use profile::{select, Mode};
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context,
};

fn context() -> Context {
    let mut point = [0x66; 32];
    point[0] = 0x58;
    Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(point).unwrap(),
        device: Key::from_bytes(point).unwrap(),
    }
}

fn encoded(format: u8, origin: &str) -> serde_json::Value {
    serde_json::json!({"format": format, "origin": origin, "namespace": "03".repeat(32),
        "capability": "04".repeat(32), "initial_cursor": "0"})
}

fn bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

#[test]
fn retained_loopback_binding_is_byte_identical_and_credentials_do_not_rebind() {
    let origin = "http://127.0.0.1:8790";
    let mut value = encoded(1, origin);
    let old = select(&bytes(&value), origin, true).unwrap();
    assert_eq!(old.mode, Mode::Loopback);
    let hex: String = old
        .binding(context())
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect();
    assert_eq!(
        hex,
        "75951ff09094e49256ba2d297a1bddde18500edfc38619e9c0d8f98eb0dfa9ed"
    );
    value["capability"] = "05".repeat(32).into();
    let rotated = select(&bytes(&value), origin, true).unwrap();
    assert_eq!(rotated.binding(context()), old.binding(context()));
    assert_ne!(*rotated.capability, *old.capability);
}

#[test]
fn https_requires_explicit_format_and_secure_same_origin() {
    let https = "https://rooms.example.com";
    let selected = select(&bytes(&encoded(2, https)), https, true).unwrap();
    assert_eq!(selected.mode, Mode::Https);
    assert!(select(&bytes(&encoded(1, https)), https, true).is_err());
    assert!(select(&bytes(&encoded(2, https)), https, false).is_err());
    assert!(select(
        &bytes(&encoded(2, https)),
        "https://other.example.com",
        true
    )
    .is_err());
    for format in [0, 3, 255] {
        assert!(select(&bytes(&encoded(format, https)), https, true).is_err());
    }
    for origin in [
        "http://127.0.0.1:8790",
        "http://rooms.example.com",
        "https://rooms.example.com/",
        "https://rooms.example.com:443",
        "https://rooms.example.com:0443",
        "https://ROOMS.example.com",
        "https://rooms.example.com.",
        "https://user@rooms.example.com",
        "https://rooms.example.com?target=x",
        "https://rooms.example.com#secret",
        "https://127.0.0.1:8790",
    ] {
        assert!(
            select(&bytes(&encoded(2, origin)), origin, true).is_err(),
            "{origin}"
        );
    }
}

#[test]
fn malformed_profile_never_selects_transport_authority() {
    let origin = "https://rooms.example.com";
    for field in ["capability", "namespace"] {
        for invalid in [
            "00".repeat(32),
            "AA".repeat(32),
            "01".repeat(31),
            "01".repeat(33),
        ] {
            let mut value = encoded(2, origin);
            value[field] = invalid.into();
            assert!(select(&bytes(&value), origin, true).is_err());
        }
    }
    for invalid in ["-1", "00", "01", "+1", "4097", "18446744073709551616"] {
        let mut value = encoded(2, origin);
        value["initial_cursor"] = invalid.into();
        assert!(select(&bytes(&value), origin, true).is_err());
    }
    let mut unknown = encoded(2, origin);
    unknown["upstream_token"] = "06".repeat(32).into();
    assert!(select(&bytes(&unknown), origin, true).is_err());
    let duplicate = String::from_utf8(bytes(&encoded(2, origin)))
        .unwrap()
        .replace("\"format\":2", "\"format\":2,\"format\":1");
    assert!(select(duplicate.as_bytes(), origin, true).is_err());
    assert!(select(&vec![b' '; 4097], origin, true).is_err());
}

#[test]
fn retained_binding_covers_each_context_and_transport_scope() {
    let origin = "https://rooms.example.com";
    let selected = select(&bytes(&encoded(2, origin)), origin, true).unwrap();
    let original = selected.binding(context());
    for field in ["origin", "namespace", "initial_cursor"] {
        let mut value = encoded(2, origin);
        value[field] = match field {
            "origin" => "https://other.example.com".into(),
            "namespace" => "07".repeat(32).into(),
            _ => "1".into(),
        };
        let changed = select(&bytes(&value), value["origin"].as_str().unwrap(), true).unwrap();
        assert_ne!(original, changed.binding(context()), "{field}");
    }
    for field in 0..4 {
        let mut changed = context();
        let other = Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        match field {
            0 => changed.scope.room = RoomId::from_bytes([8; 32]).unwrap(),
            1 => changed.scope.anchor = AnchorId::from_bytes([8; 32]).unwrap(),
            2 => changed.account = other,
            _ => changed.device = other,
        }
        assert_ne!(original, selected.binding(changed));
    }
    // Even an internal accidental mode substitution cannot reinterpret old
    // binding bytes as a hosted profile; parse separately forbids this input.
    let mut changed = selected;
    changed.mode = Mode::Loopback;
    assert_ne!(original, changed.binding(context()));
}
