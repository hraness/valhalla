use super::*;
use vhalla_social::{Body, OwnerId};

const PASSWORD: &[u8] = b"Valhalla public fixture password v1";

fn seed() -> Zeroizing<[u8; 32]> {
    Zeroizing::new(core::array::from_fn(|i| i as u8))
}

fn salt() -> [u8; 16] {
    core::array::from_fn(|i| (i + 32) as u8)
}

fn nonce() -> [u8; 24] {
    core::array::from_fn(|i| (i + 48) as u8)
}

fn decode_fixture(text: &str) -> [u8; ENVELOPE_BYTES] {
    let hex = text.trim();
    assert_eq!(hex.len(), 2 * ENVELOPE_BYTES);
    core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
}

fn fixture() -> [u8; ENVELOPE_BYTES] {
    decode_fixture(include_str!("../vectors/v1-envelope.hex"))
}

#[test]
fn frozen_libsodium_envelope_round_trips_and_signs_only_typed_social_requests() {
    // Independent libsodium 1.0.20 fixture; the test uses production KDF costs.
    let expected = fixture();
    let sealed = seal(seed(), PASSWORD, salt(), nonce()).unwrap();
    assert_eq!(sealed.as_bytes(), &expected);
    assert_eq!(
        Envelope::from_bytes(&expected).unwrap().as_bytes(),
        &expected
    );
    let identity = unlock(&expected, PASSWORD).unwrap();
    assert_eq!(identity.public_key(), sealed.claimed_public_key());
    let request = UnsignedRecord::new(
        identity.public_key(),
        Body::OwnerGenesis {
            controller: identity.public_key(),
            recovery: None,
            nonce: [92; 32],
        },
    )
    .unwrap();
    let signed = identity.sign_social(request).unwrap().finish().unwrap();
    assert!(signed.verify().is_ok());

    let owner = SigningKey::from_bytes(&[1; 32]);
    let owner_public = owner.verifying_key().to_bytes();
    let owner_request = UnsignedRecord::new(
        owner_public,
        Body::OwnerGenesis {
            controller: owner_public,
            recovery: None,
            nonce: [93; 32],
        },
    )
    .unwrap();
    assert!(matches!(
        identity.sign_social(owner_request.clone()),
        Err(vhalla_social::Error::SigningKey)
    ));
    let owner_record = owner_request
        .sign_with_key(&owner)
        .unwrap()
        .finish()
        .unwrap();
    let agent_request = UnsignedRecord::new(
        owner_public,
        Body::AgentGenesis {
            owner: OwnerId::from_bytes(*owner_record.id().as_bytes()),
            control: owner_record.id(),
            key: identity.public_key(),
            nonce: [94; 32],
        },
    )
    .unwrap();
    let agent_record = identity
        .countersign_social(agent_request.sign_with_key(&owner).unwrap())
        .unwrap();
    assert!(agent_record.verify().is_ok());
    assert!(matches!(
        identity.countersign_social(
            UnsignedRecord::new(
                owner_public,
                Body::OwnerGenesis {
                    controller: owner_public,
                    recovery: None,
                    nonce: [95; 32],
                },
            )
            .unwrap()
            .sign_with_key(&owner)
            .unwrap()
        ),
        Err(vhalla_social::Error::SigningKey)
    ));
}

#[test]
fn wrong_password_and_every_authenticated_field_class_fail_closed() {
    let original = fixture();
    assert!(matches!(
        unlock(&original, b"Another sufficiently long password"),
        Err(Error::Authentication)
    ));
    // Sample each independent authenticated field, not hundreds of repeated KDFs.
    for index in [SALT_START, NONCE_START, CIPHER_START, TAG_START] {
        let mut changed = original;
        changed[index] ^= 1;
        assert!(matches!(
            unlock(&changed, PASSWORD),
            Err(Error::Authentication)
        ));
    }
    let mut changed = original;
    changed[PUBLIC_START..CIPHER_START]
        .copy_from_slice(&SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes());
    assert!(matches!(
        unlock(&changed, PASSWORD),
        Err(Error::Authentication)
    ));
    // This independently generated envelope has a VALID AEAD tag for the wrong
    // public-key header. Its decrypted seed must still fail the identity binding.
    let authenticated_mismatch = decode_fixture(include_str!("../vectors/v1-wrong-public.hex"));
    assert!(matches!(
        unlock(&authenticated_mismatch, PASSWORD),
        Err(Error::Authentication)
    ));
}

#[test]
fn independent_salt_nonce_and_password_change_the_envelope_not_the_identity() {
    let original = fixture();
    let expected_public = Envelope::from_bytes(&original)
        .unwrap()
        .claimed_public_key();
    let mut other_nonce = nonce();
    other_nonce[0] ^= 1;
    let mut other_salt = salt();
    other_salt[0] ^= 1;
    let new_password = b"A different public fixture password v1";
    let alternatives = [
        (
            seal(seed(), PASSWORD, salt(), other_nonce).unwrap(),
            PASSWORD,
        ),
        (
            seal(seed(), PASSWORD, other_salt, nonce()).unwrap(),
            PASSWORD,
        ),
        (
            seal(seed(), new_password, salt(), nonce()).unwrap(),
            new_password.as_slice(),
        ),
    ];
    for (changed, password) in alternatives {
        assert_ne!(changed.as_bytes(), &original);
        assert_ne!(
            &changed.as_bytes()[CIPHER_START..],
            &original[CIPHER_START..]
        );
        assert_eq!(
            unlock(changed.as_bytes(), password).unwrap().public_key(),
            expected_public
        );
    }
}

#[test]
fn exact_format_and_password_bounds_reject_before_kdf_work() {
    let original = fixture();
    for len in 0..ENVELOPE_BYTES {
        assert!(matches!(
            unlock(&original[..len], PASSWORD),
            Err(Error::Malformed)
        ));
    }
    let mut extra = original.to_vec();
    extra.push(0);
    assert!(matches!(unlock(&extra, PASSWORD), Err(Error::Malformed)));
    for index in 0..MAGIC.len() {
        let mut changed = original;
        changed[index] ^= 1;
        assert!(matches!(unlock(&changed, PASSWORD), Err(Error::Malformed)));
    }
    let mut weak_public = original;
    weak_public[PUBLIC_START..CIPHER_START].fill(0);
    assert!(matches!(
        unlock(&weak_public, PASSWORD),
        Err(Error::Malformed)
    ));
    for password in [
        &b""[..],
        &b"too short"[..],
        &[0; MAX_PASSWORD_BYTES + 1][..],
    ] {
        assert!(matches!(
            seal(seed(), password, salt(), nonce()),
            Err(Error::PasswordBounds)
        ));
        assert!(matches!(
            unlock(&original, password),
            Err(Error::PasswordBounds)
        ));
    }
    assert_eq!(check_password(&[0; MIN_PASSWORD_BYTES]), Ok(()));
    assert_eq!(check_password(&[0; MAX_PASSWORD_BYTES]), Ok(()));
}
