use super::*;
use alloc::vec;

#[test]
fn activity_targets_body_hashes_and_bounds_are_canonical() {
    let post = ActivityRequest::post([1; 32], [2; 32], b"signed bytes").unwrap();
    assert_eq!(ActivityRequest::parse_target(&post.target()), Ok(post));
    assert!(post.check_body(b"signed byteS").is_err());
    assert!(ActivityRequest::post([0; 32], [2; 32], b"x").is_err());
    assert!(ActivityRequest::post([1; 32], [2; 32], &vec![0; MAX_EVENT_BYTES + 1]).is_err());
    for count in [0, 33, 255] {
        assert!(ActivityRequest::page([1; 32], [2; 32], 0, count).is_err());
    }
    let page = ActivityRequest::page([1; 32], [2; 32], 0, 32).unwrap();
    assert_eq!(ActivityRequest::parse_target(&page.target()), Ok(page));
    for target in [
        page.target().replace("after=0", "after=00"),
        format!("{}&extra=1", page.target()),
        page.target().replace("count=32", "count=256"),
        post.target().replace("event=", "Event="),
    ] {
        assert!(ActivityRequest::parse_target(&target).is_err());
    }
}

#[test]
fn activity_proof_binds_every_byte_nonce_operation_network_and_peer() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = key.verifying_key().to_bytes();
    let request = ActivityRequest::page([1; 32], [2; 32], 0, 3).unwrap();
    let body = ActivityPage::new(&request, 0, 7, [9; 32], vec![])
        .unwrap()
        .encode();
    let proof = UnsignedActivityResponse::new([3; 32], public, request, &body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap();
    proof.verify([3; 32], public, &request, &body).unwrap();
    let raw = proof.encode();
    assert_eq!(proof_from_hex(&hex(&raw)).unwrap(), proof);
    for at in 0..raw.len() {
        let mut tampered = raw.clone();
        tampered[at] ^= 1;
        assert!(
            ActivityResponseProof::decode(&tampered)
                .and_then(|p| p.verify([3; 32], public, &request, &body))
                .is_err(),
            "byte {at}"
        );
    }
    for at in 0..body.len() {
        let mut tampered = body.clone();
        tampered[at] ^= 1;
        assert!(proof.verify([3; 32], public, &request, &tampered).is_err());
    }
    assert!(proof.verify([4; 32], public, &request, &body).is_err());
    assert!(proof
        .verify(
            [3; 32],
            SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
            &request,
            &body
        )
        .is_err());
    for wrong in [
        ActivityRequest::page([9; 32], [2; 32], 0, 3).unwrap(),
        ActivityRequest::page([1; 32], [8; 32], 0, 3).unwrap(),
        ActivityRequest::page([1; 32], [2; 32], 0, 2).unwrap(),
        ActivityRequest::post([1; 32], [2; 32], b"x").unwrap(),
    ] {
        assert!(proof.verify([3; 32], public, &wrong, &body).is_err());
    }
    assert!(crate::response::PeerResponseProof::decode(&raw).is_err());
    assert!(proof_from_hex(&hex(&raw).to_uppercase()).is_err());
}

#[test]
fn activity_page_never_claims_missing_history_or_accepts_trailing_bytes() {
    let request = ActivityRequest::page([1; 32], [2; 32], 0, 1).unwrap();
    assert!(ActivityPage::new(&request, 1, 2, [3; 32], vec![]).is_err());
    let body = ActivityPage::new(&request, 0, 2, [3; 32], vec![])
        .unwrap()
        .encode();
    for len in 0..body.len() {
        assert!(ActivityPage::decode(&body[..len], &request).is_err());
    }
    let mut extra = body.clone();
    extra.push(0);
    assert!(ActivityPage::decode(&extra, &request).is_err());
    assert_eq!(
        ActivityPage::decode(&body, &request)
            .unwrap()
            .observed_height(),
        2
    );
}
