use super::*;
use alloc::vec;

fn request() -> ReadRequest {
    ReadRequest::new(
        [7; 32],
        ReadKind::Bundles {
            after: 12,
            frontier: [9; 32],
            count: 3,
            bytes: 4096,
        },
    )
    .unwrap()
}
fn signed(request: ReadRequest, body: &[u8]) -> (SigningKey, PeerResponseProof) {
    let key = SigningKey::from_bytes(&[42; 32]);
    let proof = UnsignedResponse::new([5; 32], key.verifying_key().to_bytes(), request, body)
        .unwrap()
        .sign_with_key(&key)
        .unwrap();
    (key, proof)
}
#[test]
fn strict_requests_roundtrip_and_reject_ambiguous_targets() {
    for kind in [
        ReadKind::Advertisement,
        ReadKind::Bootstrap,
        request().kind(),
    ] {
        let request = ReadRequest::new([7; 32], kind).unwrap();
        assert_eq!(ReadRequest::parse_target(&request.target()), Ok(request));
        for suffix in ["&nonce=11", "#a", " ", "&x=1"] {
            assert!(ReadRequest::parse_target(&(request.target() + suffix)).is_err());
        }
    }
    let valid = request().target();
    for bad in [
        valid.replace("after=12", "after=012"),
        valid.replace("count=3", "count=0"),
        valid.replace("count=3", "count=33"),
        valid.replace("bytes=4096", "bytes=2097153"),
        valid.replace("after=12", "after=18446744073709551616"),
        valid.replace("0707", "07%37"),
        valid.replace("frontier=09", "frontier=0A"),
    ] {
        assert!(ReadRequest::parse_target(&bad).is_err(), "{bad}");
    }
    assert!(ReadRequest::parse_target(&"x".repeat(MAX_REQUEST_TARGET + 1)).is_err());
    assert_eq!(
        ReadRequest::new([0; 32], ReadKind::Bootstrap),
        Err(ResponseError::Nonce)
    );
}
#[test]
fn proof_binds_nonce_full_peer_network_exact_request_and_body() {
    let request = request();
    let body = b"opaque page";
    let (key, proof) = signed(request, body);
    let public = key.verifying_key().to_bytes();
    let decoded = proof_from_hex(&hex(&proof.encode())).unwrap();
    assert_eq!(decoded, proof);
    assert_eq!(
        decoded
            .verify([5; 32], public, &request, body)
            .unwrap()
            .body_hash(),
        <[u8; 32]>::from(Sha256::digest(body))
    );
    assert_eq!(
        decoded.verify([6; 32], public, &request, body),
        Err(ResponseError::Network)
    );
    assert_eq!(
        decoded.verify([5; 32], [3; 32], &request, body),
        Err(ResponseError::Peer)
    );
    let fresh = ReadRequest::new([8; 32], request.kind()).unwrap();
    assert_eq!(
        decoded.verify([5; 32], public, &fresh, body),
        Err(ResponseError::Nonce)
    );
    let different = ReadRequest::new(request.nonce(), ReadKind::Bootstrap).unwrap();
    assert_eq!(
        decoded.verify([5; 32], public, &different, body),
        Err(ResponseError::Request)
    );
    assert_eq!(
        decoded.verify([5; 32], public, &request, b"tampered"),
        Err(ResponseError::Body)
    );
    let mut changed = proof.encode();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(
        PeerResponseProof::decode(&changed)
            .unwrap()
            .verify([5; 32], public, &request, body),
        Err(ResponseError::Signature)
    );
}
#[test]
fn malformed_proofs_and_weak_signers_fail_closed() {
    let (key, proof) = signed(request(), b"page");
    let raw = proof.encode();
    for length in 0..raw.len() {
        assert!(PeerResponseProof::decode(&raw[..length]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(PeerResponseProof::decode(&trailing).is_err());
    let mut weak = raw.clone();
    weak[37..69].fill(0);
    weak[37] = 1;
    assert_eq!(PeerResponseProof::decode(&weak), Err(ResponseError::Peer));
    assert_eq!(
        UnsignedResponse::new([0; 32], key.verifying_key().to_bytes(), request(), b"x"),
        Err(ResponseError::Network)
    );
    assert!(proof_from_hex(&hex(&raw).to_uppercase()).is_err());
    assert!(proof_from_hex(&"a".repeat(MAX_RESPONSE_PROOF_BYTES * 2 + 2)).is_err());
}
#[test]
fn bounded_pages_bind_continuation_and_reject_noncanonical_framing() {
    let request = request();
    let page = BundlePage::new(&request, 20, [4; 32], vec![vec![1; 300], vec![2; 400]]).unwrap();
    assert_eq!(page.next_after(), 14);
    assert!(page.has_more());
    let raw = page.encode();
    assert_eq!(BundlePage::decode(&raw, &request), Ok(page));
    let mut corrupt = raw.clone();
    corrupt[45..53].copy_from_slice(&15u64.to_be_bytes());
    assert!(BundlePage::decode(&corrupt, &request).is_err());
    let mut trailing = raw;
    trailing.push(0);
    assert!(BundlePage::decode(&trailing, &request).is_err());
    assert!(BundlePage::new(&request, 20, [4; 32], vec![]).is_err());
    assert!(BundlePage::new(&request, 12, [4; 32], vec![vec![1]]).is_err());
    assert!(BundlePage::new(&request, 20, [4; 32], vec![vec![0; 4097]]).is_err());
    assert!(BundlePage::new(&request, 20, [4; 32], vec![vec![1]; 4]).is_err());
    assert!(BundlePage::new(&request, 20, [4; 32], vec![vec![]]).is_err());
    let end = ReadRequest::new(
        [7; 32],
        ReadKind::Bundles {
            after: u64::MAX,
            frontier: [9; 32],
            count: 1,
            bytes: 4096,
        },
    )
    .unwrap();
    assert!(BundlePage::new(&end, u64::MAX, [4; 32], vec![vec![1]]).is_err());
    assert!(!BundlePage::new(&end, u64::MAX, [4; 32], vec![])
        .unwrap()
        .has_more());
}
#[test]
fn body_hashing_has_per_kind_byte_ceiling() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = ReadRequest::new([7; 32], ReadKind::Advertisement).unwrap();
    assert!(UnsignedResponse::new(
        [5; 32],
        key.verifying_key().to_bytes(),
        request,
        &vec![0; crate::MAX_ADVERTISEMENT_BYTES + 1]
    )
    .is_err());
    assert!(ReadRequest::parse_target(&request.target().replace("nonce=", "nonce=%")).is_err());
    assert_eq!(decimal("0"), Ok(0));
    assert!(decimal("+1").is_err());
}
