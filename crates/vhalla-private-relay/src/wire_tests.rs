use super::*;
use crate::codec::*;
use std::time::Duration;
fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn frozen_v1_item_and_page_request_bytes_survive_extraction() {
    let raw = bytes(
        "56485052454c4159010909090909090909090909090909090909090909090909090909090909090909000000000000000101010101010101010101010101010101050000000a63697068657274657874c244c1e36896476b54aca9f9241462c6b8f759e8910a92bd4d56aaeab52b86e2",
    );
    let item = RelayItem::decode(&raw).unwrap();
    assert_eq!(item.encode().unwrap(), raw);
    assert_eq!(item.kind(), OutboxKind::Application);
    assert_eq!(item.payload(), b"ciphertext");
    assert_eq!(
        frame(OP_PAGE, &page_request(0x0102030405060708, 64).unwrap()),
        bytes("0000000b0201020304050607080040")
    );
    let receipt = RelayReceipt {
        position: 8,
        digest: item.digest(),
        duplicate: true,
    };
    assert_eq!(
        decode_receipt(&encode_receipt(receipt), &item).unwrap(),
        receipt
    );
    let page = RelayPage {
        head: 8,
        next: None,
        records: vec![PositionedItem {
            position: 8,
            item: item.clone(),
        }],
    };
    let decoded = decode_page(&encode_page(&page).unwrap(), 7, 1).unwrap();
    assert_eq!(decoded.records[0].item, item);
}
#[test]
fn hostile_frames_pages_status_and_receipt_are_bounded() {
    for raw in [
        vec![],
        vec![0; 4],
        vec![0, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
    ] {
        assert!(decode_frame(&raw, MAX_RESPONSE).is_err());
    }
    assert!(decode_frame(&frame(OP_PAGE, &[0; 10]), 5).is_err());
    assert!(decode_page(&[0; 11], 0, 65).is_err());
    assert!(decode_page(&vec![0; MAX_PAGE_BODY + 1], 0, 1).is_err());
    assert!(decode_status(STATUS_DENIED, b"secret").is_err());
    assert!(decode_status(255, b"").is_err());
    assert!(page_request(0, 0).is_err());
    assert!(page_request(0, 65).is_err());
    // A waited page request is the same head plus a two-byte wait bound;
    // a host that predates it answers bounds-refusal instead of hanging.
    assert_eq!(
        page_wait_request(0x0102030405060708, 64, Duration::from_secs(60)).unwrap(),
        bytes("01020304050607080040ea60")
    );
    assert_eq!(
        page_wait_request(9, 1, Duration::ZERO).unwrap(),
        page_request(9, 1)
            .unwrap()
            .into_iter()
            .chain([0, 0])
            .collect::<Vec<u8>>()
    );
    assert!(page_wait_request(0, 0, Duration::from_secs(1)).is_err());
    assert!(page_wait_request(0, 64, Duration::from_millis(65536)).is_err());
    let absent = decode_page(&[0; 11], 9, 1).unwrap();
    assert_eq!(absent.head, 0);
    assert!(absent.records.is_empty());
}
