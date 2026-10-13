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
fn frozen_v1_item_bytes() -> Vec<u8> {
    bytes(
        "56485052454c4159010909090909090909090909090909090909090909090909090909090909090909000000000000000101010101010101010101010101010101050000000a63697068657274657874c244c1e36896476b54aca9f9241462c6b8f759e8910a92bd4d56aaeab52b86e2",
    )
}
#[test]
fn frozen_v1_item_and_page_request_bytes_survive_extraction() {
    let raw = frozen_v1_item_bytes();
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
fn retention_receipt_refuses_corruption() {
    let item = RelayItem::decode(&frozen_v1_item_bytes()).unwrap();
    let different_item = RelayItem::new(
        item.namespace(),
        item.sequence(),
        item.operation(),
        item.kind(),
        b"different ciphertext",
    )
    .unwrap();
    assert_ne!(different_item.digest(), item.digest());

    // This wire receipt claims local retention, never recipient delivery.
    // Matching the item digest and requiring a nonzero position do not prove
    // relay custody or authenticate the mailbox position.
    for duplicate in [false, true] {
        let receipt = RelayReceipt {
            position: 8,
            digest: item.digest(),
            duplicate,
        };
        let raw = encode_receipt(receipt);
        assert_eq!(raw.len(), 41);
        assert_eq!(&raw[..8], &8u64.to_be_bytes());
        assert_eq!(&raw[8..40], &item.digest());
        assert_eq!(raw[40], u8::from(duplicate));
        assert_eq!(decode_receipt(&raw, &item), Ok(receipt));
        assert_eq!(
            decode_receipt(&raw, &different_item),
            Err(NetError::Malformed)
        );

        for len in 0..raw.len() {
            assert_eq!(
                decode_receipt(&raw[..len], &item),
                Err(NetError::Malformed),
                "accepted prefix {len} (duplicate={duplicate})"
            );
        }
        for trailing in u8::MIN..=u8::MAX {
            let mut corrupt = raw.clone();
            corrupt.push(trailing);
            assert_eq!(
                decode_receipt(&corrupt, &item),
                Err(NetError::Malformed),
                "accepted trailing byte {trailing} (duplicate={duplicate})"
            );
        }
        let mut zero = raw.clone();
        zero[..8].fill(0);
        assert_eq!(decode_receipt(&zero, &item), Err(NetError::Malformed));

        for index in 8..40 {
            for bit in 0..8 {
                let mut corrupt = raw.clone();
                corrupt[index] ^= 1u8 << bit;
                assert_eq!(
                    decode_receipt(&corrupt, &item),
                    Err(NetError::Malformed),
                    "accepted digest byte {index}, bit {bit} (duplicate={duplicate})"
                );
            }
        }
        for flag in 2..=u8::MAX {
            let mut corrupt = raw.clone();
            corrupt[40] = flag;
            assert_eq!(
                decode_receipt(&corrupt, &item),
                Err(NetError::Malformed),
                "accepted noncanonical flag {flag}"
            );
        }
    }
}

#[test]
fn relay_item_single_bit_mutations_refuse() {
    let raw = frozen_v1_item_bytes();
    assert_eq!(RelayItem::decode(&raw).unwrap().encode().unwrap(), raw);

    // Cover every bit of the frozen valid item, including header, ciphertext,
    // and retained digest. A malformed item cannot produce a retention receipt.
    for byte_index in 0..raw.len() {
        for bit in 0..8 {
            let mut changed = raw.clone();
            changed[byte_index] ^= 1u8 << bit;
            assert!(
                RelayItem::decode(&changed).is_err(),
                "accepted byte {byte_index}, bit {bit}"
            );
        }
    }
    for len in 0..raw.len() {
        assert!(
            RelayItem::decode(&raw[..len]).is_err(),
            "accepted prefix {len}"
        );
    }
    for trailing in u8::MIN..=u8::MAX {
        let mut changed = raw.clone();
        changed.push(trailing);
        assert!(
            RelayItem::decode(&changed).is_err(),
            "accepted trailing byte {trailing}"
        );
    }
}

#[test]
fn byte_cap_pages_keep_mailbox_positions_and_reject_corrupt_continuations() {
    let namespace = RelayNamespace::from_bytes([9; 32]).unwrap();
    let records: Vec<_> = (1..=16u8)
        .map(|position| PositionedItem {
            position: u64::from(position),
            item: RelayItem::new(
                namespace,
                // Sender-local sequences overlap; only mailbox positions page.
                1 + u64::from(position % 2),
                OperationId::from_bytes([position; 16]).unwrap(),
                OutboxKind::Application,
                &vec![position; MAX_RELAY_PAYLOAD],
            )
            .unwrap(),
        })
        .collect();
    let item_bytes = records[0].item.encode().unwrap().len();
    assert!(11 + 15 * (12 + item_bytes) <= MAX_PAGE_BODY);
    assert!(11 + 16 * (12 + item_bytes) > MAX_PAGE_BODY);

    let first = encode_page(&RelayPage {
        head: 16,
        next: None,
        records: records.clone(),
    })
    .unwrap();
    assert!(first.len() <= MAX_PAGE_BODY);
    let first_page = decode_page(&first, 0, MAX_RELAY_PAGE).unwrap();
    assert_eq!(first_page.head, 16);
    assert_eq!(first_page.records, records[..15]);
    let cursor = first_page.next.unwrap();
    assert_eq!(cursor, 15);
    assert_eq!(
        page_request(cursor, MAX_RELAY_PAGE).unwrap()[..8],
        cursor.to_be_bytes()
    );

    // A truncated page cannot silently claim completion or yield a new cursor
    // if its continuation, head, count, position, item length or digest is corrupt.
    let refused = |body: &[u8]| {
        assert!(matches!(
            decode_page(body, 0, MAX_RELAY_PAGE),
            Err(NetError::Malformed)
        ));
    };
    let mut corrupt = first.clone();
    corrupt[8] = 0; // Lost continuation despite a retained head of 16.
    refused(&corrupt);
    let mut corrupt = first.clone();
    corrupt[8] = 2; // Noncanonical continuation flag.
    refused(&corrupt);
    for head in [cursor - 1, cursor] {
        let mut corrupt = first.clone();
        corrupt[..8].copy_from_slice(&head.to_be_bytes());
        // Below the last retained position, or falsely complete with more set.
        refused(&corrupt);
    }
    for count in [14u16, 16, (MAX_RELAY_PAGE + 1) as u16] {
        let mut corrupt = first.clone();
        corrupt[9..11].copy_from_slice(&count.to_be_bytes());
        // Too few leaves trailing records; too many lacks bytes or exceeds the limit.
        refused(&corrupt);
    }
    let mut corrupt = first.clone();
    corrupt[11..19].copy_from_slice(&2u64.to_be_bytes());
    refused(&corrupt);
    let mut corrupt = first.clone();
    corrupt[19..23].copy_from_slice(&((item_bytes + 1) as u32).to_be_bytes());
    refused(&corrupt);
    let mut corrupt = first.clone();
    corrupt[23 + item_bytes - 1] ^= 1; // Break the first item's digest.
    refused(&corrupt);

    // The response from the exact exclusive cursor recovers the sole remaining
    // item. Neither a skipped nor a replayed cursor can accept that response.
    let rest = encode_page(&RelayPage {
        head: 16,
        next: None,
        records: records
            .iter()
            .filter(|record| record.position > cursor)
            .cloned()
            .collect(),
    })
    .unwrap();
    for wrong_cursor in [cursor - 1, cursor + 1] {
        assert!(matches!(
            decode_page(&rest, wrong_cursor, MAX_RELAY_PAGE),
            Err(NetError::Malformed)
        ));
    }
    let last_page = decode_page(&rest, cursor, MAX_RELAY_PAGE).unwrap();
    assert_eq!(last_page.head, 16);
    assert_eq!(last_page.next, None);
    assert_eq!(last_page.records, records[15..]);
    let mut collected = first_page.records;
    collected.extend(last_page.records);
    assert_eq!(collected, records);
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
