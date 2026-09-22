use super::*;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_private_kernel::protocol::{AnchorId, Key, PrivateRoomScope, RoomId};

#[test]
fn archive_file_interrupted_output_is_preserved_and_never_accepted_as_complete() {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "vhalla-archive-framing-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes([1; 32]).unwrap(),
            anchor: AnchorId::from_bytes([2; 32]).unwrap(),
        },
        account: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
        device: Key::from_bytes(
            ed25519_dalek::SigningKey::from_bytes(&[4; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap(),
    };
    let bounds = Bounds::new(Limits {
        max_records: 2,
        max_record_bytes: 1024,
    })
    .unwrap();
    let path = root.join("interrupted.vharchive");
    let mut writer = Writer::create(&path, bounds, context, [5; 32]).unwrap();
    // Framing only: these are deliberately not authenticated kernel pages.
    writer.page(&[8; 32]).unwrap();
    drop(writer); // Simulate caller loss before the final page/end marker.
    let before = fs::read(&path).unwrap();
    let mut reader = Reader::open(&path, bounds).unwrap();
    assert_eq!(reader.next_page().unwrap().unwrap(), [8; 32]);
    assert!(reader.next_page().is_err());
    drop(reader);
    assert!(Writer::create(&path, bounds, context, [6; 32]).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(Bounds::new(Limits {
        max_records: u64::MAX,
        max_record_bytes: u64::MAX
    })
    .is_err());
    fs::remove_dir_all(root).unwrap();
}
