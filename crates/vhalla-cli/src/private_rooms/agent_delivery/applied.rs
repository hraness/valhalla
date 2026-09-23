//! Closed host evidence and recoverable, no-clobber publication. No plaintext.
use super::{files, hex, unhex, OutboxKind, RelayItem, REFUSED};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::Path,
};
use vhalla_custody as custody;
use vhalla_private_kernel::Status;

const MAX_BYTES: usize = 2048;

fn number(value: &Value, key: &str, head: u64) -> Result<u64, String> {
    let text = value.get(key).and_then(Value::as_str).ok_or(REFUSED)?;
    let n: u64 = text.parse().map_err(|_| REFUSED)?;
    if n == 0 || n > head || n.to_string() != text {
        return Err(REFUSED.into());
    }
    Ok(n)
}

/// True requires exact kernel reauthentication below. JSON never authenticates
/// a member claim or a control transition, even when its shape is valid.
pub(super) fn validate(
    bytes: &[u8],
    item: &RelayItem,
    position: u64,
    status: Status,
    own_echo: bool,
    emit_acceptance: bool,
) -> Result<bool, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
    let object = value.as_object().ok_or(REFUSED)?;
    if serde_json::to_vec(&value).map_err(|_| REFUSED)? != bytes
        || value.get("digest").and_then(Value::as_str) != Some(hex(&item.digest()).as_str())
        || number(&value, "position", position)? != position
    {
        return Err(REFUSED.into());
    }
    let state = value.get("state").and_then(Value::as_str).ok_or(REFUSED)?;
    let mut fields = vec!["digest", "position", "state"];
    let mut reauthenticate = false;
    match state {
        "exact-local-outbox-echo" if own_echo => (),
        "locally-received" | "unmatched-receipt-content" | "recipient-device-claim"
            if item.kind() == OutboxKind::Application && !own_echo =>
        {
            fields.push("inbox_sequence");
            number(&value, "inbox_sequence", status.inbox_head)?;
            if state == "locally-received" && emit_acceptance {
                fields.push("receipt_outbox_sequence");
                number(&value, "receipt_outbox_sequence", status.outbox_head)?;
            }
            if state == "recipient-device-claim" {
                fields.extend(["outbox_sequence", "recipient", "recipient_inbox_sequence"]);
                number(&value, "outbox_sequence", status.outbox_head)?;
                number(&value, "recipient_inbox_sequence", u64::MAX)?;
                let recipient: [u8; 32] = unhex(
                    value
                        .get("recipient")
                        .and_then(Value::as_str)
                        .ok_or(REFUSED)?,
                )?;
                if recipient == [0; 32] || recipient == *status.context.device.as_bytes() {
                    return Err(REFUSED.into());
                }
                reauthenticate = true;
            }
        }
        "locally-applied-control"
            if !own_echo
                && matches!(
                    item.kind(),
                    OutboxKind::Removal | OutboxKind::OwnerUpdate | OutboxKind::Succession
                ) =>
        {
            // Current status is not the original control floor on retry. Use
            // exact retained ciphertext verification instead of a mutable floor
            // in the canonical marker; this also makes pending replay stable.
            reauthenticate = true;
        }
        "dedicated-bootstrap-command-required"
            if !own_echo
                && matches!(
                    item.kind(),
                    OutboxKind::ContactInvitation | OutboxKind::ContactRequest
                ) => {}
        _ => return Err(REFUSED.into()),
    }
    if fields.len() != object.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err(REFUSED.into());
    }
    Ok(reauthenticate)
}

/// Caller holds the driver root lock and has recomputed `expected` from exact
/// durable kernel evidence. Preserve every foreign or conflicting prefix.
pub(super) fn publish(path: &Path, expected: &[u8]) -> Result<(), String> {
    if expected.is_empty() || expected.len() > MAX_BYTES {
        return Err(REFUSED.into());
    }
    let parent = path.parent().ok_or(REFUSED)?;
    let (directory, uid) = custody::open_private_directory(parent).map_err(|_| REFUSED)?;
    if custody::private_file_present(path, uid, MAX_BYTES).map_err(|_| REFUSED)? {
        if files::read(path, MAX_BYTES, false)?.as_slice() != expected {
            return Err(REFUSED.into());
        }
        directory.sync_all().map_err(|_| REFUSED)?;
        return Ok(());
    }
    let pending = path.with_extension("pending");
    let mut file =
        if custody::private_file_present(&pending, uid, MAX_BYTES).map_err(|_| REFUSED)? {
            custody::open_private_file(&pending, uid, MAX_BYTES).map_err(|_| REFUSED)?
        } else {
            custody::create_private_file(&pending).map_err(|_| REFUSED)?
        };
    let mut prefix = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut prefix)
        .map_err(|_| REFUSED)?;
    if !expected.starts_with(&prefix) {
        return Err(REFUSED.into());
    }
    // Read left the exact owned descriptor at its end, so retry only appends
    // the missing suffix; it never truncates or overwrites retained evidence.
    file.write_all(&expected[prefix.len()..])
        .and_then(|()| file.sync_all())
        .map_err(|_| REFUSED)?;
    if files::read(&pending, MAX_BYTES, false)?.as_slice() != expected {
        return Err(REFUSED.into());
    }
    rename_new(
        &directory,
        pending.file_name().ok_or(REFUSED)?,
        path.file_name().ok_or(REFUSED)?,
    )?;
    directory.sync_all().map_err(|_| REFUSED)?;
    if files::read(path, MAX_BYTES, false)?.as_slice() != expected {
        return Err(REFUSED.into());
    }
    Ok(())
}

fn rename_new(
    directory: &std::fs::File,
    pending: &std::ffi::OsStr,
    target: &std::ffi::OsStr,
) -> Result<(), String> {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            directory,
            pending,
            directory,
            target,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| REFUSED.into())
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    )))]
    {
        let _ = (directory, pending, target);
        Err(REFUSED.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use vhalla_private_kernel::{
        protocol::{AnchorId, ControlFloor, Key, PrivateRoomScope, RoomId},
        Context, OperationId, Phase,
    };
    use vhalla_private_native::relay::RelayNamespace;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vhalla-applied-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            custody::create_private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn interrupted_marker_prefixes_complete_without_overwriting_evidence() {
        let directory = Directory::new();
        let expected = br#"{"digest":"synthetic","position":"1","state":"locally-received"}"#;
        for cut in 0..=expected.len() {
            let final_path = directory.0.join(format!("{cut:016x}.json"));
            let pending = final_path.with_extension("pending");
            files::write(&pending, &expected[..cut]).unwrap();
            publish(&final_path, expected).unwrap();
            assert_eq!(fs::read(&final_path).unwrap(), expected);
            assert!(!pending.exists());
            publish(&final_path, expected).unwrap();
            assert!(publish(&final_path, b"foreign replacement").is_err());
            assert_eq!(fs::read(&final_path).unwrap(), expected);
        }
    }

    #[test]
    fn foreign_pending_and_linked_files_are_preserved_and_refused() {
        let directory = Directory::new();
        let target = directory.0.join("0000000000000001.json");
        let pending = target.with_extension("pending");
        files::write(&pending, b"foreign").unwrap();
        assert!(publish(&target, b"expected").is_err());
        assert_eq!(fs::read(&pending).unwrap(), b"foreign");
        assert!(!target.exists());
        let other = directory.0.join("0000000000000002.json");
        std::os::unix::fs::symlink(&pending, other.with_extension("pending")).unwrap();
        assert!(publish(&other, b"foreign").is_err());
        assert!(!other.exists());
    }

    fn fixture(kind: OutboxKind) -> (RelayItem, Status) {
        let key = |n| {
            Key::from_bytes(
                ed25519_dalek::SigningKey::from_bytes(&[n; 32])
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap()
        };
        let context = Context {
            scope: PrivateRoomScope {
                room: RoomId::from_bytes([1; 32]).unwrap(),
                anchor: AnchorId::from_bytes([2; 32]).unwrap(),
            },
            account: key(3),
            device: key(4),
        };
        let floor = ControlFloor::new(0, None).unwrap();
        let status = Status {
            context,
            phase: Phase::MemberJoined,
            epoch: 1,
            clock: 0,
            control_sequence: 0,
            control_floor: floor,
            outbox_head: 3,
            inbox_head: 2,
            history_base: floor,
            roster: [5; 32],
            members: 2,
            quarantined: false,
        };
        let item = RelayItem::new(
            RelayNamespace::from_bytes([6; 32]).unwrap(),
            1,
            OperationId::from_bytes([7; 16]).unwrap(),
            kind,
            b"synthetic ciphertext",
        )
        .unwrap();
        (item, status)
    }

    #[test]
    fn marker_states_positions_kinds_and_local_heads_are_closed() {
        let (item, status) = fixture(OutboxKind::Application);
        let base = json!({"digest":hex(&item.digest()),"position":"1","state":"locally-received","inbox_sequence":"2"});
        let check = |v: &Value, own, emit| {
            validate(&serde_json::to_vec(v).unwrap(), &item, 1, status, own, emit)
        };
        assert!(!check(&base, false, false).unwrap());
        assert!(check(&base, false, true).is_err());
        assert!(check(&base, true, false).is_err());
        for (key, value) in [
            ("state", json!("unknown")),
            ("position", json!("2")),
            ("inbox_sequence", json!("3")),
            ("inbox_sequence", json!("0")),
            ("inbox_sequence", json!("02")),
            ("digest", json!(hex(&[9; 32]))),
            ("extra", json!(true)),
        ] {
            let mut bad = base.clone();
            bad[key] = value;
            assert!(check(&bad, false, false).is_err(), "{key}");
        }
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("state");
        assert!(check(&missing, false, false).is_err());
        let echo =
            json!({"digest":hex(&item.digest()),"position":"1","state":"exact-local-outbox-echo"});
        assert!(!check(&echo, true, false).unwrap());
        assert!(check(&echo, false, false).is_err());
        let (control, _) = fixture(OutboxKind::OwnerUpdate);
        let marker = json!({"digest":hex(&control.digest()),"position":"1","state":"locally-applied-control"});
        assert!(validate(
            &serde_json::to_vec(&marker).unwrap(),
            &control,
            1,
            status,
            false,
            false
        )
        .unwrap());
        let mut wrong_kind = marker;
        wrong_kind["digest"] = json!(hex(&item.digest()));
        assert!(check(&wrong_kind, false, false).is_err());
    }
}
