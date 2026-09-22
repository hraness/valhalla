use super::*;

fn export(f: &Fixture) {
    f.ok(
        "archive-export",
        "owner-key",
        Some("owner-room"),
        &[("out", f.path("owner.vharchive"))],
    );
}
fn inspect_archive(f: &Fixture, output: &str) -> Value {
    f.ok(
        "archive-inspect",
        "owner-key",
        Some("archive"),
        &[
            ("archive", f.path("owner.vharchive")),
            ("out", f.path(output)),
        ],
    );
    f.json(output)
}
fn failed(result: Output) {
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!result
        .stderr
        .windows(b"private archive sentinel".len())
        .any(|w| w == b"private archive sentinel"));
}

#[test]
fn private_archive_cli_streams_complete_group_and_keeps_destination_inert() {
    let f = Fixture::new();
    f.join();
    let owner = f.inspect("owner-key", "owner-room", "before.json");
    f.write("text", b"private archive sentinel");
    f.ok(
        "send",
        "owner-key",
        Some("owner-room"),
        &send_options(&f, &owner, 3, "message"),
    );
    f.ok(
        "receive",
        "member-key",
        Some("member-room"),
        &[("message", f.path("message")), ("out", f.path("plaintext"))],
    );
    let source = f.snapshot("owner-room");
    export(&f);
    let encrypted = fs::read(f.root.join("owner.vharchive")).unwrap();
    assert!(!encrypted
        .windows(24)
        .any(|b| b == b"private archive sentinel"));
    assert_eq!(
        fs::metadata(f.root.join("owner.vharchive")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(f.snapshot("owner-room"), source);
    failed(f.run(
        "archive-export",
        "owner-key",
        Some("owner-room"),
        &[("out", f.path("owner.vharchive"))],
        None,
    ));
    assert_eq!(fs::read(f.root.join("owner.vharchive")).unwrap(), encrypted);
    f.ok(
        "archive-import",
        "owner-key",
        Some("archive"),
        &[("archive", f.path("owner.vharchive"))],
    );
    let archive = f.snapshot("archive");
    let inspected = inspect_archive(&f, "archive.json");
    assert_eq!(inspected["kind"], "read-only-private-archive");
    assert_eq!(inspected["view"]["recipients"], owner["recipients"]);
    f.ok(
        "archive-outbox",
        "owner-key",
        Some("archive"),
        &[
            ("archive", f.path("owner.vharchive")),
            ("after", "0".into()),
            ("limit", "16".into()),
            ("out", f.path("archive-outbox.json")),
        ],
    );
    let outbox = f.json("archive-outbox.json");
    assert_eq!(outbox["view"]["records"][0]["kind"], "ContactOffer");
    assert!(outbox["view"]["records"][0]["artifact_bytes"].is_null());
    for command in ["archive-import", "archive-resume"] {
        failed(f.run(
            command,
            "owner-key",
            Some("archive"),
            &[("archive", f.path("owner.vharchive"))],
            None,
        ));
    }
    failed(f.run(
        "inspect",
        "owner-key",
        Some("archive"),
        &[("out", f.path("not-live.json"))],
        None,
    ));
    assert_eq!(f.snapshot("archive"), archive);
    assert_eq!(f.snapshot("owner-room"), source);
}

#[test]
fn private_archive_cli_refuses_bad_prefix_account_bounds_and_trailing_data() {
    let f = Fixture::new();
    f.ok("create", "owner-key", Some("owner-room"), &f.validity());
    export(&f);
    let good = fs::read(f.root.join("owner.vharchive")).unwrap();
    failed(f.run(
        "archive-import",
        "member-key",
        Some("wrong-account"),
        &[("archive", f.path("owner.vharchive"))],
        None,
    ));
    assert!(!f.root.join("wrong-account").exists());
    let mut bad = good.clone();
    bad[168..172].copy_from_slice(&u32::MAX.to_be_bytes());
    f.write("length.vharchive", &bad);
    let mut bad = good.clone();
    let len = u32::from_be_bytes(bad[168..172].try_into().unwrap()) as usize;
    bad[172 + len - 1] ^= 1;
    f.write("tampered.vharchive", &bad);
    f.write("truncated.vharchive", &good[..170]);
    for name in ["length", "tampered", "truncated"] {
        failed(f.run(
            "archive-import",
            "owner-key",
            Some(name),
            &[("archive", f.path(&format!("{name}.vharchive")))],
            None,
        ));
        assert!(!f.root.join(name).exists());
    }
    f.ok(
        "archive-import",
        "owner-key",
        Some("archive"),
        &[("archive", f.path("owner.vharchive"))],
    );
    let before = f.snapshot("archive");
    let mut trailing = good.clone();
    trailing.push(0);
    f.write("trailing.vharchive", &trailing);
    failed(f.run(
        "archive-inspect",
        "owner-key",
        Some("archive"),
        &[
            ("archive", f.path("trailing.vharchive")),
            ("out", f.path("invalid.json")),
        ],
        None,
    ));
    failed(f.run(
        "archive-inspect",
        "owner-key",
        Some("archive"),
        &[
            ("archive", f.path("owner.vharchive")),
            ("out", f.path("invalid.json")),
            ("max-records", "1000001".into()),
        ],
        None,
    ));
    assert_eq!(f.snapshot("archive"), before);
    assert!(!f.root.join("invalid.json").exists());
    assert_eq!(
        fs::read(f.root.join("trailing.vharchive")).unwrap(),
        trailing
    );
}

#[test]
fn private_archive_cli_resumes_exact_committed_prefix_and_reconciles_final_by_inspect() {
    let f = Fixture::new();
    f.join();
    export(&f);
    // Fixture-only parsing of a small source-produced container; production
    // Reader streams with limits and no lifetime Vec.
    let raw = fs::read(f.root.join("owner.vharchive")).unwrap();
    let hint = vhalla_private_native::private_rooms::NativePrivateStore::locate_context(
        f.root.join("owner-room"),
    )
    .unwrap();
    let bytes = hint.as_bytes();
    use vhalla_private_kernel::{
        protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
        Context,
    };
    let context = Context {
        scope: PrivateRoomScope {
            room: RoomId::from_bytes(bytes[..32].try_into().unwrap()).unwrap(),
            anchor: AnchorId::from_bytes(bytes[32..64].try_into().unwrap()).unwrap(),
        },
        account: Key::from_bytes(bytes[64..96].try_into().unwrap()).unwrap(),
        device: Key::from_bytes(bytes[96..].try_into().unwrap()).unwrap(),
    };
    let id = raw[136..168].try_into().unwrap();
    let mut offset = 168;
    let mut next = || {
        let length = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let page = &raw[offset..offset + length];
        offset += length;
        page
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let identity = vhalla_identity::Identity::open(f.root.join("owner-key")).unwrap();
        let mut input =
            vhalla_private_native::archive::ArchiveInput::new(identity, context, id).unwrap();
        while !input.push_source(next()).unwrap() {}
        let mut receiver = input
            .create(
                f.root.join("archive"),
                vhalla_private_native::private_rooms::Limits {
                    max_records: 100_000,
                    max_record_bytes: 256 * 1024 * 1024,
                },
            )
            .await
            .unwrap();
        receiver.append(next()).await.unwrap();
        drop(receiver); // Durable append, caller lifetime ended before rest.
    });
    f.ok(
        "archive-resume",
        "owner-key",
        Some("archive"),
        &[("archive", f.path("owner.vharchive"))],
    );
    let before = f.snapshot("archive");
    inspect_archive(&f, "reconciled.json");
    assert_eq!(f.snapshot("archive"), before);
    failed(f.run(
        "archive-resume",
        "owner-key",
        Some("archive"),
        &[("archive", f.path("owner.vharchive"))],
        None,
    ));
    assert_eq!(f.snapshot("archive"), before);
}
