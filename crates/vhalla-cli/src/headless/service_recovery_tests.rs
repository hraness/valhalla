//! Stopped-home private archival preserves history without activating a copy.

use super::*;
use crate::headless::{catalog::Hex, local};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn id(value: u8) -> Id {
    Hex([value; 16])
}

async fn ready(home: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if local::admin_request(home, json!({"op":"control.hello"}))
                .await
                .is_ok()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("synthetic daemon becomes ready");
}

async fn admin(home: &Path, request: Value) -> Value {
    local::admin_request(home, request).await.unwrap()
}

fn private_command(
    action: &str,
    identity: &Path,
    store: &Path,
    flags: &[(&str, OsString)],
) -> std::result::Result<(), String> {
    let mut args = vec![
        OsString::from("private"),
        OsString::from(action),
        identity.as_os_str().to_owned(),
        store.as_os_str().to_owned(),
    ];
    for (name, value) in flags {
        args.push(OsString::from(format!("--{name}")));
        args.push(value.clone());
    }
    crate::private_rooms::run(&args)
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                visit(root, &entry.path(), files);
            } else {
                assert!(kind.is_file());
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn stopped_headless_private_archive_is_inert_and_original_home_keeps_its_sequence() {
    // Short canonical names keep actual Unix socket paths valid on macOS.
    let temp = tempfile::Builder::new()
        .prefix("vh-archive-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().canonicalize().unwrap();
    let home = root.join("home");
    vhalla_custody::create_private_directory(&home).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let room = id(1);
    let text = "private archive from a stopped headless daemon";
    let (status, send, committed) = runtime.block_on(Box::pin(async {
        let (evidence, service) = tokio::join!(
            Box::pin(async {
                ready(&home).await;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let initial = admin(
                    &home,
                    json!({"op":"room.create","operation":room,
                    "kind":"private","limits":{"max_records":10000,"max_record_bytes":8388608},
                    "validity":{"not_before":now-1,"expires_at":now+3600}}),
                )
                .await;
                let send = json!({"op":"room.send","room":room,"operation":id(2),"body":text,
                    "epoch":initial["epoch"],"roster":initial["roster"]});
                let committed = admin(&home, send.clone()).await;
                let status = admin(&home, json!({"op":"room.status","room":room})).await;
                assert!(
                    status["storage"]["records"].as_u64().unwrap()
                        > initial["storage"]["records"].as_u64().unwrap()
                );
                assert!(status["storage"]["bytes"].as_u64().unwrap() > 0);
                assert_eq!(status["storage"]["max_records"], 10000);
                assert_eq!(status["storage"]["max_record_bytes"], 8388608);
                assert_eq!(status["storage"]["immutable_limits"], true);
                assert_eq!(
                    admin(&home, json!({"op":"control.stop"})).await["stopping"],
                    true
                );
                (status, send, committed)
            }),
            Box::pin(local::serve_factory(
                &home,
                |generation| {
                    let selected = &home;
                    async move {
                        Ok(local::Launch {
                            backend: Box::pin(ServiceBackend::initialize(selected, generation))
                                .await?,
                            endpoint: None,
                        })
                    }
                },
                std::future::pending(),
            )),
        );
        service.unwrap(); // All account, room and service handles are joined.
        evidence
    }));

    let account = home.join("account");
    let source = home.join("rooms/private").join(room.to_string());
    let archive = root.join("stopped.vharchive");
    let destination = root.join("inert-archive");
    let retained = snapshot(&source);
    private_command(
        "archive-export",
        &account,
        &source,
        &[("out", archive.clone().into())],
    )
    .unwrap();
    assert_eq!(snapshot(&source), retained);
    let encrypted = fs::read(&archive).unwrap();
    assert!(!encrypted
        .windows(text.len())
        .any(|bytes| bytes == text.as_bytes()));
    assert_eq!(
        fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
        0o600
    );
    private_command(
        "archive-import",
        &account,
        &destination,
        &[("archive", archive.clone().into())],
    )
    .unwrap();
    let inspected = root.join("archive-membership.json");
    private_command(
        "archive-inspect",
        &account,
        &destination,
        &[
            ("archive", archive.clone().into()),
            ("out", inspected.clone().into()),
        ],
    )
    .unwrap();
    let view: Value = serde_json::from_slice(&fs::read(inspected).unwrap()).unwrap();
    assert_eq!(view["kind"], "read-only-private-archive");
    for field in ["epoch", "roster", "outbox_head", "inbox_head"] {
        assert_eq!(view["view"]["status"][field], status[field]);
    }
    let outbox = root.join("archive-outbox.json");
    private_command(
        "archive-outbox",
        &account,
        &destination,
        &[
            ("archive", archive.clone().into()),
            ("after", "0".into()),
            ("limit", "16".into()),
            ("out", outbox.clone().into()),
        ],
    )
    .unwrap();
    let history: Value = serde_json::from_slice(&fs::read(outbox).unwrap()).unwrap();
    assert_eq!(history["view"]["records"].as_array().unwrap().len(), 1);
    assert_eq!(
        history["view"]["records"][0]["operation"],
        committed["operation"]
    );
    assert_eq!(
        history["view"]["records"][0]["sequence"],
        committed["sequence"]
    );

    let inert = snapshot(&destination);
    let body = root.join("body.txt");
    fs::write(&body, text).unwrap();
    fs::set_permissions(&body, fs::Permissions::from_mode(0o600)).unwrap();
    let forbidden = root.join("must-not-sign");
    assert!(private_command(
        "send",
        &account,
        &destination,
        &[
            ("text", body.into()),
            ("operation", id(3).to_string().into()),
            (
                "epoch",
                status["epoch"].as_u64().unwrap().to_string().into()
            ),
            ("roster", status["roster"].as_str().unwrap().into()),
            ("out", forbidden.clone().into())
        ]
    )
    .is_err());
    assert!(!forbidden.exists());
    assert_eq!(snapshot(&destination), inert);
    assert_eq!(snapshot(&source), retained);

    runtime.block_on(Box::pin(async {
        let (_, service) = tokio::join!(
            Box::pin(async {
                ready(&home).await;
                let reopened = admin(&home, json!({"op":"room.status","room":room})).await;
                assert_eq!(reopened["context"], status["context"]);
                assert_eq!(reopened["storage"], status["storage"]);
                let retry = admin(&home, send.clone()).await;
                assert_eq!(retry["artifact"], committed["artifact"]);
                assert_eq!(retry["sequence"], committed["sequence"]);
                assert_eq!(retry["exact_retry"], true);
                let mut next = send.clone();
                next["operation"] = json!(id(3));
                next["body"] = json!("continued from exact original home");
                let advanced = admin(&home, next).await;
                assert_eq!(
                    advanced["sequence"].as_u64().unwrap(),
                    committed["sequence"].as_u64().unwrap() + 1
                );
                admin(&home, json!({"op":"control.stop"})).await;
            }),
            Box::pin(local::serve_factory(
                &home,
                |generation| {
                    let selected = &home;
                    async move {
                        Ok(local::Launch {
                            backend: Box::pin(ServiceBackend::open(selected, generation)).await?,
                            endpoint: None,
                        })
                    }
                },
                std::future::pending(),
            )),
        );
        service.unwrap();
    }));
    assert_eq!(snapshot(&destination), inert);
}
