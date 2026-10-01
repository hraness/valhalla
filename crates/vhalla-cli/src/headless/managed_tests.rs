use super::*;
use crate::headless::{local, service::ServiceBackend};
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::TempDir;

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = custody::create_private_file(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn executable(path: &Path) {
    private_file(path, b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn observed(action: Action, _: &Spec) -> std::result::Result<Value, String> {
    Ok(match action {
        Action::Status => json!({"installed":true,"loaded":true,"state":"running"}),
        _ => Value::Null,
    })
}
fn not_called(_: Action, _: &Spec) -> std::result::Result<Value, String> {
    panic!("the supervisor must not be consulted")
}

struct Fixture {
    _temp: TempDir,
    base: PathBuf,
    home: PathBuf,
    executable: PathBuf,
    listen: Listen,
}
impl Fixture {
    async fn new() -> Self {
        Self::named("home", "vhalla").await
    }
    async fn named(home_name: &str, binary_name: &str) -> Self {
        // Keep Unix socket names beneath sockaddr_un's platform limit.
        let temp = TempDir::new_in("/tmp").unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let base = temp.path().canonicalize().unwrap();
        let home = base.join(home_name);
        custody::create_private_directory(&home).unwrap();
        let selected = &home;
        local::serve_factory(
            selected,
            |generation| async move {
                Ok(local::Launch {
                    backend: ServiceBackend::initialize(selected, generation).await?,
                    endpoint: None,
                })
            },
            async {},
        )
        .await
        .unwrap();
        let binary = base.join(binary_name);
        executable(&binary);
        Self {
            _temp: temp,
            base,
            home,
            executable: binary,
            listen: Listen {
                bind: "127.0.0.1:48888".parse().unwrap(),
                relay_url: None,
                relay_only: false,
            },
        }
    }
    fn install(&self) -> Value {
        install_with(
            &self.home,
            &self.executable,
            &self.listen,
            Platform::Mac,
            observed,
        )
        .unwrap()
    }
    fn config_path(&self) -> PathBuf {
        self.home.join(CONFIG_NAME)
    }
    fn config(&self) -> Vec<u8> {
        fs::read(self.config_path()).unwrap()
    }
}

#[tokio::test]
async fn install_persists_one_private_selection_and_exact_retry_keeps_its_inode() {
    let fixture = Fixture::new().await;
    let mut calls = Vec::new();
    let result = install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Mac,
        |action, spec| {
            calls.push(action);
            observed(action, spec)
        },
    )
    .unwrap();
    assert_eq!(calls, [Action::Install, Action::Status]);
    assert_eq!(result["operation"], "install");
    assert_eq!(result["home"], json!(fixture.home));
    assert_eq!(result["listen"]["relay_url"], Value::Null);
    assert!(result["label"]
        .as_str()
        .unwrap()
        .starts_with("me.vhalla.daemon."));
    assert!(result.get("native").is_none());
    let owner = Owner::current().unwrap();
    let original = custody::open_private_file(&fixture.config_path(), owner, MAX_CONFIG).unwrap();
    assert_eq!(original.metadata().unwrap().mode() & 0o7777, 0o600);
    let bytes = fixture.config();
    let decoded: Config = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.selection.version, 1);
    assert_eq!(decoded.encode().unwrap(), bytes);
    fixture.install();
    let retry = custody::open_private_file(&fixture.config_path(), owner, MAX_CONFIG).unwrap();
    assert!(custody::same_open_file(&original, &retry).unwrap());
    assert_eq!(fixture.config(), bytes);
}

#[tokio::test]
async fn differing_executable_listener_or_relay_never_overwrites_the_selection() {
    let fixture = Fixture::new().await;
    fixture.install();
    let bytes = fixture.config();
    let other_binary = fixture.base.join("other-vhalla");
    executable(&other_binary);
    let mut other_bind = fixture.listen.clone();
    other_bind.bind = "[::1]:48889".parse().unwrap();
    let mut other_relay = fixture.listen.clone();
    other_relay.relay_url = Some("https://relay.example/".to_owned());
    let mut relay_only = other_relay.clone();
    relay_only.relay_only = true;
    for (binary, listen) in [
        (&other_binary, &fixture.listen),
        (&fixture.executable, &other_bind),
        (&fixture.executable, &other_relay),
        (&fixture.executable, &relay_only),
    ] {
        assert_eq!(
            install_with(&fixture.home, binary, listen, Platform::Mac, not_called)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(fixture.config(), bytes);
    }
}

#[tokio::test]
async fn a_supervisor_refusal_preserves_the_selection_for_an_exact_retry() {
    let fixture = Fixture::new().await;
    assert_eq!(
        install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Mac,
            |action, _| {
                assert_eq!(action, Action::Install);
                Err("manager unavailable".to_owned())
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    let bytes = fixture.config();
    fixture.install();
    assert_eq!(fixture.config(), bytes);
}

#[tokio::test]
async fn partial_corrupt_extended_and_noncanonical_configurations_are_never_repaired() {
    let fixture = Fixture::new().await;
    fixture.install();
    let original = fixture.config();
    let value: Value = serde_json::from_slice(&original).unwrap();
    let mut extended = value.clone();
    extended["ignored"] = json!(true);
    let mut changed = value.clone();
    changed["selection"]["label"] = json!("another-service");
    for bytes in [
        Vec::new(),
        b"{\"selection\":".to_vec(),
        serde_json::to_vec(&extended).unwrap(),
        serde_json::to_vec(&changed).unwrap(),
        serde_json::to_vec_pretty(&value).unwrap(),
    ] {
        fs::write(fixture.config_path(), &bytes).unwrap();
        assert!(install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Mac,
            not_called,
        )
        .is_err());
        assert!(inspect_with(&fixture.home, Platform::Mac, false, not_called).is_err());
        assert!(inspect_with(&fixture.home, Platform::Mac, true, not_called).is_err());
        assert_eq!(fixture.config(), bytes);
    }
    fs::write(fixture.config_path(), original).unwrap();
    fixture.install();
}

#[tokio::test]
async fn missing_native_namespaces_and_unsafe_files_refuse_install_before_publication() {
    let fixture = Fixture::new().await;
    let identity = fixture.home.join("account/identity");
    let retained = fixture.base.join("retained-identity");
    fs::rename(&identity, &retained).unwrap();
    assert!(install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Mac,
        not_called,
    )
    .is_err());
    assert!(!fixture.config_path().exists());
    symlink(&retained, &identity).unwrap();
    assert!(install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Mac,
        not_called,
    )
    .is_err());
    assert!(!fixture.config_path().exists());
    assert!(retained.exists());
}

#[tokio::test]
async fn immutable_native_commitment_drift_refuses_reinstallation() {
    let fixture = Fixture::new().await;
    fixture.install();
    let config = fixture.config();
    for name in [
        "account/identity",
        "peer.key",
        "catalog/FORMAT",
        "public-sync/metadata/FORMAT",
        "private-delivery/FORMAT",
    ] {
        let path = fixture.home.join(name);
        let original = fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 1;
        fs::write(&path, &changed).unwrap();
        assert!(install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Mac,
            not_called,
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), changed);
        assert_eq!(fixture.config(), config);
        fs::write(&path, original).unwrap();
    }
    fixture.install();
}

#[tokio::test]
async fn moved_copied_replaced_and_symlinked_homes_cannot_select_a_foreign_service() {
    let fixture = Fixture::new().await;
    fixture.install();
    let config = fixture.config();
    let retained = fixture.base.join("retained-home");
    fs::rename(&fixture.home, &retained).unwrap();
    assert!(inspect_with(&retained, Platform::Mac, false, not_called).is_err());
    custody::create_private_directory(&fixture.home).unwrap();
    private_file(&fixture.config_path(), &config);
    assert!(inspect_with(&fixture.home, Platform::Mac, true, not_called).is_err());
    let replacement = fixture.base.join("replacement-home");
    fs::rename(&fixture.home, &replacement).unwrap();
    symlink(&retained, &fixture.home).unwrap();
    assert!(inspect_with(&fixture.home, Platform::Mac, false, not_called).is_err());
    fs::remove_file(&fixture.home).unwrap();
    fs::rename(&retained, &fixture.home).unwrap();
    inspect_with(&fixture.home, Platform::Mac, false, observed).unwrap();
    assert_eq!(fs::read(replacement.join(CONFIG_NAME)).unwrap(), config);
}

#[tokio::test]
async fn configuration_and_executable_symlinks_or_permissions_are_refused() {
    let fixture = Fixture::new().await;
    let binary_link = fixture.base.join("binary-link");
    symlink(&fixture.executable, &binary_link).unwrap();
    assert!(install_with(
        &fixture.home,
        &binary_link,
        &fixture.listen,
        Platform::Mac,
        not_called,
    )
    .is_err());
    for mode in [0o600, 0o777, 0o4700] {
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(mode)).unwrap();
        assert!(install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Mac,
            not_called,
        )
        .is_err());
        assert!(!fixture.config_path().exists());
    }
    fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700)).unwrap();
    fixture.install();
    let retained = fixture.base.join("retained-config");
    fs::rename(fixture.config_path(), &retained).unwrap();
    symlink(&retained, fixture.config_path()).unwrap();
    assert!(inspect_with(&fixture.home, Platform::Mac, true, not_called).is_err());
    assert!(retained.exists());
}

#[tokio::test]
async fn executable_fifo_is_refused_without_waiting_for_a_writer() {
    let fixture = Fixture::new().await;
    let fifo = fixture.base.join("binary-fifo");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    assert!(install_with(
        &fixture.home,
        &fifo,
        &fixture.listen,
        Platform::Mac,
        not_called,
    )
    .is_err());
    assert!(!fixture.config_path().exists());
}

#[tokio::test]
async fn damaged_native_state_and_missing_binary_do_not_block_status_or_uninstall() {
    let fixture = Fixture::new().await;
    fixture.install();
    let config = fixture.config();
    let log = fixture.home.join(launchd::SUPERVISOR_LOG_NAME);
    let room = fixture.home.join("rooms/private/preserved-room-data");
    private_file(&log, b"diagnostic evidence\n");
    private_file(&room, b"retained room data");
    for name in [
        "account/identity",
        "peer.key",
        "public-sync/metadata/FORMAT",
    ] {
        fs::remove_file(fixture.home.join(name)).unwrap();
    }
    fs::write(fixture.home.join("catalog/direct.sqlite"), b"broken").unwrap();
    fs::remove_file(&fixture.executable).unwrap();
    let status = inspect_with(&fixture.home, Platform::Mac, false, observed).unwrap();
    assert_eq!(status["service"]["state"], "running");
    let mut calls = Vec::new();
    let removed = inspect_with(&fixture.home, Platform::Mac, true, |action, _| {
        calls.push(action);
        Ok(json!({"installed":false,"loaded":false,"state":"absent"}))
    })
    .unwrap();
    assert_eq!(calls, [Action::Uninstall, Action::Status]);
    for field in [
        "home_preserved",
        "configuration_preserved",
        "logs_preserved",
    ] {
        assert_eq!(removed[field], true);
    }
    assert_eq!(fixture.config(), config);
    assert_eq!(fs::read(log).unwrap(), b"diagnostic evidence\n");
    assert_eq!(fs::read(room).unwrap(), b"retained room data");
    assert_eq!(
        fs::read(fixture.home.join("catalog/direct.sqlite")).unwrap(),
        b"broken"
    );
}

#[tokio::test]
async fn unavailable_manager_is_unknown_and_an_uncertain_uninstall_is_an_error() {
    let fixture = Fixture::new().await;
    fixture.install();
    let before = fixture.config();
    let unavailable = |_: Action, _: &Spec| Err("not verified".to_owned());
    let status = inspect_with(&fixture.home, Platform::Mac, false, unavailable).unwrap();
    assert_eq!(status["service"]["state"], "unknown");
    assert_eq!(status["service"]["installed"], Value::Null);
    assert_eq!(status["service"]["loaded"], Value::Null);
    assert_eq!(
        inspect_with(&fixture.home, Platform::Mac, true, unavailable)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(fixture.config(), before);
}

#[tokio::test]
async fn config_or_native_replacement_during_startup_refuses_success_without_cleanup() {
    for name in [
        CONFIG_NAME,
        "account/identity",
        "peer.key",
        "catalog/FORMAT",
    ] {
        let fixture = Fixture::new().await;
        let selected = fixture.home.join(name);
        let retained = fixture.base.join("original-file");
        let mut calls = Vec::new();
        assert!(install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Mac,
            |action, _| {
                calls.push(action);
                assert_eq!(action, Action::Install);
                let bytes = fs::read(&selected).unwrap();
                fs::rename(&selected, &retained).unwrap();
                private_file(&selected, &bytes);
                Ok(Value::Null)
            },
        )
        .is_err());
        assert_eq!(calls, [Action::Install]);
        assert_eq!(fs::read(selected).unwrap(), fs::read(retained).unwrap());
        assert!(fixture.config_path().exists());
    }
}

#[tokio::test]
async fn home_replacement_during_supervisor_startup_is_not_cleaned_up_or_reported_ready() {
    let fixture = Fixture::new().await;
    let retained = fixture.base.join("retained-home");
    assert!(install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Mac,
        |action, _| {
            assert_eq!(action, Action::Install);
            let bytes = fixture.config();
            fs::rename(&fixture.home, &retained).unwrap();
            custody::create_private_directory(&fixture.home).unwrap();
            private_file(&fixture.config_path(), &bytes);
            Ok(Value::Null)
        },
    )
    .is_err());
    assert!(retained.join("account/identity").exists());
    assert!(retained.join(CONFIG_NAME).exists());
    assert!(fixture.config_path().exists());
}

#[tokio::test]
async fn status_and_uninstall_recheck_config_after_the_supervisor_returns() {
    for remove in [false, true] {
        let fixture = Fixture::new().await;
        fixture.install();
        let retained = fixture.base.join("retained-config");
        assert!(
            inspect_with(&fixture.home, Platform::Mac, remove, |action, _| {
                assert_eq!(
                    action,
                    if remove {
                        Action::Uninstall
                    } else {
                        Action::Status
                    }
                );
                let bytes = fixture.config();
                fs::rename(fixture.config_path(), &retained).unwrap();
                private_file(&fixture.config_path(), &bytes);
                Ok(Value::Null)
            })
            .is_err()
        );
        assert_eq!(fixture.config(), fs::read(retained).unwrap());
    }
}

#[tokio::test]
async fn macos_spec_encodes_exact_arguments_and_retains_bounded_restart_diagnostics() {
    let fixture = Fixture::named("home &<>'\" name", "binary &<>'\" name").await;
    let listen = Listen {
        bind: "[::1]:48888".parse().unwrap(),
        relay_url: Some("https://relay.example/".to_owned()),
        relay_only: true,
    };
    install_with(&fixture.home, &fixture.executable, &listen, Platform::Mac, |action, spec| {
        let Spec::Mac(spec) = spec else { panic!("expected launchd") };
        assert!(spec.alternates.is_empty());
        assert!(spec.label.starts_with("me.vhalla.daemon."));
        let arguments = spec.plist.split("<key>ProgramArguments</key><array>").nth(1).unwrap().split("</array>").next().unwrap();
        let expected = format!(
            "<string>{}</string><string>daemon</string><string>run</string><string>--home</string><string>{}</string><string>--bind</string><string>[::1]:48888</string><string>--relay-url</string><string>https://relay.example/</string><string>--relay-only</string>",
            launchd::xml(fixture.executable.to_str().unwrap()).unwrap(),
            launchd::xml(fixture.home.to_str().unwrap()).unwrap(),
        );
        assert_eq!(arguments, expected);
        assert!(arguments.contains("&amp;&lt;&gt;&apos;&quot;"));
        for fragment in ["<key>ThrottleInterval</key><integer>30</integer>", "<key>ExitTimeOut</key><integer>15</integer>", "<key>Umask</key><integer>63</integer>", "<key>SuccessfulExit</key><false/>"] {
            assert!(spec.plist.contains(fragment));
        }
        assert_eq!(spec.plist.matches("supervisor.log").count(), 2);
        assert!(!spec.plist.contains("private-host"));
        Ok(if action == Action::Status { json!({"state":"running"}) } else { Value::Null })
    }).unwrap();
}

#[tokio::test]
async fn linux_spec_has_exact_argv_without_enabling_lingering_or_an_implicit_relay() {
    let fixture = Fixture::new().await;
    install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Linux,
        |action, spec| {
            let Spec::Linux(spec) = spec else {
                panic!("expected systemd")
            };
            assert!(spec.alternates.is_empty());
            assert!(spec.unit.contains(&format!(
                "ExecStart={} daemon run --home {} --bind 127.0.0.1:48888\n",
                fixture.executable.display(),
                fixture.home.display()
            )));
            for fragment in [
                "Restart=on-failure\n",
                "RestartSec=30\n",
                "TimeoutStopSec=15\n",
                "UMask=0077\n",
                "WantedBy=default.target\n",
            ] {
                assert!(spec.unit.contains(fragment));
            }
            assert_eq!(spec.unit.matches("supervisor.log").count(), 2);
            assert!(!spec.unit.contains("--relay-url"));
            assert!(!spec.unit.contains("--relay-only"));
            assert!(!spec.unit.contains("linger"));
            Ok(if action == Action::Status {
                json!({"state":"running"})
            } else {
                Value::Null
            })
        },
    )
    .unwrap();
}

#[tokio::test]
async fn unsafe_systemd_expansions_are_rejected_before_config_publication() {
    let fixture = Fixture::new().await;
    for name in ["a b", "a%b", "a$b", "a;b", "a\\b", "a'b", "a\"b"] {
        let binary = fixture.base.join(name);
        executable(&binary);
        assert_eq!(
            install_with(
                &fixture.home,
                &binary,
                &fixture.listen,
                Platform::Linux,
                not_called
            )
            .unwrap_err()
            .code,
            ErrorCode::Usage
        );
        assert!(!fixture.config_path().exists());
    }
}

#[tokio::test]
async fn relay_only_requires_an_explicit_relay_and_is_preserved_in_the_unit() {
    let fixture = Fixture::new().await;
    let mut listen = fixture.listen.clone();
    listen.relay_only = true;
    assert_eq!(
        install_with(
            &fixture.home,
            &fixture.executable,
            &listen,
            Platform::Linux,
            not_called
        )
        .unwrap_err()
        .code,
        ErrorCode::Usage
    );
    assert!(!fixture.config_path().exists());
    listen.relay_url = Some("https://relay.example/".to_owned());
    install_with(
        &fixture.home,
        &fixture.executable,
        &listen,
        Platform::Linux,
        |action, spec| {
            let Spec::Linux(spec) = spec else {
                panic!("expected systemd")
            };
            assert!(spec.unit.contains(
                "--bind 127.0.0.1:48888 --relay-url https://relay.example/ --relay-only\n"
            ));
            Ok(if action == Action::Status {
                json!({"state":"running"})
            } else {
                Value::Null
            })
        },
    )
    .unwrap();
    let config: Config = serde_json::from_slice(&fixture.config()).unwrap();
    assert!(config.selection.listen.relay_only);
}

#[tokio::test]
async fn supervisor_startup_holds_no_service_identity_or_native_store_writer_locks() {
    let fixture = Fixture::new().await;
    install_with(
        &fixture.home,
        &fixture.executable,
        &fixture.listen,
        Platform::Mac,
        |action, spec| {
            if action == Action::Install {
                for name in [
                    "control/supervisor.lock",
                    "account/lock",
                    "catalog/lock",
                    "public-sync/metadata/lock",
                    "private-delivery/lock",
                ] {
                    let lock = custody::open_private_file(
                        &fixture.home.join(name),
                        Owner::current().unwrap(),
                        0,
                    )
                    .unwrap_or_else(|error| panic!("open retained {name}: {error:?}"));
                    custody::acquire_exclusive(&lock).unwrap();
                    drop(lock);
                }
            }
            observed(action, spec)
        },
    )
    .unwrap();
}

#[tokio::test]
async fn unsupported_platform_does_not_publish_or_manage_a_selection() {
    let fixture = Fixture::new().await;
    assert_eq!(
        install_with(
            &fixture.home,
            &fixture.executable,
            &fixture.listen,
            Platform::Unsupported,
            not_called
        )
        .unwrap_err()
        .code,
        ErrorCode::Usage
    );
    assert!(!fixture.config_path().exists());
    fixture.install();
    let status = inspect_with(&fixture.home, Platform::Unsupported, false, not_called).unwrap();
    assert_eq!(status["supported"], false);
    assert_eq!(status["service"]["state"], "unknown");
    assert_eq!(
        inspect_with(&fixture.home, Platform::Unsupported, true, not_called)
            .unwrap_err()
            .code,
        ErrorCode::Usage
    );
    assert!(fixture.config_path().exists());
}
