use super::*;
use std::path::PathBuf;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, PrivateRoomScope, RoomId},
    Context, OperationId, OutboxKind,
};
use vhalla_private_native::{
    client::generation::{controller_id, Accounting, BrowserSharedAccounting},
    relay::RelayItem,
};

fn key(seed: u8) -> Key {
    Key::from_bytes(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
    .unwrap()
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    receipts: PathBuf,
    plan: Plan,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vhalla-host-generation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        custody::create_private_directory(&root).unwrap();
        let home = root.join("host");
        let loaded = config::initialize(
            &home,
            "127.0.0.1:19473".parse().unwrap(),
            "generation.test.invalid",
            &std::env::current_exe().unwrap(),
        )
        .unwrap();
        let receipts = root.join("receipts");
        custody::create_private_directory(&receipts).unwrap();
        let store =
            FileStore::open(home.join("mailbox"), ns(&loaded.config.namespace).unwrap()).unwrap();
        let (head, items) = store.retained_head().unwrap();
        drop(store);
        let mut plan = Plan {
            version: 1,
            complete_controller_inventory: true,
            config_sha256: config::digest(&config::read(&home, "config.json", 65536).unwrap()),
            transition: config::hex(&[7; 32]),
            generation: 0,
            predecessor: loaded.config.namespace.clone(),
            successor: config::hex(&[8; 32]),
            successor_address: "127.0.0.1:19474".parse().unwrap(),
            expected_head: head,
            items_commitment: config::hex(&items),
            controllers: Vec::new(),
            allowances: Vec::new(),
        };
        for (index, id) in loaded.config.credential_ids.iter().enumerate() {
            let context = Context {
                scope: PrivateRoomScope {
                    room: RoomId::from_bytes([1; 32]).unwrap(),
                    anchor: AnchorId::from_bytes([2; 32]).unwrap(),
                },
                account: key(3 + index as u8),
                device: key(5 + index as u8),
            };
            let mut counters = BrowserSharedAccounting {
                attempts: 3,
                wire_bytes: 2048,
                retained: 0,
                received: head,
                refused_total: 0,
                total_byte_ceiling: 8192,
                total_attempt_ceiling: 64,
                commitment: [0; 32],
            };
            counters.commitment = counters.computed_commitment();
            let receipt = ControllerPauseReceipt {
                context,
                controller_id: controller_id(context, [9 + index as u8; 32]),
                original_profile_binding: [9 + index as u8; 32],
                transition: [7; 32],
                generation: 0,
                namespace: config::decode_hex(&plan.predecessor).unwrap(),
                endpoint: [11 + index as u8; 32],
                profile_binding: [9 + index as u8; 32],
                terminal_head: head,
                items_commitment: items,
                outbox_head: 0,
                control_head: 0,
                image_commitment: [13; 32],
                accounting: Accounting::BrowserShared(counters),
                prior_ledger_commitment: [0; 32],
            };
            let controller = Controller {
                credential_id: id.clone(),
                room: config::hex(context.scope.room.as_bytes()),
                anchor: config::hex(context.scope.anchor.as_bytes()),
                account: config::hex(context.account.as_bytes()),
                device: config::hex(context.device.as_bytes()),
                controller_id: config::hex(&receipt.controller_id),
                original_profile_binding: config::hex(&receipt.original_profile_binding),
                profile_binding: config::hex(&receipt.profile_binding),
                endpoint: config::hex(&receipt.endpoint),
                receipt_commitment: config::hex(&receipt.commitment().unwrap()),
            };
            config::write(
                &receipts,
                &format!("{}.receipt", controller.controller_id),
                &receipt.encode().unwrap(),
            )
            .unwrap();
            plan.controllers.push(controller);
        }
        Self {
            root,
            home,
            receipts,
            plan,
        }
    }
    fn plan_path(&self) -> PathBuf {
        self.root.join("plan.json")
    }
    fn write_plan(&self) {
        config::rewrite(
            &self.root,
            "plan.json",
            &serde_json::to_vec(&self.plan).unwrap(),
        )
        .unwrap();
    }
    fn prepare(&self) {
        self.write_plan();
        check(&self.home, &self.plan_path(), &self.receipts, true).unwrap();
    }
    fn old(&self) -> FileStore {
        FileStore::open(
            self.home.join("mailbox"),
            ns(&self.plan.predecessor).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn dry_run_is_read_only_and_inventory_is_complete() {
    let mut f = Fixture::new();
    f.write_plan();
    let config_before = config::read(&f.home, "config.json", 65536).unwrap();
    check(&f.home, &f.plan_path(), &f.receipts, false).unwrap();
    assert!(!present(&f.home, PENDING, 1024).unwrap());
    assert!(f.old().generation_fence().unwrap().is_none());
    f.plan.controllers.pop();
    f.write_plan();
    assert!(check(&f.home, &f.plan_path(), &f.receipts, true).is_err());
    assert_eq!(
        *config_before,
        *config::read(&f.home, "config.json", 65536).unwrap()
    );
}
#[test]
fn wrong_receipt_or_unknown_file_refuses_before_intent() {
    let mut f = Fixture::new();
    f.plan.controllers[0].endpoint = config::hex(&[91; 32]);
    f.write_plan();
    assert!(check(&f.home, &f.plan_path(), &f.receipts, true).is_err());
    f.plan.controllers[0].endpoint = config::hex(&[11; 32]);
    f.write_plan();
    config::write(&f.receipts, "unknown.receipt", b"unknown").unwrap();
    assert!(check(&f.home, &f.plan_path(), &f.receipts, true).is_err());
    assert!(!present(&f.home, PENDING, 1024).unwrap());
}
#[test]
fn changed_head_cannot_fence_and_keeps_pause_evidence() {
    let f = Fixture::new();
    f.prepare();
    let mut store = f.old();
    store
        .put(
            RelayItem::new(
                ns(&f.plan.predecessor).unwrap(),
                1,
                OperationId::from_bytes([1; 16]).unwrap(),
                OutboxKind::Application,
                b"racing ciphertext",
            )
            .unwrap(),
        )
        .unwrap();
    drop(store);
    assert!(fence(&f.home).unwrap_err().contains("head changed"));
    assert!(f.old().generation_fence().unwrap().is_none());
    assert!(present(&f.home, PENDING, 1024).unwrap());
    assert!(cutover(&f.home).is_err());
    assert!(config::add_credential(&f.home).is_err());
    assert!(!f.home.join("mailbox-2").exists());
}
#[test]
fn fence_is_permanent_and_successor_preserves_allowances() {
    let mut f = Fixture::new();
    f.plan.allowances.push(Allowance {
        credential_id: f.plan.controllers[0].credential_id.clone(),
        additional_items: 5,
        additional_bytes: 1024,
    });
    f.prepare();
    fence(&f.home).unwrap();
    fence(&f.home).unwrap();
    let old_fence = f.old().generation_fence().unwrap().unwrap();
    cutover(&f.home).unwrap();
    cutover(&f.home).unwrap();
    let loaded = config::load(&f.home).unwrap();
    assert_eq!(loaded.config.version, 3);
    assert_eq!(loaded.config.retained_generations.len(), 1);
    assert_eq!(loaded.config.namespace, f.plan.successor);
    assert_eq!(f.old().generation_fence().unwrap(), Some(old_fence));
    validate_retained(&f.home, &loaded.config.retained_generations[0]).unwrap();
    let next = FileStore::open(f.home.join("mailbox-2"), ns(&f.plan.successor).unwrap()).unwrap();
    let spend = Service::credential_spend(&next).unwrap();
    for c in spend {
        assert_eq!(c.spent_items(), 0);
        assert_eq!(
            c.authorized_items(),
            if config::hex(&c.id()) == f.plan.controllers[0].credential_id {
                2053
            } else {
                2048
            }
        );
    }
    assert_eq!(next.retained_head().unwrap().0, 0);
    assert!(!present(&f.home, PENDING, 1024).unwrap());
}
#[test]
fn interrupted_cutover_reopens_only_the_exact_intent() {
    for boundary in [
        "successor-seeded",
        "connection-written",
        "selection-committing",
        "selection-committed",
    ] {
        let f = Fixture::new();
        f.prepare();
        fence(&f.home).unwrap();
        assert!(cutover_with(&f.home, |step| if step == boundary {
            Err("injected interruption".into())
        } else {
            Ok(())
        })
        .is_err());
        assert!(f.old().generation_fence().unwrap().is_some());
        cutover(&f.home).unwrap();
        let loaded = config::load(&f.home).unwrap();
        assert_eq!(loaded.config.namespace, f.plan.successor);
        assert_eq!(loaded.config.retained_generations.len(), 1);
        validate_retained(&f.home, &loaded.config.retained_generations[0]).unwrap();
    }
}
#[test]
fn invalid_targets_or_allowances_do_not_publish_intent() {
    for mutation in 0..5 {
        let mut f = Fixture::new();
        match mutation {
            0 => f.plan.successor = f.plan.predecessor.clone(),
            1 => f.plan.successor_address = "127.0.0.1:19473".parse().unwrap(),
            2 => f.plan.complete_controller_inventory = false,
            3 => f.plan.allowances.push(Allowance {
                credential_id: f.plan.controllers[0].credential_id.clone(),
                additional_items: u64::MAX,
                additional_bytes: 0,
            }),
            _ => f.plan.config_sha256 = config::hex(&[22; 32]),
        }
        f.write_plan();
        assert!(check(&f.home, &f.plan_path(), &f.receipts, true).is_err());
        assert!(!present(&f.home, PENDING, 1024).unwrap());
        assert!(f.old().generation_fence().unwrap().is_none());
    }
}
#[test]
fn unenrolled_credentials_require_service_start_before_preparing() {
    let mut f = Fixture::new();
    let (_, id) = config::add_credential(&f.home).unwrap();
    let mut third = f.plan.controllers[0].clone();
    let raw = config::read(
        &f.receipts,
        &format!("{}.receipt", third.controller_id),
        1024,
    )
    .unwrap();
    let mut receipt = ControllerPauseReceipt::decode(&raw).unwrap();
    receipt.context.account = key(21);
    receipt.context.device = key(22);
    receipt.controller_id = controller_id(receipt.context, receipt.original_profile_binding);
    third.credential_id = id;
    third.account = config::hex(receipt.context.account.as_bytes());
    third.device = config::hex(receipt.context.device.as_bytes());
    third.controller_id = config::hex(&receipt.controller_id);
    third.receipt_commitment = config::hex(&receipt.commitment().unwrap());
    config::write(
        &f.receipts,
        &format!("{}.receipt", third.controller_id),
        &receipt.encode().unwrap(),
    )
    .unwrap();
    let loaded = config::load(&f.home).unwrap();
    assert_eq!(loaded.config.credential_ids.len(), 3);
    assert_eq!(Service::credential_spend(&f.old()).unwrap().len(), 2);
    f.plan.config_sha256 = config::digest(&config::read(&f.home, "config.json", 65536).unwrap());
    f.plan.controllers.push(third);
    f.write_plan();
    assert!(check(&f.home, &f.plan_path(), &f.receipts, true)
        .unwrap_err()
        .contains("not all enrolled"));
    assert!(!present(&f.home, PENDING, 1024).unwrap());
}

#[test]
fn inspect_receipt_writes_non_authoritative_private_view_once() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let receipt_name = format!("{}.receipt", fixture.plan.controllers[0].controller_id);
    let receipt = fixture.receipts.join(receipt_name);
    let output = fixture.root.join("controller-view.json");
    let original = fs::read(&receipt).unwrap();
    inspect(&receipt, &output).unwrap();
    let written = fs::read(&output).unwrap();
    let view: serde_json::Value = serde_json::from_slice(&written).unwrap();
    assert_eq!(view["version"], 1);
    assert_eq!(view["accounting"]["mode"], "browser_shared");
    assert_eq!(
        view["controller"]["controller_id"],
        fixture.plan.controllers[0].controller_id
    );
    assert!(view["controller"].get("credential_id").is_none());
    let mut expected = serde_json::to_value(&fixture.plan.controllers[0]).unwrap();
    expected.as_object_mut().unwrap().remove("credential_id");
    assert_eq!(view["controller"], expected);
    assert_eq!(view["transition"], fixture.plan.transition);
    assert_eq!(view["predecessor"], fixture.plan.predecessor);
    assert_eq!(view["generation"], fixture.plan.generation);
    assert_eq!(view["expected_head"], fixture.plan.expected_head);
    assert_eq!(view["items_commitment"], fixture.plan.items_commitment);
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&receipt).unwrap(), original);
    assert!(
        inspect(&receipt, &output).is_err(),
        "inspection must not overwrite evidence"
    );
    assert_eq!(fs::read(&output).unwrap(), written);
    let malformed = fixture.root.join("malformed.receipt");
    // A private file reaches the decoder; permissive fixture permissions must
    // not accidentally make malformed-input coverage pass before decoding.
    config::write(&fixture.root, "malformed.receipt", b"not a receipt").unwrap();
    let refused_output = fixture.root.join("malformed.json");
    assert!(inspect(&malformed, &refused_output).is_err());
    assert!(!refused_output.exists());
    let alias = fixture.root.join("receipt-alias");
    std::os::unix::fs::symlink(&receipt, &alias).unwrap();
    assert!(inspect(&alias, &refused_output).is_err());
    assert!(!refused_output.exists());
    let public = fixture.root.join("public-output");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(inspect(&receipt, &public.join("view.json")).is_err());
    assert!(!public.join("view.json").exists());
}

#[test]
fn inspect_native_receipt_preserves_split_accounting_without_fabricated_credential() {
    use vhalla_private_native::relay::delivery::LedgerSnapshot;
    let fixture = Fixture::new();
    let original = config::read(
        &fixture.receipts,
        &format!("{}.receipt", fixture.plan.controllers[0].controller_id),
        1024,
    )
    .unwrap();
    let mut receipt = ControllerPauseReceipt::decode(&original).unwrap();
    let normal = LedgerSnapshot {
        outgoing: 5,
        applied: receipt.terminal_head,
        retained_jobs: 4,
        canonical_bytes: 1024,
        charged_attempts: 7,
        outages: 3,
        resumes: 2,
        commitment: [21; 32],
    };
    let controls = LedgerSnapshot {
        outgoing: 2,
        applied: 0,
        retained_jobs: 2,
        canonical_bytes: 512,
        charged_attempts: 3,
        outages: 1,
        resumes: 0,
        commitment: [22; 32],
    };
    receipt.outbox_head = normal.outgoing;
    receipt.control_head = controls.outgoing;
    receipt.accounting = Accounting::NativeSplit {
        normal,
        controls,
        normal_total_byte_ceiling: 8192,
        control_total_byte_ceiling: 4096,
    };
    config::write(&fixture.root, "native.receipt", &receipt.encode().unwrap()).unwrap();
    let output = fixture.root.join("native.json");
    inspect(&fixture.root.join("native.receipt"), &output).unwrap();
    let view: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(view["accounting"]["mode"], "native_split");
    for (name, ledger, ceiling) in [("normal", normal, 8192), ("controls", controls, 4096)] {
        let value = &view["accounting"][name];
        assert_eq!(value["outgoing"], ledger.outgoing);
        assert_eq!(value["applied"], ledger.applied);
        assert_eq!(value["canonical_bytes"], ledger.canonical_bytes);
        assert_eq!(value["charged_attempts"], ledger.charged_attempts);
        assert_eq!(value["outages"], ledger.outages);
        assert_eq!(value["resumes"], ledger.resumes);
        assert_eq!(value["commitment"], config::hex(&ledger.commitment));
        let key = if name == "normal" {
            "normal_total_byte_ceiling"
        } else {
            "control_total_byte_ceiling"
        };
        assert_eq!(view["accounting"][key], ceiling);
    }
    assert_eq!(
        view["receipt_commitment"],
        config::hex(&receipt.commitment().unwrap())
    );
    assert!(view["controller"].get("credential_id").is_none());
}
