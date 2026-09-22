#![cfg(all(unix, feature = "client"))]
//! Install as private-native/tests/derived_custody.rs with the client feature.
//! Real SQLite reopen using an opaque key from existing account custody.

use futures::executor::block_on;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{Key, Validity},
    storage::Store,
    Error, Kernel, OwnerDraft,
};
use vhalla_private_native::{bridge::KernelStore, private_rooms::Limits};

#[test]
fn derived_account_custody_reopens_exact_sqlite_image_and_refuses_key_only_recovery() {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let home = std::env::temp_dir().join(format!(
        "vhalla-derived-sqlite-{}-{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
    let account_path = home.join("account");
    let store_path = home.join("room");
    let identity = Identity::create_new(&account_path).unwrap();
    let draft = OwnerDraft::new(
        Key::from_bytes(identity.public_key()).unwrap(),
        Validity::new(now.as_secs() - 1, now.as_secs() + 3600).unwrap(),
    )
    .unwrap();
    let enrollment = identity
        .sign_private_enrollment(draft.enrollment_request())
        .unwrap();
    let anchor = identity
        .sign_private_anchor(draft.anchor_request())
        .unwrap();
    let context = draft.context(&anchor).unwrap();
    let key = identity.private_storage_key(context).unwrap();
    let store = KernelStore::create_new(
        &store_path,
        context,
        Limits {
            max_records: 16,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let kernel = block_on(draft.create(store, &key, enrollment, anchor, now.as_secs())).unwrap();
    let status = kernel.status();
    let mut store = kernel.into_store();
    let retained = block_on(store.load(context)).unwrap().unwrap();
    drop(store);
    drop(key);
    drop(identity);

    let identity = Identity::open(&account_path).unwrap();
    let key = identity.private_storage_key(context).unwrap();
    let store = KernelStore::open(&store_path, context).unwrap();
    let kernel = block_on(Kernel::open(store, &key, context)).unwrap();
    assert_eq!(kernel.status(), status);
    drop(kernel);
    let mut store = KernelStore::open(&store_path, context).unwrap();
    assert!(block_on(store.load(context)).unwrap().as_ref() == Some(&retained));
    drop(store);

    let wrong = Identity::create_new(home.join("wrong")).unwrap();
    assert!(matches!(
        wrong.private_storage_key(context),
        Err(Error::Scope)
    ));
    drop(wrong);
    let empty_path = home.join("explicit-empty");
    let empty = KernelStore::create_new(
        &empty_path,
        context,
        Limits {
            max_records: 16,
            max_record_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    assert!(matches!(
        block_on(Kernel::open(empty, &key, context)),
        Err(Error::Missing)
    ));
    let mut unchanged = KernelStore::open(&empty_path, context).unwrap();
    assert!(block_on(unchanged.load(context)).unwrap().is_none());
    drop(unchanged);
    drop(key);
    drop(identity);
    fs::remove_dir_all(home).unwrap();
}
