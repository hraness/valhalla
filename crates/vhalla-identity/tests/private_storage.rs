#![cfg(all(unix, feature = "private-storage"))]
//! Account custody parity without a secret getter or a second private key store.

use futures::executor::block_on;
use std::{
    cell::RefCell,
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_browser_vault::{seal, unlock};
use vhalla_identity::Identity;
use vhalla_private_kernel::{
    protocol::{AnchorId, Key, Validity},
    storage::{Image, RecordKey, Store, StoreError, StoredRecord},
    Context, Error, Kernel, OwnerDraft,
};
use zeroize::Zeroizing;

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-private-account-custody-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// Only the one image needed to exercise initial encryption and authenticated
/// reopen. This is a test model, not a durable Store implementation.
#[derive(Clone)]
struct InitialImage {
    context: Context,
    image: Rc<RefCell<Option<Image>>>,
}
impl InitialImage {
    fn new(context: Context) -> Self {
        Self {
            context,
            image: Rc::new(RefCell::new(None)),
        }
    }
}
impl Store for InitialImage {
    async fn load(&mut self, context: Context) -> Result<Option<Image>, StoreError> {
        if context != self.context {
            return Err(StoreError::Corrupt);
        }
        Ok(self.image.borrow().clone())
    }
    async fn read(&mut self, _: Context, _: RecordKey) -> Result<Option<StoredRecord>, StoreError> {
        Err(StoreError::Refused)
    }
    async fn publish(
        &mut self,
        context: Context,
        expected: Option<&Image>,
        next: &Image,
        records: &[StoredRecord],
    ) -> Result<(), StoreError> {
        if context != self.context || !records.is_empty() {
            return Err(StoreError::Refused);
        }
        let mut image = self.image.borrow_mut();
        if expected.is_some() || image.is_some() {
            return Err(StoreError::Conflict);
        }
        *image = Some(next.clone());
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn initialize(identity: &Identity) -> (InitialImage, Context) {
    let now = now();
    let account = Key::from_bytes(identity.public_key()).unwrap();
    let draft = OwnerDraft::new(account, Validity::new(now - 1, now + 3600).unwrap()).unwrap();
    let enrollment = identity
        .sign_private_enrollment(draft.enrollment_request())
        .unwrap();
    let anchor = identity
        .sign_private_anchor(draft.anchor_request())
        .unwrap();
    let context = draft.context(&anchor).unwrap();
    let store = InitialImage::new(context);
    let key = identity.private_storage_key(context).unwrap();
    let kernel = block_on(draft.create(store.clone(), &key, enrollment, anchor, now)).unwrap();
    assert_eq!(kernel.status().context, context);
    drop(kernel);
    (store, context)
}

#[test]
fn native_reopen_rederives_exact_key_and_never_replaces_missing_or_foreign_state() {
    let temp = Temp::new();
    let path = temp.0.join("account");
    let identity = Identity::create_new(&path).unwrap();
    let (store, context) = initialize(&identity);
    let retained = store.image.borrow().clone().unwrap();
    drop(identity);
    let reopened = Identity::open(&path).unwrap();
    let key = reopened.private_storage_key(context).unwrap();
    let kernel = block_on(Kernel::open(store.clone(), &key, context)).unwrap();
    assert_eq!(kernel.status().context, context);
    drop(kernel);

    let wrong = Identity::create_new(temp.0.join("wrong")).unwrap();
    assert!(matches!(
        wrong.private_storage_key(context),
        Err(Error::Scope)
    ));
    let mut changed = context;
    let mut anchor = *changed.scope.anchor.as_bytes();
    anchor[0] ^= 1;
    changed.scope.anchor = AnchorId::from_bytes(anchor).unwrap();
    let changed_key = reopened.private_storage_key(changed).unwrap();
    assert!(matches!(
        block_on(Kernel::open(store.clone(), &changed_key, context)),
        Err(Error::Authentication)
    ));
    assert!(store.image.borrow().as_ref() == Some(&retained));

    let missing = InitialImage::new(context);
    assert!(matches!(
        block_on(Kernel::open(missing.clone(), &key, context)),
        Err(Error::Missing)
    ));
    assert!(missing.image.borrow().is_none());
}

#[test]
fn browser_password_reencryption_preserves_native_derived_custody_and_account_binding() {
    let temp = Temp::new();
    // Public synthetic fixture only. No production method exports a seed or
    // permits caller-selected default entropy during identity creation.
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let phrase = Zeroizing::new(bip39::Mnemonic::from_entropy(&seed).unwrap().to_string());
    let native = Identity::restore(&phrase, temp.0.join("account")).unwrap();
    let (store, context) = initialize(&native);
    let retained = store.image.borrow().clone().unwrap();
    let before = seal(
        Zeroizing::new(seed),
        b"public test password before",
        [3; 16],
        [4; 24],
    )
    .unwrap();
    let after = seal(
        Zeroizing::new(seed),
        b"public test password changed",
        [5; 16],
        [6; 24],
    )
    .unwrap();
    assert!(before.as_bytes() != after.as_bytes());
    for (envelope, password) in [
        (&before, b"public test password before".as_slice()),
        (&after, b"public test password changed".as_slice()),
    ] {
        let vault = unlock(envelope.as_bytes(), password).unwrap();
        assert_eq!(vault.public_key(), native.public_key());
        let key = vault.private_storage_key(context).unwrap();
        let kernel = block_on(Kernel::open(store.clone(), &key, context)).unwrap();
        assert_eq!(kernel.status().context, context);
        drop(kernel);
        let mut wrong_account = context;
        wrong_account.account = Key::from_bytes(
            Identity::create_new(temp.0.join(if password == b"public test password before" {
                "other1"
            } else {
                "other2"
            }))
            .unwrap()
            .public_key(),
        )
        .unwrap();
        assert!(matches!(
            vault.private_storage_key(wrong_account),
            Err(Error::Scope)
        ));
    }
    assert!(unlock(after.as_bytes(), b"public test password before").is_err());
    assert!(store.image.borrow().as_ref() == Some(&retained));
}
