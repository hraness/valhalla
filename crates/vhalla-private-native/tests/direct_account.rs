#![cfg(all(unix, feature = "direct-rooms"))]
//! One account remains locked across private and public room lifetimes.

use futures::executor::block_on;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use vhalla_direct_native::{Error as PublicError, Limits as PublicLimits};
use vhalla_identity::{Identity, IdentityError};
use vhalla_private_kernel::{protocol::Validity, OperationId};
use vhalla_private_native::{client::AccountController, private_rooms::Limits};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "vhalla-direct-account-{}-{}",
            std::process::id(),
            stamp.as_nanos()
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

#[test]
fn account_custody_survives_mixed_room_handles_and_join_never_inherits_owner_role() {
    block_on(async {
        let temp = Temp::new();
        let identity_path = temp.0.join("account");
        let account = AccountController::new(Identity::create_new(&identity_path).unwrap());
        let owner = account.public_key();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut private = account
            .prepare_owner(Validity::new(now - 1, now + 3600).unwrap())
            .unwrap()
            .commit(
                temp.0.join("private"),
                Limits {
                    max_records: 128,
                    max_record_bytes: 8 * 1024 * 1024,
                },
            )
            .await
            .unwrap();
        let public_limits = PublicLimits {
            max_records: 256,
            max_record_bytes: 8 * 1024 * 1024,
        };
        let public_path = temp.0.join("public");
        let mut public = account
            .create_public_room(&public_path, public_limits)
            .unwrap();
        let room = public.room_id();
        assert_eq!(public.genesis().claims().owner, owner);
        assert_ne!(public.author_key(), owner);
        let mut joined = account
            .join_public_room(
                temp.0.join("joined"),
                &public.genesis().encode(),
                room,
                public_limits,
            )
            .unwrap();
        assert_ne!(joined.author_key(), public.author_key());
        assert_eq!(
            joined.set_writers([1; 16], vec![owner]),
            Err(PublicError::NotOwner)
        );
        assert!(account.open_public_room(&public_path, room).is_err());

        drop(account);
        assert!(matches!(
            Identity::open(&identity_path),
            Err(IdentityError::Busy)
        ));
        let draft = private
            .prepare_message(b"private remains available")
            .unwrap();
        private
            .send(OperationId::from_bytes([2; 16]).unwrap(), &draft)
            .await
            .unwrap();
        let retained = public
            .send([2; 16], "public remains available", now)
            .unwrap();
        private.lock();
        drop(private);
        drop(joined);
        assert!(matches!(
            Identity::open(&identity_path),
            Err(IdentityError::Busy)
        ));
        drop(public);

        let reopened = AccountController::new(Identity::open(&identity_path).unwrap());
        let mut public = reopened.open_public_room(&public_path, room).unwrap();
        let retried = public
            .send([2; 16], "public remains available", now + 10)
            .unwrap();
        assert_eq!(retried.bytes, retained.bytes);
        assert!(retried.exact_retry);
    });
}
