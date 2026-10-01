//! Public rooms borrow the account controller's existing custody lifetime.

use super::AccountController;
use std::{path::Path, sync::Arc};
use vhalla_direct_native::{Limits, Result, RoomSession};
use vhalla_direct_room::RoomId;

impl AccountController {
    /// Create a public room with a fresh room author and retained owner state.
    /// The returned controller keeps account custody even after this handle drops.
    pub fn create_public_room(
        &self,
        path: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<RoomSession> {
        RoomSession::create(Arc::clone(&self.identity), path, limits)
    }

    /// Create a public room bound to a previously retained random nonzero nonce.
    /// The nonce is signed into genesis; account signing custody stays internal.
    pub fn create_public_room_bound(
        &self,
        path: impl AsRef<Path>,
        creation_nonce: [u8; 32],
        limits: Limits,
    ) -> Result<RoomSession> {
        RoomSession::create_bound(Arc::clone(&self.identity), path, creation_nonce, limits)
    }

    /// Join a pinned public room using a fresh author that its owner must admit.
    /// This never grants owner-policy signing rights, even to the owner's account.
    pub fn join_public_room(
        &self,
        path: impl AsRef<Path>,
        signed_genesis: &[u8],
        expected_pin: RoomId,
        limits: Limits,
    ) -> Result<RoomSession> {
        RoomSession::join(
            Arc::clone(&self.identity),
            path,
            signed_genesis,
            expected_pin,
            limits,
        )
    }

    /// Join a pinned public room bound to a retained local creation nonce.
    /// A fresh author is generated; the pinned genesis and owner rights do not change.
    pub fn join_public_room_bound(
        &self,
        path: impl AsRef<Path>,
        signed_genesis: &[u8],
        expected_pin: RoomId,
        creation_nonce: [u8; 32],
        limits: Limits,
    ) -> Result<RoomSession> {
        RoomSession::join_bound(
            Arc::clone(&self.identity),
            path,
            signed_genesis,
            expected_pin,
            creation_nonce,
            limits,
        )
    }

    /// Open intact public-room controller state; missing author state is refused.
    /// Restored account keys and archive copies are not signing-state recovery.
    pub fn open_public_room(
        &self,
        path: impl AsRef<Path>,
        expected_pin: RoomId,
    ) -> Result<RoomSession> {
        RoomSession::open(Arc::clone(&self.identity), path, expected_pin)
    }
}
