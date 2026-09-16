//! The one-use window: at most one admitted response per dedup scope.

use alloc::collections::BTreeMap;

/// Most open (consumed, unexpired) challenges one window retains.
pub const MAX_OPEN_CHALLENGES: usize = 4096;

/// Why a scope could not be consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The same response was already consumed for this scope.
    Replay,
    /// A different response was already consumed for this scope; the stored
    /// entry is kept.
    Equivocation,
    /// The window holds [`MAX_OPEN_CHALLENGES`] unexpired entries.
    Capacity,
}

/// Non-`Clone`, volatile. A restarted verifier restores it durably or starts
/// with a fresh `started_at`, which the challenge time-window step enforces.
///
/// ```compile_fail
/// use vhalla_botcaptcha::window::OneUseWindow;
/// fn dup(window: &OneUseWindow) -> OneUseWindow { window.clone() }
/// ```
#[derive(Debug, Default)]
pub struct OneUseWindow {
    entries: BTreeMap<[u8; 32], ([u8; 32], u64)>,
}

impl OneUseWindow {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
    /// Consumes `scope_key` for `response_hash`, retaining the entry until
    /// `expires_at`. The last fallible step of verification.
    pub fn consume(
        &mut self,
        scope_key: [u8; 32],
        response_hash: [u8; 32],
        expires_at: u64,
    ) -> Result<(), WindowError> {
        match self.entries.get(&scope_key) {
            Some((stored, _)) if *stored == response_hash => Err(WindowError::Replay),
            Some(_) => Err(WindowError::Equivocation),
            None if self.entries.len() >= MAX_OPEN_CHALLENGES => Err(WindowError::Capacity),
            None => {
                self.entries.insert(scope_key, (response_hash, expires_at));
                Ok(())
            }
        }
    }
    /// Removes entries whose `expires_at < now`. Never removes an unexpired
    /// entry; the expiry check precedes the dedup check, so a pruned
    /// challenge cannot be replayed.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|_, (_, expires_at)| *expires_at >= now);
    }
    /// Open entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no entry is open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// The stored response hash for a scope, if consumed.
    #[must_use]
    pub fn consumed(&self, scope_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.entries.get(scope_key).map(|(hash, _)| *hash)
    }
}
