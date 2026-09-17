//! The one-use window: at most one admitted response per dedup scope.

use alloc::collections::BTreeMap;

/// Most open (consumed, unexpired) challenges one window retains.
pub const MAX_OPEN_CHALLENGES: usize = 4096;
/// Most open challenges one subject key may hold, so one subject cannot fill
/// the window for everyone.
pub const MAX_OPEN_PER_SUBJECT: usize = 64;

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
    /// This subject holds [`MAX_OPEN_PER_SUBJECT`] unexpired entries.
    SubjectCapacity,
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
    entries: BTreeMap<[u8; 32], Entry>,
    per_subject: BTreeMap<[u8; 32], usize>,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    response_hash: [u8; 32],
    expires_at: u64,
    subject_key: [u8; 32],
}

impl OneUseWindow {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            per_subject: BTreeMap::new(),
        }
    }
    /// What consuming `scope_key` for `response_hash` would return, without
    /// changing anything: lets a verifier refuse a replayed or equivocating
    /// response before paying for a full replay.
    #[must_use]
    pub fn peek(&self, scope_key: &[u8; 32], response_hash: &[u8; 32]) -> Option<WindowError> {
        match self.entries.get(scope_key) {
            Some(entry) if entry.response_hash == *response_hash => Some(WindowError::Replay),
            Some(_) => Some(WindowError::Equivocation),
            None => None,
        }
    }
    /// Consumes `scope_key` for `response_hash`, retaining the entry until
    /// `expires_at`. The last fallible step of verification.
    pub fn consume(
        &mut self,
        scope_key: [u8; 32],
        subject_key: [u8; 32],
        response_hash: [u8; 32],
        expires_at: u64,
    ) -> Result<(), WindowError> {
        if let Some(error) = self.peek(&scope_key, &response_hash) {
            return Err(error);
        }
        if self.entries.len() >= MAX_OPEN_CHALLENGES {
            return Err(WindowError::Capacity);
        }
        let held = self.per_subject.get(&subject_key).copied().unwrap_or(0);
        if held >= MAX_OPEN_PER_SUBJECT {
            return Err(WindowError::SubjectCapacity);
        }
        self.entries.insert(
            scope_key,
            Entry {
                response_hash,
                expires_at,
                subject_key,
            },
        );
        self.per_subject.insert(subject_key, held + 1);
        Ok(())
    }
    /// Removes entries whose `expires_at < now`. Never removes an unexpired
    /// entry; the expiry check precedes the dedup check, so a pruned
    /// challenge cannot be replayed.
    pub fn prune(&mut self, now: u64) {
        let per_subject = &mut self.per_subject;
        self.entries.retain(|_, entry| {
            if entry.expires_at >= now {
                return true;
            }
            if let Some(count) = per_subject.get_mut(&entry.subject_key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    per_subject.remove(&entry.subject_key);
                }
            }
            false
        });
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
        self.entries.get(scope_key).map(|entry| entry.response_hash)
    }
    /// Open entries held by a subject.
    #[must_use]
    pub fn held_by(&self, subject_key: &[u8; 32]) -> usize {
        self.per_subject.get(subject_key).copied().unwrap_or(0)
    }
}
