//! Verus pilot (4th model): inductive proof of HostRecovery's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs` and
//! `verify/private-publication/publication.rs`: `HostRecovery.tla` under
//! `normal.cfg` (all five switches false) is re-stated as a Verus
//! transition system and the five checked safety invariants are proved
//! inductive. Each of the four mutant configurations is proved to reach a
//! violation of the invariant TLC found for it — `mutant-consume` breaks
//! `RestoreEvidence`, `mutant-cleanup` and `mutant-absent-marker` break
//! `RestartEvidence`, `mutant-pair-only` breaks `SealedAdmission` — and a
//! completion witness runs a seal plus one interruption through recovery
//! to `done`. The same inductive invariant is also proved for the
//! `uncertain.cfg` configuration (AllowCorruption = TRUE), matching its
//! positive TLC result.
//!
//! Encoding notes:
//!   * Files == {a,b} is the concrete set {1,2}; Targets adds "config" as
//!     3. Phase and marker strings are int constants.
//!   * `live : [Targets -> 0..1]` becomes the characteristic set `live1`
//!     of the targets mapped to 1; `live[f] = 0` is removal and
//!     `live[f] = complete` is membership == flag, since `complete` is a
//!     bool. The BOOLEAN fields `damaged`/`badRead` are bools too.
//!   * `refusedAt` is the `Snap` record holding the five `Persistent`
//!     components; `RefusalKeepsEvidence` compares it fieldwise via
//!     `snap_eq`. The initial empty tuple is unconstrained (TypeOK does
//!     not mention it), so `init` takes the empty snap.
//!   * The TLA+ existentials `\E f \in Targets : Backup \/ Cleanup \/
//!     Restore \/ CorruptBackup` and `\E f \in Files : WriteFile \/
//!     DriftFile` become one existential per action, which is equivalent.
//!
//! Verify with:
//!   verus --crate-type=lib verify/host-recovery/recovery.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Files == {a, b} as {1, 2}.
pub open spec fn files() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

/// "config" as 3.
pub open spec fn cfg_file() -> int {
    3
}

/// Targets == Files \cup {"config"} as {1, 2, 3}.
pub open spec fn targets() -> Set<int> {
    files().insert(cfg_file())
}

pub open spec fn is_target(t: int) -> bool {
    targets().contains(t)
}

pub open spec fn is_file(f: int) -> bool {
    files().contains(f)
}

/// Marker encoding for the {"none","files","committing"} alphabet.
pub open spec fn m_none() -> int {
    0
}

pub open spec fn m_files() -> int {
    1
}

pub open spec fn m_commit() -> int {
    2
}

pub open spec fn is_marker(m: int) -> bool {
    m == m_none() || m == m_files() || m == m_commit()
}

/// Phase encoding for the Phases alphabet.
pub open spec fn p_backup() -> int {
    0
}

pub open spec fn p_files() -> int {
    1
}

pub open spec fn p_config() -> int {
    2
}

pub open spec fn p_complete() -> int {
    3
}

pub open spec fn p_unlink() -> int {
    4
}

pub open spec fn p_sync() -> int {
    5
}

pub open spec fn p_cleanup() -> int {
    6
}

pub open spec fn p_recover() -> int {
    7
}

pub open spec fn p_restore() -> int {
    8
}

pub open spec fn p_validate() -> int {
    9
}

pub open spec fn p_done() -> int {
    10
}

pub open spec fn p_uncertain() -> int {
    11
}

pub open spec fn is_phase(p: int) -> bool {
    0 <= p <= 11
}

/// CrashBudget = 2 from the checked configurations.
pub open spec fn crash_budget() -> int {
    2
}

/// Snapshot of the Persistent tuple <<live, complete, marker, backups,
/// tampered>> recorded by Refuse and compared by RefusalKeepsEvidence.
pub struct Snap {
    pub live1: Set<int>,
    pub complete: bool,
    pub marker: int,
    pub backups: Set<int>,
    pub tampered: Set<int>,
}

/// VARIABLE s: record fields pc, live (as live1), complete, marker,
/// durableMarker, backups, restoreTodo, crashes, tampered, damaged,
/// badRead, refusedAt.
pub struct State {
    pub pc: int,
    pub live1: Set<int>,
    pub complete: bool,
    pub marker: int,
    pub durable: int,
    pub backups: Set<int>,
    pub rt: Set<int>,
    pub crashes: int,
    pub tampered: Set<int>,
    pub damaged: bool,
    pub bad_read: bool,
    pub refused_at: Snap,
}

/// The Persistent tuple of a state.
pub open spec fn persistent(s: State) -> Snap {
    Snap {
        live1: s.live1,
        complete: s.complete,
        marker: s.marker,
        backups: s.backups,
        tampered: s.tampered,
    }
}

/// Fieldwise equality for snapshots (extensional on the set components).
pub open spec fn snap_eq(a: Snap, b: Snap) -> bool {
    &&& a.live1 =~= b.live1
    &&& a.complete == b.complete
    &&& a.marker == b.marker
    &&& a.backups =~= b.backups
    &&& a.tampered =~= b.tampered
}

/// The initial refusedAt: TLA's <<>> has no Persistent shape and TypeOK
/// leaves it free; the empty snap is a convenient concrete value.
pub open spec fn empty_snap() -> Snap {
    Snap {
        live1: Set::empty(),
        complete: false,
        marker: m_none(),
        backups: Set::empty(),
        tampered: Set::empty(),
    }
}

/// PairMatches == s.live["config"] = s.complete
pub open spec fn pair_matches(s: State) -> bool {
    s.live1.contains(cfg_file()) == s.complete
}

/// WholeSnapshot == PairMatches /\ \A f \in Files : s.live[f] = s.complete
pub open spec fn whole_snapshot(s: State) -> bool {
    &&& pair_matches(s)
    &&& forall|f: int| is_file(f) ==> s.live1.contains(f) == s.complete
}

/// NeedsRestore == s.marker = "files"
///                 \/ (s.marker = "committing"
///                     /\ (~PairMatches \/ s.live["config"] = 0))
pub open spec fn needs_restore(s: State) -> bool {
    ||| s.marker == m_files()
    ||| (s.marker == m_commit() && (!pair_matches(s) || !s.live1.contains(cfg_file())))
}

/// CanKeep == (s.marker = "none" /\ PairMatches)
///            \/ (s.marker = "committing" /\ PairMatches
///                /\ s.live["config"] = 1 /\ "config" \in s.backups)
pub open spec fn can_keep(s: State) -> bool {
    ||| (s.marker == m_none() && pair_matches(s))
    ||| (s.marker == m_commit() && pair_matches(s) && s.live1.contains(cfg_file())
        && s.backups.contains(cfg_file()))
}

pub open spec fn init(s: State) -> bool {
    &&& s.pc == p_backup()
    &&& s.live1 =~= Set::empty()
    &&& !s.complete
    &&& s.marker == m_none()
    &&& s.durable == m_none()
    &&& s.backups =~= Set::empty()
    &&& s.rt =~= Set::empty()
    &&& s.crashes == 0
    &&& s.tampered =~= Set::empty()
    &&& !s.damaged
    &&& !s.bad_read
    &&& snap_eq(s.refused_at, empty_snap())
}

/// Backup(f) == /\ s.pc = "backup" /\ f \notin s.backups
///              /\ s' = [s EXCEPT !.backups = @ \cup {f}]
pub open spec fn backup(pre: State, post: State, f: int) -> bool {
    &&& pre.pc == p_backup()
    &&& !pre.backups.contains(f)
    &&& post.pc == pre.pc
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups.insert(f)
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// MarkFiles == /\ s.pc = "backup" /\ s.backups = Targets
///              /\ s' = [s EXCEPT !.pc = "files", !.marker = "files",
///                                 !.durableMarker = "files"]
pub open spec fn mark_files(pre: State, post: State) -> bool {
    &&& pre.pc == p_backup()
    &&& pre.backups =~= targets()
    &&& post.pc == p_files()
    &&& post.marker == m_files()
    &&& post.durable == m_files()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// WriteFile(f) == /\ s.pc = "files" /\ s.live[f] = 0
///                 /\ s' = [s EXCEPT !.live[f] = 1]
pub open spec fn write_file(pre: State, post: State, f: int) -> bool {
    &&& pre.pc == p_files()
    &&& !pre.live1.contains(f)
    &&& post.live1 =~= pre.live1.insert(f)
    &&& post.pc == pre.pc
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// SealFiles == /\ s.pc = "files" /\ \A f \in Files : s.live[f] = 1
///              /\ s' = [s EXCEPT !.pc = "config", !.marker = "committing",
///                                 !.durableMarker = "committing"]
pub open spec fn seal_files(pre: State, post: State) -> bool {
    &&& pre.pc == p_files()
    &&& forall|f: int| is_file(f) ==> pre.live1.contains(f)
    &&& post.pc == p_config()
    &&& post.marker == m_commit()
    &&& post.durable == m_commit()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// WriteConfig == /\ s.pc = "config"
///                /\ s' = [s EXCEPT !.live["config"] = 1, !.pc = "complete"]
pub open spec fn write_config(pre: State, post: State) -> bool {
    &&& pre.pc == p_config()
    &&& post.live1 =~= pre.live1.insert(cfg_file())
    &&& post.pc == p_complete()
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// WriteComplete == /\ s.pc = "complete"
///                  /\ s' = [s EXCEPT !.complete = 1, !.pc = "unlink"]
pub open spec fn write_complete(pre: State, post: State) -> bool {
    &&& pre.pc == p_complete()
    &&& post.complete
    &&& post.pc == p_unlink()
    &&& post.live1 =~= pre.live1
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// UnlinkPresent == /\ s.pc = "unlink" /\ s.marker # "none"
///                  /\ s' = [s EXCEPT !.marker = "none", !.pc = "sync"]
pub open spec fn unlink_present(pre: State, post: State) -> bool {
    &&& pre.pc == p_unlink()
    &&& pre.marker != m_none()
    &&& post.marker == m_none()
    &&& post.pc == p_sync()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// UnlinkAbsent == /\ s.pc = "unlink" /\ s.marker = "none"
///                 /\ s' = [s EXCEPT !.pc = IF SkipAbsentBarrier
///                                              THEN "cleanup" ELSE "sync"]
pub open spec fn unlink_absent(pre: State, post: State, sab: bool) -> bool {
    &&& pre.pc == p_unlink()
    &&& pre.marker == m_none()
    &&& post.pc == if sab {
        p_cleanup()
    } else {
        p_sync()
    }
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// SyncMarker == /\ s.pc = "sync"
///               /\ s' = [s EXCEPT !.pc = "cleanup",
///                                  !.durableMarker = IF CleanupBeforeSync
///                                                      THEN @ ELSE "none"]
pub open spec fn sync_marker(pre: State, post: State, cbs: bool) -> bool {
    &&& pre.pc == p_sync()
    &&& post.pc == p_cleanup()
    &&& post.durable == if cbs {
        pre.durable
    } else {
        m_none()
    }
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Cleanup(f) == /\ s.pc = "cleanup" /\ f \in s.backups
///               /\ s' = [s EXCEPT !.backups = @ \ {f}, !.tampered = @ \ {f}]
pub open spec fn cleanup(pre: State, post: State, f: int) -> bool {
    &&& pre.pc == p_cleanup()
    &&& pre.backups.contains(f)
    &&& post.backups =~= pre.backups.remove(f)
    &&& post.tampered =~= pre.tampered.remove(f)
    &&& post.pc == pre.pc
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Finish == /\ s.pc = "cleanup" /\ s.backups = {}
///           /\ s' = [s EXCEPT !.pc = "done", !.durableMarker = "none"]
pub open spec fn finish(pre: State, post: State) -> bool {
    &&& pre.pc == p_cleanup()
    &&& pre.backups =~= Set::empty()
    &&& post.pc == p_done()
    &&& post.durable == m_none()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// ProcessInterruption == /\ s.pc \notin {"done", "uncertain"}
///                        /\ s.crashes < CrashBudget
///                        /\ s' = [s EXCEPT !.pc = "recover", !.restoreTodo = {},
///                                           !.crashes = @ + 1]
pub open spec fn process_interruption(pre: State, post: State) -> bool {
    &&& pre.pc != p_done() && pre.pc != p_uncertain()
    &&& pre.crashes < crash_budget()
    &&& post.pc == p_recover()
    &&& post.rt =~= Set::empty()
    &&& post.crashes == pre.crashes + 1
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// PowerLoss == /\ s.pc \notin {"done", "uncertain"}
///              /\ s.crashes < CrashBudget
///              /\ s' = [s EXCEPT !.pc = "recover", !.restoreTodo = {},
///                                 !.marker = s.durableMarker, !.crashes = @ + 1]
pub open spec fn power_loss(pre: State, post: State) -> bool {
    &&& pre.pc != p_done() && pre.pc != p_uncertain()
    &&& pre.crashes < crash_budget()
    &&& post.pc == p_recover()
    &&& post.rt =~= Set::empty()
    &&& post.marker == pre.durable
    &&& post.crashes == pre.crashes + 1
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// PersistUnlink == /\ s.marker = "none" /\ s.durableMarker # "none"
///                  /\ s' = [s EXCEPT !.durableMarker = "none"]
pub open spec fn persist_unlink(pre: State, post: State) -> bool {
    &&& pre.marker == m_none()
    &&& pre.durable != m_none()
    &&& post.durable == m_none()
    &&& post.pc == pre.pc
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// RecoverRestore == /\ s.pc = "recover" /\ NeedsRestore
///                   /\ "config" \in s.backups /\ s.tampered = {}
///                   /\ s' = [s EXCEPT !.pc = "restore", !.restoreTodo = s.backups]
pub open spec fn recover_restore(pre: State, post: State) -> bool {
    &&& pre.pc == p_recover()
    &&& needs_restore(pre)
    &&& pre.backups.contains(cfg_file())
    &&& pre.tampered =~= Set::empty()
    &&& post.pc == p_restore()
    &&& post.rt =~= pre.backups
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Restore(f) == /\ s.pc = "restore" /\ f \in s.restoreTodo
///               /\ s' = [s EXCEPT !.live[f] = 0, !.restoreTodo = @ \ {f},
///                                  !.backups = IF ConsumeBackup
///                                                    THEN @ \ {f} ELSE @]
pub open spec fn restore(pre: State, post: State, cb: bool, f: int) -> bool {
    &&& pre.pc == p_restore()
    &&& pre.rt.contains(f)
    &&& post.live1 =~= pre.live1.remove(f)
    &&& post.rt =~= pre.rt.remove(f)
    &&& post.backups =~= if cb {
        pre.backups.remove(f)
    } else {
        pre.backups
    }
    &&& post.pc == pre.pc
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// RestoreComplete == /\ s.pc = "restore" /\ s.restoreTodo = {}
///                    /\ s' = [s EXCEPT !.complete = s.live["config"],
///                                       !.pc = "validate"]
pub open spec fn restore_complete(pre: State, post: State) -> bool {
    &&& pre.pc == p_restore()
    &&& pre.rt =~= Set::empty()
    &&& post.complete == pre.live1.contains(cfg_file())
    &&& post.pc == p_validate()
    &&& post.live1 =~= pre.live1
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// ValidateRestore == /\ s.pc = "validate" /\ WholeSnapshot
///                    /\ s' = [s EXCEPT !.pc = "unlink"]
pub open spec fn validate_restore(pre: State, post: State) -> bool {
    &&& pre.pc == p_validate()
    &&& whole_snapshot(pre)
    &&& post.pc == p_unlink()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// RecoverKeep == /\ s.pc = "recover" /\ CanKeep /\ WholeSnapshot
///                /\ s' = [s EXCEPT !.pc = "unlink"]
pub open spec fn recover_keep(pre: State, post: State) -> bool {
    &&& pre.pc == p_recover()
    &&& can_keep(pre)
    &&& whole_snapshot(pre)
    &&& post.pc == p_unlink()
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Refuse == /\ (s.pc = "validate" /\ ~WholeSnapshot)
///                 \/ (s.pc = "recover"
///                     /\ ~(NeedsRestore /\ "config" \in s.backups /\ s.tampered = {})
///                     /\ ~(CanKeep /\ WholeSnapshot))
///           /\ s' = [s EXCEPT !.pc = "uncertain", !.refusedAt = Persistent]
pub open spec fn refuse(pre: State, post: State) -> bool {
    &&& ((pre.pc == p_validate() && !whole_snapshot(pre)) || (pre.pc == p_recover()
        && !(needs_restore(pre) && pre.backups.contains(cfg_file()) && pre.tampered
            =~= Set::empty()) && !(can_keep(pre) && whole_snapshot(pre))))
    &&& post.pc == p_uncertain()
    &&& snap_eq(post.refused_at, persistent(pre))
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& post.bad_read == pre.bad_read
}

/// CorruptBackup(f) == /\ AllowCorruption /\ ~s.damaged /\ s.pc = "recover"
///                     /\ NeedsRestore /\ f \in s.backups
///                     /\ s' = [s EXCEPT !.tampered = {f}, !.damaged = TRUE]
pub open spec fn corrupt_backup(pre: State, post: State, ac: bool, f: int) -> bool {
    &&& ac
    &&& !pre.damaged
    &&& pre.pc == p_recover()
    &&& needs_restore(pre)
    &&& pre.backups.contains(f)
    &&& post.tampered =~= Set::empty().insert(f)
    &&& post.damaged
    &&& post.pc == pre.pc
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// DriftFile(f) == /\ AllowCorruption /\ ~s.damaged /\ s.pc = "recover"
///                 /\ CanKeep /\ s.live["config"] = 1
///                 /\ s' = [s EXCEPT !.live[f] = 0, !.damaged = TRUE]
pub open spec fn drift_file(pre: State, post: State, ac: bool, f: int) -> bool {
    &&& ac
    &&& !pre.damaged
    &&& pre.pc == p_recover()
    &&& can_keep(pre)
    &&& pre.live1.contains(cfg_file())
    &&& post.live1 =~= pre.live1.remove(f)
    &&& post.damaged
    &&& post.pc == pre.pc
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.bad_read == pre.bad_read
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Read == /\ ~s.badRead /\ PairMatches /\ (PairOnlyAdmission \/ WholeSnapshot)
///         /\ s' = [s EXCEPT !.badRead = ~WholeSnapshot]
pub open spec fn read(pre: State, post: State, poa: bool) -> bool {
    &&& !pre.bad_read
    &&& pair_matches(pre)
    &&& (poa || whole_snapshot(pre))
    &&& post.bad_read == !whole_snapshot(pre)
    &&& post.pc == pre.pc
    &&& post.live1 =~= pre.live1
    &&& post.complete == pre.complete
    &&& post.marker == pre.marker
    &&& post.durable == pre.durable
    &&& post.backups =~= pre.backups
    &&& post.rt =~= pre.rt
    &&& post.crashes == pre.crashes
    &&& post.tampered =~= pre.tampered
    &&& post.damaged == pre.damaged
    &&& snap_eq(post.refused_at, pre.refused_at)
}

/// Next under arbitrary config constants ConsumeBackup, CleanupBeforeSync,
/// SkipAbsentBarrier, PairOnlyAdmission, AllowCorruption.
pub open spec fn next_cfg(
    cb: bool,
    cbs: bool,
    sab: bool,
    poa: bool,
    ac: bool,
    pre: State,
    post: State
) -> bool {
    ||| mark_files(pre, post)
    ||| seal_files(pre, post)
    ||| write_config(pre, post)
    ||| write_complete(pre, post)
    ||| unlink_present(pre, post)
    ||| unlink_absent(pre, post, sab)
    ||| sync_marker(pre, post, cbs)
    ||| finish(pre, post)
    ||| process_interruption(pre, post)
    ||| power_loss(pre, post)
    ||| persist_unlink(pre, post)
    ||| recover_restore(pre, post)
    ||| restore_complete(pre, post)
    ||| validate_restore(pre, post)
    ||| recover_keep(pre, post)
    ||| refuse(pre, post)
    ||| read(pre, post, poa)
    ||| exists|f: int| is_target(f) && #[trigger] backup(pre, post, f)
    ||| exists|f: int| is_target(f) && #[trigger] cleanup(pre, post, f)
    ||| exists|f: int| is_target(f) && #[trigger] restore(pre, post, cb, f)
    ||| exists|f: int| is_target(f) && #[trigger] corrupt_backup(pre, post, ac, f)
    ||| exists|f: int| is_file(f) && #[trigger] write_file(pre, post, f)
    ||| exists|f: int| is_file(f) && #[trigger] drift_file(pre, post, ac, f)
}

/// normal.cfg: every mutant switch false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, pre, post)
}

/// mutant-consume.cfg: ConsumeBackup = TRUE.
pub open spec fn next_mutant_consume(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, pre, post)
}

/// mutant-cleanup.cfg: CleanupBeforeSync = TRUE.
pub open spec fn next_mutant_cleanup(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, pre, post)
}

/// mutant-absent-marker.cfg: SkipAbsentBarrier = TRUE.
pub open spec fn next_mutant_absent(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, pre, post)
}

/// mutant-pair-only.cfg: PairOnlyAdmission = TRUE.
pub open spec fn next_mutant_pair_only(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, pre, post)
}

/// uncertain.cfg: AllowCorruption = TRUE (a positive configuration).
pub open spec fn next_uncertain(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, true, pre, post)
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& is_phase(s.pc)
    &&& s.live1.subset_of(targets())
    &&& is_marker(s.marker)
    &&& is_marker(s.durable)
    &&& s.backups.subset_of(targets())
    &&& s.rt.subset_of(targets())
    &&& 0 <= s.crashes <= crash_budget()
    &&& s.tampered.subset_of(s.backups)
}

/// RestoreEvidence == s.pc = "restore" => Targets \subseteq s.backups
pub open spec fn restore_evidence(s: State) -> bool {
    s.pc == p_restore() ==> targets().subset_of(s.backups)
}

/// RestartEvidence == (s.pc = "recover" /\ s.marker # "none" /\ ~s.damaged)
///                    => "config" \in s.backups
pub open spec fn restart_evidence(s: State) -> bool {
    (s.pc == p_recover() && s.marker != m_none() && !s.damaged)
        ==> s.backups.contains(cfg_file())
}

/// SealedAdmission == ~s.badRead
pub open spec fn sealed_admission(s: State) -> bool {
    !s.bad_read
}

/// CompletedSnapshot == s.pc = "done" => WholeSnapshot
pub open spec fn completed_snapshot(s: State) -> bool {
    s.pc == p_done() ==> whole_snapshot(s)
}

/// RefusalKeepsEvidence == s.pc = "uncertain" => Persistent = s.refusedAt
pub open spec fn refusal_keeps_evidence(s: State) -> bool {
    s.pc == p_uncertain() ==> snap_eq(persistent(s), s.refused_at)
}

/// Auxiliary: a non-"none" visible marker only exists while the full
/// backup set is retained — markers are set beside backups = Targets and
/// the only backup-shrinking action (Cleanup) runs where the marker is
/// already visibly absent.
pub open spec fn aux_marker_backups(s: State) -> bool {
    s.marker != m_none() ==> targets().subset_of(s.backups)
}

/// Auxiliary: the same for the durable marker — a power loss restores
/// durableMarker into marker, so the retention fact must hold for it too.
pub open spec fn aux_durable_backups(s: State) -> bool {
    s.durable != m_none() ==> targets().subset_of(s.backups)
}

/// Auxiliary: in the files phase the visible marker is "files" (the only
/// entry is MarkFiles, which sets it, and nothing clears it there).
pub open spec fn aux_files_marker(s: State) -> bool {
    s.pc == p_files() ==> s.marker == m_files()
}

/// Auxiliary: the sync phase is only entered from unlink, which always
/// leaves the marker visibly absent.
pub open spec fn aux_sync_marker(s: State) -> bool {
    s.pc == p_sync() ==> s.marker == m_none()
}

/// Auxiliary: cleanup always runs with the marker visibly absent, so its
/// backup removals can never strand a non-"none" marker.
pub open spec fn aux_cleanup_marker(s: State) -> bool {
    s.pc == p_cleanup() ==> s.marker == m_none()
}

/// Auxiliary: in the safe configuration the sync step durably clears the
/// marker before cleanup, so cleanup also runs with durableMarker "none"
/// — this is exactly what CleanupBeforeSync breaks.
pub open spec fn aux_cleanup_durable(s: State) -> bool {
    s.pc == p_cleanup() ==> s.durable == m_none()
}

/// Auxiliary: the post-commit window (unlink, sync, cleanup, done) always
/// holds a whole snapshot — every entry path (WriteComplete, the two
/// recovery branches) establishes it and nothing inside breaks it.
pub open spec fn aux_window_snapshot(s: State) -> bool {
    (s.pc == p_unlink() || s.pc == p_sync() || s.pc == p_cleanup() || s.pc == p_done())
        ==> whole_snapshot(s)
}

/// Auxiliary: from the config phase onward every data file is written —
/// SealFiles requires all files at 1 and nothing else lowers them there.
pub open spec fn aux_files_written(s: State) -> bool {
    (s.pc == p_config() || s.pc == p_complete()) ==> forall|f: int| is_file(f)
        ==> s.live1.contains(f)
}

/// Auxiliary: at complete the config write has already landed.
pub open spec fn aux_config_written(s: State) -> bool {
    s.pc == p_complete() ==> s.live1.contains(cfg_file())
}

/// The inductive invariant: TypeOK plus the five checked safety
/// invariants, strengthened by the eight auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& restore_evidence(s)
    &&& restart_evidence(s)
    &&& sealed_admission(s)
    &&& completed_snapshot(s)
    &&& refusal_keeps_evidence(s)
    &&& aux_marker_backups(s)
    &&& aux_durable_backups(s)
    &&& aux_files_marker(s)
    &&& aux_sync_marker(s)
    &&& aux_cleanup_marker(s)
    &&& aux_cleanup_durable(s)
    &&& aux_window_snapshot(s)
    &&& aux_files_written(s)
    &&& aux_config_written(s)
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
}

proof fn backup_preserves(pre: State, post: State, f: int)
    requires
        inv(pre),
        is_target(f),
        backup(pre, post, f),
    ensures
        inv(post),
{
    assert(post.backups.subset_of(targets())) by {
        assert forall|x: int| post.backups.contains(x) implies targets().contains(x) by {
            if x == f {
                assert(is_target(f));
            } else {
                assert(pre.backups.contains(x));
            }
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn mark_files_preserves(pre: State, post: State)
    requires
        inv(pre),
        mark_files(pre, post),
    ensures
        inv(post),
{
    assert(pre.backups =~= targets());
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn write_file_preserves(pre: State, post: State, f: int)
    requires
        inv(pre),
        is_file(f),
        write_file(pre, post, f),
    ensures
        inv(post),
{
    assert(post.live1.subset_of(targets())) by {
        assert forall|x: int| post.live1.contains(x) implies targets().contains(x) by {
            if x == f {
                assert(targets().contains(f));
            } else {
                assert(pre.live1.contains(x));
            }
        }
    }
    // aux_window_snapshot / aux_files_written: pc stays "files", outside
    // those phases.
    assert(post.pc == p_files());
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn seal_files_preserves(pre: State, post: State)
    requires
        inv(pre),
        seal_files(pre, post),
    ensures
        inv(post),
{
    // The committing marker/durable need backups ⊇ Targets: at pc = files
    // the marker is "files" (aux_files_marker), which gives the full set.
    assert(pre.marker == m_files());
    assert(targets().subset_of(pre.backups));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn write_config_preserves(pre: State, post: State)
    requires
        inv(pre),
        write_config(pre, post),
    ensures
        inv(post),
{
    assert(post.live1.subset_of(targets())) by {
        assert forall|x: int| post.live1.contains(x) implies targets().contains(x) by {
            if x == cfg_file() {
                assert(targets().contains(cfg_file()));
            } else {
                assert(pre.live1.contains(x));
            }
        }
    }
    // aux_files_written at post (pc = complete): the added member is
    // config; file members come from pre.
    assert forall|f: int| is_file(f) implies post.live1.contains(f) by {
        assert(pre.live1.contains(f));
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn write_complete_preserves(pre: State, post: State)
    requires
        inv(pre),
        write_complete(pre, post),
    ensures
        inv(post),
{
    // aux_window_snapshot at post (pc = unlink): live is all ones on
    // files plus config (aux_files_written + aux_config_written), and
    // complete becomes 1.
    assert(post.live1.contains(cfg_file()));
    assert forall|f: int| is_file(f) implies post.live1.contains(f) == post.complete by {
        assert(pre.live1.contains(f));
    }
    assert(whole_snapshot(post));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn unlink_present_preserves(pre: State, post: State)
    requires
        inv(pre),
        unlink_present(pre, post),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn unlink_absent_preserves(pre: State, post: State)
    requires
        inv(pre),
        unlink_absent(pre, post, false),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn sync_marker_preserves(pre: State, post: State)
    requires
        inv(pre),
        sync_marker(pre, post, false),
    ensures
        inv(post),
{
    // aux_cleanup_marker: the marker was already none at sync.
    assert(pre.marker == m_none());
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn cleanup_preserves(pre: State, post: State, f: int)
    requires
        inv(pre),
        is_target(f),
        cleanup(pre, post, f),
    ensures
        inv(post),
{
    // aux_cleanup_marker / aux_cleanup_durable make both markers none at
    // cleanup, so shrinking backups cannot strand aux_marker_backups or
    // aux_durable_backups.
    assert(pre.marker == m_none());
    assert(pre.durable == m_none());
    assert(post.tampered.subset_of(post.backups)) by {
        assert forall|x: int| post.tampered.contains(x) implies post.backups.contains(x) by {
            assert(pre.tampered.contains(x));
            assert(pre.backups.contains(x));
            assert(x != f);
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn finish_preserves(pre: State, post: State)
    requires
        inv(pre),
        finish(pre, post),
    ensures
        inv(post),
{
    // completed_snapshot: cleanup carries WholeSnapshot.
    assert(whole_snapshot(pre));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn process_interruption_preserves(pre: State, post: State)
    requires
        inv(pre),
        process_interruption(pre, post),
    ensures
        inv(post),
{
    // restart_evidence: marker unchanged; a non-none marker carried the
    // full backup set.
    if post.marker != m_none() && !post.damaged {
        assert(pre.marker != m_none());
        assert(targets().subset_of(pre.backups));
        assert(pre.backups.contains(cfg_file()));
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn power_loss_preserves(pre: State, post: State)
    requires
        inv(pre),
        power_loss(pre, post),
    ensures
        inv(post),
{
    // restart_evidence + aux_marker_backups: marker' = durableMarker, so
    // the durable side of the same fact applies.
    if post.marker != m_none() {
        assert(pre.durable != m_none());
        assert(targets().subset_of(pre.backups));
        assert(pre.backups.contains(cfg_file()));
    }
    assert(is_marker(post.marker));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn persist_unlink_preserves(pre: State, post: State)
    requires
        inv(pre),
        persist_unlink(pre, post),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    // refusal_keeps_evidence: durableMarker is outside the Persistent
    // tuple, so the recorded snapshot still matches.
    if post.pc == p_uncertain() {
        assert(snap_eq(persistent(pre), pre.refused_at));
        assert(snap_eq(persistent(post), post.refused_at));
    }
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn recover_restore_preserves(pre: State, post: State)
    requires
        inv(pre),
        recover_restore(pre, post),
    ensures
        inv(post),
{
    // NeedsRestore makes the marker non-none; aux_marker_backups supplies
    // the full backup set for restore_evidence at post.
    assert(pre.marker != m_none());
    assert(targets().subset_of(pre.backups));
    assert(post.rt.subset_of(targets())) by {
        assert forall|x: int| post.rt.contains(x) implies targets().contains(x) by {
            assert(pre.backups.contains(x));
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn restore_preserves(pre: State, post: State, f: int)
    requires
        inv(pre),
        is_target(f),
        restore(pre, post, false, f),
    ensures
        inv(post),
{
    // ConsumeBackup = FALSE keeps backups; restore_evidence carried the
    // full set into the phase.
    assert(targets().subset_of(post.backups));
    assert(post.rt.subset_of(targets())) by {
        assert forall|x: int| post.rt.contains(x) implies targets().contains(x) by {
            assert(pre.rt.contains(x));
        }
    }
    assert(post.live1.subset_of(targets())) by {
        assert forall|x: int| post.live1.contains(x) implies targets().contains(x) by {
            assert(pre.live1.contains(x));
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn restore_complete_preserves(pre: State, post: State)
    requires
        inv(pre),
        restore_complete(pre, post),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn validate_restore_preserves(pre: State, post: State)
    requires
        inv(pre),
        validate_restore(pre, post),
    ensures
        inv(post),
{
    assert(whole_snapshot(pre));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn recover_keep_preserves(pre: State, post: State)
    requires
        inv(pre),
        recover_keep(pre, post),
    ensures
        inv(post),
{
    assert(whole_snapshot(pre));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn refuse_preserves(pre: State, post: State)
    requires
        inv(pre),
        refuse(pre, post),
    ensures
        inv(post),
{
    // refusal_keeps_evidence: refusedAt' = Persistent and the persistent
    // fields are unchanged, so the snapshot matches the post state.
    assert(snap_eq(persistent(post), post.refused_at));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

/// Holds for any AllowCorruption flag: the fault only marks evidence and
/// raises damaged, which masks RestartEvidence's antecedent.
proof fn corrupt_backup_preserves(pre: State, post: State, ac: bool, f: int)
    requires
        inv(pre),
        is_target(f),
        corrupt_backup(pre, post, ac, f),
    ensures
        inv(post),
{
    assert(post.tampered.subset_of(post.backups)) by {
        assert forall|x: int| post.tampered.contains(x) implies post.backups.contains(x) by {
            assert(x == f);
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

/// Holds for any AllowCorruption flag: the drifted live file lowers a
/// member of live1 and raises damaged; the recover phase is outside every
/// phase-restricted auxiliary.
proof fn drift_file_preserves(pre: State, post: State, ac: bool, f: int)
    requires
        inv(pre),
        is_file(f),
        drift_file(pre, post, ac, f),
    ensures
        inv(post),
{
    assert(post.live1.subset_of(targets())) by {
        assert forall|x: int| post.live1.contains(x) implies targets().contains(x) by {
            assert(pre.live1.contains(x));
        }
    }
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn read_preserves(pre: State, post: State)
    requires
        inv(pre),
        read(pre, post, false),
    ensures
        inv(post),
{
    // sealed_admission: with PairOnlyAdmission = FALSE the guard includes
    // WholeSnapshot, so badRead' = ~WholeSnapshot is false.
    assert(whole_snapshot(pre));
    assert(type_ok(post));
    assert(restore_evidence(post));
    assert(restart_evidence(post));
    assert(sealed_admission(post));
    assert(completed_snapshot(post));
    // refusal_keeps_evidence: badRead is outside the Persistent tuple.
    if post.pc == p_uncertain() {
        assert(snap_eq(persistent(pre), pre.refused_at));
        assert(snap_eq(persistent(post), post.refused_at));
    }
    assert(refusal_keeps_evidence(post));
    assert(aux_marker_backups(post));
    assert(aux_durable_backups(post));
    assert(aux_files_marker(post));
    assert(aux_sync_marker(post));
    assert(aux_cleanup_marker(post));
    assert(aux_cleanup_durable(post));
    assert(aux_window_snapshot(post));
    assert(aux_files_written(post));
    assert(aux_config_written(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if mark_files(pre, post) {
        mark_files_preserves(pre, post);
    } else if seal_files(pre, post) {
        seal_files_preserves(pre, post);
    } else if write_config(pre, post) {
        write_config_preserves(pre, post);
    } else if write_complete(pre, post) {
        write_complete_preserves(pre, post);
    } else if unlink_present(pre, post) {
        unlink_present_preserves(pre, post);
    } else if unlink_absent(pre, post, false) {
        unlink_absent_preserves(pre, post);
    } else if sync_marker(pre, post, false) {
        sync_marker_preserves(pre, post);
    } else if finish(pre, post) {
        finish_preserves(pre, post);
    } else if process_interruption(pre, post) {
        process_interruption_preserves(pre, post);
    } else if power_loss(pre, post) {
        power_loss_preserves(pre, post);
    } else if persist_unlink(pre, post) {
        persist_unlink_preserves(pre, post);
    } else if recover_restore(pre, post) {
        recover_restore_preserves(pre, post);
    } else if restore_complete(pre, post) {
        restore_complete_preserves(pre, post);
    } else if validate_restore(pre, post) {
        validate_restore_preserves(pre, post);
    } else if recover_keep(pre, post) {
        recover_keep_preserves(pre, post);
    } else if refuse(pre, post) {
        refuse_preserves(pre, post);
    } else if read(pre, post, false) {
        read_preserves(pre, post);
    } else if exists|f: int| is_target(f) && backup(pre, post, f) {
        let f = choose|f: int| is_target(f) && backup(pre, post, f);
        backup_preserves(pre, post, f);
    } else if exists|f: int| is_target(f) && cleanup(pre, post, f) {
        let f = choose|f: int| is_target(f) && cleanup(pre, post, f);
        cleanup_preserves(pre, post, f);
    } else if exists|f: int| is_target(f) && restore(pre, post, false, f) {
        let f = choose|f: int| is_target(f) && restore(pre, post, false, f);
        restore_preserves(pre, post, f);
    } else if exists|f: int| is_file(f) && write_file(pre, post, f) {
        let f = choose|f: int| is_file(f) && write_file(pre, post, f);
        write_file_preserves(pre, post, f);
    } else {
        // Only the AllowCorruption-gated actions remain; under normal.cfg
        // both are disabled.
        assert(!(exists|f: int| is_target(f) && corrupt_backup(pre, post, false, f)));
        assert(!(exists|f: int| is_file(f) && drift_file(pre, post, false, f)));
        assert(false);
    }
}

proof fn step_inv_uncertain(pre: State, post: State)
    requires
        inv(pre),
        next_uncertain(pre, post),
    ensures
        inv(post),
{
    if mark_files(pre, post) {
        mark_files_preserves(pre, post);
    } else if seal_files(pre, post) {
        seal_files_preserves(pre, post);
    } else if write_config(pre, post) {
        write_config_preserves(pre, post);
    } else if write_complete(pre, post) {
        write_complete_preserves(pre, post);
    } else if unlink_present(pre, post) {
        unlink_present_preserves(pre, post);
    } else if unlink_absent(pre, post, false) {
        unlink_absent_preserves(pre, post);
    } else if sync_marker(pre, post, false) {
        sync_marker_preserves(pre, post);
    } else if finish(pre, post) {
        finish_preserves(pre, post);
    } else if process_interruption(pre, post) {
        process_interruption_preserves(pre, post);
    } else if power_loss(pre, post) {
        power_loss_preserves(pre, post);
    } else if persist_unlink(pre, post) {
        persist_unlink_preserves(pre, post);
    } else if recover_restore(pre, post) {
        recover_restore_preserves(pre, post);
    } else if restore_complete(pre, post) {
        restore_complete_preserves(pre, post);
    } else if validate_restore(pre, post) {
        validate_restore(pre, post);
    } else if recover_keep(pre, post) {
        recover_keep_preserves(pre, post);
    } else if refuse(pre, post) {
        refuse_preserves(pre, post);
    } else if read(pre, post, false) {
        read_preserves(pre, post);
    } else if exists|f: int| is_target(f) && backup(pre, post, f) {
        let f = choose|f: int| is_target(f) && backup(pre, post, f);
        backup_preserves(pre, post, f);
    } else if exists|f: int| is_target(f) && cleanup(pre, post, f) {
        let f = choose|f: int| is_target(f) && cleanup(pre, post, f);
        cleanup_preserves(pre, post, f);
    } else if exists|f: int| is_target(f) && restore(pre, post, false, f) {
        let f = choose|f: int| is_target(f) && restore(pre, post, false, f);
        restore_preserves(pre, post, f);
    } else if exists|f: int| is_file(f) && write_file(pre, post, f) {
        let f = choose|f: int| is_file(f) && write_file(pre, post, f);
        write_file_preserves(pre, post, f);
    } else if exists|f: int| is_target(f) && corrupt_backup(pre, post, true, f) {
        let f = choose|f: int| is_target(f) && corrupt_backup(pre, post, true, f);
        corrupt_backup_preserves(pre, post, true, f);
    } else {
        let f = choose|f: int| is_file(f) && drift_file(pre, post, true, f);
        drift_file_preserves(pre, post, true, f);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

/// Every finite execution of the uncertain.cfg model (AllowCorruption).
pub open spec fn is_uncertain_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_uncertain(t[i], t[i + 1])
}

pub open spec fn is_consume_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_consume(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_cleanup_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_cleanup(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_absent_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_absent(
        t[i],
        t[i + 1]
    )
}

pub open spec fn is_pair_only_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_pair_only(
        t[i],
        t[i + 1]
    )
}

proof fn trace_satisfies_inv(t: Seq<State>)
    requires
        is_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i]),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next(
                prefix[i],
                prefix[i + 1]
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next(t[i], t[i + 1]));
            }
        }
        trace_satisfies_inv(prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k]));
                assert(next(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i]));
            }
        }
    } else {
        init_inv(t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            assert(i == 0);
        }
    }
}

proof fn uncertain_trace_satisfies_inv(t: Seq<State>)
    requires
        is_uncertain_trace(t),
    ensures
        forall|i: int| 0 <= i < t.len() ==> inv(t[i]),
    decreases t.len(),
{
    if t.len() > 1 {
        let prefix = t.drop_last();
        assert(is_uncertain_trace(prefix)) by {
            assert forall|i: int| 0 <= i < prefix.len() - 1 implies #[trigger] next_uncertain(
                prefix[i],
                prefix[i + 1]
            ) by {
                assert(prefix[i] == t[i]);
                assert(prefix[i + 1] == t[i + 1]);
                assert(next_uncertain(t[i], t[i + 1]));
            }
        }
        uncertain_trace_satisfies_inv(prefix);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            if i == t.len() - 1 {
                let k = i - 1;
                assert(prefix[k] == t[k]);
                assert(inv(prefix[k]));
                assert(next_uncertain(t[k], t[k + 1]));
                assert(t[k + 1] == t[i]);
                step_inv_uncertain(t[k], t[i]);
            } else {
                assert(prefix[i] == t[i]);
                assert(inv(prefix[i]));
            }
        }
    } else {
        init_inv(t[0]);
        assert forall|i: int| 0 <= i < t.len() implies inv(t[i]) by {
            assert(i == 0);
        }
    }
}

/// Constructing states concisely for the witness proofs.
pub open spec fn st(
    pc: int,
    live1: Set<int>,
    complete: bool,
    marker: int,
    durable: int,
    backups: Set<int>,
    rt: Set<int>,
    crashes: int,
    tampered: Set<int>,
    damaged: bool,
    bad_read: bool
) -> State {
    State {
        pc,
        live1,
        complete,
        marker,
        durable,
        backups,
        rt,
        crashes,
        tampered,
        damaged,
        bad_read,
        refused_at: empty_snap(),
    }
}

/// mutant-consume: Backup×3 -> MarkFiles -> ProcessInterruption ->
/// RecoverRestore -> Restore(a) with ConsumeBackup drops a's backup
/// inside the restore phase — Targets ⊄ backups.
proof fn mutant_consume_violates()
    ensures
        exists|t: Seq<State>| is_consume_trace(t) && !restore_evidence(t.last()),
{
    let e = Set::empty();
    let t3 = targets();
    let s0 = st(p_backup(), e, false, m_none(), m_none(), e, e, 0, e, false, false);
    let s1 = st(p_backup(), e, false, m_none(), m_none(), e.insert(1), e, 0, e, false, false);
    let s2 = st(
        p_backup(),
        e,
        false,
        m_none(),
        m_none(),
        e.insert(1).insert(2),
        e,
        0,
        e,
        false,
        false
    );
    let s3 = st(p_backup(), e, false, m_none(), m_none(), t3, e, 0, e, false, false);
    let s4 = st(p_files(), e, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s5 = st(p_recover(), e, false, m_files(), m_files(), t3, e, 1, e, false, false);
    let s6 = st(p_restore(), e, false, m_files(), m_files(), t3, t3, 1, e, false, false);
    let s7 = st(
        p_restore(),
        e,
        false,
        m_files(),
        m_files(),
        t3.remove(1),
        t3.remove(1),
        1,
        e,
        false,
        false
    );
    assert(init(s0));
    assert(next_mutant_consume(s0, s1)) by { assert(backup(s0, s1, 1)); }
    assert(next_mutant_consume(s1, s2)) by { assert(backup(s1, s2, 2)); }
    assert(next_mutant_consume(s2, s3)) by { assert(backup(s2, s3, 3)); }
    assert(next_mutant_consume(s3, s4)) by { assert(mark_files(s3, s4)); }
    assert(next_mutant_consume(s4, s5)) by { assert(process_interruption(s4, s5)); }
    assert(next_mutant_consume(s5, s6)) by {
        assert(needs_restore(s5));
        assert(recover_restore(s5, s6));
    }
    assert(next_mutant_consume(s6, s7)) by { assert(restore(s6, s7, true, 1)); }
    assert(!restore_evidence(s7)) by {
        assert(s7.pc == p_restore());
        assert(!targets().subset_of(s7.backups)) by {
            assert(targets().contains(1));
            assert(!s7.backups.contains(1));
        }
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7);
    assert(is_consume_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_consume(
            t[i],
            t[i + 1]
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7
            );
        }
    }
    assert(t.last() == s7);
    assert(is_consume_trace(t) && !restore_evidence(t.last()));
}

/// mutant-cleanup: full seal -> UnlinkPresent -> SyncMarker with
/// CleanupBeforeSync (durableMarker stays "committing") -> Cleanup(config)
/// -> PowerLoss restores "committing" with no config backup at recover.
proof fn mutant_cleanup_violates()
    ensures
        exists|t: Seq<State>| is_cleanup_trace(t) && !restart_evidence(t.last()),
{
    let e = Set::empty();
    let t3 = targets();
    let l1 = e.insert(1);
    let l12 = e.insert(1).insert(2);
    let s0 = st(p_backup(), e, false, m_none(), m_none(), e, e, 0, e, false, false);
    let s1 = st(p_backup(), e, false, m_none(), m_none(), l1, e, 0, e, false, false);
    let s2 = st(p_backup(), e, false, m_none(), m_none(), l12, e, 0, e, false, false);
    let s3 = st(p_backup(), e, false, m_none(), m_none(), t3, e, 0, e, false, false);
    let s4 = st(p_files(), e, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s5 = st(p_files(), l1, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s6 = st(p_files(), l12, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s7 = st(p_config(), l12, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s8 = st(p_complete(), t3, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s9 = st(p_unlink(), t3, true, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s10 = st(p_sync(), t3, true, m_none(), m_commit(), t3, e, 0, e, false, false);
    let s11 = st(p_cleanup(), t3, true, m_none(), m_commit(), t3, e, 0, e, false, false);
    let s12 = st(
        p_cleanup(),
        t3,
        true,
        m_none(),
        m_commit(),
        l12,
        e,
        0,
        e,
        false,
        false
    );
    let s13 = st(
        p_recover(),
        t3,
        true,
        m_commit(),
        m_commit(),
        l12,
        e,
        1,
        e,
        false,
        false
    );
    assert(init(s0));
    assert(next_mutant_cleanup(s0, s1)) by { assert(backup(s0, s1, 1)); }
    assert(next_mutant_cleanup(s1, s2)) by { assert(backup(s1, s2, 2)); }
    assert(next_mutant_cleanup(s2, s3)) by { assert(backup(s2, s3, 3)); }
    assert(next_mutant_cleanup(s3, s4)) by { assert(mark_files(s3, s4)); }
    assert(next_mutant_cleanup(s4, s5)) by { assert(write_file(s4, s5, 1)); }
    assert(next_mutant_cleanup(s5, s6)) by { assert(write_file(s5, s6, 2)); }
    assert(next_mutant_cleanup(s6, s7)) by { assert(seal_files(s6, s7)); }
    assert(next_mutant_cleanup(s7, s8)) by { assert(write_config(s7, s8)); }
    assert(next_mutant_cleanup(s8, s9)) by { assert(write_complete(s8, s9)); }
    assert(next_mutant_cleanup(s9, s10)) by { assert(unlink_present(s9, s10)); }
    assert(next_mutant_cleanup(s10, s11)) by { assert(sync_marker(s10, s11, true)); }
    assert(next_mutant_cleanup(s11, s12)) by { assert(cleanup(s11, s12, 3)); }
    assert(next_mutant_cleanup(s12, s13)) by { assert(power_loss(s12, s13)); }
    assert(!restart_evidence(s13)) by {
        assert(s13.pc == p_recover());
        assert(s13.marker != m_none());
        assert(!s13.damaged);
        assert(!s13.backups.contains(cfg_file()));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10).push(s11).push(s12).push(s13);
    assert(is_cleanup_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_cleanup(
            t[i],
            t[i + 1]
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                    || t[i] == s11 || t[i] == s12
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
                    || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12 || t[i + 1] == s13
            );
        }
    }
    assert(t.last() == s13);
    assert(is_cleanup_trace(t) && !restart_evidence(t.last()));
}

/// mutant-absent-marker: the interrupted first cleanup skips the barrier
/// on retry (marker already absent), Cleanup(config) runs with
/// durableMarker still "committing", and PowerLoss restores it at recover.
proof fn mutant_absent_violates()
    ensures
        exists|t: Seq<State>| is_absent_trace(t) && !restart_evidence(t.last()),
{
    let e = Set::empty();
    let t3 = targets();
    let l1 = e.insert(1);
    let l12 = e.insert(1).insert(2);
    let s0 = st(p_backup(), e, false, m_none(), m_none(), e, e, 0, e, false, false);
    let s1 = st(p_backup(), e, false, m_none(), m_none(), l1, e, 0, e, false, false);
    let s2 = st(p_backup(), e, false, m_none(), m_none(), l12, e, 0, e, false, false);
    let s3 = st(p_backup(), e, false, m_none(), m_none(), t3, e, 0, e, false, false);
    let s4 = st(p_files(), e, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s5 = st(p_files(), l1, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s6 = st(p_files(), l12, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s7 = st(p_config(), l12, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s8 = st(p_complete(), t3, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s9 = st(p_unlink(), t3, true, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s10 = st(p_sync(), t3, true, m_none(), m_commit(), t3, e, 0, e, false, false);
    let s11 = st(p_recover(), t3, true, m_none(), m_commit(), t3, e, 1, e, false, false);
    let s12 = st(p_unlink(), t3, true, m_none(), m_commit(), t3, e, 1, e, false, false);
    let s13 = st(p_cleanup(), t3, true, m_none(), m_commit(), t3, e, 1, e, false, false);
    let s14 = st(
        p_cleanup(),
        t3,
        true,
        m_none(),
        m_commit(),
        l12,
        e,
        1,
        e,
        false,
        false
    );
    let s15 = st(
        p_recover(),
        t3,
        true,
        m_commit(),
        m_commit(),
        l12,
        e,
        2,
        e,
        false,
        false
    );
    assert(init(s0));
    assert(next_mutant_absent(s0, s1)) by { assert(backup(s0, s1, 1)); }
    assert(next_mutant_absent(s1, s2)) by { assert(backup(s1, s2, 2)); }
    assert(next_mutant_absent(s2, s3)) by { assert(backup(s2, s3, 3)); }
    assert(next_mutant_absent(s3, s4)) by { assert(mark_files(s3, s4)); }
    assert(next_mutant_absent(s4, s5)) by { assert(write_file(s4, s5, 1)); }
    assert(next_mutant_absent(s5, s6)) by { assert(write_file(s5, s6, 2)); }
    assert(next_mutant_absent(s6, s7)) by { assert(seal_files(s6, s7)); }
    assert(next_mutant_absent(s7, s8)) by { assert(write_config(s7, s8)); }
    assert(next_mutant_absent(s8, s9)) by { assert(write_complete(s8, s9)); }
    assert(next_mutant_absent(s9, s10)) by { assert(unlink_present(s9, s10)); }
    assert(next_mutant_absent(s10, s11)) by { assert(process_interruption(s10, s11)); }
    assert(next_mutant_absent(s11, s12)) by {
        assert(can_keep(s11));
        assert(whole_snapshot(s11));
        assert(recover_keep(s11, s12));
    }
    assert(next_mutant_absent(s12, s13)) by { assert(unlink_absent(s12, s13, true)); }
    assert(next_mutant_absent(s13, s14)) by { assert(cleanup(s13, s14, 3)); }
    assert(next_mutant_absent(s14, s15)) by { assert(power_loss(s14, s15)); }
    assert(!restart_evidence(s15)) by {
        assert(s15.pc == p_recover());
        assert(s15.marker != m_none());
        assert(!s15.damaged);
        assert(!s15.backups.contains(cfg_file()));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10).push(s11).push(s12).push(s13).push(s14).push(s15);
    assert(is_absent_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_absent(
            t[i],
            t[i + 1]
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                    || t[i] == s11 || t[i] == s12 || t[i] == s13 || t[i] == s14
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
                    || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12 || t[i + 1] == s13
                    || t[i + 1] == s14 || t[i + 1] == s15
            );
        }
    }
    assert(t.last() == s15);
    assert(is_absent_trace(t) && !restart_evidence(t.last()));
}

/// mutant-pair-only: after WriteFile(a) the pair still matches
/// (live["config"] = complete = 0) but WholeSnapshot fails; Read with
/// PairOnlyAdmission sets badRead.
proof fn mutant_pair_only_violates()
    ensures
        exists|t: Seq<State>| is_pair_only_trace(t) && !sealed_admission(t.last()),
{
    let e = Set::empty();
    let t3 = targets();
    let l1 = e.insert(1);
    let l12 = e.insert(1).insert(2);
    let s0 = st(p_backup(), e, false, m_none(), m_none(), e, e, 0, e, false, false);
    let s1 = st(p_backup(), e, false, m_none(), m_none(), l1, e, 0, e, false, false);
    let s2 = st(p_backup(), e, false, m_none(), m_none(), l12, e, 0, e, false, false);
    let s3 = st(p_backup(), e, false, m_none(), m_none(), t3, e, 0, e, false, false);
    let s4 = st(p_files(), e, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s5 = st(p_files(), l1, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s6 = st(p_files(), l1, false, m_files(), m_files(), t3, e, 0, e, false, true);
    assert(init(s0));
    assert(next_mutant_pair_only(s0, s1)) by { assert(backup(s0, s1, 1)); }
    assert(next_mutant_pair_only(s1, s2)) by { assert(backup(s1, s2, 2)); }
    assert(next_mutant_pair_only(s2, s3)) by { assert(backup(s2, s3, 3)); }
    assert(next_mutant_pair_only(s3, s4)) by { assert(mark_files(s3, s4)); }
    assert(next_mutant_pair_only(s4, s5)) by { assert(write_file(s4, s5, 1)); }
    assert(next_mutant_pair_only(s5, s6)) by {
        assert(pair_matches(s5));
        assert(!whole_snapshot(s5)) by {
            assert(is_file(1));
            assert(s5.live1.contains(1) != s5.complete);
        }
        assert(read(s5, s6, true));
    }
    assert(!sealed_admission(s6));
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6);
    assert(is_pair_only_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_pair_only(
            t[i],
            t[i + 1]
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6
            );
        }
    }
    assert(t.last() == s6);
    assert(is_pair_only_trace(t) && !sealed_admission(t.last()));
}

/// Completion witness for the safe model: a full seal, one process
/// interruption recovered through RecoverKeep, then unlink, sync, cleanup
/// and finish reaching done with a whole snapshot.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().pc == p_done() && whole_snapshot(
            t.last()
        ),
{
    let e = Set::empty();
    let t3 = targets();
    let l1 = e.insert(1);
    let l12 = e.insert(1).insert(2);
    let l23 = e.insert(2).insert(3);
    let l3 = e.insert(3);
    let s0 = st(p_backup(), e, false, m_none(), m_none(), e, e, 0, e, false, false);
    let s1 = st(p_backup(), e, false, m_none(), m_none(), l1, e, 0, e, false, false);
    let s2 = st(p_backup(), e, false, m_none(), m_none(), l12, e, 0, e, false, false);
    let s3 = st(p_backup(), e, false, m_none(), m_none(), t3, e, 0, e, false, false);
    let s4 = st(p_files(), e, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s5 = st(p_files(), l1, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s6 = st(p_files(), l12, false, m_files(), m_files(), t3, e, 0, e, false, false);
    let s7 = st(p_config(), l12, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s8 = st(p_complete(), t3, false, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s9 = st(p_unlink(), t3, true, m_commit(), m_commit(), t3, e, 0, e, false, false);
    let s10 = st(p_recover(), t3, true, m_commit(), m_commit(), t3, e, 1, e, false, false);
    let s11 = st(p_unlink(), t3, true, m_commit(), m_commit(), t3, e, 1, e, false, false);
    let s12 = st(p_sync(), t3, true, m_none(), m_commit(), t3, e, 1, e, false, false);
    let s13 = st(p_cleanup(), t3, true, m_none(), m_none(), t3, e, 1, e, false, false);
    let s14 = st(p_cleanup(), t3, true, m_none(), m_none(), l23, e, 1, e, false, false);
    let s15 = st(p_cleanup(), t3, true, m_none(), m_none(), l3, e, 1, e, false, false);
    let s16 = st(p_cleanup(), t3, true, m_none(), m_none(), e, e, 1, e, false, false);
    let s17 = st(p_done(), t3, true, m_none(), m_none(), e, e, 1, e, false, false);
    assert(init(s0));
    assert(next(s0, s1)) by { assert(backup(s0, s1, 1)); }
    assert(next(s1, s2)) by { assert(backup(s1, s2, 2)); }
    assert(next(s2, s3)) by { assert(backup(s2, s3, 3)); }
    assert(next(s3, s4)) by { assert(mark_files(s3, s4)); }
    assert(next(s4, s5)) by { assert(write_file(s4, s5, 1)); }
    assert(next(s5, s6)) by { assert(write_file(s5, s6, 2)); }
    assert(next(s6, s7)) by { assert(seal_files(s6, s7)); }
    assert(next(s7, s8)) by { assert(write_config(s7, s8)); }
    assert(next(s8, s9)) by { assert(write_complete(s8, s9)); }
    assert(next(s9, s10)) by { assert(process_interruption(s9, s10)); }
    assert(next(s10, s11)) by {
        assert(can_keep(s10));
        assert(whole_snapshot(s10));
        assert(recover_keep(s10, s11));
    }
    assert(next(s11, s12)) by { assert(unlink_present(s11, s12)); }
    assert(next(s12, s13)) by { assert(sync_marker(s12, s13, false)); }
    assert(next(s13, s14)) by { assert(cleanup(s13, s14, 1)); }
    assert(next(s14, s15)) by { assert(cleanup(s14, s15, 2)); }
    assert(next(s15, s16)) by { assert(cleanup(s15, s16, 3)); }
    assert(next(s16, s17)) by { assert(finish(s16, s17)); }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7)
        .push(s8).push(s9).push(s10).push(s11).push(s12).push(s13).push(s14).push(s15).push(s16)
        .push(s17);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                    || t[i] == s11 || t[i] == s12 || t[i] == s13 || t[i] == s14 || t[i] == s15
                    || t[i] == s16
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1]
                    == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
                    || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12 || t[i + 1] == s13
                    || t[i + 1] == s14 || t[i + 1] == s15 || t[i + 1] == s16 || t[i + 1] == s17
            );
        }
    }
    assert(t.last() == s17);
    assert(whole_snapshot(s17));
    assert(is_trace(t) && t.last().pc == p_done() && whole_snapshot(t.last()));
}

}
