//! Verus pilot (4th model): inductive proof of RelayQuota's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs` and
//! `verify/private-publication/publication.rs`: `RelayQuota.tla` under
//! `normal.cfg` (MaxItems = 1, MaxBytes = 3, CrashBudget = 2, all five
//! mutant switches false) is re-stated as a Verus transition system and
//! the six checked invariants are proved inductive. Each of the five
//! mutant configurations is proved to reach a violation of the invariant
//! TLC found for it — `mutant-early-charge` breaks `ItemsChargedTogether`,
//! `mutant-duplicate-charge` and `mutant-duplicate-position` break
//! `RetryKeepsPositionAndCharge`, `mutant-token-reset` breaks
//! `StableIdentitySpend`, `mutant-early-receipt` breaks
//! `ReceiptAfterDurableRetention` — and a completion witness commits both
//! items through the full Begin→StageCharge→StageItem→Commit→Barrier→
//! Receipt lifecycle.
//!
//! Encoding notes:
//!   * Items == {"first","second"} is {1,2} (first ↦ 1), Keys ==
//!     {"owner","other"} is {1,2} (owner ↦ 1; the owner-map's "none" is
//!     0), Tokens == {"old","new"} is {0,1} and the seven phases are the
//!     int constants idle..closed = 0..6. Size(first) = 1, Size(second) =
//!     2; `size` is read only on Items.
//!   * `positions`, `original` and `owner` are `[Items -> int]` functions
//!     and become `Map<int,int>` built on the Items domain (`zmap`,
//!     updated by `insert`), read through `map_at` (0 off-domain, the
//!     model never reads elsewhere). `positions = original` keeps the
//!     literal map equality; TypeOK quantifies the codomains over Items.
//!   * `s.charges` / `s.stagedCharges` are sets of the `Charge` record
//!     datatype and `s.receipts` a set of `Receipt` — direct
//!     record-set encodings.
//!   * `Cardinality`/`ChargeBytes` over the key-filtered charge set are
//!     stated through its item projection `charged_items(k) = {i ∈ Items :
//!     ∃c ∈ charges, c.item = i ∧ c.key = k}`: per-item charge uniqueness
//!     and `bytes = Size(item)` (themselves checked conjuncts of
//!     `RetryKeepsPositionAndCharge`) make `c ↦ c.item` a bijection
//!     between key-k charges and `charged_items(k)` carrying each byte
//!     weight, so the equalities and bounds agree with the TLC
//!     cardinality/sum on every reachable state. `ItemBytes` and set
//!     cardinality over item sets are the closed forms `item_bytes` /
//!     `item_count` specialized to the two-element Items alphabet — every
//!     set the model sums is a subset of Items. `Spent(k) < MaxItems`
//!     (MaxItems = 1) is the literal `∄ c ∈ charges : c.key = k`.
//!   * The single TLA existential `\E i, k, t : Begin(i, k, t)` is one
//!     existential over the triple, and the five mutant switches are
//!     explicit parameters of `next_cfg` fixed by each config.
//!
//! Verify with:
//!   verus --crate-type=lib verify/relay-quota/quota.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Items == {"first", "second"} as {1, 2}.
pub open spec fn item_first() -> int {
    1
}

pub open spec fn item_second() -> int {
    2
}

pub open spec fn all_items() -> Set<int> {
    Set::empty().insert(1).insert(2)
}

pub open spec fn is_item(i: int) -> bool {
    i == item_first() || i == item_second()
}

/// Keys == {"owner", "other"} as {1, 2}; owner-map value "none" is 0.
pub open spec fn key_owner() -> int {
    1
}

pub open spec fn key_other() -> int {
    2
}

pub open spec fn is_key(k: int) -> bool {
    k == key_owner() || k == key_other()
}

/// Tokens == {"old", "new"} as {0, 1}.
pub open spec fn tok_old() -> int {
    0
}

pub open spec fn tok_new() -> int {
    1
}

pub open spec fn is_token(t: int) -> bool {
    t == tok_old() || t == tok_new()
}

/// Phases == {"idle","charge","item","commit","barrier","reply","closed"}
/// as 0..6.
pub open spec fn ph_idle() -> int {
    0
}

pub open spec fn ph_charge() -> int {
    1
}

pub open spec fn ph_item() -> int {
    2
}

pub open spec fn ph_commit() -> int {
    3
}

pub open spec fn ph_barrier() -> int {
    4
}

pub open spec fn ph_reply() -> int {
    5
}

pub open spec fn ph_closed() -> int {
    6
}

pub open spec fn is_phase(p: int) -> bool {
    0 <= p <= 6
}

/// normal.cfg constants.
pub open spec fn max_items() -> int {
    1
}

pub open spec fn max_bytes() -> int {
    3
}

pub open spec fn crash_budget() -> int {
    2
}

/// Size(i) == IF i = "first" THEN 1 ELSE 2; only read on Items.
pub open spec fn size(i: int) -> int {
    if i == item_first() {
        1
    } else {
        2
    }
}

/// The charge record [item |-> Items, key |-> Keys, bytes |-> 1..2,
/// serial |-> 0..4].
pub struct Charge {
    pub item: int,
    pub key: int,
    pub bytes: int,
    pub serial: int,
}

/// The receipt record [item, position, durable].
pub struct Receipt {
    pub item: int,
    pub position: int,
    pub durable: bool,
}

/// Total map read at int keys (see header note).
pub open spec fn map_at(m: Map<int, int>, j: int) -> int {
    if m.dom().contains(j) {
        m[j]
    } else {
        0
    }
}

/// The all-zero item map at Init (positions, original, owner).
pub open spec fn zmap() -> Map<int, int> {
    Map::new(all_items(), |i: int| 0)
}

/// VARIABLE s — one field per TLA record component.
pub struct State {
    pub pc: int,
    pub items: Set<int>,
    pub charges: Set<Charge>,
    pub positions: Map<int, int>,
    pub original: Map<int, int>,
    pub owner: Map<int, int>,
    pub synced: Set<int>,
    pub head: int,
    pub token: int,
    pub rotated: bool,
    pub item: int,
    pub key: int,
    pub duplicate: bool,
    pub staged_items: Set<int>,
    pub staged_charges: Set<Charge>,
    pub receipts: Set<Receipt>,
    pub crashes: int,
    pub attempts: int,
}

/// The record-set membership bound of TypeOK.
pub open spec fn is_charge(c: Charge) -> bool {
    &&& is_item(c.item)
    &&& is_key(c.key)
    &&& 1 <= c.bytes <= 2
    &&& 0 <= c.serial <= 4
}

/// Charged(i) == \E charge \in s.charges : charge.item = i.
pub open spec fn charged(s: State, i: int) -> bool {
    exists|c: Charge| #[trigger] s.charges.contains(c) && c.item == i
}

/// Position(i) == IF i \in s.items THEN s.positions[i] ELSE 0.
pub open spec fn position(s: State, i: int) -> int {
    if s.items.contains(i) {
        map_at(s.positions, i)
    } else {
        0
    }
}

/// The item projection of the key-k charges,
/// {c.item : c \in s.charges, c.key = k}. Under the per-item uniqueness of
/// RetryKeepsPositionAndCharge this bijects to {c : c.key = k}, so its
/// cardinality is Spent(k) and item_bytes of it is SpentBytes(k).
pub open spec fn charged_items(s: State, k: int) -> Set<int> {
    all_items().filter(|i: int| exists|c: Charge| #[trigger] s.charges.contains(c)
        && c.item == i && c.key == k)
}

/// {i \in s.items : s.owner[i] = k}.
pub open spec fn owned_items(s: State, k: int) -> Set<int> {
    s.items.filter(|i: int| map_at(s.owner, i) == k)
}

/// ItemBytes specialized to subsets of the two-item alphabet.
pub open spec fn item_bytes(items: Set<int>) -> int {
    (if items.contains(item_first()) {
        1int
    } else {
        0
    }) + (if items.contains(item_second()) {
        2int
    } else {
        0
    })
}

/// Cardinality specialized to subsets of the two-item alphabet.
pub open spec fn item_count(items: Set<int>) -> int {
    (if items.contains(item_first()) {
        1int
    } else {
        0
    }) + (if items.contains(item_second()) {
        1int
    } else {
        0
    })
}

/// The charge a safe StageCharge stages for the in-flight request.
pub open spec fn fresh_charge(s: State) -> Charge {
    Charge { item: s.item, key: s.key, bytes: size(s.item), serial: 0 }
}

/// Init.
pub open spec fn init(s: State) -> bool {
    &&& s.pc == ph_idle()
    &&& s.items =~= Set::empty()
    &&& s.charges =~= Set::empty()
    &&& s.positions =~= zmap()
    &&& s.original =~= zmap()
    &&& s.owner =~= zmap()
    &&& s.synced =~= Set::empty()
    &&& s.head == 0
    &&& s.token == tok_old()
    &&& !s.rotated
    &&& s.item == item_first()
    &&& s.key == key_owner()
    &&& !s.duplicate
    &&& s.staged_items =~= Set::empty()
    &&& s.staged_charges =~= Set::empty()
    &&& s.receipts =~= Set::empty()
    &&& s.crashes == 0
    &&& s.attempts == 0
}

/// Begin(i, k, token): idle, under the four-request bound, authenticated
/// (the "other" credential carries independent work permission, else the
/// token must match), and either an already-committed item (exact retry)
/// or quota headroom under k.
pub open spec fn begin(pre: State, post: State, i: int, k: int, t: int) -> bool {
    &&& pre.pc == ph_idle()
    &&& pre.attempts < 4
    &&& (k == key_other() || t == pre.token)
    &&& (pre.items.contains(i) || (!(exists|c: Charge| #[trigger] pre.charges.contains(
        c,
    ) && c.key == k) && item_bytes(charged_items(pre, k)) + size(i) <= max_bytes()))
    &&& post.pc == ph_charge()
    &&& post.item == i
    &&& post.key == k
    &&& post.duplicate == pre.items.contains(i)
    &&& post.staged_items =~= pre.items
    &&& post.staged_charges =~= pre.charges
    &&& post.attempts == pre.attempts + 1
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
}

/// StageCharge, parameterized by EarlyCharge / DuplicateCharge: stage the
/// constructed charge unless the item is already charged (DuplicateCharge
/// keeps the fresh serial instead); EarlyCharge also publishes it to the
/// durable ledger before its item transaction commits.
pub open spec fn stage_charge(pre: State, post: State, ec: bool, dc: bool) -> bool {
    &&& pre.pc == ph_charge()
    &&& post.pc == ph_item()
    &&& post.staged_charges =~= if charged(pre, pre.item) && !dc {
        pre.charges
    } else {
        pre.charges.insert(Charge {
            item: pre.item,
            key: pre.key,
            bytes: size(pre.item),
            serial: if dc {
                pre.attempts
            } else {
                0
            },
        })
    }
    &&& post.charges =~= if ec {
        post.staged_charges
    } else {
        pre.charges
    }
    &&& post.items =~= pre.items
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// StageItem: stage the item alongside its charge.
pub open spec fn stage_item(pre: State, post: State) -> bool {
    &&& pre.pc == ph_item()
    &&& post.pc == ph_commit()
    &&& post.staged_items =~= pre.staged_items.insert(pre.item)
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.charges =~= pre.charges
    &&& post.items =~= pre.items
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Commit, parameterized by MoveDuplicate: one transaction publishes the
/// staged items and charges; a non-duplicate item takes position head+1,
/// records the original position and the stable charge owner, and bumps
/// head. A duplicate retry keeps all three.
pub open spec fn commit(pre: State, post: State, md: bool) -> bool {
    &&& pre.pc == ph_commit()
    &&& post.pc == ph_barrier()
    &&& post.items =~= pre.staged_items
    &&& post.charges =~= pre.staged_charges
    &&& post.positions =~= pre.positions.insert(pre.item, if pre.duplicate && !md {
        map_at(pre.positions, pre.item)
    } else {
        pre.head + 1
    })
    &&& post.original =~= pre.original.insert(pre.item, if pre.duplicate {
        map_at(pre.original, pre.item)
    } else {
        pre.head + 1
    })
    &&& post.owner =~= pre.owner.insert(pre.item, if pre.duplicate {
        map_at(pre.owner, pre.item)
    } else {
        pre.key
    })
    &&& post.head == if pre.duplicate {
        pre.head
    } else {
        pre.head + 1
    }
    &&& post.synced =~= pre.synced
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Barrier: the separate successful durability barrier snapshots the
/// committed items before any receipt is constructed.
pub open spec fn barrier(pre: State, post: State) -> bool {
    &&& pre.pc == ph_barrier()
    &&& post.pc == ph_reply()
    &&& post.synced =~= pre.items
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Receipt, parameterized by EarlyReceipt: record the reply's position
/// and whether the item was durable at receipt time.
pub open spec fn receipt(pre: State, post: State, er: bool) -> bool {
    &&& (pre.pc == ph_reply() || (er && pre.pc == ph_barrier()))
    &&& post.pc == ph_idle()
    &&& post.receipts =~= pre.receipts.insert(Receipt {
        item: pre.item,
        position: position(pre, pre.item),
        durable: pre.synced.contains(pre.item),
    })
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// LostReceipt: the peer can lose the response after commit/barrier;
/// nothing retained is removed.
pub open spec fn lost_receipt(pre: State, post: State) -> bool {
    &&& pre.pc == ph_reply()
    &&& post.pc == ph_idle()
    &&& post.receipts =~= pre.receipts
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Rollback: an uncommitted transaction drops its staged writes.
pub open spec fn rollback(pre: State, post: State) -> bool {
    &&& (pre.pc == ph_charge() || pre.pc == ph_item() || pre.pc == ph_commit())
    &&& post.pc == ph_idle()
    &&& post.staged_items =~= Set::empty()
    &&& post.staged_charges =~= Set::empty()
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Crash: within the interruption budget, staged writes disappear and the
/// committed transaction ledger is retained.
pub open spec fn crash(pre: State, post: State) -> bool {
    &&& pre.pc != ph_closed()
    &&& pre.crashes < crash_budget()
    &&& post.pc == ph_closed()
    &&& post.crashes == pre.crashes + 1
    &&& post.staged_items =~= Set::empty()
    &&& post.staged_charges =~= Set::empty()
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.receipts =~= pre.receipts
    &&& post.attempts == pre.attempts
}

/// Reopen: successful validation of the retained ledger establishes a new
/// barrier.
pub open spec fn reopen(pre: State, post: State) -> bool {
    &&& pre.pc == ph_closed()
    &&& post.pc == ph_idle()
    &&& post.synced =~= pre.items
    &&& post.items =~= pre.items
    &&& post.charges =~= pre.charges
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.head == pre.head
    &&& post.token == pre.token
    &&& post.rotated == pre.rotated
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// RotateToken, parameterized by ResetQuota: token replacement preserves
/// the stable key identity; ResetQuota forgets the owner's charges.
pub open spec fn rotate_token(pre: State, post: State, rq: bool) -> bool {
    &&& pre.pc == ph_idle()
    &&& !pre.rotated
    &&& post.token == tok_new()
    &&& post.rotated
    &&& post.charges =~= if rq {
        pre.charges.filter(|c: Charge| c.key != key_owner())
    } else {
        pre.charges
    }
    &&& post.pc == pre.pc
    &&& post.items =~= pre.items
    &&& post.positions =~= pre.positions
    &&& post.original =~= pre.original
    &&& post.owner =~= pre.owner
    &&& post.synced =~= pre.synced
    &&& post.head == pre.head
    &&& post.item == pre.item
    &&& post.key == pre.key
    &&& post.duplicate == pre.duplicate
    &&& post.staged_items =~= pre.staged_items
    &&& post.staged_charges =~= pre.staged_charges
    &&& post.receipts =~= pre.receipts
    &&& post.crashes == pre.crashes
    &&& post.attempts == pre.attempts
}

/// Next under arbitrary config constants (EarlyCharge, DuplicateCharge,
/// MoveDuplicate, ResetQuota, EarlyReceipt).
pub open spec fn next_cfg(
    ec: bool,
    dc: bool,
    md: bool,
    rq: bool,
    er: bool,
    pre: State,
    post: State,
) -> bool {
    ||| stage_charge(pre, post, ec, dc)
    ||| stage_item(pre, post)
    ||| commit(pre, post, md)
    ||| barrier(pre, post)
    ||| receipt(pre, post, er)
    ||| lost_receipt(pre, post)
    ||| rollback(pre, post)
    ||| crash(pre, post)
    ||| reopen(pre, post)
    ||| rotate_token(pre, post, rq)
    ||| exists|i: int, k: int, t: int|
        is_item(i) && is_key(k) && is_token(t) && #[trigger] begin(pre, post, i, k, t)
}

/// normal.cfg: all five mutant switches false.
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, false, pre, post)
}

/// The five mutant configurations.
pub open spec fn next_mutant_early_charge(pre: State, post: State) -> bool {
    next_cfg(true, false, false, false, false, pre, post)
}

pub open spec fn next_mutant_duplicate_charge(pre: State, post: State) -> bool {
    next_cfg(false, true, false, false, false, pre, post)
}

pub open spec fn next_mutant_duplicate_position(pre: State, post: State) -> bool {
    next_cfg(false, false, true, false, false, pre, post)
}

pub open spec fn next_mutant_token_reset(pre: State, post: State) -> bool {
    next_cfg(false, false, false, true, false, pre, post)
}

pub open spec fn next_mutant_early_receipt(pre: State, post: State) -> bool {
    next_cfg(false, false, false, false, true, pre, post)
}

/// TypeOK.
pub open spec fn type_ok(s: State) -> bool {
    &&& is_phase(s.pc)
    &&& s.items.subset_of(all_items())
    &&& s.synced.subset_of(s.items)
    &&& s.positions.dom() =~= all_items()
    &&& forall|i: int| is_item(i) ==> 0 <= map_at(s.positions, i) <= 2
    &&& s.original.dom() =~= all_items()
    &&& forall|i: int| is_item(i) ==> 0 <= map_at(s.original, i) <= 2
    &&& s.owner.dom() =~= all_items()
    &&& forall|i: int| is_item(i) ==> (is_key(map_at(s.owner, i)) || map_at(s.owner, i) == 0)
    &&& is_item(s.item)
    &&& is_key(s.key)
    &&& is_token(s.token)
    &&& 0 <= s.head <= 2
    &&& 0 <= s.crashes <= crash_budget()
    &&& 0 <= s.attempts <= 4
    &&& s.staged_items.subset_of(all_items())
    &&& forall|c: Charge| s.charges.contains(c) ==> is_charge(c)
    &&& forall|c: Charge| s.staged_charges.contains(c) ==> is_charge(c)
}

/// ItemsChargedTogether == {c.item : c \in s.charges} = s.items.
pub open spec fn items_charged_together(s: State) -> bool {
    &&& forall|c: Charge| s.charges.contains(c) ==> s.items.contains(c.item)
    &&& forall|i: int| s.items.contains(i) ==> exists|c: Charge|
        #[trigger] s.charges.contains(c) && c.item == i
}

/// RetryKeepsPositionAndCharge == positions = original /\\ every committed
/// item carries exactly one charge bound to its stable owner and size.
/// `Cardinality({c : c.item = i}) = 1` is exists + pairwise equality.
pub open spec fn retry_keeps(s: State) -> bool {
    &&& s.positions =~= s.original
    &&& forall|i: int| s.items.contains(i) ==> {
        &&& exists|c: Charge| #[trigger] s.charges.contains(c) && c.item == i
        &&& forall|c1: Charge, c2: Charge| s.charges.contains(c1) && s.charges.contains(c2)
            && c1.item == i && c2.item == i ==> c1 == c2
        &&& forall|c: Charge| s.charges.contains(c) && c.item == i
            ==> c.key == map_at(s.owner, i) && c.bytes == size(i)
    }
}

/// StableIdentitySpend == \A k : Spent(k) = |{i \in items : owner[i] = k}|
/// /\ SpentBytes(k) = ItemBytes(that set). Stated as equality of the
/// item projections plus their byte sums (see header note).
pub open spec fn stable_identity_spend(s: State) -> bool {
    forall|k: int| is_key(k) ==> {
        &&& charged_items(s, k) =~= owned_items(s, k)
        &&& item_bytes(charged_items(s, k)) == item_bytes(owned_items(s, k))
    }
}

/// QuotaBound == \A k : Spent(k) <= MaxItems /\ SpentBytes(k) <= MaxBytes.
/// Spent(k) <= 1 is pairwise equality of the key-k charge items.
pub open spec fn quota_bound(s: State) -> bool {
    forall|k: int| is_key(k) ==> {
        &&& forall|i: int, j: int| charged_items(s, k).contains(i) && charged_items(s, k)
            .contains(j) ==> i == j
        &&& item_bytes(charged_items(s, k)) <= max_bytes()
    }
}

/// ReceiptAfterDurableRetention == \A r \in s.receipts :
/// r.durable /\ r.position > 0 /\ r.position = s.original[r.item].
pub open spec fn receipt_after_durable(s: State) -> bool {
    forall|r: Receipt| s.receipts.contains(r) ==> (r.durable && r.position > 0
        && r.position == map_at(s.original, r.item))
}

/// Auxiliary: while a transaction is in flight, `duplicate` still records
/// whether its item was already committed.
pub open spec fn duplicate_flag(s: State) -> bool {
    (s.pc == ph_charge() || s.pc == ph_item() || s.pc == ph_commit())
        ==> (s.duplicate == s.items.contains(s.item))
}

/// Auxiliary: a non-duplicate transaction passed the Begin quota check —
/// no retained charge carries its key and its byte budget fits.
pub open spec fn begin_quota(s: State) -> bool {
    ((s.pc == ph_charge() || s.pc == ph_item() || s.pc == ph_commit())
        && !s.items.contains(s.item)) ==> (!(exists|c: Charge| #[trigger] s.charges
        .contains(c) && c.key == s.key) && item_bytes(charged_items(s, s.key)) + size(
        s.item,
    ) <= max_bytes())
}

/// Auxiliary: the staged snapshots track the durable ledger by phase —
/// Begin copies the ledger, StageCharge adds the new charge only for an
/// uncommitted item, StageItem adds the item.
pub open spec fn staged_consistent(s: State) -> bool {
    &&& (s.pc == ph_charge() ==> (s.staged_items =~= s.items && s.staged_charges
        =~= s.charges))
    &&& (s.pc == ph_item() ==> s.staged_items =~= s.items)
    &&& (s.pc == ph_commit() ==> s.staged_items =~= s.items.insert(s.item))
    &&& ((s.pc == ph_item() || s.pc == ph_commit()) && s.items.contains(s.item)
        ==> s.staged_charges =~= s.charges)
    &&& ((s.pc == ph_item() || s.pc == ph_commit()) && !s.items.contains(s.item)
        ==> s.staged_charges =~= s.charges.insert(fresh_charge(s)))
}

/// Auxiliary: after Commit the acted item is committed.
pub open spec fn item_committed(s: State) -> bool {
    (s.pc == ph_barrier() || s.pc == ph_reply()) ==> s.items.contains(s.item)
}

/// Auxiliary: the reply phase's barrier snapshot is exactly the committed
/// items — only Barrier enters reply, and it copies items.
pub open spec fn reply_synced(s: State) -> bool {
    s.pc == ph_reply() ==> s.synced =~= s.items
}

/// Auxiliary: distinct committed items have distinct owners — MaxItems = 1
/// means a key can own at most one commit.
pub open spec fn owners_distinct(s: State) -> bool {
    forall|i: int, j: int| s.items.contains(i) && s.items.contains(j) && map_at(s.owner, i)
        == map_at(s.owner, j) ==> i == j
}

/// Auxiliary: head counts the committed items.
pub open spec fn head_count(s: State) -> bool {
    s.head == item_count(s.items)
}

/// Auxiliary: a committed item's position is positive (it was assigned
/// head+1 at its commit).
pub open spec fn positions_positive(s: State) -> bool {
    forall|i: int| s.items.contains(i) ==> map_at(s.positions, i) > 0
}

/// Auxiliary: every receipt refers to a committed item.
pub open spec fn receipt_items(s: State) -> bool {
    forall|r: Receipt| s.receipts.contains(r) ==> s.items.contains(r.item)
}

/// The inductive invariant: the six checked invariants strengthened by
/// the nine auxiliaries above.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& items_charged_together(s)
    &&& retry_keeps(s)
    &&& stable_identity_spend(s)
    &&& quota_bound(s)
    &&& receipt_after_durable(s)
    &&& duplicate_flag(s)
    &&& begin_quota(s)
    &&& staged_consistent(s)
    &&& item_committed(s)
    &&& reply_synced(s)
    &&& owners_distinct(s)
    &&& head_count(s)
    &&& positions_positive(s)
    &&& receipt_items(s)
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert forall|i: int| is_item(i) implies 0 <= map_at(s.positions, i) <= 2 by {
        assert(s.positions.dom().contains(i));
    }
    assert forall|i: int| is_item(i) implies 0 <= map_at(s.original, i) <= 2 by {
        assert(s.original.dom().contains(i));
    }
    assert forall|i: int| is_item(i) implies (is_key(map_at(s.owner, i))
        || map_at(s.owner, i) == 0) by {
        assert(s.owner.dom().contains(i));
    }
    assert(item_count(s.items) == 0) by {
        assert(!s.items.contains(item_first()));
        assert(!s.items.contains(item_second()));
    }
    assert forall|k: int| is_key(k) implies (charged_items(s, k) =~= owned_items(s, k)
        && item_bytes(charged_items(s, k)) == item_bytes(owned_items(s, k))) by {
        assert forall|i: int| charged_items(s, k).contains(i) implies owned_items(
            s,
            k,
        ).contains(i) by {
            assert(exists|c: Charge| s.charges.contains(c) && c.item == i && c.key == k);
            assert(!(exists|c: Charge| s.charges.contains(c) && c.item == i && c.key == k)) by {
                assert forall|c: Charge| !(s.charges.contains(c) && c.item == i && c.key
                    == k) by {}
            }
            assert(false);
        }
    }
}

/// Map insert propagation used everywhere below.
proof fn map_insert_at(m: Map<int, int>, k: int, v: int, x: int)
    ensures
        map_at(m.insert(k, v), x) == if x == k {
            v
        } else {
            map_at(m, x)
        },
{
}

/// items ⊆ {1,2} implies |items| <= 2, and < 2 when an item is absent.
proof fn count_bounds(items: Set<int>, i: int)
    requires
        items.subset_of(all_items()),
        is_item(i),
        !items.contains(i),
    ensures
        item_count(items) <= 1,
        item_count(items.insert(i)) == item_count(items) + 1,
        items.insert(i).subset_of(all_items()),
{
    assert(items.contains(item_first()) ==> i != item_first());
    assert(items.contains(item_second()) ==> i != item_second());
    assert forall|x: int| items.insert(i).contains(x) implies all_items().contains(x) by {
        if x == i {
            assert(is_item(i));
        } else {
            assert(items.contains(x));
        }
    }
}

proof fn begin_preserves(pre: State, post: State, i: int, k: int, t: int)
    requires
        inv(pre),
        is_item(i),
        is_key(k),
        is_token(t),
        begin(pre, post, i, k, t),
    ensures
        inv(post),
{
    // staged_consistent at pc = charge follows from the Begin snapshot.
    // begin_quota: for i ∉ items the guard's second disjunct held.
    if !pre.items.contains(i) {
        assert(!(exists|c: Charge| #[trigger] pre.charges.contains(c) && c.key == k));
        assert(item_bytes(charged_items(pre, k)) + size(i) <= max_bytes());
        // charged_items depends only on charges, which is unchanged.
        assert(charged_items(post, k) =~= charged_items(pre, k));
        assert(!post.items.contains(post.item));
        assert(!(exists|c: Charge| #[trigger] post.charges.contains(c) && c.key
            == post.key));
    }
    assert forall|c: Charge| post.charges.contains(c) implies is_charge(c) by {
        assert(pre.charges.contains(c));
    }
    assert forall|c: Charge| post.staged_charges.contains(c) implies is_charge(c) by {
        assert(pre.charges.contains(c));
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        assert(pre.items.contains(r.item));
    }
    // stable_identity_spend / quota_bound: charges, items and owner are
    // unchanged, so the projections are unchanged.
    assert forall|kk: int| is_key(kk) implies (charged_items(post, kk)
        =~= owned_items(post, kk) && item_bytes(charged_items(post, kk))
        == item_bytes(owned_items(post, kk))) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(owned_items(post, kk) =~= owned_items(pre, kk));
        assert(charged_items(pre, kk) =~= owned_items(pre, kk));
        assert(item_bytes(charged_items(pre, kk)) == item_bytes(owned_items(pre, kk)));
    }
    assert forall|kk: int| is_key(kk) implies ((forall|x: int, y: int| charged_items(
        post,
        kk,
    ).contains(x) && charged_items(post, kk).contains(y) ==> x == y)
        && item_bytes(charged_items(post, kk)) <= max_bytes()) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(item_bytes(charged_items(post, kk)) == item_bytes(charged_items(pre, kk)));
        assert(item_bytes(charged_items(pre, kk)) <= max_bytes());
        assert forall|x: int, y: int| charged_items(post, kk).contains(x) && charged_items(
            post,
            kk,
        ).contains(y) implies x == y by {
            assert(charged_items(pre, kk).contains(x));
            assert(charged_items(pre, kk).contains(y));
        }
    }
    assert forall|x: int| post.items.contains(x) implies exists|c: Charge|
        #[trigger] post.charges.contains(c) && c.item == x by {
        assert(pre.items.contains(x));
        let c = choose|c: Charge| pre.charges.contains(c) && c.item == x;
        assert(post.charges.contains(c));
    }
    assert forall|x: int| post.items.contains(x) implies map_at(post.positions, x)
        > 0 by {
        assert(pre.items.contains(x));
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn stage_charge_preserves(pre: State, post: State)
    requires
        inv(pre),
        stage_charge(pre, post, false, false),
    ensures
        inv(post),
{
    let i = pre.item;
    let c0 = fresh_charge(pre);
    // staged_consistent gives staged_items =~= items at pc = charge.
    assert(pre.staged_items =~= pre.items);
    assert(pre.staged_charges =~= pre.charges);
    assert(pre.duplicate == pre.items.contains(i));
    if pre.items.contains(i) {
        // items ⊆ image(charges) supplies the charge; charged(i) holds, so
        // stagedCharges' = charges.
        let c = choose|c: Charge| pre.charges.contains(c) && c.item == i;
        assert(charged(pre, i));
        assert(post.staged_charges =~= pre.charges);
    } else {
        // i ∉ items = image(charges), so Charged(i) fails and the fresh
        // charge is staged.
        if charged(pre, i) {
            let c = choose|c: Charge| pre.charges.contains(c) && c.item == i;
            assert(pre.items.contains(c.item));
            assert(false);
        }
        assert(post.staged_charges =~= pre.charges.insert(c0));
    }
    // is_charge bounds for the possibly-new staged record.
    assert(1 <= size(i) <= 2) by {
        assert(is_item(i));
    }
    assert forall|c: Charge| post.staged_charges.contains(c) implies is_charge(c) by {
        if pre.items.contains(i) {
            assert(pre.charges.contains(c));
        } else {
            if c == c0 {
            } else {
                assert(pre.charges.contains(c));
            }
        }
    }
    assert forall|c: Charge| post.charges.contains(c) implies is_charge(c) by {
        assert(pre.charges.contains(c));
    }
    assert forall|c: Charge| post.charges.contains(c) implies post.items.contains(
        c.item,
    ) by {
        assert(pre.charges.contains(c));
    }
    assert forall|x: int| post.items.contains(x) implies exists|c: Charge|
        #[trigger] post.charges.contains(c) && c.item == x by {
        assert(pre.items.contains(x));
    }
    assert forall|kk: int| is_key(kk) implies (charged_items(post, kk)
        =~= owned_items(post, kk) && item_bytes(charged_items(post, kk))
        == item_bytes(owned_items(post, kk))) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(owned_items(post, kk) =~= owned_items(pre, kk));
    }
    assert forall|kk: int| is_key(kk) implies ((forall|x: int, y: int| charged_items(
        post,
        kk,
    ).contains(x) && charged_items(post, kk).contains(y) ==> x == y)
        && item_bytes(charged_items(post, kk)) <= max_bytes()) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(item_bytes(charged_items(post, kk)) == item_bytes(charged_items(pre, kk)));
        assert forall|x: int, y: int| charged_items(post, kk).contains(x) && charged_items(
            post,
            kk,
        ).contains(y) implies x == y by {
            assert(charged_items(pre, kk).contains(x));
            assert(charged_items(pre, kk).contains(y));
        }
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        assert(pre.items.contains(r.item));
    }
    assert forall|x: int| post.items.contains(x) implies map_at(post.positions, x)
        > 0 by {
        assert(pre.items.contains(x));
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn stage_item_preserves(pre: State, post: State)
    requires
        inv(pre),
        stage_item(pre, post),
    ensures
        inv(post),
{
    let i = pre.item;
    assert(pre.staged_items =~= pre.items);
    assert(post.staged_items =~= pre.items.insert(i));
    if pre.items.contains(i) {
        assert(pre.items.insert(i) =~= pre.items);
        assert(pre.staged_charges =~= pre.charges);
    } else {
        assert(pre.staged_charges =~= pre.charges.insert(fresh_charge(pre)));
    }
    assert forall|c: Charge| post.charges.contains(c) implies is_charge(c) by {
        assert(pre.charges.contains(c));
    }
    assert forall|c: Charge| post.staged_charges.contains(c) implies is_charge(c) by {
        assert(pre.staged_charges.contains(c));
    }
    assert forall|c: Charge| post.charges.contains(c) implies post.items.contains(
        c.item,
    ) by {
        assert(pre.charges.contains(c));
    }
    assert forall|x: int| post.items.contains(x) implies exists|c: Charge|
        #[trigger] post.charges.contains(c) && c.item == x by {
        assert(pre.items.contains(x));
    }
    assert forall|kk: int| is_key(kk) implies (charged_items(post, kk)
        =~= owned_items(post, kk) && item_bytes(charged_items(post, kk))
        == item_bytes(owned_items(post, kk))) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(owned_items(post, kk) =~= owned_items(pre, kk));
    }
    assert forall|kk: int| is_key(kk) implies ((forall|x: int, y: int| charged_items(
        post,
        kk,
    ).contains(x) && charged_items(post, kk).contains(y) ==> x == y)
        && item_bytes(charged_items(post, kk)) <= max_bytes()) by {
        assert(charged_items(post, kk) =~= charged_items(pre, kk));
        assert(item_bytes(charged_items(post, kk)) == item_bytes(charged_items(pre, kk)));
        assert forall|x: int, y: int| charged_items(post, kk).contains(x) && charged_items(
            post,
            kk,
        ).contains(y) implies x == y by {
            assert(charged_items(pre, kk).contains(x));
            assert(charged_items(pre, kk).contains(y));
        }
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        assert(pre.items.contains(r.item));
    }
    assert forall|x: int| post.items.contains(x) implies map_at(post.positions, x)
        > 0 by {
        assert(pre.items.contains(x));
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn commit_preserves(pre: State, post: State)
    requires
        inv(pre),
        commit(pre, post, false),
    ensures
        inv(post),
{
    let i = pre.item;
    let k = pre.key;
    let c0 = fresh_charge(pre);
    assert(pre.duplicate == pre.items.contains(i));
    assert(pre.staged_items =~= pre.items.insert(i));
    if pre.items.contains(i) {
        assert(pre.items.insert(i) =~= pre.items);
        assert(pre.staged_charges =~= pre.charges);
    } else {
        assert(pre.staged_charges =~= pre.charges.insert(c0));
    }
    assert(post.items =~= pre.items.insert(i));
    assert(post.items.contains(i));
    assert(post.items.subset_of(all_items()));
    // begin_quota gives the head bounds: a new item needed a fresh key.
    if !pre.items.contains(i) {
        assert(!(exists|c: Charge| #[trigger] pre.charges.contains(c) && c.key == k));
        assert(item_bytes(charged_items(pre, k)) + size(i) <= max_bytes());
        count_bounds(pre.items, i);
    }

    // items_charged_together(post)
    assert forall|c: Charge| post.charges.contains(c) implies post.items.contains(
        c.item,
    ) by {
        assert(pre.staged_charges.contains(c));
        if pre.items.contains(i) {
            assert(pre.charges.contains(c));
            assert(pre.items.contains(c.item));
        } else {
            if c == c0 {
                assert(c.item == i);
            } else {
                assert(pre.charges.contains(c));
                assert(pre.items.contains(c.item));
            }
        }
    }
    assert forall|x: int| post.items.contains(x) implies exists|c: Charge|
        #[trigger] post.charges.contains(c) && c.item == x by {
        if x == i {
            if pre.items.contains(i) {
                let c = choose|c: Charge| pre.charges.contains(c) && c.item == i;
                assert(post.charges.contains(c));
            } else {
                assert(post.staged_charges.contains(c0));
            }
        } else {
            assert(pre.items.contains(x));
            let c = choose|c: Charge| pre.charges.contains(c) && c.item == x;
            assert(pre.staged_charges.contains(c));
            assert(post.charges.contains(c));
        }
    }

    // retry_keeps(post): positions' = original' first.
    assert(post.positions.dom() =~= all_items());
    assert(post.original.dom() =~= all_items());
    assert forall|x: int| post.positions.dom().contains(x) implies post.positions[x]
        == post.original[x] by {
        map_insert_at(pre.positions, i, if pre.duplicate {
            map_at(pre.positions, i)
        } else {
            pre.head + 1
        }, x);
        map_insert_at(pre.original, i, if pre.duplicate {
            map_at(pre.original, i)
        } else {
            pre.head + 1
        }, x);
        assert(is_item(x));
        if x == i {
            if pre.duplicate {
                assert(map_at(pre.positions, i) == map_at(pre.original, i));
            }
        } else {
            assert(map_at(pre.positions, x) == map_at(pre.original, x));
        }
    }
    assert(post.positions =~= post.original);
    // retry_keeps(post): exactly one charge per committed item.
    assert forall|x: int| post.items.contains(x) implies ((exists|c: Charge|
        #[trigger] post.charges.contains(c) && c.item == x) && (forall|c1: Charge,
        c2: Charge| post.charges.contains(c1) && post.charges.contains(c2) && c1.item
        == x && c2.item == x ==> c1 == c2) && (forall|c: Charge| post.charges.contains(
        c,
    ) && c.item == x ==> c.key == map_at(post.owner, x) && c.bytes == size(x))) by {
        // membership direction first: every post charge came from staged,
        // which is charges or charges + c0.
        if x == i {
            if pre.items.contains(i) {
                let c = choose|c: Charge| pre.charges.contains(c) && c.item == i;
                assert(post.charges.contains(c) && c.item == x);
            } else {
                assert(post.charges.contains(c0) && c0.item == x);
            }
        } else {
            assert(pre.items.contains(x));
            let c = choose|c: Charge| pre.charges.contains(c) && c.item == x;
            assert(pre.staged_charges.contains(c));
            assert(post.charges.contains(c) && c.item == x);
        }
        assert forall|c1: Charge, c2: Charge| post.charges.contains(c1)
            && post.charges.contains(c2) && c1.item == x && c2.item == x implies c1
            == c2 by {
            if !pre.items.contains(i) {
                if c1 == c0 {
                } else {
                    assert(pre.charges.contains(c1));
                }
                if c2 == c0 {
                } else {
                    assert(pre.charges.contains(c2));
                }
                // any charge from pre.charges with item x: x ∈ items, so
                // x == i impossible here; use pre uniqueness.
                if pre.charges.contains(c1) && pre.charges.contains(c2) {
                    assert(pre.items.contains(c1.item));
                    assert(pre.items.contains(x));
                }
                if c1 == c0 && c2 != c0 {
                    // c2.item == x == i, but c2 ∈ charges forces x ∈ items.
                    assert(pre.charges.contains(c2));
                    assert(pre.items.contains(c2.item));
                    assert(c2.item == x);
                    assert(pre.items.contains(x));
                    assert(x == i);
                    assert(false);
                }
                if c2 == c0 && c1 != c0 {
                    assert(pre.charges.contains(c1));
                    assert(pre.items.contains(c1.item));
                    assert(c1.item == x);
                    assert(pre.items.contains(x));
                    assert(x == i);
                    assert(false);
                }
            } else {
                assert(pre.charges.contains(c1));
                assert(pre.charges.contains(c2));
            }
        }
        assert forall|c: Charge| post.charges.contains(c) && c.item == x implies c.key
            == map_at(post.owner, x) && c.bytes == size(x) by {
            if !pre.items.contains(i) {
                if c == c0 {
                    assert(c.key == k && c.bytes == size(i));
                    map_insert_at(pre.owner, i, k, x);
                    assert(map_at(post.owner, x) == k);
                } else {
                    assert(pre.charges.contains(c));
                    assert(pre.items.contains(x));
                    // c.key = owner[x], and x != i here.
                    assert(c.key == map_at(pre.owner, x) && c.bytes == size(x));
                    map_insert_at(pre.owner, i, k, x);
                    assert(map_at(post.owner, x) == map_at(pre.owner, x));
                }
            } else {
                assert(pre.charges.contains(c));
                assert(c.key == map_at(pre.owner, x) && c.bytes == size(x));
                map_insert_at(pre.owner, i, map_at(pre.owner, i), x);
                assert(map_at(post.owner, x) == map_at(pre.owner, x));
            }
        }
    }

    // owners_distinct(post)
    assert forall|x: int, y: int| post.items.contains(x) && post.items.contains(y)
        && map_at(post.owner, x) == map_at(post.owner, y) implies x == y by {
        let ov = if pre.duplicate {
            map_at(pre.owner, i)
        } else {
            k
        };
        map_insert_at(pre.owner, i, ov, x);
        map_insert_at(pre.owner, i, ov, y);
        if x == i && y == i {
        } else if x == i {
            assert(pre.items.contains(y));
            if pre.duplicate {
                assert(map_at(post.owner, x) == map_at(pre.owner, i));
                assert(map_at(pre.owner, y) == map_at(pre.owner, i));
                // pre owners_distinct on y, i:
                assert(y == i);
            } else {
                assert(map_at(post.owner, x) == k);
                if map_at(pre.owner, y) == k {
                    // y's retained charge has key owner[y] = k — but the
                    // Begin quota check made k fresh.
                    let cy = choose|c: Charge| pre.charges.contains(c) && c.item == y;
                    assert(cy.key == map_at(pre.owner, y));
                    assert(cy.key == k);
                    assert(exists|c: Charge| pre.charges.contains(c) && c.key == k) by {
                        assert(pre.charges.contains(cy) && cy.key == k);
                    }
                    assert(false);
                }
                assert(false);
            }
        } else if y == i {
            assert(pre.items.contains(x));
            if pre.duplicate {
                assert(map_at(post.owner, y) == map_at(pre.owner, i));
                assert(x == i);
            } else {
                assert(map_at(post.owner, y) == k);
                if map_at(pre.owner, x) == k {
                    let cx = choose|c: Charge| pre.charges.contains(c) && c.item == x;
                    assert(cx.key == map_at(pre.owner, x));
                    assert(cx.key == k);
                    assert(exists|c: Charge| pre.charges.contains(c) && c.key == k) by {
                        assert(pre.charges.contains(cx) && cx.key == k);
                    }
                    assert(false);
                }
                assert(false);
            }
        } else {
            assert(pre.items.contains(x));
            assert(pre.items.contains(y));
            assert(map_at(pre.owner, x) == map_at(pre.owner, y));
        }
    }

    // stable_identity_spend(post): pointwise equality of the two filters.
    assert forall|kk: int| is_key(kk) implies (charged_items(post, kk)
        =~= owned_items(post, kk) && item_bytes(charged_items(post, kk))
        == item_bytes(owned_items(post, kk))) by {
        assert forall|x: int| charged_items(post, kk).contains(x) implies owned_items(
            post,
            kk,
        ).contains(x) by {
            let c = choose|c: Charge| post.charges.contains(c) && c.item == x && c.key
                == kk;
            assert(post.items.contains(x));
            if x == i {
                if pre.items.contains(i) {
                    assert(pre.charges.contains(c));
                    assert(c.key == map_at(pre.owner, i));
                    map_insert_at(pre.owner, i, map_at(pre.owner, i), x);
                    assert(map_at(post.owner, x) == map_at(pre.owner, i) == kk);
                } else {
                    if c == c0 {
                        map_insert_at(pre.owner, i, k, x);
                        assert(map_at(post.owner, x) == k == kk);
                    } else {
                        assert(pre.charges.contains(c));
                        assert(pre.items.contains(c.item));
                        assert(c.item == x);
                        assert(pre.items.contains(x));
                        assert(false);
                    }
                }
            } else {
                // c.item = x ∈ post.items ⊆ items ∪ {i}, so x ∈ items.
                assert(pre.items.contains(x));
                if pre.items.contains(i) {
                    assert(pre.charges.contains(c));
                } else {
                    if c == c0 {
                        assert(c.item == i);
                        assert(x == i);
                        assert(false);
                    }
                    assert(pre.charges.contains(c));
                }
                assert(c.key == map_at(pre.owner, x));
                map_insert_at(pre.owner, i, if pre.duplicate {
                    map_at(pre.owner, i)
                } else {
                    k
                }, x);
                assert(map_at(post.owner, x) == map_at(pre.owner, x) == kk);
            }
        }
        assert forall|x: int| owned_items(post, kk).contains(x) implies charged_items(
            post,
            kk,
        ).contains(x) by {
            assert(post.items.contains(x));
            assert(map_at(post.owner, x) == kk);
            assert(is_item(x));
            if x == i {
                if pre.items.contains(i) {
                    let c = choose|c: Charge| pre.charges.contains(c) && c.item == i;
                    assert(c.key == map_at(pre.owner, i));
                    map_insert_at(pre.owner, i, map_at(pre.owner, i), x);
                    assert(map_at(post.owner, x) == map_at(pre.owner, i));
                    assert(c.key == kk);
                    assert(post.charges.contains(c));
                    assert(charged_items(post, kk).contains(x)) by {
                        assert(all_items().contains(x));
                        assert(post.charges.contains(c) && c.item == x && c.key == kk);
                    }
                } else {
                    map_insert_at(pre.owner, i, k, x);
                    assert(map_at(post.owner, x) == k);
                    assert(kk == k);
                    assert(charged_items(post, kk).contains(x)) by {
                        assert(all_items().contains(x));
                        assert(post.charges.contains(c0) && c0.item == x && c0.key == kk);
                    }
                }
            } else {
                assert(pre.items.contains(x));
                map_insert_at(pre.owner, i, if pre.duplicate {
                    map_at(pre.owner, i)
                } else {
                    k
                }, x);
                assert(map_at(pre.owner, x) == map_at(pre.owner, x));
                let c = choose|c: Charge| pre.charges.contains(c) && c.item == x;
                assert(c.key == map_at(pre.owner, x) == kk);
                if pre.items.contains(i) {
                    assert(post.charges.contains(c));
                } else {
                    assert(pre.staged_charges.contains(c));
                    assert(post.charges.contains(c));
                }
                assert(charged_items(post, kk).contains(x)) by {
                    assert(all_items().contains(x));
                    assert(post.charges.contains(c) && c.item == x && c.key == kk);
                }
            }
        }
        assert(charged_items(post, kk) =~= owned_items(post, kk));
        assert(item_bytes(charged_items(post, kk)) == item_bytes(owned_items(post, kk)));
    }

    // quota_bound(post)
    assert forall|kk: int| is_key(kk) implies ((forall|x: int, y: int| charged_items(
        post,
        kk,
    ).contains(x) && charged_items(post, kk).contains(y) ==> x == y)
        && item_bytes(charged_items(post, kk)) <= max_bytes()) by {
        assert(charged_items(post, kk) =~= owned_items(post, kk));
        assert forall|x: int, y: int| charged_items(post, kk).contains(x)
            && charged_items(post, kk).contains(y) implies x == y by {
            assert(owned_items(post, kk).contains(x));
            assert(owned_items(post, kk).contains(y));
            assert(map_at(post.owner, x) == kk && map_at(post.owner, y) == kk);
            assert(post.items.contains(x) && post.items.contains(y));
            // owners_distinct(post)
            assert(x == y) by {
                let ov = if pre.duplicate {
                    map_at(pre.owner, i)
                } else {
                    k
                };
                map_insert_at(pre.owner, i, ov, x);
                map_insert_at(pre.owner, i, ov, y);
                if x == i && y == i {
                } else if x == i {
                    assert(pre.items.contains(y));
                    if pre.duplicate {
                        assert(y == i);
                    } else {
                        assert(map_at(post.owner, x) == k);
                        if map_at(pre.owner, y) == k {
                            let cy = choose|c: Charge| pre.charges.contains(c) && c.item
                                == y;
                            assert(cy.key == map_at(pre.owner, y));
                            assert(cy.key == k);
                            assert(exists|c: Charge| pre.charges.contains(c) && c.key
                                == k) by {
                                assert(pre.charges.contains(cy) && cy.key == k);
                            }
                            assert(false);
                        }
                        assert(false);
                    }
                } else if y == i {
                    assert(pre.items.contains(x));
                    if pre.duplicate {
                        assert(x == i);
                    } else {
                        assert(map_at(post.owner, y) == k);
                        if map_at(pre.owner, x) == k {
                            let cx = choose|c: Charge| pre.charges.contains(c) && c.item
                                == x;
                            assert(cx.key == map_at(pre.owner, x));
                            assert(cx.key == k);
                            assert(exists|c: Charge| pre.charges.contains(c) && c.key
                                == k) by {
                                assert(pre.charges.contains(cx) && cx.key == k);
                            }
                            assert(false);
                        }
                        assert(false);
                    }
                } else {
                    assert(pre.items.contains(x));
                    assert(pre.items.contains(y));
                    assert(map_at(pre.owner, x) == map_at(pre.owner, y));
                }
            }
        }
        // byte bound: owned(post,kk) ⊆ owned(pre,kk) ∪ {i}; when kk = k and
        // i is new, the Begin byte check bound it.
        assert(item_bytes(charged_items(post, kk)) <= max_bytes()) by {
            if !pre.items.contains(i) && kk == k {
                assert(owned_items(post, kk) =~= owned_items(pre, kk).insert(i)) by {
                    assert forall|x: int| owned_items(post, kk).contains(x)
                        implies owned_items(pre, kk).insert(i).contains(x) by {
                        if x == i {
                        } else {
                            assert(pre.items.contains(x));
                            map_insert_at(pre.owner, i, k, x);
                            assert(map_at(pre.owner, x) == kk);
                        }
                    }
                    assert forall|x: int| owned_items(pre, kk).insert(i).contains(x)
                        implies owned_items(post, kk).contains(x) by {
                        if x == i {
                            map_insert_at(pre.owner, i, k, x);
                            assert(map_at(post.owner, i) == k);
                        } else {
                            assert(pre.items.contains(x));
                            assert(map_at(pre.owner, x) == kk);
                            map_insert_at(pre.owner, i, k, x);
                        }
                    }
                }
                assert(owned_items(pre, kk) =~= charged_items(pre, kk));
                assert(item_bytes(owned_items(pre, kk).insert(i)) == item_bytes(
                    owned_items(pre, kk),
                ) + size(i)) by {
                    assert(!owned_items(pre, kk).contains(i));
                }
                assert(item_bytes(charged_items(pre, kk)) + size(i) <= max_bytes());
            } else {
                // no new owner-k member: owned(post,kk) ⊆ owned(pre,kk).
                assert(owned_items(post, kk) =~= owned_items(pre, kk)) by {
                    assert forall|x: int| owned_items(post, kk).contains(x)
                        implies owned_items(pre, kk).contains(x) by {
                        assert(post.items.contains(x));
                        if x == i {
                            map_insert_at(pre.owner, i, if pre.duplicate {
                                map_at(pre.owner, i)
                            } else {
                                k
                            }, x);
                            if pre.duplicate {
                                assert(pre.items.contains(i));
                                assert(map_at(post.owner, x) == map_at(pre.owner, i));
                                assert(map_at(pre.owner, i) == kk);
                            } else {
                                assert(map_at(post.owner, x) == k);
                                assert(k == kk);
                            }
                        } else {
                            assert(pre.items.contains(x));
                            map_insert_at(pre.owner, i, if pre.duplicate {
                                map_at(pre.owner, i)
                            } else {
                                k
                            }, x);
                            assert(map_at(pre.owner, x) == kk);
                        }
                    }
                    assert forall|x: int| owned_items(pre, kk).contains(x)
                        implies owned_items(post, kk).contains(x) by {
                        assert(pre.items.contains(x));
                        assert(post.items.contains(x));
                        if x == i {
                        } else {
                            map_insert_at(pre.owner, i, if pre.duplicate {
                                map_at(pre.owner, i)
                            } else {
                                k
                            }, x);
                        }
                    }
                }
                assert(owned_items(pre, kk) =~= charged_items(pre, kk));
                assert(item_bytes(charged_items(pre, kk)) <= max_bytes());
            }
        }
    }

    // positions_positive(post), head_count(post), receipt_items(post),
    // receipt_after_durable(post).
    assert forall|x: int| post.items.contains(x) implies map_at(post.positions, x)
        > 0 by {
        map_insert_at(pre.positions, i, if pre.duplicate {
            map_at(pre.positions, i)
        } else {
            pre.head + 1
        }, x);
        if x == i {
            if pre.duplicate {
                assert(pre.items.contains(i));
            } else {
                assert(map_at(post.positions, x) == pre.head + 1);
            }
        } else {
            assert(pre.items.contains(x));
        }
    }
    assert(head_count(post)) by {
        if pre.duplicate {
            assert(pre.items.insert(i) =~= pre.items);
            assert(item_count(pre.items.insert(i)) == item_count(pre.items));
            assert(post.items =~= pre.items);
        } else {
            assert(item_count(post.items) == item_count(pre.items) + 1);
        }
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        assert(pre.items.contains(r.item));
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies (r.durable
        && r.position > 0 && r.position == map_at(post.original, r.item)) by {
        assert(pre.receipts.contains(r));
        assert(pre.items.contains(r.item));
        map_insert_at(pre.original, i, if pre.duplicate {
            map_at(pre.original, i)
        } else {
            pre.head + 1
        }, r.item);
        if r.item == i {
            // a receipted item is committed, so this commit is a duplicate.
            assert(pre.items.contains(i));
            assert(pre.duplicate);
            assert(map_at(post.original, r.item) == map_at(pre.original, r.item));
        }
    }
    // type_ok(post) remainder: codomain bounds.
    assert forall|x: int| is_item(x) implies 0 <= map_at(post.positions, x) <= 2 by {
        map_insert_at(pre.positions, i, if pre.duplicate {
            map_at(pre.positions, i)
        } else {
            pre.head + 1
        }, x);
        if x == i {
            if !pre.duplicate {
                assert(pre.head <= 1);
                assert(map_at(post.positions, x) == pre.head + 1);
            }
        }
    }
    assert forall|x: int| is_item(x) implies 0 <= map_at(post.original, x) <= 2 by {
        map_insert_at(pre.original, i, if pre.duplicate {
            map_at(pre.original, i)
        } else {
            pre.head + 1
        }, x);
        if x == i {
            if !pre.duplicate {
                assert(pre.head <= 1);
            }
        }
    }
    assert forall|x: int| is_item(x) implies (is_key(map_at(post.owner, x))
        || map_at(post.owner, x) == 0) by {
        map_insert_at(pre.owner, i, if pre.duplicate {
            map_at(pre.owner, i)
        } else {
            k
        }, x);
        if x == i {
            if !pre.duplicate {
                assert(is_key(k));
            }
        }
    }
    assert(post.owner.dom() =~= all_items());
    assert forall|c: Charge| post.charges.contains(c) implies is_charge(c) by {
        assert(pre.staged_charges.contains(c));
    }
    assert(post.synced.subset_of(post.items)) by {
        assert forall|x: int| post.synced.contains(x) implies post.items.contains(x) by {
            assert(pre.synced.contains(x));
            assert(pre.items.contains(x));
        }
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn barrier_preserves(pre: State, post: State)
    requires
        inv(pre),
        barrier(pre, post),
    ensures
        inv(post),
{
    assert(post.synced =~= post.items);
    assert(post.items.contains(post.item));
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        assert(pre.items.contains(r.item));
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn receipt_preserves(pre: State, post: State)
    requires
        inv(pre),
        receipt(pre, post, false),
    ensures
        inv(post),
{
    let r0 = Receipt {
        item: pre.item,
        position: position(pre, pre.item),
        durable: pre.synced.contains(pre.item),
    };
    assert(pre.pc == ph_reply());
    assert(pre.items.contains(pre.item));
    assert(pre.synced =~= pre.items);
    assert(pre.synced.contains(pre.item));
    assert(r0.durable);
    assert(position(pre, pre.item) == map_at(pre.positions, pre.item));
    assert(map_at(pre.positions, pre.item) > 0);
    assert(r0.position > 0);
    // positions =~= original, and item ∈ items ⊆ dom.
    assert(pre.positions.dom().contains(pre.item));
    assert(pre.original.dom().contains(pre.item));
    assert(pre.positions[pre.item] == pre.original[pre.item]);
    assert(r0.position == map_at(pre.original, pre.item));
    assert forall|r: Receipt| post.receipts.contains(r) implies (r.durable
        && r.position > 0 && r.position == map_at(post.original, r.item)) by {
        if r == r0 {
        } else {
            assert(pre.receipts.contains(r));
        }
    }
    assert forall|r: Receipt| post.receipts.contains(r) implies post.items.contains(
        r.item,
    ) by {
        if r == r0 {
        } else {
            assert(pre.receipts.contains(r));
            assert(pre.items.contains(r.item));
        }
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn lost_receipt_preserves(pre: State, post: State)
    requires
        inv(pre),
        lost_receipt(pre, post),
    ensures
        inv(post),
{
}

proof fn rollback_preserves(pre: State, post: State)
    requires
        inv(pre),
        rollback(pre, post),
    ensures
        inv(post),
{
    assert forall|c: Charge| post.staged_charges.contains(c) implies is_charge(c) by {
        assert(post.staged_charges =~= Set::empty());
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn crash_preserves(pre: State, post: State)
    requires
        inv(pre),
        crash(pre, post),
    ensures
        inv(post),
{
    assert forall|c: Charge| post.staged_charges.contains(c) implies is_charge(c) by {
        assert(post.staged_charges =~= Set::empty());
    }
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn reopen_preserves(pre: State, post: State)
    requires
        inv(pre),
        reopen(pre, post),
    ensures
        inv(post),
{
    assert(post.synced =~= post.items);
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn rotate_token_preserves(pre: State, post: State)
    requires
        inv(pre),
        rotate_token(pre, post, false),
    ensures
        inv(post),
{
    assert(post.charges =~= pre.charges);
    assert(type_ok(post));
    assert(items_charged_together(post));
    assert(retry_keeps(post));
    assert(stable_identity_spend(post));
    assert(quota_bound(post));
    assert(receipt_after_durable(post));
    assert(duplicate_flag(post));
    assert(begin_quota(post));
    assert(staged_consistent(post));
    assert(item_committed(post));
    assert(reply_synced(post));
    assert(owners_distinct(post));
    assert(head_count(post));
    assert(positions_positive(post));
    assert(receipt_items(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if stage_charge(pre, post, false, false) {
        stage_charge_preserves(pre, post);
    } else if stage_item(pre, post) {
        stage_item_preserves(pre, post);
    } else if commit(pre, post, false) {
        commit_preserves(pre, post);
    } else if barrier(pre, post) {
        barrier_preserves(pre, post);
    } else if receipt(pre, post, false) {
        receipt_preserves(pre, post);
    } else if lost_receipt(pre, post) {
        lost_receipt_preserves(pre, post);
    } else if rollback(pre, post) {
        rollback_preserves(pre, post);
    } else if crash(pre, post) {
        crash_preserves(pre, post);
    } else if reopen(pre, post) {
        reopen_preserves(pre, post);
    } else if rotate_token(pre, post, false) {
        rotate_token_preserves(pre, post);
    } else {
        let (i, k, t) = choose|i: int, k: int, t: int| is_item(i) && is_key(k)
            && is_token(t) && begin(pre, post, i, k, t);
        begin_preserves(pre, post, i, k, t);
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_early_charge_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_early_charge(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_duplicate_charge_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_duplicate_charge(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_duplicate_position_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_duplicate_position(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_token_reset_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_token_reset(
        t[i],
        t[i + 1],
    )
}

pub open spec fn is_early_receipt_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_early_receipt(
        t[i],
        t[i + 1],
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
                prefix[i + 1],
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

/// Constructing states concisely for the witness proofs.
pub open spec fn st(
    pc: int,
    items: Set<int>,
    charges: Set<Charge>,
    positions: Map<int, int>,
    original: Map<int, int>,
    owner: Map<int, int>,
    synced: Set<int>,
    head: int,
    token: int,
    rotated: bool,
    item: int,
    key: int,
    duplicate: bool,
    staged_items: Set<int>,
    staged_charges: Set<Charge>,
    receipts: Set<Receipt>,
    crashes: int,
    attempts: int,
) -> State {
    State {
        pc,
        items,
        charges,
        positions,
        original,
        owner,
        synced,
        head,
        token,
        rotated,
        item,
        key,
        duplicate,
        staged_items,
        staged_charges,
        receipts,
        crashes,
        attempts,
    }
}

pub open spec fn es() -> Set<int> {
    Set::empty()
}

pub open spec fn es1() -> Set<int> {
    Set::empty().insert(1)
}

/// mutant-early-charge: Begin(first, owner, old) -> StageCharge publishes
/// the staged charge before its item commits — charges ⊋ ∅ while items = ∅.
proof fn mutant_early_charge_violates()
    ensures
        exists|t: Seq<State>| is_early_charge_trace(t) && !items_charged_together(
            t.last(),
        ),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c0 = Charge { item: 1, key: 1, bytes: 1, serial: 0 };
    let cs = ec.insert(c0);
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, cs, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs, er, 0, 1);
    assert(init(s0));
    assert(next_mutant_early_charge(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next_mutant_early_charge(s1, s2)) by {
        assert(stage_charge(s1, s2, true, false));
    }
    assert(!items_charged_together(s2)) by {
        assert(s2.charges.contains(c0));
        assert(!s2.items.contains(c0.item));
        assert(!(forall|c: Charge| s2.charges.contains(c) ==> s2.items.contains(c.item)));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_early_charge_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_early_charge(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_early_charge_trace(t) && !items_charged_together(t.last()));
}

/// mutant-duplicate-charge: a full commit cycle then an exact retry whose
/// DuplicateCharge serial inserts a second charge record for the item —
/// the retained ledger now holds two charges for "first".
proof fn mutant_duplicate_charge_violates()
    ensures
        exists|t: Seq<State>| is_duplicate_charge_trace(t) && !retry_keeps(t.last()),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c1 = Charge { item: 1, key: 1, bytes: 1, serial: 1 };
    let c2 = Charge { item: 1, key: 1, bytes: 1, serial: 2 };
    let cs1 = ec.insert(c1);
    let cs2 = cs1.insert(c2);
    let i1 = es1();
    let pos1 = zmap().insert(1, 1);
    let own1 = zmap().insert(1, 1);
    let r1 = Receipt { item: 1, position: 1, durable: true };
    let rs = er.insert(r1);
    // cycle 1: Begin -> StageCharge -> StageItem -> Commit -> Barrier -> Receipt
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs1, er, 0, 1);
    let s3 = st(3, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s4 = st(4, i1, cs1, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s5 = st(5, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s6 = st(0, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs1, rs, 0, 1);
    // cycle 2: duplicate retry adds serial-2 charge to the ledger.
    let s7 = st(1, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs1, rs, 0, 2);
    let s8 = st(2, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs2, rs, 0, 2);
    let s9 = st(3, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs2, rs, 0, 2);
    let s10 = st(4, i1, cs2, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs2, rs, 0, 2);
    assert(init(s0));
    assert(next_mutant_duplicate_charge(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next_mutant_duplicate_charge(s1, s2)) by {
        assert(stage_charge(s1, s2, false, true));
    }
    assert(next_mutant_duplicate_charge(s2, s3)) by {
        assert(stage_item(s2, s3));
    }
    assert(next_mutant_duplicate_charge(s3, s4)) by {
        assert(commit(s3, s4, false));
    }
    assert(next_mutant_duplicate_charge(s4, s5)) by {
        assert(barrier(s4, s5));
    }
    assert(next_mutant_duplicate_charge(s5, s6)) by {
        assert(receipt(s5, s6, false));
    }
    assert(next_mutant_duplicate_charge(s6, s7)) by {
        assert(begin(s6, s7, 1, 1, 0));
    }
    assert(next_mutant_duplicate_charge(s7, s8)) by {
        assert(stage_charge(s7, s8, false, true));
    }
    assert(next_mutant_duplicate_charge(s8, s9)) by {
        assert(stage_item(s8, s9));
    }
    assert(next_mutant_duplicate_charge(s9, s10)) by {
        assert(commit(s9, s10, false));
    }
    // two distinct charges both bound to item "first".
    assert(c1 != c2);
    assert(s10.charges.contains(c1) && s10.charges.contains(c2));
    assert(c1.item == 1 && c2.item == 1);
    assert(s10.items.contains(1));
    assert(!(forall|c1x: Charge, c2x: Charge| s10.charges.contains(c1x) && s10.charges
        .contains(c2x) && c1x.item == 1 && c2x.item == 1 ==> c1x == c2x)) by {
        assert(s10.charges.contains(c1) && s10.charges.contains(c2));
        assert(c1.item == 1 && c2.item == 1 && c1 != c2);
    }
    assert(!retry_keeps(s10)) by {
        assert(s10.items.contains(1));
        assert(!(exists|c: Charge| #[trigger] s10.charges.contains(c) && c.item == 1) || !(forall|c1x: Charge, c2x: Charge| s10.charges.contains(c1x)
            && s10.charges.contains(c2x) && c1x.item == 1 && c2x.item == 1 ==> c1x
            == c2x) || !(forall|c: Charge| s10.charges.contains(c) && c.item == 1
            ==> c.key == map_at(s10.owner, 1) && c.bytes == size(1)));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(
        s7,
    ).push(s8).push(s9).push(s10);
    assert(is_duplicate_charge_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_duplicate_charge(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i]
                == s5 || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
                || t[i + 1] == s9 || t[i + 1] == s10);
        }
    }
    assert(t.last() == s10);
    assert(is_duplicate_charge_trace(t) && !retry_keeps(t.last()));
}

/// mutant-duplicate-position: the duplicate retry moves "first" to a fresh
/// position while `original` keeps the first committed one — positions ≠
/// original afterwards.
proof fn mutant_duplicate_position_violates()
    ensures
        exists|t: Seq<State>| is_duplicate_position_trace(t) && !retry_keeps(t.last()),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c0 = Charge { item: 1, key: 1, bytes: 1, serial: 0 };
    let cs = ec.insert(c0);
    let i1 = es1();
    let pos1 = zmap().insert(1, 1);
    let pos2 = zmap().insert(1, 2);
    let own1 = zmap().insert(1, 1);
    let r1 = Receipt { item: 1, position: 1, durable: true };
    let rs = er.insert(r1);
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs, er, 0, 1);
    let s3 = st(3, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s4 = st(4, i1, cs, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s5 = st(5, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s6 = st(0, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs, rs, 0, 1);
    let s7 = st(1, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs, rs, 0, 2);
    let s8 = st(2, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs, rs, 0, 2);
    let s9 = st(3, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs, rs, 0, 2);
    // MoveDuplicate: positions[first] = head+1 = 2 while original[first] = 1.
    let s10 = st(4, i1, cs, pos2, pos1, own1, i1, 1, 0, false, 1, 1, true, i1, cs, rs, 0, 2);
    assert(init(s0));
    assert(next_mutant_duplicate_position(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next_mutant_duplicate_position(s1, s2)) by {
        assert(stage_charge(s1, s2, false, false));
    }
    assert(next_mutant_duplicate_position(s2, s3)) by {
        assert(stage_item(s2, s3));
    }
    assert(next_mutant_duplicate_position(s3, s4)) by {
        assert(commit(s3, s4, false));
    }
    assert(next_mutant_duplicate_position(s4, s5)) by {
        assert(barrier(s4, s5));
    }
    assert(next_mutant_duplicate_position(s5, s6)) by {
        assert(receipt(s5, s6, false));
    }
    assert(next_mutant_duplicate_position(s6, s7)) by {
        assert(begin(s6, s7, 1, 1, 0));
    }
    assert(next_mutant_duplicate_position(s7, s8)) by {
        // charged(first) holds, so staged charges stay the ledger's.
        assert(charged(s7, 1)) by {
            assert(s7.charges.contains(c0) && c0.item == 1);
        }
        assert(stage_charge(s7, s8, false, false));
    }
    assert(next_mutant_duplicate_position(s8, s9)) by {
        assert(stage_item(s8, s9));
    }
    assert(next_mutant_duplicate_position(s9, s10)) by {
        assert(commit(s9, s10, true));
    }
    assert(map_at(s10.positions, 1) == 2);
    assert(map_at(s10.original, 1) == 1);
    assert(!(s10.positions =~= s10.original)) by {
        assert(s10.positions.dom().contains(1));
        assert(s10.original.dom().contains(1));
        assert(s10.positions[1] == 2);
        assert(s10.original[1] == 1);
    }
    assert(!retry_keeps(s10));
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(
        s7,
    ).push(s8).push(s9).push(s10);
    assert(is_duplicate_position_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_duplicate_position(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i]
                == s5 || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
                || t[i + 1] == s9 || t[i + 1] == s10);
        }
    }
    assert(t.last() == s10);
    assert(is_duplicate_position_trace(t) && !retry_keeps(t.last()));
}

/// mutant-token-reset: a full commit cycle then RotateToken under
/// ResetQuota drops the owner-keyed charge while the item stays owned —
/// Spent(owner) no longer matches the owned items.
proof fn mutant_token_reset_violates()
    ensures
        exists|t: Seq<State>| is_token_reset_trace(t) && !stable_identity_spend(t.last()),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c0 = Charge { item: 1, key: 1, bytes: 1, serial: 0 };
    let cs = ec.insert(c0);
    let i1 = es1();
    let pos1 = zmap().insert(1, 1);
    let own1 = zmap().insert(1, 1);
    let r1 = Receipt { item: 1, position: 1, durable: true };
    let rs = er.insert(r1);
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs, er, 0, 1);
    let s3 = st(3, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s4 = st(4, i1, cs, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s5 = st(5, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s6 = st(0, i1, cs, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs, rs, 0, 1);
    // ResetQuota removes every key = owner charge.
    let s7 = st(0, i1, ec, pos1, pos1, own1, i1, 1, 1, true, 1, 1, false, i1, cs, rs, 0, 1);
    assert(init(s0));
    assert(next_mutant_token_reset(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next_mutant_token_reset(s1, s2)) by {
        assert(stage_charge(s1, s2, false, false));
    }
    assert(next_mutant_token_reset(s2, s3)) by {
        assert(stage_item(s2, s3));
    }
    assert(next_mutant_token_reset(s3, s4)) by {
        assert(commit(s3, s4, false));
    }
    assert(next_mutant_token_reset(s4, s5)) by {
        assert(barrier(s4, s5));
    }
    assert(next_mutant_token_reset(s5, s6)) by {
        assert(receipt(s5, s6, false));
    }
    assert(next_mutant_token_reset(s6, s7)) by {
        assert(rotate_token(s6, s7, true)) by {
            assert(s6.pc == 0 && !s6.rotated);
            // the ledger's sole charge is owner-keyed, so the ResetQuota
            // filter leaves it empty.
            assert forall|c: Charge| #[trigger] s6.charges.contains(c) implies c.key
                == key_owner() by {
                assert(c == c0);
            }
            assert(s7.charges =~= s6.charges.filter(|c: Charge| c.key != key_owner()));
        }
    }
    // owned(owner) = {first} but no owner-keyed charge remains.
    assert(owned_items(s7, 1).contains(1)) by {
        assert(s7.items.contains(1));
        assert(map_at(s7.owner, 1) == 1);
    }
    assert(!charged_items(s7, 1).contains(1)) by {
        assert(!(exists|c: Charge| #[trigger] s7.charges.contains(c) && c.item == 1
            && c.key == 1)) by {
            assert forall|c: Charge| !(s7.charges.contains(c) && c.item == 1 && c.key
                == 1) by {}
        }
    }
    assert(!(charged_items(s7, 1) =~= owned_items(s7, 1)));
    assert(!stable_identity_spend(s7)) by {
        assert(is_key(1));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(
        s7,
    );
    assert(is_token_reset_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_token_reset(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i]
                == s5 || t[i] == s6);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7);
        }
    }
    assert(t.last() == s7);
    assert(is_token_reset_trace(t) && !stable_identity_spend(t.last()));
}

/// mutant-early-receipt: Receipt fires at the barrier phase before the
/// durability snapshot — the recorded receipt carries durable = FALSE.
proof fn mutant_early_receipt_violates()
    ensures
        exists|t: Seq<State>| is_early_receipt_trace(t) && !receipt_after_durable(
            t.last(),
        ),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c0 = Charge { item: 1, key: 1, bytes: 1, serial: 0 };
    let cs = ec.insert(c0);
    let i1 = es1();
    let pos1 = zmap().insert(1, 1);
    let own1 = zmap().insert(1, 1);
    let r0 = Receipt { item: 1, position: 1, durable: false };
    let rs = er.insert(r0);
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs, er, 0, 1);
    let s3 = st(3, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    let s4 = st(4, i1, cs, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs, er, 0, 1);
    // EarlyReceipt: fire Receipt at pc = barrier; synced is still empty.
    let s5 = st(0, i1, cs, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs, rs, 0, 1);
    assert(init(s0));
    assert(next_mutant_early_receipt(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next_mutant_early_receipt(s1, s2)) by {
        assert(stage_charge(s1, s2, false, false));
    }
    assert(next_mutant_early_receipt(s2, s3)) by {
        assert(stage_item(s2, s3));
    }
    assert(next_mutant_early_receipt(s3, s4)) by {
        assert(commit(s3, s4, false));
    }
    assert(next_mutant_early_receipt(s4, s5)) by {
        assert(receipt(s4, s5, true)) by {
            assert(position(s4, 1) == 1) by {
                assert(s4.items.contains(1));
                assert(map_at(s4.positions, 1) == 1);
            }
            assert(!s4.synced.contains(1));
        }
    }
    assert(!receipt_after_durable(s5)) by {
        assert(s5.receipts.contains(r0));
        assert(!r0.durable);
        assert(!(forall|r: Receipt| s5.receipts.contains(r) ==> (r.durable && r.position
            > 0 && r.position == map_at(s5.original, r.item))));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5);
    assert(is_early_receipt_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_early_receipt(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5);
        }
    }
    assert(t.last() == s5);
    assert(is_early_receipt_trace(t) && !receipt_after_durable(t.last()));
}

/// Non-vacuity witness for the safe model: item "first" commits under the
/// owner credential, then "second" under the other credential — ending
/// with both items committed, two durable receipts and head = 2.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().items =~= all_items()
            && t.last().head == 2 && t.last().pc == ph_idle() && t.last().receipts.contains(
            Receipt { item: 2, position: 2, durable: true },
        ),
{
    let e: Set<int> = Set::empty();
    let ec: Set<Charge> = Set::empty();
    let er: Set<Receipt> = Set::empty();
    let c1 = Charge { item: 1, key: 1, bytes: 1, serial: 0 };
    let c2 = Charge { item: 2, key: 2, bytes: 2, serial: 0 };
    let cs1 = ec.insert(c1);
    let cs12 = cs1.insert(c2);
    let i1 = es1();
    let i12 = all_items();
    let pos1 = zmap().insert(1, 1);
    let pos12 = pos1.insert(2, 2);
    let own1 = zmap().insert(1, 1);
    let own12 = own1.insert(2, 2);
    let r1 = Receipt { item: 1, position: 1, durable: true };
    let r2 = Receipt { item: 2, position: 2, durable: true };
    let rs1 = er.insert(r1);
    let rs12 = rs1.insert(r2);
    let s0 = st(0, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 0);
    let s1 = st(1, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, ec, er, 0, 1);
    let s2 = st(2, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, e, cs1, er, 0, 1);
    let s3 = st(3, e, ec, zmap(), zmap(), zmap(), e, 0, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s4 = st(4, i1, cs1, pos1, pos1, own1, e, 1, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s5 = st(5, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs1, er, 0, 1);
    let s6 = st(0, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 1, 1, false, i1, cs1, rs1, 0, 1);
    let s7 = st(1, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 2, 2, false, i1, cs1, rs1, 0, 2);
    let s8 = st(2, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 2, 2, false, i1, cs12, rs1, 0, 2);
    let s9 = st(3, i1, cs1, pos1, pos1, own1, i1, 1, 0, false, 2, 2, false, i12, cs12, rs1, 0, 2);
    let s10 = st(4, i12, cs12, pos12, pos12, own12, i1, 2, 0, false, 2, 2, false, i12, cs12, rs1, 0, 2);
    let s11 = st(5, i12, cs12, pos12, pos12, own12, i12, 2, 0, false, 2, 2, false, i12, cs12, rs1, 0, 2);
    let s12 = st(0, i12, cs12, pos12, pos12, own12, i12, 2, 0, false, 2, 2, false, i12, cs12, rs12, 0, 2);
    assert(init(s0));
    assert(next(s0, s1)) by {
        assert(begin(s0, s1, 1, 1, 0)) by {
            assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.key == 1)) by {
                assert forall|c: Charge| !(s0.charges.contains(c) && c.key == 1) by {}
            }
            assert(item_bytes(charged_items(s0, 1)) == 0) by {
                assert forall|x: int| !charged_items(s0, 1).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s0.charges.contains(c) && c.item
                        == x && c.key == 1)) by {
                        assert forall|c: Charge| !(s0.charges.contains(c) && c.item == x
                            && c.key == 1) by {}
                    }
                }
            }
        }
    }
    assert(next(s1, s2)) by {
        assert(stage_charge(s1, s2, false, false));
    }
    assert(next(s2, s3)) by {
        assert(stage_item(s2, s3));
    }
    assert(next(s3, s4)) by {
        assert(commit(s3, s4, false));
    }
    assert(next(s4, s5)) by {
        assert(barrier(s4, s5));
    }
    assert(next(s5, s6)) by {
        assert(receipt(s5, s6, false));
    }
    assert(next(s6, s7)) by {
        assert(begin(s6, s7, 2, 2, 0)) by {
            // k = "other" satisfies auth; quota headroom under key 2.
            assert(!(exists|c: Charge| #[trigger] s6.charges.contains(c) && c.key == 2)) by {
                assert forall|c: Charge| !(s6.charges.contains(c) && c.key == 2) by {
                    assert(s6.charges.contains(c) ==> c == c1);
                }
            }
            assert(item_bytes(charged_items(s6, 2)) == 0) by {
                assert forall|x: int| !charged_items(s6, 2).contains(x) by {
                    assert(!(exists|c: Charge| #[trigger] s6.charges.contains(c) && c.item
                        == x && c.key == 2)) by {
                        assert forall|c: Charge| !(s6.charges.contains(c) && c.item == x
                            && c.key == 2) by {
                            assert(s6.charges.contains(c) ==> c == c1);
                        }
                    }
                }
            }
            assert(size(2) == 2);
        }
    }
    assert(next(s7, s8)) by {
        assert(stage_charge(s7, s8, false, false)) by {
            assert(!charged(s7, 2)) by {
                assert forall|c: Charge| !(s7.charges.contains(c) && c.item == 2) by {
                    assert(s7.charges.contains(c) ==> c == c1);
                }
            }
        }
    }
    assert(next(s8, s9)) by {
        assert(stage_item(s8, s9));
    }
    assert(next(s9, s10)) by {
        assert(commit(s9, s10, false));
    }
    assert(next(s10, s11)) by {
        assert(barrier(s10, s11));
    }
    assert(next(s11, s12)) by {
        assert(receipt(s11, s12, false)) by {
            assert(position(s11, 2) == 2) by {
                assert(s11.items.contains(2));
                assert(map_at(s11.positions, 2) == 2);
            }
            assert(s11.synced.contains(2));
        }
    }
    assert(s12.items =~= all_items());
    assert(s12.receipts.contains(r2));
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(
        s7,
    ).push(s8).push(s9).push(s10).push(s11).push(s12);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i]
                == s5 || t[i] == s6 || t[i] == s7 || t[i] == s8 || t[i] == s9 || t[i] == s10
                || t[i] == s11);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4
                || t[i + 1] == s5 || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
                || t[i + 1] == s9 || t[i + 1] == s10 || t[i + 1] == s11 || t[i + 1] == s12);
        }
    }
    assert(t.last() == s12);
    assert(is_trace(t) && t.last().items =~= all_items() && t.last().head == 2
        && t.last().pc == ph_idle() && t.last().receipts.contains(r2));
}

}
