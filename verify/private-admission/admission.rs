//! Verus pilot (5th model): inductive proof of PrivateAdmission's invariants.
//!
//! Same pattern as `verify/private-egress/egress.rs`,
//! `verify/private-rotation/rotation.rs`,
//! `verify/private-publication/publication.rs` and
//! `verify/host-recovery/recovery.rs`: `PrivateAdmission.tla` under
//! `normal.cfg` (`Mutant = "none"`) is re-stated as a Verus transition
//! system and the seven checked invariants — `TypeOK`, `ConsentLifetime`,
//! `ConsumedBeforeCheck`, `ExactReview`, `CurrentMembership`,
//! `LiveAtConfirmation`, `ExclusivePublication` — are proved inductive.
//! Each of the eight mutant configurations is proved to reach a violation
//! of the invariant the case pins: `mutant-intervene` and `mutant-reload`
//! break `ConsentLifetime`, `mutant-consume` breaks `ConsumedBeforeCheck`,
//! `mutant-packet` and `mutant-ciphertext` break `ExactReview`,
//! `mutant-membership` breaks `CurrentMembership`, `mutant-expiry` breaks
//! `LiveAtConfirmation` and `mutant-custody` breaks
//! `ExclusivePublication`. A completion witness reaches `done` with a
//! recorded publication effect, matching `witness-admitted.cfg`'s
//! intentional `NoSuccessfulAdmission` failure.
//!
//! Encoding notes:
//!   * Records are structs: `Pend` carries the `pending`/`taken` shape
//!     (present flag, consent field map, bytes, stamp), `Shown` carries the
//!     `shown`/`packet` shape (present flag + consent field map), `Item`
//!     the retained item triple and `Effect` the publication record. The
//!     TLA `None` sentinel is the canonical all-default struct (`pnone()`,
//!     `snone()`, `enone()`); its record fields are never read when
//!     `present` is false.
//!   * Status/consent record fields are int constants: `StatusFields` are
//!     1..9 with `TokenFields` 1..7 and the extra `PacketFields` 10..17.
//!     `status`, consent, packet and effect maps are `Map<int,int>` read
//!     through `map_at` (0 off-domain); `status` carries its exact domain
//!     through TypeOK.
//!   * `Mutant` is an int parameter of `next_cfg`: 0 is "none", 1..8 select
//!     the eight mutant switches; `next` is `next_cfg(0)` and each
//!     `next_mutant_*` fixes one switch.
//!   * `Bound(p)` is dead code in the model (no action or invariant reads
//!     it) and is not translated; `NoSuccessfulAdmission` is the coverage
//!     probe discharged by `completion_witness`.
//!
//! Verify with:
//!   verus --crate-type=lib verify/private-admission/admission.rs
//! Pinned tool: verus 0.2026.09.13.671956e (see ../tools.json).

use vstd::prelude::*;

verus! {

/// Total map read at int keys (0 off-domain, as in publication.rs).
pub open spec fn map_at(m: Map<int, int>, k: int) -> int {
    if m.dom().contains(k) {
        m[k]
    } else {
        0
    }
}

/// StatusFields / TokenFields / PacketFields encoding.
/// StatusFields == {"room","anchor","account","custodyDevice","epoch",
///                  "roster","floor","owner","quarantined"} as 1..9.
pub open spec fn f_room() -> int {
    1
}

pub open spec fn f_anchor() -> int {
    2
}

pub open spec fn f_account() -> int {
    3
}

pub open spec fn f_custody_device() -> int {
    4
}

pub open spec fn f_epoch() -> int {
    5
}

pub open spec fn f_roster() -> int {
    6
}

pub open spec fn f_floor() -> int {
    7
}

pub open spec fn f_owner() -> int {
    8
}

pub open spec fn f_quarantined() -> int {
    9
}

/// Extra PacketFields: session, id, position, digest, recipient, device,
/// start, expires as 10..17.
pub open spec fn f_session() -> int {
    10
}

pub open spec fn f_id() -> int {
    11
}

pub open spec fn f_position() -> int {
    12
}

pub open spec fn f_digest() -> int {
    13
}

pub open spec fn f_recipient() -> int {
    14
}

pub open spec fn f_device() -> int {
    15
}

pub open spec fn f_start() -> int {
    16
}

pub open spec fn f_expires() -> int {
    17
}

pub open spec fn token_fields() -> Set<int> {
    Set::empty().insert(1).insert(2).insert(3).insert(4).insert(5).insert(6).insert(7)
}

pub open spec fn status_fields() -> Set<int> {
    token_fields().insert(8).insert(9)
}

pub open spec fn packet_fields() -> Set<int> {
    token_fields().insert(10).insert(11).insert(12).insert(13).insert(14).insert(15).insert(16).insert(
        17,
    )
}

/// Phase encoding for {"ready","retained","take","binding","membership",
/// "publish","dead","done"}.
pub open spec fn ph_ready() -> int {
    0
}

pub open spec fn ph_retained() -> int {
    1
}

pub open spec fn ph_take() -> int {
    2
}

pub open spec fn ph_binding() -> int {
    3
}

pub open spec fn ph_membership() -> int {
    4
}

pub open spec fn ph_publish() -> int {
    5
}

pub open spec fn ph_dead() -> int {
    6
}

pub open spec fn ph_done() -> int {
    7
}

pub open spec fn is_phase(p: int) -> bool {
    0 <= p <= 7
}

/// Mutant encoding: "none" plus one id per mutant-*.cfg switch.
pub open spec fn m_none() -> int {
    0
}

pub open spec fn m_intervene() -> int {
    1
}

pub open spec fn m_reload() -> int {
    2
}

pub open spec fn m_consume() -> int {
    3
}

pub open spec fn m_packet() -> int {
    4
}

pub open spec fn m_ciphertext() -> int {
    5
}

pub open spec fn m_membership() -> int {
    6
}

pub open spec fn m_expiry() -> int {
    7
}

pub open spec fn m_custody() -> int {
    8
}

/// The pending/taken record: [present, consent, bytes, stamp].
pub struct Pend {
    pub present: bool,
    pub consent: Map<int, int>,
    pub bytes: int,
    pub stamp: int,
}

/// The shown/packet record: [present] ++ PacketFields as a field map.
pub struct Shown {
    pub present: bool,
    pub fields: Map<int, int>,
}

/// The retained item: [position, digest, payload].
pub struct Item {
    pub position: int,
    pub digest: int,
    pub payload: int,
}

/// The publication effect record.
pub struct Effect {
    pub present: bool,
    pub supplied: Map<int, int>,
    pub reviewed: Pend,
    pub selected: Item,
    pub current: Map<int, int>,
    pub at: int,
    pub observed: int,
    pub committed: int,
    pub session: int,
    pub stamp: int,
}

/// VARIABLES worker, serial, reviews, requestVersion, clock, status,
/// revision, changed, competed, phase, pending, shown, packet, item, taken,
/// checkedAt, expected, effect.
pub struct State {
    pub worker: int,
    pub serial: int,
    pub reviews: int,
    pub request_version: int,
    pub clock: int,
    pub status: Map<int, int>,
    pub revision: int,
    pub changed: bool,
    pub competed: bool,
    pub phase: int,
    pub pending: Pend,
    pub shown: Shown,
    pub packet: Shown,
    pub item: Item,
    pub taken: Pend,
    pub checked_at: int,
    pub expected: int,
    pub effect: Effect,
}

/// The all-zero status map (InitialStatus).
pub open spec fn zstatus() -> Map<int, int> {
    Map::new(status_fields(), |f: int| 0)
}

/// The all-zero packet-field map used inside the canonical None records.
pub open spec fn zpacket() -> Map<int, int> {
    Map::new(packet_fields(), |f: int| 0)
}

/// None == [present |-> FALSE], canonicalized for each record shape.
pub open spec fn pnone() -> Pend {
    Pend { present: false, consent: zpacket(), bytes: 0, stamp: 0 }
}

pub open spec fn snone() -> Shown {
    Shown { present: false, fields: zpacket() }
}

pub open spec fn enone() -> Effect {
    Effect {
        present: false,
        supplied: zpacket(),
        reviewed: pnone(),
        selected: Item { position: 0, digest: 0, payload: 0 },
        current: zstatus(),
        at: 0,
        observed: 0,
        committed: 0,
        session: 0,
        stamp: 0,
    }
}

/// ExactItem == [position |-> 1, digest |-> 1, payload |-> 1].
pub open spec fn exact_item() -> Item {
    Item { position: 1, digest: 1, payload: 1 }
}

/// OtherItem == [position |-> 2, digest |-> 2, payload |-> 2].
pub open spec fn other_item() -> Item {
    Item { position: 2, digest: 2, payload: 2 }
}

/// The Consent CASE expression over one packet field.
pub open spec fn consent_val(s: State, f: int) -> int {
    if f == f_session() {
        s.worker
    } else if f == f_id() {
        s.serial + 1
    } else if f == f_position() {
        1
    } else if f == f_digest() {
        1
    } else if f == f_recipient() {
        1
    } else if f == f_device() {
        1
    } else if f == f_start() {
        s.clock
    } else if f == f_expires() {
        2
    } else {
        map_at(s.status, f)
    }
}

/// Consent == [f \in PacketFields |-> consent_val]; the "present" field is
/// the record flag, tracked separately.
pub open spec fn consent_map(s: State) -> Map<int, int> {
    Map::new(packet_fields(), |f: int| consent_val(s, f))
}

/// SameMembership(c) with c == packet.
pub open spec fn same_membership(s: State) -> bool {
    &&& forall|f: int| token_fields().contains(f) ==> map_at(s.packet.fields, f) == map_at(
        s.status,
        f,
    )
    &&& map_at(s.status, f_owner()) == 0
    &&& map_at(s.status, f_quarantined()) == 0
}

/// packet.start <= checkedAt < packet.expires.
pub open spec fn live_window(s: State) -> bool {
    &&& map_at(s.packet.fields, f_start()) <= s.checked_at
    &&& s.checked_at < map_at(s.packet.fields, f_expires())
}

/// The exact-request conjunction CheckBinding establishes:
/// packet = taken.consent and the retained item matches the packet's
/// position/digest and the taken bytes.
pub open spec fn bound_request(s: State) -> bool {
    &&& s.packet.fields =~= s.taken.consent
    &&& s.item.position == map_at(s.packet.fields, f_position())
    &&& s.item.digest == map_at(s.packet.fields, f_digest())
    &&& s.item.payload == s.taken.bytes
}

pub open spec fn init(s: State) -> bool {
    &&& s.worker == 1
    &&& s.serial == 0
    &&& s.reviews == 0
    &&& s.request_version == 0
    &&& s.clock == 0
    &&& s.status =~= zstatus()
    &&& s.revision == 0
    &&& !s.changed
    &&& !s.competed
    &&& s.phase == ph_ready()
    &&& s.pending == pnone()
    &&& s.shown == snone()
    &&& s.packet == snone()
    &&& s.item == exact_item()
    &&& s.taken == pnone()
    &&& s.checked_at == 0
    &&& s.expected == 0
    &&& s.effect == enone()
}

/// Review == /\ phase = "ready" /\ reviews < 2 /\ clock < 2
///           /\ status.owner = 0 /\ status.quarantined = 0
///           /\ pending' = [present |-> TRUE, consent |-> Consent,
///              bytes |-> 1, stamp |-> requestVersion]
///           /\ shown' = Consent /\ serial' = serial + 1
///           /\ reviews' = reviews + 1 /\ UNCHANGED (13 vars).
pub open spec fn review(pre: State, post: State) -> bool {
    &&& pre.phase == ph_ready()
    &&& pre.reviews < 2
    &&& pre.clock < 2
    &&& map_at(pre.status, f_owner()) == 0
    &&& map_at(pre.status, f_quarantined()) == 0
    &&& post.pending == Pend {
        present: true,
        consent: consent_map(pre),
        bytes: 1,
        stamp: pre.request_version,
    }
    &&& post.shown == Shown { present: true, fields: consent_map(pre) }
    &&& post.serial == pre.serial + 1
    &&& post.reviews == pre.reviews + 1
    &&& post.worker == pre.worker
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.phase == pre.phase
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Intervene == /\ phase = "ready" /\ requestVersion = 0
///              /\ requestVersion' = 1
///              /\ pending' = IF Mutant = "intervene" THEN pending ELSE None.
pub open spec fn intervene(m: int, pre: State, post: State) -> bool {
    &&& pre.phase == ph_ready()
    &&& pre.request_version == 0
    &&& post.request_version == 1
    &&& post.pending == if m == m_intervene() {
        pre.pending
    } else {
        pnone()
    }
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.phase == pre.phase
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Reload == /\ worker = 1 /\ worker' = 2 /\ serial' = 0 /\ phase' = "ready"
///           /\ pending' = IF Mutant = "reload" THEN pending ELSE None
///           /\ taken' = None /\ UNCHANGED (12 vars).
pub open spec fn reload(m: int, pre: State, post: State) -> bool {
    &&& pre.worker == 1
    &&& post.worker == 2
    &&& post.serial == 0
    &&& post.phase == ph_ready()
    &&& post.pending == if m == m_reload() {
        pre.pending
    } else {
        pnone()
    }
    &&& post.taken == pnone()
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Start(c) == /\ phase = "ready" /\ shown.present
///             /\ packet' = c /\ phase' = "retained".
/// `c` is the packet field map: `shown` itself or one field incremented.
pub open spec fn start(pre: State, post: State, c: Map<int, int>) -> bool {
    &&& pre.phase == ph_ready()
    &&& pre.shown.present
    &&& post.packet == Shown { present: true, fields: c }
    &&& post.phase == ph_retained()
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// ReadRetained(i) == phase "retained" -> "take" with item' = i.
pub open spec fn read_retained(pre: State, post: State, i: Item) -> bool {
    &&& pre.phase == ph_retained()
    &&& post.item == i
    &&& post.phase == ph_take()
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Take == phase "take": consume pending (or keep it under
/// Mutant = "consume"); binding when pending was present, dead otherwise;
/// checkedAt' = clock.
pub open spec fn take(m: int, pre: State, post: State) -> bool {
    &&& pre.phase == ph_take()
    &&& (if !pre.pending.present {
        post.phase == ph_dead() && post.taken == pnone()
    } else {
        post.phase == ph_binding() && post.taken == pre.pending
    })
    &&& post.pending == if m == m_consume() {
        pre.pending
    } else {
        pnone()
    }
    &&& post.checked_at == pre.clock
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// The CheckBinding gate: exact consent equality (skipped under
/// Mutant = "packet") and the retained-item/packet binding (skipped under
/// Mutant = "ciphertext").
pub open spec fn binding_gate(m: int, s: State) -> bool {
    &&& (s.packet.fields =~= s.taken.consent || m == m_packet())
    &&& ((s.item.position == map_at(s.packet.fields, f_position()) && s.item.digest == map_at(
        s.packet.fields,
        f_digest(),
    ) && s.item.payload == s.taken.bytes) || m == m_ciphertext())
}

/// CheckBinding == phase "binding" -> "membership" when the gate holds,
/// else "dead".
pub open spec fn check_binding(m: int, pre: State, post: State) -> bool {
    &&& pre.phase == ph_binding()
    &&& post.phase == if binding_gate(m, pre) {
        ph_membership()
    } else {
        ph_dead()
    }
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// The CheckMembership gate: SameMembership(packet) (skipped under
/// Mutant = "membership") and the captured-time validity window (skipped
/// under Mutant = "expiry").
pub open spec fn membership_gate(m: int, s: State) -> bool {
    &&& (same_membership(s) || m == m_membership())
    &&& (live_window(s) || m == m_expiry())
}

/// CheckMembership == phase "membership" -> "publish" when the gate holds,
/// else "dead"; expected' = revision either way.
pub open spec fn check_membership(m: int, pre: State, post: State) -> bool {
    &&& pre.phase == ph_membership()
    &&& post.phase == if membership_gate(m, pre) {
        ph_publish()
    } else {
        ph_dead()
    }
    &&& post.expected == pre.revision
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.effect == pre.effect
}

/// Compete == /\ ~competed /\ competed' = TRUE /\ revision' = revision + 1.
pub open spec fn compete(pre: State, post: State) -> bool {
    &&& !pre.competed
    &&& post.competed
    &&& post.revision == pre.revision + 1
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.changed == pre.changed
    &&& post.phase == pre.phase
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Change(f) == /\ ~changed /\ phase # "publish" /\ changed' = TRUE
///              /\ status' = [status EXCEPT ![f] = 1]
///              /\ revision' = revision + 1.
pub open spec fn change(pre: State, post: State, f: int) -> bool {
    &&& !pre.changed
    &&& pre.phase != ph_publish()
    &&& post.changed
    &&& post.status =~= pre.status.insert(f, 1)
    &&& post.revision == pre.revision + 1
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.competed == pre.competed
    &&& post.phase == pre.phase
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Publish == /\ phase = "publish"
///            /\ phase' = IF revision = expected \/ Mutant = "custody"
///               THEN "done" ELSE "dead"
///            /\ effect' = the recorded publication on success.
pub open spec fn publish(m: int, pre: State, post: State) -> bool {
    let ok = pre.revision == pre.expected || m == m_custody();
    &&& pre.phase == ph_publish()
    &&& post.phase == if ok {
        ph_done()
    } else {
        ph_dead()
    }
    &&& post.effect == if ok {
        Effect {
            present: true,
            supplied: pre.packet.fields,
            reviewed: pre.taken,
            selected: pre.item,
            current: pre.status,
            at: pre.checked_at,
            observed: pre.expected,
            committed: pre.revision,
            session: pre.worker,
            stamp: pre.request_version,
        }
    } else {
        pre.effect
    }
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
}

/// Interrupt == phase busy -> "dead"; pending' = taken' = None.
pub open spec fn interrupt(pre: State, post: State) -> bool {
    &&& (pre.phase == ph_retained() || pre.phase == ph_take() || pre.phase == ph_binding()
        || pre.phase == ph_membership() || pre.phase == ph_publish())
    &&& post.phase == ph_dead()
    &&& post.pending == pnone()
    &&& post.taken == pnone()
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.clock == pre.clock
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Tick == /\ clock < 2 /\ clock' = clock + 1.
pub open spec fn tick(pre: State, post: State) -> bool {
    &&& pre.clock < 2
    &&& post.clock == pre.clock + 1
    &&& post.worker == pre.worker
    &&& post.serial == pre.serial
    &&& post.reviews == pre.reviews
    &&& post.request_version == pre.request_version
    &&& post.status =~= pre.status
    &&& post.revision == pre.revision
    &&& post.changed == pre.changed
    &&& post.competed == pre.competed
    &&& post.phase == pre.phase
    &&& post.pending == pre.pending
    &&& post.shown == pre.shown
    &&& post.packet == pre.packet
    &&& post.item == pre.item
    &&& post.taken == pre.taken
    &&& post.checked_at == pre.checked_at
    &&& post.expected == pre.expected
    &&& post.effect == pre.effect
}

/// Next under an arbitrary Mutant constant.
pub open spec fn next_cfg(m: int, pre: State, post: State) -> bool {
    ||| review(pre, post)
    ||| intervene(m, pre, post)
    ||| reload(m, pre, post)
    ||| take(m, pre, post)
    ||| check_binding(m, pre, post)
    ||| check_membership(m, pre, post)
    ||| compete(pre, post)
    ||| publish(m, pre, post)
    ||| interrupt(pre, post)
    ||| tick(pre, post)
    ||| exists|f: int| status_fields().contains(f) && #[trigger] change(pre, post, f)
    ||| (pre.shown.present && start(pre, post, pre.shown.fields))
    ||| exists|f: int|
        packet_fields().contains(f) && #[trigger] start(
            pre,
            post,
            pre.shown.fields.insert(f, map_at(pre.shown.fields, f) + 1),
        )
    ||| read_retained(pre, post, exact_item())
    ||| read_retained(pre, post, other_item())
}

/// normal.cfg: Mutant = "none".
pub open spec fn next(pre: State, post: State) -> bool {
    next_cfg(m_none(), pre, post)
}

pub open spec fn next_mutant_intervene(pre: State, post: State) -> bool {
    next_cfg(m_intervene(), pre, post)
}

pub open spec fn next_mutant_reload(pre: State, post: State) -> bool {
    next_cfg(m_reload(), pre, post)
}

pub open spec fn next_mutant_consume(pre: State, post: State) -> bool {
    next_cfg(m_consume(), pre, post)
}

pub open spec fn next_mutant_packet(pre: State, post: State) -> bool {
    next_cfg(m_packet(), pre, post)
}

pub open spec fn next_mutant_ciphertext(pre: State, post: State) -> bool {
    next_cfg(m_ciphertext(), pre, post)
}

pub open spec fn next_mutant_membership(pre: State, post: State) -> bool {
    next_cfg(m_membership(), pre, post)
}

pub open spec fn next_mutant_expiry(pre: State, post: State) -> bool {
    next_cfg(m_expiry(), pre, post)
}

pub open spec fn next_mutant_custody(pre: State, post: State) -> bool {
    next_cfg(m_custody(), pre, post)
}

/// TypeOK. BOOLEAN conjuncts are type-level in this encoding; the optional
/// records' present flags are bools.
pub open spec fn type_ok(s: State) -> bool {
    &&& 1 <= s.worker <= 2
    &&& 0 <= s.serial <= 2
    &&& 0 <= s.reviews <= 2
    &&& 0 <= s.request_version <= 1
    &&& 0 <= s.clock <= 2
    &&& 0 <= s.revision <= 2
    &&& s.status.dom() =~= status_fields()
    &&& forall|f: int| status_fields().contains(f) ==> 0 <= map_at(s.status, f) <= 1
    &&& is_phase(s.phase)
}

/// ConsentLifetime ==
///   ~pending.present \/ (pending.consent.session = worker
///                        /\ pending.stamp = requestVersion).
pub open spec fn consent_lifetime(s: State) -> bool {
    ||| !s.pending.present
    ||| (map_at(s.pending.consent, f_session()) == s.worker && s.pending.stamp
        == s.request_version)
}

/// ConsumedBeforeCheck ==
///   phase \notin {"binding","membership","publish","done"} \/ ~pending.present.
pub open spec fn consumed_before_check(s: State) -> bool {
    ||| !(s.phase == ph_binding() || s.phase == ph_membership() || s.phase == ph_publish()
        || s.phase == ph_done())
    ||| !s.pending.present
}

/// ExactReview == ~effect.present \/ (supplied = reviewed.consent and the
/// selected item matches supplied position/digest and reviewed bytes).
pub open spec fn exact_review(s: State) -> bool {
    ||| !s.effect.present
    ||| (s.effect.supplied =~= s.effect.reviewed.consent && s.effect.selected.position == map_at(
        s.effect.supplied,
        f_position(),
    ) && s.effect.selected.digest == map_at(s.effect.supplied, f_digest())
        && s.effect.selected.payload == s.effect.reviewed.bytes)
}

/// CurrentMembership == ~effect.present \/ (supplied token fields equal
/// current status fields /\ current owner/quarantined are 0).
pub open spec fn current_membership(s: State) -> bool {
    ||| !s.effect.present
    ||| (forall|f: int| token_fields().contains(f) ==> map_at(s.effect.supplied, f) == map_at(
        s.effect.current,
        f,
    )) && map_at(s.effect.current, f_owner()) == 0 && map_at(s.effect.current, f_quarantined()) == 0
}

/// LiveAtConfirmation == ~effect.present \/
///   (supplied.start <= at < supplied.expires).
pub open spec fn live_at_confirmation(s: State) -> bool {
    ||| !s.effect.present
    ||| (map_at(s.effect.supplied, f_start()) <= s.effect.at && s.effect.at < map_at(
        s.effect.supplied,
        f_expires(),
    ))
}

/// ExclusivePublication == ~effect.present \/ observed = committed.
pub open spec fn exclusive_publication(s: State) -> bool {
    !s.effect.present || s.effect.observed == s.effect.committed
}

/// Auxiliary: serial never exceeds reviews (Reload resets serial only), so
/// Review's reviews < 2 bound also bounds serial. Needed for the serial
/// half of TypeOK.
pub open spec fn serial_le_reviews(s: State) -> bool {
    s.serial <= s.reviews
}

/// Boolean to int for the revision accounting below.
pub open spec fn b2i(b: bool) -> int {
    if b {
        1int
    } else {
        0int
    }
}

/// Auxiliary: revision accounting — Compete and Change each fire at most
/// once and each adds exactly one revision. Needed for the revision half
/// of TypeOK.
pub open spec fn rev_accounting(s: State) -> bool {
    s.revision == b2i(s.competed) + b2i(s.changed)
}

/// Auxiliary: once the broker has passed CheckBinding (membership) and for
/// as long as the packet/taken/item triple stays frozen (publish, done),
/// the exact-request binding holds. CheckMembership and Publish read the
/// triple without rechecking it; Publish copies it into effect.
pub open spec fn binding_holds(s: State) -> bool {
    (s.phase == ph_membership() || s.phase == ph_publish() || s.phase == ph_done())
        ==> bound_request(s)
}

/// Auxiliary: at the publish phase the membership snapshot and the
/// captured-time validity window that CheckMembership gated on still hold —
/// no action between "membership" and "publish" mutates status, packet or
/// checkedAt (Change excludes the publish phase). Publish copies packet,
/// status and checkedAt into effect.
pub open spec fn publish_facts(s: State) -> bool {
    s.phase == ph_publish() ==> (same_membership(s) && live_window(s))
}

/// The inductive invariant: the model's seven checked invariants plus the
/// four auxiliaries.
pub open spec fn inv(s: State) -> bool {
    &&& type_ok(s)
    &&& serial_le_reviews(s)
    &&& rev_accounting(s)
    &&& binding_holds(s)
    &&& publish_facts(s)
    &&& consent_lifetime(s)
    &&& consumed_before_check(s)
    &&& exact_review(s)
    &&& current_membership(s)
    &&& live_at_confirmation(s)
    &&& exclusive_publication(s)
}

/// Map insert propagation (same helper as publication.rs).
proof fn map_insert_at(m: Map<int, int>, k: int, v: int, x: int)
    ensures
        map_at(m.insert(k, v), x) == if x == k {
            v
        } else {
            map_at(m, x)
        },
{
}

/// Consent CASE lookup: reading a consent map at a packet field evaluates
/// to consent_val.
proof fn consent_at(s: State, f: int)
    requires
        packet_fields().contains(f),
    ensures
        map_at(consent_map(s), f) == consent_val(s, f),
{
    assert(consent_map(s).dom().contains(f));
    assert(consent_map(s)[f] == consent_val(s, f));
}

proof fn init_inv(s: State)
    requires
        init(s),
    ensures
        inv(s),
{
    assert(s.status.dom() =~= status_fields());
}

proof fn review_preserves(pre: State, post: State)
    requires
        inv(pre),
        review(pre, post),
    ensures
        inv(post),
{
    // type_ok: serial' <= reviews' <= 2 via serial_le_reviews + reviews < 2.
    assert(post.serial <= 2 && post.reviews <= 2);
    // ConsentLifetime: the fresh pending carries session = worker and
    // stamp = requestVersion.
    consent_at(pre, f_session());
    assert(consent_lifetime(post));
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn intervene_preserves(pre: State, post: State)
    requires
        inv(pre),
        intervene(m_none(), pre, post),
    ensures
        inv(post),
{
    // pending' = None, so ConsentLifetime is vacuous; the rest is unchanged.
    assert(!post.pending.present);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn reload_preserves(pre: State, post: State)
    requires
        inv(pre),
        reload(m_none(), pre, post),
    ensures
        inv(post),
{
    // pending' = taken' = None and phase' = "ready": every phase/record
    // conjunct is vacuous; serial resets to 0 <= reviews.
    assert(!post.pending.present);
    assert(post.serial <= post.reviews);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn start_preserves(pre: State, post: State, c: Map<int, int>)
    requires
        inv(pre),
        start(pre, post, c),
    ensures
        inv(post),
{
    // Only packet and phase change (ready -> retained); all invariants are
    // vacuous or unchanged.
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn read_retained_preserves(pre: State, post: State, i: Item)
    requires
        inv(pre),
        read_retained(pre, post, i),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn take_preserves(pre: State, post: State)
    requires
        inv(pre),
        take(m_none(), pre, post),
    ensures
        inv(post),
{
    // pending' = None in the safe model; phase moves to binding or dead,
    // both outside binding_holds' and publish_facts' claims.
    assert(!post.pending.present);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn check_binding_preserves(pre: State, post: State)
    requires
        inv(pre),
        check_binding(m_none(), pre, post),
    ensures
        inv(post),
{
    if post.phase == ph_membership() {
        // The safe gate is exactly bound_request on the unchanged triple.
        assert(binding_gate(m_none(), pre));
        assert(bound_request(post));
    }
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn check_membership_preserves(pre: State, post: State)
    requires
        inv(pre),
        check_membership(m_none(), pre, post),
    ensures
        inv(post),
{
    if post.phase == ph_publish() {
        // The safe gate gave SameMembership and the live window in pre;
        // status/packet/checkedAt are unchanged into post.
        assert(membership_gate(m_none(), pre));
        assert(same_membership(pre));
        assert(live_window(pre));
        assert forall|f: int| token_fields().contains(f) implies map_at(post.packet.fields, f)
            == map_at(post.status, f) by {
            assert(map_at(pre.packet.fields, f) == map_at(pre.status, f));
            assert(post.packet.fields.dom().contains(f) == pre.packet.fields.dom().contains(f));
            assert(post.status.dom().contains(f) == pre.status.dom().contains(f));
        }
        assert(same_membership(post));
        assert(live_window(post));
        // The binding facts established at CheckBinding persist unchanged.
        assert(bound_request(pre));
        assert(post.packet.fields =~= pre.taken.consent);
        assert(bound_request(post));
    }
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn compete_preserves(pre: State, post: State)
    requires
        inv(pre),
        compete(pre, post),
    ensures
        inv(post),
{
    // revision' = 0 + changed + 1 <= 2 by rev_accounting.
    assert(post.revision <= 2);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn change_preserves(pre: State, post: State, f: int)
    requires
        inv(pre),
        status_fields().contains(f),
        change(pre, post, f),
    ensures
        inv(post),
{
    // status'[f] = 1 stays in 0..1; other fields unchanged.
    assert forall|g: int| status_fields().contains(g) implies 0 <= map_at(post.status, g) <= 1 by {
        map_insert_at(pre.status, f, 1, g);
    }
    assert(post.status.dom() =~= status_fields());
    // revision' <= 2 by rev_accounting.
    assert(post.revision <= 2);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    // publish_facts: Change is blocked in the publish phase, so post.phase
    // is publish only if pre.phase already was — impossible; the auxiliary
    // is vacuous here. spell it out for the solver.
    assert(pre.phase != ph_publish());
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn publish_preserves(pre: State, post: State)
    requires
        inv(pre),
        publish(m_none(), pre, post),
    ensures
        inv(post),
{
    if post.phase == ph_done() {
        // Safe success: revision = expected. The effect copies the frozen
        // publish-phase facts.
        assert(pre.revision == pre.expected);
        // binding_holds at publish gives the packet/taken/item binding.
        assert(bound_request(pre));
        // publish_facts gives SameMembership and the live window.
        assert(same_membership(pre));
        assert(live_window(pre));
        assert(post.effect.present);
        assert(post.effect.supplied =~= post.effect.reviewed.consent);
        assert forall|f: int| token_fields().contains(f) implies map_at(post.effect.supplied, f)
            == map_at(post.effect.current, f) by {
            assert(map_at(pre.packet.fields, f) == map_at(pre.status, f));
        }
        assert(bound_request(post));
        assert(exact_review(post));
        assert(current_membership(post));
        assert(live_at_confirmation(post));
        assert(exclusive_publication(post));
    }
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn interrupt_preserves(pre: State, post: State)
    requires
        inv(pre),
        interrupt(pre, post),
    ensures
        inv(post),
{
    assert(!post.pending.present);
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn tick_preserves(pre: State, post: State)
    requires
        inv(pre),
        tick(pre, post),
    ensures
        inv(post),
{
    assert(type_ok(post));
    assert(serial_le_reviews(post));
    assert(rev_accounting(post));
    assert(binding_holds(post));
    assert(publish_facts(post));
    assert(consent_lifetime(post));
    assert(consumed_before_check(post));
    assert(exact_review(post));
    assert(current_membership(post));
    assert(live_at_confirmation(post));
    assert(exclusive_publication(post));
}

proof fn step_inv(pre: State, post: State)
    requires
        inv(pre),
        next(pre, post),
    ensures
        inv(post),
{
    if review(pre, post) {
        review_preserves(pre, post);
    } else if intervene(m_none(), pre, post) {
        intervene_preserves(pre, post);
    } else if reload(m_none(), pre, post) {
        reload_preserves(pre, post);
    } else if take(m_none(), pre, post) {
        take_preserves(pre, post);
    } else if check_binding(m_none(), pre, post) {
        check_binding_preserves(pre, post);
    } else if check_membership(m_none(), pre, post) {
        check_membership_preserves(pre, post);
    } else if compete(pre, post) {
        compete_preserves(pre, post);
    } else if publish(m_none(), pre, post) {
        publish_preserves(pre, post);
    } else if interrupt(pre, post) {
        interrupt_preserves(pre, post);
    } else if tick(pre, post) {
        tick_preserves(pre, post);
    } else if exists|f: int| status_fields().contains(f) && change(pre, post, f) {
        let f = choose|f: int| status_fields().contains(f) && change(pre, post, f);
        change_preserves(pre, post, f);
    } else if pre.shown.present && start(pre, post, pre.shown.fields) {
        start_preserves(pre, post, pre.shown.fields);
    } else if exists|f: int|
        packet_fields().contains(f) && start(
            pre,
            post,
            pre.shown.fields.insert(f, map_at(pre.shown.fields, f) + 1),
        ) {
        let f = choose|f: int| packet_fields().contains(f) && start(
            pre,
            post,
            pre.shown.fields.insert(f, map_at(pre.shown.fields, f) + 1)
        );
        start_preserves(pre, post, pre.shown.fields.insert(f, map_at(pre.shown.fields, f) + 1));
    } else if read_retained(pre, post, exact_item()) {
        read_retained_preserves(pre, post, exact_item());
    } else {
        assert(read_retained(pre, post, other_item()));
        read_retained_preserves(pre, post, other_item());
    }
}

/// Every state of every finite execution of the safe model satisfies inv.
pub open spec fn is_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next(t[i], t[i + 1])
}

pub open spec fn is_intervene_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_intervene(t[i], t[i + 1])
}

pub open spec fn is_reload_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_reload(t[i], t[i + 1])
}

pub open spec fn is_consume_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_consume(t[i], t[i + 1])
}

pub open spec fn is_packet_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_packet(t[i], t[i + 1])
}

pub open spec fn is_ciphertext_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_ciphertext(t[i], t[i + 1])
}

pub open spec fn is_membership_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_membership(t[i], t[i + 1])
}

pub open spec fn is_expiry_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_expiry(t[i], t[i + 1])
}

pub open spec fn is_custody_trace(t: Seq<State>) -> bool {
    &&& t.len() >= 1
    &&& init(t[0])
    &&& forall|i: int| 0 <= i < t.len() - 1 ==> #[trigger] next_mutant_custody(t[i], t[i + 1])
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

/// Concise state constructor for the witness proofs.
pub open spec fn st(
    worker: int,
    serial: int,
    reviews: int,
    rv: int,
    clock: int,
    status: Map<int, int>,
    revision: int,
    changed: bool,
    competed: bool,
    phase: int,
    pending: Pend,
    shown: Shown,
    packet: Shown,
    item: Item,
    taken: Pend,
    checked_at: int,
    expected: int,
    effect: Effect,
) -> State {
    State {
        worker,
        serial,
        reviews,
        request_version: rv,
        clock,
        status,
        revision,
        changed,
        competed,
        phase,
        pending,
        shown,
        packet,
        item,
        taken,
        checked_at,
        expected,
        effect,
    }
}

/// pending record with present = TRUE.
pub open spec fn pend(consent: Map<int, int>, bytes: int, stamp: int) -> Pend {
    Pend { present: true, consent, bytes, stamp }
}

/// shown/packet record with present = TRUE.
pub open spec fn presenting(fields: Map<int, int>) -> Shown {
    Shown { present: true, fields }
}

/// The init state, shared by every witness below.
pub open spec fn init_st() -> State {
    st(
        1,
        0,
        0,
        0,
        0,
        zstatus(),
        0,
        false,
        false,
        ph_ready(),
        pnone(),
        snone(),
        snone(),
        exact_item(),
        pnone(),
        0,
        0,
        enone(),
    )
}

/// The consent issued by the first review of s0 (worker 1, serial 0,
/// clock 0, zero status).
pub open spec fn consent0() -> Map<int, int> {
    consent_map(init_st())
}

/// The pending record produced by that first review.
pub open spec fn pending0() -> Pend {
    pend(consent0(), 1, 0)
}

/// The state after init -> Review.
pub open spec fn reviewed_st() -> State {
    st(
        1,
        1,
        1,
        0,
        0,
        zstatus(),
        0,
        false,
        false,
        ph_ready(),
        pending0(),
        presenting(consent0()),
        snone(),
        exact_item(),
        pnone(),
        0,
        0,
        enone(),
    )
}

/// The state after Review -> Start(shown): packet = c0, phase retained.
pub open spec fn started_st() -> State {
    State { phase: ph_retained(), packet: presenting(consent0()), ..reviewed_st() }
}

/// The state after Start -> ReadRetained(ExactItem): phase take.
pub open spec fn read_st() -> State {
    State { phase: ph_take(), ..started_st() }
}

/// The state after ReadRetained -> Take (safe): pending consumed, taken =
/// p0, checkedAt = 0, phase binding.
pub open spec fn bound_st() -> State {
    State { phase: ph_binding(), pending: pnone(), taken: pending0(), checked_at: 0, ..read_st() }
}

/// The state after Take -> CheckBinding: phase membership.
pub open spec fn member_st() -> State {
    State { phase: ph_membership(), ..bound_st() }
}

/// The state after CheckBinding -> CheckMembership: phase publish,
/// expected = revision = 0.
pub open spec fn publishable_st() -> State {
    State { phase: ph_publish(), expected: 0, ..member_st() }
}

/// The publication effect recorded by a successful Publish from s6.
pub open spec fn admitted_effect() -> Effect {
    Effect {
        present: true,
        supplied: consent0(),
        reviewed: pending0(),
        selected: exact_item(),
        current: zstatus(),
        at: 0,
        observed: 0,
        committed: 0,
        session: 1,
        stamp: 0,
    }
}

/// The state after CheckMembership -> Publish: phase done, effect present.
pub open spec fn admitted_st() -> State {
    State { phase: ph_done(), effect: admitted_effect(), ..publishable_st() }
}

/// mutant-intervene: Review -> Intervene keeps the pending permission while
/// requestVersion moves to 1 — pending.stamp = 0 # requestVersion.
proof fn mutant_intervene_violates()
    ensures
        exists|t: Seq<State>| is_intervene_trace(t) && !consent_lifetime(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = State { request_version: 1, ..s1 };
    assert(init(s0));
    assert(next_mutant_intervene(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_intervene(s1, s2)) by { assert(intervene(m_intervene(), s1, s2)); }
    assert(!consent_lifetime(s2)) by {
        consent_at(s0, f_session());
        assert(s2.pending.present);
        assert(s2.pending.stamp == 0);
        assert(s2.request_version == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_intervene_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_intervene(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_intervene_trace(t) && !consent_lifetime(t.last()));
}

/// mutant-reload: Review -> Reload keeps the previous worker's pending
/// permission — pending.consent.session = 1 # worker = 2.
proof fn mutant_reload_violates()
    ensures
        exists|t: Seq<State>| is_reload_trace(t) && !consent_lifetime(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = State { worker: 2, serial: 0, ..s1 };
    assert(init(s0));
    assert(next_mutant_reload(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_reload(s1, s2)) by { assert(reload(m_reload(), s1, s2)); }
    assert(!consent_lifetime(s2)) by {
        consent_at(s0, f_session());
        assert(s2.pending.present);
        assert(map_at(s2.pending.consent, f_session()) == 1);
        assert(s2.worker == 2);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2);
    assert(is_reload_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_reload(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1);
            assert(t[i + 1] == s1 || t[i + 1] == s2);
        }
    }
    assert(t.last() == s2);
    assert(is_reload_trace(t) && !consent_lifetime(t.last()));
}

/// mutant-consume: Review -> Start -> ReadRetained -> Take keeps pending
/// while entering the binding phase — phase = "binding" /\
/// pending.present.
proof fn mutant_consume_violates()
    ensures
        exists|t: Seq<State>| is_consume_trace(t) && !consumed_before_check(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = started_st();
    let s3 = read_st();
    let s4 = State { pending: pending0(), taken: pending0(), checked_at: 0, ..bound_st() };
    assert(init(s0));
    assert(next_mutant_consume(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_consume(s1, s2)) by { assert(start(s1, s2, consent0())); }
    assert(next_mutant_consume(s2, s3)) by { assert(read_retained(s2, s3, exact_item())); }
    assert(next_mutant_consume(s3, s4)) by { assert(take(m_consume(), s3, s4)); }
    assert(!consumed_before_check(s4)) by {
        assert(s4.phase == ph_binding());
        assert(s4.pending.present);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4);
    assert(is_consume_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_consume(
            t[i],
            t[i + 1],
        ) by {
            assert(t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3);
            assert(t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4);
        }
    }
    assert(t.last() == s4);
    assert(is_consume_trace(t) && !consumed_before_check(t.last()));
}

/// mutant-packet: the admitted packet is a mutated shown consent (id field
/// bumped); CheckBinding skips the equality so confirmation proceeds and
/// Publish records supplied # reviewed.consent — ExactReview fails.
/// Trace: Review -> Start(mutated) -> ReadRetained -> Take ->
/// CheckBinding -> CheckMembership -> Publish.
proof fn mutant_packet_violates()
    ensures
        exists|t: Seq<State>| is_packet_trace(t) && !exact_review(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let c1 = s1.shown.fields.insert(f_id(), map_at(s1.shown.fields, f_id()) + 1);
    let s2 = State { phase: ph_retained(), packet: presenting(c1), ..s1 };
    let s3 = State { phase: ph_take(), ..s2 };
    let s4 = State { phase: ph_binding(), pending: pnone(), taken: pending0(), checked_at: 0, ..s3 };
    let s5 = State { phase: ph_membership(), ..s4 };
    let s6 = State { phase: ph_publish(), expected: 0, ..s5 };
    let e6 = Effect { supplied: c1, ..admitted_effect() };
    let s7 = State { phase: ph_done(), effect: e6, ..s6 };
    assert(init(s0));
    assert(next_mutant_packet(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_packet(s1, s2)) by {
        consent_at(s0, f_id());
        assert(packet_fields().contains(f_id()));
        assert(start(s1, s2, c1));
    }
    assert(next_mutant_packet(s2, s3)) by { assert(read_retained(s2, s3, exact_item())); }
    assert(next_mutant_packet(s3, s4)) by { assert(take(m_packet(), s3, s4)); }
    assert(next_mutant_packet(s4, s5)) by {
        consent_at(s0, f_position());
        consent_at(s0, f_digest());
        assert(map_at(c1, f_position()) == 1 && map_at(c1, f_digest()) == 1);
        assert(binding_gate(m_packet(), s4));
        assert(check_binding(m_packet(), s4, s5));
    }
    assert(next_mutant_packet(s5, s6)) by {
        assert forall|f: int| token_fields().contains(f) implies map_at(s5.packet.fields, f)
            == map_at(s5.status, f) by {
            consent_at(s0, f);
            map_insert_at(consent0(), f_id(), 2, f);
        }
        consent_at(s0, f_start());
        consent_at(s0, f_expires());
        map_insert_at(consent0(), f_id(), 2, f_start());
        map_insert_at(consent0(), f_id(), 2, f_expires());
        assert(membership_gate(m_packet(), s5));
        assert(check_membership(m_packet(), s5, s6));
    }
    assert(next_mutant_packet(s6, s7)) by { assert(publish(m_packet(), s6, s7)); }
    assert(!exact_review(s7)) by {
        consent_at(s0, f_id());
        map_insert_at(consent0(), f_id(), 2, f_id());
        assert(map_at(s7.effect.supplied, f_id()) == 2);
        assert(map_at(s7.effect.reviewed.consent, f_id()) == 1);
        assert(!(s7.effect.supplied =~= s7.effect.reviewed.consent));
        assert(s7.effect.present);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7);
    assert(is_packet_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_packet(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7
            );
        }
    }
    assert(t.last() == s7);
    assert(is_packet_trace(t) && !exact_review(t.last()));
}

/// mutant-ciphertext: the retained item is swapped for OtherItem before
/// Take; CheckBinding skips the item/packet binding so Publish records
/// selected.position = 2 # supplied.position = 1 — ExactReview fails.
/// Trace: Review -> Start -> ReadRetained(OtherItem) -> Take ->
/// CheckBinding -> CheckMembership -> Publish.
proof fn mutant_ciphertext_violates()
    ensures
        exists|t: Seq<State>| is_ciphertext_trace(t) && !exact_review(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = started_st();
    let s3 = State { phase: ph_take(), item: other_item(), ..s2 };
    let s4 = State { phase: ph_binding(), pending: pnone(), taken: pending0(), checked_at: 0, ..s3 };
    let s5 = State { phase: ph_membership(), ..s4 };
    let s6 = State { phase: ph_publish(), expected: 0, ..s5 };
    let e6 = Effect { selected: other_item(), ..admitted_effect() };
    let s7 = State { phase: ph_done(), effect: e6, ..s6 };
    assert(init(s0));
    assert(next_mutant_ciphertext(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_ciphertext(s1, s2)) by { assert(start(s1, s2, consent0())); }
    assert(next_mutant_ciphertext(s2, s3)) by { assert(read_retained(s2, s3, other_item())); }
    assert(next_mutant_ciphertext(s3, s4)) by { assert(take(m_ciphertext(), s3, s4)); }
    assert(next_mutant_ciphertext(s4, s5)) by {
        assert(binding_gate(m_ciphertext(), s4));
        assert(check_binding(m_ciphertext(), s4, s5));
    }
    assert(next_mutant_ciphertext(s5, s6)) by {
        assert forall|f: int| token_fields().contains(f) implies map_at(s5.packet.fields, f)
            == map_at(s5.status, f) by {
            consent_at(s0, f);
        }
        consent_at(s0, f_start());
        consent_at(s0, f_expires());
        assert(membership_gate(m_ciphertext(), s5));
        assert(check_membership(m_ciphertext(), s5, s6));
    }
    assert(next_mutant_ciphertext(s6, s7)) by { assert(publish(m_ciphertext(), s6, s7)); }
    assert(!exact_review(s7)) by {
        consent_at(s0, f_position());
        assert(s7.effect.present);
        assert(s7.effect.selected.position == 2);
        assert(map_at(s7.effect.supplied, f_position()) == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7);
    assert(is_ciphertext_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_ciphertext(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7
            );
        }
    }
    assert(t.last() == s7);
    assert(is_ciphertext_trace(t) && !exact_review(t.last()));
}

/// mutant-membership: a membership-field change lands between the binding
/// check and the membership check; the mutant skips SameMembership so
/// Publish records supplied.room = 0 # current.room = 1 —
/// CurrentMembership fails.
/// Trace: Review -> Start -> ReadRetained -> Take -> CheckBinding ->
/// Change("room") -> CheckMembership -> Publish.
proof fn mutant_membership_violates()
    ensures
        exists|t: Seq<State>| is_membership_trace(t) && !current_membership(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = started_st();
    let s3 = read_st();
    let s4 = bound_st();
    let s5 = member_st();
    let z1 = zstatus().insert(f_room(), 1);
    let s6 = State { status: z1, changed: true, revision: 1, ..s5 };
    let s7 = State { phase: ph_publish(), expected: 1, ..s6 };
    let e7 = Effect {
        present: true,
        supplied: consent0(),
        reviewed: pending0(),
        selected: exact_item(),
        current: z1,
        at: 0,
        observed: 1,
        committed: 1,
        session: 1,
        stamp: 0,
    };
    let s8 = State { phase: ph_done(), effect: e7, ..s7 };
    assert(init(s0));
    assert(next_mutant_membership(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_membership(s1, s2)) by { assert(start(s1, s2, consent0())); }
    assert(next_mutant_membership(s2, s3)) by { assert(read_retained(s2, s3, exact_item())); }
    assert(next_mutant_membership(s3, s4)) by { assert(take(m_membership(), s3, s4)); }
    assert(next_mutant_membership(s4, s5)) by {
        assert(bound_request(s4)) by {
            consent_at(s0, f_position());
            consent_at(s0, f_digest());
        }
        assert(binding_gate(m_membership(), s4));
        assert(check_binding(m_membership(), s4, s5));
    }
    assert(next_mutant_membership(s5, s6)) by {
        assert(status_fields().contains(f_room()));
        assert(change(s5, s6, f_room()));
    }
    assert(next_mutant_membership(s6, s7)) by {
        consent_at(s0, f_start());
        consent_at(s0, f_expires());
        assert(membership_gate(m_membership(), s6));
        assert(check_membership(m_membership(), s6, s7));
    }
    assert(next_mutant_membership(s7, s8)) by { assert(publish(m_membership(), s7, s8)); }
    assert(!current_membership(s8)) by {
        consent_at(s0, f_room());
        map_insert_at(zstatus(), f_room(), 1, f_room());
        assert(s8.effect.present);
        assert(map_at(s8.effect.supplied, f_room()) == 0);
        assert(map_at(s8.effect.current, f_room()) == 1);
        assert(token_fields().contains(f_room()));
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    );
    assert(is_membership_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_membership(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
            );
        }
    }
    assert(t.last() == s8);
    assert(is_membership_trace(t) && !current_membership(t.last()));
}

/// mutant-expiry: the clock advances to 2 before Take captures checkedAt;
/// CheckMembership skips the validity window so Publish records
/// at = 2 >= supplied.expires = 2 — LiveAtConfirmation fails.
/// Trace: Review -> Tick -> Tick -> Start -> ReadRetained -> Take ->
/// CheckBinding -> CheckMembership -> Publish.
proof fn mutant_expiry_violates()
    ensures
        exists|t: Seq<State>| is_expiry_trace(t) && !live_at_confirmation(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = State { clock: 1, ..s1 };
    let s3 = State { clock: 2, ..s2 };
    let s4 = State { phase: ph_retained(), packet: presenting(consent0()), ..s3 };
    let s5 = State { phase: ph_take(), ..s4 };
    let s6 = State { phase: ph_binding(), pending: pnone(), taken: pending0(), checked_at: 2, ..s5 };
    let s7 = State { phase: ph_membership(), ..s6 };
    let s8 = State { phase: ph_publish(), expected: 0, ..s7 };
    let e8 = Effect { at: 2, ..admitted_effect() };
    let s9 = State { phase: ph_done(), effect: e8, ..s8 };
    assert(init(s0));
    assert(next_mutant_expiry(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_expiry(s1, s2)) by { assert(tick(s1, s2)); }
    assert(next_mutant_expiry(s2, s3)) by { assert(tick(s2, s3)); }
    assert(next_mutant_expiry(s3, s4)) by { assert(start(s3, s4, consent0())); }
    assert(next_mutant_expiry(s4, s5)) by { assert(read_retained(s4, s5, exact_item())); }
    assert(next_mutant_expiry(s5, s6)) by { assert(take(m_expiry(), s5, s6)); }
    assert(next_mutant_expiry(s6, s7)) by {
        assert(bound_request(s6)) by {
            consent_at(s0, f_position());
            consent_at(s0, f_digest());
        }
        assert(binding_gate(m_expiry(), s6));
        assert(check_binding(m_expiry(), s6, s7));
    }
    assert(next_mutant_expiry(s7, s8)) by {
        assert forall|f: int| token_fields().contains(f) implies map_at(s7.packet.fields, f)
            == map_at(s7.status, f) by {
            consent_at(s0, f);
        }
        assert(membership_gate(m_expiry(), s7));
        assert(check_membership(m_expiry(), s7, s8));
    }
    assert(next_mutant_expiry(s8, s9)) by { assert(publish(m_expiry(), s8, s9)); }
    assert(!live_at_confirmation(s9)) by {
        consent_at(s0, f_expires());
        assert(s9.effect.present);
        assert(s9.effect.at == 2);
        assert(map_at(s9.effect.supplied, f_expires()) == 2);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    ).push(s9);
    assert(is_expiry_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_expiry(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7 || t[i] == s8
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8 || t[i + 1] == s9
            );
        }
    }
    assert(t.last() == s9);
    assert(is_expiry_trace(t) && !live_at_confirmation(t.last()));
}

/// mutant-custody: a competing publication lands after the membership
/// snapshot; the mutant skips the revision = expected check so Publish
/// records observed = 0 # committed = 1 — ExclusivePublication fails.
/// Trace: Review -> Start -> ReadRetained -> Take -> CheckBinding ->
/// CheckMembership -> Compete -> Publish.
proof fn mutant_custody_violates()
    ensures
        exists|t: Seq<State>| is_custody_trace(t) && !exclusive_publication(t.last()),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = started_st();
    let s3 = read_st();
    let s4 = bound_st();
    let s5 = member_st();
    let s6 = publishable_st();
    let s7 = State { competed: true, revision: 1, ..s6 };
    let e8 = Effect { observed: 0, committed: 1, ..admitted_effect() };
    let s8 = State { phase: ph_done(), effect: e8, ..s7 };
    assert(init(s0));
    assert(next_mutant_custody(s0, s1)) by { assert(review(s0, s1)); }
    assert(next_mutant_custody(s1, s2)) by { assert(start(s1, s2, consent0())); }
    assert(next_mutant_custody(s2, s3)) by { assert(read_retained(s2, s3, exact_item())); }
    assert(next_mutant_custody(s3, s4)) by { assert(take(m_custody(), s3, s4)); }
    assert(next_mutant_custody(s4, s5)) by {
        assert(bound_request(s4)) by {
            consent_at(s0, f_position());
            consent_at(s0, f_digest());
        }
        assert(binding_gate(m_custody(), s4));
        assert(check_binding(m_custody(), s4, s5));
    }
    assert(next_mutant_custody(s5, s6)) by {
        assert forall|f: int| token_fields().contains(f) implies map_at(s5.packet.fields, f)
            == map_at(s5.status, f) by {
            consent_at(s0, f);
        }
        consent_at(s0, f_start());
        consent_at(s0, f_expires());
        assert(membership_gate(m_custody(), s5));
        assert(check_membership(m_custody(), s5, s6));
    }
    assert(next_mutant_custody(s6, s7)) by { assert(compete(s6, s7)); }
    assert(next_mutant_custody(s7, s8)) by { assert(publish(m_custody(), s7, s8)); }
    assert(!exclusive_publication(s8)) by {
        assert(s8.effect.present);
        assert(s8.effect.observed == 0);
        assert(s8.effect.committed == 1);
    }
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7).push(
        s8,
    );
    assert(is_custody_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next_mutant_custody(
            t[i],
            t[i + 1],
        ) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6 || t[i] == s7
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7 || t[i + 1] == s8
            );
        }
    }
    assert(t.last() == s8);
    assert(is_custody_trace(t) && !exclusive_publication(t.last()));
}

/// Non-vacuity witness for the safe model, matching witness-admitted.cfg's
/// intentional NoSuccessfulAdmission failure: Review -> Start ->
/// ReadRetained(ExactItem) -> Take -> CheckBinding -> CheckMembership ->
/// Publish reaches done with a recorded effect. Every gate is checked on
/// the way — the safe model does admit a valid request.
proof fn completion_witness()
    ensures
        exists|t: Seq<State>| is_trace(t) && t.last().effect.present && t.last().phase == ph_done(),
{
    let s0 = init_st();
    let s1 = reviewed_st();
    let s2 = started_st();
    let s3 = read_st();
    let s4 = bound_st();
    let s5 = member_st();
    let s6 = publishable_st();
    let s7 = admitted_st();
    assert(init(s0));
    assert(next(s0, s1)) by { assert(review(s0, s1)); }
    assert(next(s1, s2)) by { assert(start(s1, s2, consent0())); }
    assert(next(s2, s3)) by { assert(read_retained(s2, s3, exact_item())); }
    assert(next(s3, s4)) by { assert(take(m_none(), s3, s4)); }
    assert(next(s4, s5)) by {
        assert(bound_request(s4)) by {
            consent_at(s0, f_position());
            consent_at(s0, f_digest());
        }
        assert(binding_gate(m_none(), s4));
        assert(check_binding(m_none(), s4, s5));
    }
    assert(next(s5, s6)) by {
        assert forall|f: int| token_fields().contains(f) implies map_at(s5.packet.fields, f)
            == map_at(s5.status, f) by {
            consent_at(s0, f);
        }
        consent_at(s0, f_start());
        consent_at(s0, f_expires());
        assert(membership_gate(m_none(), s5));
        assert(check_membership(m_none(), s5, s6));
    }
    assert(next(s6, s7)) by { assert(publish(m_none(), s6, s7)); }
    assert(s7.effect.present);
    assert(s7.phase == ph_done());
    let t = Seq::empty().push(s0).push(s1).push(s2).push(s3).push(s4).push(s5).push(s6).push(s7);
    assert(is_trace(t)) by {
        assert forall|i: int| 0 <= i < t.len() - 1 implies #[trigger] next(t[i], t[i + 1]) by {
            assert(
                t[i] == s0 || t[i] == s1 || t[i] == s2 || t[i] == s3 || t[i] == s4 || t[i] == s5
                    || t[i] == s6
            );
            assert(
                t[i + 1] == s1 || t[i + 1] == s2 || t[i + 1] == s3 || t[i + 1] == s4 || t[i + 1] == s5
                    || t[i + 1] == s6 || t[i + 1] == s7
            );
        }
    }
    assert(t.last() == s7);
    assert(is_trace(t) && t.last().effect.present && t.last().phase == ph_done());
}

}
