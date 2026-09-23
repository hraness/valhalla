---------------------------- MODULE RelayQuota ----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS MaxItems, MaxBytes, CrashBudget,
          EarlyCharge, DuplicateCharge, MoveDuplicate, ResetQuota, EarlyReceipt
Items == {"first", "second"}
Keys == {"owner", "other"}
Tokens == {"old", "new"}
Phases == {"idle", "charge", "item", "commit", "barrier", "reply", "closed"}
\* Payloads use one and two abstract byte units; item and byte bounds are
\* independent. The other key permits exact duplicate retries with independent
\* work permission; the retained charge stays with the original stable owner.
Size(i) == IF i = "first" THEN 1 ELSE 2
RECURSIVE ChargeBytes(_), ItemBytes(_)
ChargeBytes(charges) == IF charges = {} THEN 0 ELSE
    LET c == CHOOSE c \in charges : TRUE
    IN c.bytes + ChargeBytes(charges \ {c})
ItemBytes(items) == IF items = {} THEN 0 ELSE
    LET i == CHOOSE i \in items : TRUE
    IN Size(i) + ItemBytes(items \ {i})

VARIABLE s
vars == <<s>>
Spent(k) == Cardinality({charge \in s.charges : charge.key = k})
SpentBytes(k) == ChargeBytes({charge \in s.charges : charge.key = k})
Charged(i) == \E charge \in s.charges : charge.item = i
Position(i) == IF i \in s.items THEN s.positions[i] ELSE 0

Init == s = [pc |-> "idle", items |-> {}, charges |-> {},
             positions |-> [i \in Items |-> 0],
             original |-> [i \in Items |-> 0],
             owner |-> [i \in Items |-> "none"],
             synced |-> {}, head |-> 0, token |-> "old", rotated |-> FALSE,
             item |-> "first", key |-> "owner", duplicate |-> FALSE,
             stagedItems |-> {}, stagedCharges |-> {},
             receipts |-> {}, crashes |-> 0, attempts |-> 0]

\* Authentication is checked against immutable service startup credentials.
\* Token replacement preserves the stable key identity and its storage ledger.
Begin(i, k, token) ==
    /\ s.pc = "idle" /\ s.attempts < 4
    /\ k = "other" \/ token = s.token
    /\ i \in s.items \/ (Spent(k) < MaxItems /\ SpentBytes(k) + Size(i) <= MaxBytes)
    /\ s' = [s EXCEPT !.pc = "charge", !.item = i, !.key = k,
         !.duplicate = i \in s.items, !.stagedItems = s.items,
         !.stagedCharges = s.charges, !.attempts = @ + 1]
StageCharge ==
    /\ s.pc = "charge"
    /\ LET charge == [item |-> s.item, key |-> s.key, bytes |-> Size(s.item),
                      serial |-> IF DuplicateCharge THEN s.attempts ELSE 0]
           next == IF Charged(s.item) /\ ~DuplicateCharge
                   THEN s.charges ELSE s.charges \cup {charge}
       IN s' = [s EXCEPT !.pc = "item", !.stagedCharges = next,
                           !.charges = IF EarlyCharge THEN next ELSE @]
StageItem == /\ s.pc = "item"
             /\ s' = [s EXCEPT !.pc = "commit",
                                !.stagedItems = @ \cup {s.item}]

\* One SQLite transaction publishes item and charge together. The separate
\* successful directory barrier is required before constructing a receipt.
Commit ==
    /\ s.pc = "commit"
    /\ s' = [s EXCEPT !.pc = "barrier", !.items = s.stagedItems,
         !.charges = s.stagedCharges,
         !.positions[s.item] = IF s.duplicate /\ ~MoveDuplicate THEN @ ELSE s.head + 1,
         !.original[s.item] = IF s.duplicate THEN @ ELSE s.head + 1,
         !.owner[s.item] = IF s.duplicate THEN @ ELSE s.key,
         !.head = IF s.duplicate THEN @ ELSE @ + 1]
Barrier == /\ s.pc = "barrier"
           /\ s' = [s EXCEPT !.pc = "reply", !.synced = s.items]
Receipt ==
    /\ s.pc = "reply" \/ (EarlyReceipt /\ s.pc = "barrier")
    /\ s' = [s EXCEPT !.pc = "idle",
         !.receipts = @ \cup {[item |-> s.item, position |-> Position(s.item),
                              durable |-> s.item \in s.synced]}]
\* The peer can lose the response even after the commit/barrier. No retained
\* item or charge is removed, and a later exact retry returns the same position.
LostReceipt == /\ s.pc = "reply"
               /\ s' = [s EXCEPT !.pc = "idle"]
Rollback == /\ s.pc \in {"charge", "item", "commit"}
            /\ s' = [s EXCEPT !.pc = "idle", !.stagedItems = {}, !.stagedCharges = {}]
Crash == /\ s.pc # "closed" /\ s.crashes < CrashBudget
         /\ s' = [s EXCEPT !.pc = "closed", !.crashes = @ + 1,
                            !.stagedItems = {}, !.stagedCharges = {}]
\* Process interruption (not physical power loss) retains completed SQLite
\* transactions; reopening successfully validates the item/charge ledger and
\* establishes a new barrier. Uncommitted staged writes have disappeared.
Reopen == /\ s.pc = "closed"
          /\ s' = [s EXCEPT !.pc = "idle", !.synced = s.items]
RotateToken == /\ s.pc = "idle" /\ ~s.rotated
               /\ s' = [s EXCEPT !.token = "new", !.rotated = TRUE,
                  !.charges = IF ResetQuota
                              THEN {c \in s.charges : c.key # "owner"} ELSE @]

Next == StageCharge \/ StageItem \/ Commit \/ Barrier \/ Receipt \/ LostReceipt
        \/ Rollback \/ Crash \/ Reopen \/ RotateToken
        \/ (\E i \in Items, k \in Keys, t \in Tokens : Begin(i, k, t))
Spec == Init /\ [][Next]_vars

TypeOK == /\ s.pc \in Phases /\ s.items \subseteq Items /\ s.synced \subseteq s.items
          /\ s.positions \in [Items -> 0..2] /\ s.original \in [Items -> 0..2]
          /\ s.owner \in [Items -> Keys \cup {"none"}]
          /\ s.item \in Items /\ s.key \in Keys /\ s.token \in Tokens
          /\ s.head \in 0..2 /\ s.crashes \in 0..CrashBudget
          /\ s.attempts \in 0..4 /\ s.rotated \in BOOLEAN /\ s.duplicate \in BOOLEAN
          /\ s.stagedItems \subseteq Items
          /\ s.charges \subseteq [item : Items, key : Keys, bytes : 1..2, serial : 0..4]
          /\ s.stagedCharges \subseteq [item : Items, key : Keys, bytes : 1..2, serial : 0..4]
ItemsChargedTogether == {c.item : c \in s.charges} = s.items
RetryKeepsPositionAndCharge ==
    /\ s.positions = s.original
    /\ \A i \in s.items :
         /\ Cardinality({c \in s.charges : c.item = i}) = 1
         /\ \A c \in s.charges : c.item = i => c.key = s.owner[i] /\ c.bytes = Size(i)
StableIdentitySpend == \A k \in Keys :
    /\ Spent(k) = Cardinality({i \in s.items : s.owner[i] = k})
    /\ SpentBytes(k) = ItemBytes({i \in s.items : s.owner[i] = k})
QuotaBound == \A k \in Keys : Spent(k) <= MaxItems /\ SpentBytes(k) <= MaxBytes
ReceiptAfterDurableRetention == \A r \in s.receipts :
    /\ r.durable /\ r.position > 0 /\ r.position = s.original[r.item]
=============================================================================
