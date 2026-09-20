# Private group kernel

This workspace crate implements fixed-owner private MLS rooms with up to 16 active devices, repeated invitations, later-epoch fresh joins, ordered member catch-up, messages, targeted removal, owner credential renewal and explicit new-device rejoin. It has no network endpoint, public-directory prerequisite, transport, private-room UI or agent execution. See [the release boundaries](../../docs/private-rooms.md).

The owner is the exact device pinned by the account-signed room anchor. Several
devices may belong to one account; that relationship does not grant owner powers.
Private identity is a random full room ID and signed anchor. Public bootstrap,
public room IDs, URLs and directory membership convey no private-room authority.

## Explicit lifecycle and sharing

`OwnerDraft::new` generates a fresh room/device and exposes only typed public
account-signing requests. The separate account custodian signs the exact device
enrollment and room anchor. Consuming `create` persists the device before output.
`MemberDraft` similarly initializes a fresh device against an independently
selected anchor and owner enrollment before its one-use `key_package` is released.
Neither constructor is key-only recovery or a reset of an old device.

`invite(operation, request, validity, now)` admits one fresh device while capacity
remains. Its retained output includes the exact recipient enrollment, invitation,
MLS Commit and Welcome, and owner-signed roster checkpoint. `join` accepts that
checkpoint only for a genuinely pending fresh device. It checks the full scope,
invitation/floors, Commit/Welcome digests, owner sender, serialized GroupContext
and actual complete MLS roster before committing consumed KeyPackage material.

The checkpoint is an explicit owner endorsement of the selected joining state.
It does not prove global freshness or absence of an owner fork. Existing members
cannot jump to it: `apply_control` checks the exact next retained floor, every
staged MLS proposal, enrolled device and exact KeyPackage, and full removal key
behind each leaf index. Each control supports one addition, one non-owner removal or one owner
credential renewal. `remove(operation, target_device, now)` never removes all devices of
an account implicitly. A removed device can read retained history but cannot
process new room content or reactivate from a replacement Welcome. Rejoin means
an explicitly invited new device with fresh MLS state and a new leaf.

`prepare_message(body)` creates a private-field `MessageDraft` bound to full
room/anchor/account/device, current epoch and canonical roster digest.
`send(operation, &draft, now)` rechecks those bindings against exact retained
state before encryption. A room, author or membership change cannot silently
reassign the draft. Explicitly preparing another draft is a new sharing decision.
An identical already-committed operation may return its original ciphertext even
after removal or expiration; it never re-encrypts the old body for a new roster.
If the draft is lost after a membership change, use retained outbox history to
recover the old artifact, rather than inventing a newly bound retry.

`receive` admits only current-epoch authenticated member application messages.
Plaintext stays quarantined until the receiver ratchet and encrypted inbox commit
together. Unauthenticated `OwnPrivateMessage`, standalone proposals and unexpected
controls cannot grant sender authority. Delayed old-epoch ciphertext may be refused
after a membership change. It is never automatically decrypted and re-shared with
an expanded roster. Membership changes cannot retract plaintext already received.

## Retained controls and fork quarantine

Owner transitions atomically append `Control(sequence)`, `Outbox(position)` and
`Operation(full ID)` with the next encrypted state. An existing member appends one
control when accepting it. A fresh join stores its joining control and one bounded
initial checkpoint/history-base marker. There is no lifetime-growing control map
inside current state and no rescan of old outbox records to discover the head.

`encrypted_controls(after_full_floor, limit)` returns a bounded immutable suffix
of `CommittedEncryptedControl` envelopes with its available base, observed head
and full continuation. It returns the original ciphertext without retaining an
old exporter key or encrypting it again. A fresh joiner's encrypted base is its
joining floor: it cannot supply the predecessor envelope it never authenticated.
Earlier unavailable history is an error, not an empty successful page. The owner
retains controls from genesis subject to the backend's explicit quota.

Each envelope uses XChaCha20Poly1305 with a key exported from the predecessor MLS
epoch under `vhalla/private/control-envelope/v1`. Exporter context and AEAD bind
full room/anchor, epoch, complete control floor, canonical roster commitment and
anchored owner device; the complete header is authenticated. Decryption is only
one gate: the inner owner signature, exact next parent and actual MLS staged
control are still checked. The fixed header exposes kind, epoch, sequence and
length. It does not promise traffic-analysis protection.

`apply_control` accepts only these encrypted envelopes, never a plaintext fallback.
At an old known sequence, only the exact retained envelope is a read-only retry;
changed ciphertext is a conflict, not authenticated owner-fork evidence. It does
not renew permission. `controls(after_full_floor, limit)` instead returns the
retained **signed owner proofs** for local inspection and evidence. Those proof
bytes are private metadata, not encrypted transport packets.

The invitation response and KeyPackage request remain confidential bootstrap
artifacts with visible enrollment/roster metadata. `invite` retains both the
recipient bootstrap in its outbox and a separate encrypted next control for
existing members. Generic `outbox` output therefore is not uniformly suitable
for an untrusted relay. No transport is implemented by this crate.

`observe_owner_control` compares a signed claim with known history without
admitting future state, including owner credential renewal claims.
A different valid pinned-owner signature at a locally known sequence is a fork
observation. The first proof is atomically retained in encrypted current state;
confirmed reopen allows status/history/evidence only. The fixed reserve in normal
state encoding leaves room for one bounded proof, not an unbounded fault list.
`fork_evidence` returns the conflicting signed control plus the accepted signed
control or initial checkpoint that establishes the contradiction. Unknown older
history and foreign signatures cannot manufacture a quarantine. There is no
last-write-wins, checkpoint jump or automatic fault-clear operation.

Failed/canceled quarantine publication latches the custodian and retains the
pending evidence in memory for explicit preservation/reconciliation. It is not
claimed durable until the transaction and authenticated reread complete. Encoding
reserve does not guarantee free disk, browser persistence or successful sync.
If all writes fail and the process loses memory, the software cannot promise to
remember that observation. A controller must not automatically resume after that
error or claim the fault survived merely because it was observed.

## Membership inspection

`membership()` authenticates the exact retained state before returning a bounded
`MembershipSnapshot`: status, signed anchor, local enrollment, current owner
enrollment and the complete roster. It exposes full account/device identities
and validity periods for trusted recipient inspection. These are private metadata.
The snapshot is the last locally accepted state, not a remote freshness check.
History inspection remains available after removal or fork quarantine; that does
not permit sending. A failed, stale or canceled storage access leaves the same
reopen latch as other kernel operations. A snapshot never refreshes a draft's
sharing consent or a host's agent grant.

## Time and remaining recovery boundaries

New accepted operations check an injected nondecreasing clock and relevant
half-open enrollment/invitation validity. KeyPackage validation also uses upstream
wall time and separately checks the caller's retained time. Expiration is an
admission constraint, not cryptographic deletion of a member's previously held
keys; explicit membership removal is required. Catch-up can fail when required
credentials or KeyPackages have expired. Exact history retries do not advance the
clock or renew authorization. The hosting controller must supply trustworthy time.

Owner renewal updates the MLS credential for the exact same anchored device under
an explicit current account signature. Owner-device loss remains a separate
unimplemented succession boundary. An account signature alone cannot recover MLS
secrets. Succession would require an original authorized policy, surviving current
MLS state and an exact common unconflicted floor. No surviving state means a new
explicit room, not fabricated ratchet recovery.

## Atomic encrypted storage and limits

`storage::Store` is unchanged: asynchronous exact-image CAS over full
`Context { scope, account, device }` plus up to three **new** immutable encrypted
records. Every offered existing key refuses, including identical bytes. Exact
retries read retained artifacts rather than republishing keys. Initialization
requires a wholly unused namespace. Missing published lookup/payload halves must
refuse; read-only methods do not repair damage. Backends receive no plaintext MLS
state and may not invoke untrusted reentrant callbacks.

Each operation hydrates an isolated OpenMLS provider. XChaCha20Poly1305 envelopes
bind the full context and exact state/record purpose. The kernel latches before
its first storage await and authenticates reread state and records before releasing
ciphertext or inbox plaintext. Interrupted access requires exact-store reopen.
AEAD does not detect coherent rollback, cloned custody or a backend lying about
durability. A wrapping-key backup alone cannot restore ratchets or histories.

Limits: 16 active devices; 4 MiB current plaintext including any fault evidence;
256 provider entries; 128 KiB MLS frame; 1–4096 inert application bytes; 266,280
bytes per encrypted immutable record; 16 records/512 KiB per explicit history page.
Normal state reserves 4160 bytes for the first fault. The signed checkpoint cap is
4096 bytes; its canonical 16-device frame is 2852 bytes. Aggregate packet limits
still apply when nested pieces are individually valid. Histories use checked u64
counters and separate indexed records with no artificial lifetime message cap.
Backend quotas must refuse without pruning, reset or partial acknowledgment.

Current state uses `VHPKSTATE\x03` and invitation format `VHPKINVITE\x02`.
The control envelope is `VHPKCTRL\x01`; encrypted local control records contain
`VHPKCTRLREC\x01` framing around the signed proof and optional retained envelope.
State versions 1 and 2 are refused, not loaded or migrated. Storage record keys,
outer storage AEAD and the maximum-three-record Store transaction contract remain
unchanged. Preserve compatible source and complete custody when inspecting older
experimental stores; there is no automatic format or storage-key migration.

Upstream provider/serialization allocations may contain secret copies. Wrapping
keys and serialized clear buffers use zeroizing ownership; this is not a claim
that all upstream memory is erased. Infallible upstream entropy constructors may
abort/trap on OS entropy failure; invalidate the worker/session, with no fallback.

## Qualification and integration

Pinned graph: OpenMLS0.9.0, provider/credential/storage/traits0.6.0, standard
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, no draft features. WASM development
pins match browser wasm-bindgen0.2.108/js-sys0.3.85. Native group tests, strict lint
and WASM checks have separate exact-tree receipts. Earlier real SQLite and
IndexedDB journeys covered group transactions, quotas, cancellation after commit,
reopen, removal and owner renewal; the browser journey ran in both Window and a
dedicated worker. These earlier receipts do not qualify the changed state-v3
control, account-custody or membership snapshot APIs. Combined-candidate validation
is pending. Workspace native tests and browser runtime CI cover the integrations.

All private descriptors, invitations, member identities, controls, content and
puzzle metadata stay out of public discovery/activity by default. Returning a
committed artifact means local durable storage only, not transport delivery,
verified useful work, owner acceptance of a result or authority to execute tools.
Private bootstrap transport, browser custody integration, complete-state recovery,
invite UX and enforced agent compartments remain gates before private-client
claims. The fixed-room agent API and storage journeys do not substitute for these workflows.

## Owner renewal

The exact anchored device can renew through a current account-signed enrollment using `owner_renewal_request` and `renew_owner`. This narrowly permits an expired prior owner enrollment while ordinary operations and the accepting member retain their validity checks. The checked MLS self-update advances the epoch and invalidates old roster consent. Its control, outbox, operation and current state commit together; exact retries preserve the original artifact. Owner-device succession remains unimplemented.

## Optional account-derived storage custody

`StorageKey::derive_for_account(&SigningKey, Context)` implements one frozen
HKDF-SHA256 contract for existing account custodians. It checks exact account
public-key equality, then derives 32 bytes from the secret Ed25519 seed with salt
`vhalla/private-room/storage/extract/v1\0` and expansion info
`vhalla/private-room/storage/key/v1\0` followed by the 32-byte room, anchor, account and
device fields, in that order. Both labels include the terminating NUL. All fields
are full fixed-width values; password, epoch, enrollment and roster are deliberately absent. The output
is opaque zeroizing custody, not a generic key derivation or signing callback.

This derives a key to open complete existing state; it does not initialize,
restore, import, clone, migrate or authorize it. Password changes with the same
account retain access. Account-key rotation requires old account custody or a
separately reviewed migration. Compromised account custody exposes every retained
derived store. Missing ratchets or histories cannot be recovered from the account
backup alone. Coherent rollback and two active copies remain outside this boundary.

A live kernel retains its own storage-key copy: locking the account alone does
not lock the kernel. The controller must drop both or terminate their shared
worker. The native crate's optional `client::RoomSession` enforces that joint
lifetime; the browser private-room worker/controller is not yet wired. No worker
response or agent method should expose secret bytes. Previously created
explicit-key stores are not automatically converted to this scheme.
