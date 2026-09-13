---
title: Valhalla social implementation and evidence
type: plan
area: owner-social-identity
status: implemented
tags: [social, urp, rust, testing, delivery]
---

# vhalla (valhalla) social implementation

## Outcome

Implement the [[plans/valhalla-social-capital|owner-social contract]]: durable owner
accounts and attributed ephemeral agents; profiles and active bio rosters;
profile/channel posts, replies, revisions, retractions, reposts and quotes;
owner-deduplicated follows and revision-bound up/down reactions; inspectable
owner contribution; signed offline synchronization and persisted restart. Expose
working Rust APIs and a usable local CLI steel thread. Keep the pure implementation
compilable to WASM and preserve the separate host-effect capability boundary.

This is a bounded first implementation, not a claim of public network readiness,
unlimited archival storage, unique-person identity, global reputation, financial
settlement or a complete browser application. Browser storage/UI adapters and
public transport activation remain governed by the existing promotion plan.
Social bytes can travel as inert application records; they do not widen pairing,
room membership, decryption rights or tool permissions.

## Constraints and delivery

Apply the repository's URP principles: bounded parsing before meaning, private
constructors for verified evidence, explicit current control basis, deterministic
state transitions, and no content-to-capability conversion. Cryptographic
verification is not owner authorization. Profiles, names, bios and portraits are
untrusted presentation data. Rust `no_std + alloc` core, no new JS/TS application
or generic CRDT/identity service dependency. Reuse admitted Ed25519 and SHA-256
primitives with versioned domain separation.

The root integration owner owns this plan, shared manifests/lockfiles, CI,
generated Wordcell navigation, CLI dispatch wiring and final delivery. Workers
own disjoint modules/packages and focused validation; they do not commit. Prior
portrait changes and a reviewed non-activated native admission patch are task-owned
but paused until the social slice is integrated. Another task owns marketing;
leave its branch, site and deployment alone.

Repository `AGENTS.md` controls delivery: after focused checks, independent review
and the aggregate gate, commit/push task-owned changes and observe required GitHub
checks on the exact commit. Preserve protections; no extra human confirmation is
required. No package publication or production social activation is implied.
Use `/Users/bg/.bun/bin/oompa-host-run` in the compute lane for broad builds,
aggregate checks and native process/custody work; genuinely narrow pure checks
can run normally without bypassing an existing scheduler attempt;
use the browser-auth lane only for owned live browser evidence. One owner waits
for each CI run. Never bypass a scheduler or activation gate.

## Phase map

| Phase | Deliverable | Depends on | Write scope | Parallel with |
| --- | --- | --- | --- | --- |
| 0 | Adversarially revised contract | none | social plan, this plan | independent read-only reviews |
| 1A | Lifecycle/control counterexamples and decision | 0 | `prototypes/social-lifecycle/` | 1B, 1C |
| 1B | Convergent registers/contribution counterexamples and decision | 0 | `prototypes/social-reducer/` | 1A, 1C |
| 1C | Bounded retention/sync/crash counterexamples and decision | 0 | `prototypes/social-sync/` | 1A, 1B |
| 2 | Frozen production event/API contract | 1A–C and cross-review | root-owned types, manifests and decision ledger | none |
| 3A | Verified identity/control and durable event boundary | 2 | assigned social authentication/control modules | 3B, 3C where frozen interfaces suffice |
| 3B | Social projections and contribution invariants | 2 | assigned social reducer/projection modules | 3A, 3C |
| 3C | Bounded persistence/sync adapter | 2 | assigned store/sync package | 3A, 3B |
| 4 | CLI and end-to-end social steel thread | 3A–C | CLI social module, integration tests, usage guide | independent adversarial review |
| 5 | Exact-tree integration and delivery | 4 and fixes | CI, navigation, evidence, final commit | none |
| 6 | Resume approved portrait/reference work | 5 | existing portrait and transport reference scope | independent review |

## Phase 0: Reviewed contract

- **Status:** Done
- **Depends on:** none
- **Objective:** remove contradictory promises before selecting implementations.
- **Scope:** the social contract and this execution record.
- **Approach:** three independent adversarial slices, integration review and
  executable counterexamples for every blocking claim.
- **Acceptance:** all identified blockers have explicit semantics and a named
  spike; no wall-clock authority, unique-human count, automatic network erasure,
  unlimited-memory convergence or popularity-to-authority claim remains.
- **Validation:** manual review against the security-first plan and actual
  identity/session/ledger/crypto contracts; `git diff --check`.

## Phase 1: Decision spikes

- **Status:** Done
- **Depends on:** 0
- **Objective:** select the smallest correct lifecycle, merge and storage design
  using failing alternative models and passing adversarial schedules.
- **Scope:** the three isolated packages above; not production code.
- **Acceptance:** reproduce dual-owner-key, sibling-sequence, first-seen/expiry,
  late-revocation, equal-head collapse, deletion/revision farming, missing/foreign
  dependencies, capacity starvation, unsafe GC and premature-publication failures.
  Explicitly choose the retention horizon and recovery trust model. Report limits.
- **Validation:** for each package `P`, `cargo fmt --manifest-path P/Cargo.toml --
  --check`; `cargo test --manifest-path P/Cargo.toml --locked --offline`;
  `cargo clippy --manifest-path P/Cargo.toml --all-targets --locked --offline --
  -D warnings`. Independent workers cross-review the other package's result.

## Phase 2: Production contract

- **Status:** Done
- **Depends on:** 1
- **Objective:** freeze ownership, canonical bytes, bounded types and authority
  seams so implementation workers cannot silently disagree.
- **Scope:** root-owned shared contract, crate manifests and this decision ledger.
- **Acceptance:** exact ID/signature transcript, operation vocabulary, current
  control vs historical evidence, conflict and overflow outcomes, persistence
  publication ordering and adapter inputs are documented. Every open fork has a
  selected option backed by a spike or an explicit unavailable operation.
- **Validation:** independent interface review and compileable shared types.

## Phase 3: Maintained implementation

- **Status:** Done
- **Depends on:** 2
- **Objective:** production-owned pure social boundaries plus an isolated native
  persistence adapter, with no transport or host-policy behavior change.
- **Scope:** disjoint files assigned after Phase 2; root retains shared files.
- **Acceptance:** canonical bounded decode and strict signatures; stable owner
  and owner-bound agent identities; scoped grants and terminal retirement;
  control fork/recovery and exact history semantics; all requested social views;
  one reaction/follow per owner; deterministic partition merge; no deletion or
  revision endorsement laundering; partial states visible; crash-safe persistence
  with bounded restore and no unverified state admission. Bounds apply in release
  builds, not only assertions. Malicious text never becomes a host effect.
- **Validation:** each worker runs focused unit/property/integration tests and
  Clippy for owned packages, records the exact tree/commands and reports review
  fixes. Add compile-fail tests at real trust boundaries and golden wire vectors.
  Root adds the new pure packages to the WASM check.

## Phase 4: Usable steel thread

- **Status:** Done
- **Depends on:** 3
- **Objective:** demonstrate every requested social feature across signed bytes,
  verified control, reducer, persistence and presentation.
- **Scope:** local experimental CLI/API path and integration tests/guide.
- **Acceptance:** two owners and multiple agents create bios, profile/channel
  posts, threaded replies, reposts/quotes, follows and revision-bound votes;
  partition, conflict and resolve; retire/revoke without erasing committed history;
  restart persisted state; reject forged scope/ownership and render hostile content inert;
  exports/imports converge by content ID and display explicit incomplete state.
  Default network/host capabilities stay unchanged. No automatic public posting.
- **Validation:** executable CLI process tests plus deterministic transport
  schedules, snapshot corruption/crash tests, property tests and a recorded
  end-to-end run. A compile check alone cannot claim browser runtime qualification.

## Phase 5: Integrate and deliver

- **Status:** Local admission complete; exact-commit GitHub checks gate delivery
- **Depends on:** 4 plus independent review fixes
- **Objective:** deliver only a validated, accurately documented integration.
- **Scope:** root-owned navigation, aggregate gates, dependency evidence and commit.
- **Acceptance:** Wordcell refresh/check, exact-tree aggregate Rust gate,
  pure-crate WASM checks, current dependency admission, independent final review,
  clean task-owned commit and exact-SHA required GitHub checks. Document residual
  operational limits without labelling the whole product ready.
- **Validation:** existing repository gate: workspace fmt, all-target/all-feature
  tests, doctests, default CLI identity tests, Clippy `-D warnings`; every top-level
  prototype fmt/tests/Clippy; native checkpoint-store feature checks; nested browser
  interop checks; portrait XML/golden checks; `git diff HEAD --check`. Extend the
  existing CI pure-WASM command for newly maintained pure crates and new spikes.
  Integration owner runs the aggregate only after convergence.

## Phase 6: Resume portraits and admission reference

- **Status:** Done for reference retention and gallery review; live promotion remains gated
- **Depends on:** 5
- **Objective:** complete the previously approved task-owned portrait prototype
  and retain reviewed transport admission evidence without activating the patch.
- **Acceptance:** portrait limitations and recognition evidence accurately recorded;
  source/output gallery synchronized; focused changes revalidated and independently
  reviewed; native patch provenance/reproduction preserved; required delivery gates.
- **Validation:** use the existing portrait/native evidence and repeat only changed
  inputs, plus the required final integration gate.

## Decision ledger

| Fork | Selected behavior | Executable evidence |
| --- | --- | --- |
| Identity/revocation | Owner-bound genesis, exact hash closure, terminal lifecycle, late-view rebuild | lifecycle: 14 tests + 2 compile-fail examples; missing-seal-history review regression added |
| Recovery | Dual-signed planned rotation; automatic recovery explicitly disabled | byte-identical legitimate/backdated history counterexample |
| Social conflicts | Preserve all causal heads; clear/unfollow wins; revision-specific reactions | reducer: 12 tests including independent graph oracle |
| Capital eligibility | Explicit local eligible-owner set, committed immutable cohort, per-owner cap | 1,000 observed accounts → 0 eligible score → 1 selected account score |
| Retention | Complete bounded signed archive, no GC; forward candidates preserve every prior ID | sync: 13 tests including unsafe deletion/CAS counterexamples |
| Partial state | Semantic basis excludes transient reception telemetry; missing closure remains visible | e3,e4,e2-rejected,e1,e2-retried converges with ordered history |
| Control liveness | Separate control/dependency delivery slots and storage reserve | rejected-data paging starvation regression |
| Private publication | Explicitly unavailable until encryption/membership adapter qualification | public-only production record vocabulary; label equality is not privacy |

Prototype results select architecture; they do not establish production readiness.

## Implementation log


- 2026-09-13, Phase 0: three independent reviewers found and root corrected
  owner-key binding ambiguity, expiry/backdating and terminal-lifecycle ambiguity,
  equal-head loss, deletion/retirement score laundering, revision endorsement
  theft, and audience/placement confusion. The revised contract assigns bounded
  storage/recovery questions to Phase 1. No implementation or readiness claim.
- 2026-09-13, Phase 1: disjoint lifecycle, reducer and sync workers dispatched;
  root owns synthesis and the later aggregate gate. Focused evidence pending.

- 2026-09-13, Phase 1 join: three independently checked spike packages passed
  39 unit/property tests plus two compile-fail examples before the final added
  missing-sealed-history regression. Cross-review corrected arrival-dependent
  state, control delivery starvation, forward-generation history deletion,
  unbounded repeated DAG traversal, and missing-cohort completeness. Exact command
  evidence is retained in each prototype README and worker reports.
- 2026-09-13, Phase 2: froze `model.rs`, the domain-separated canonical wire API,
  and borrowed control/projection interfaces. `cargo check -p vhalla-social
  --offline` passed against the complete initial module skeletons. The new crate
  reuses existing locked Ed25519/SHA-256 dependencies; no new third-party package.
  Root owns model/wire/manifests; lifecycle worker owns control.rs; projection
  worker owns view.rs; storage worker owns archive.rs. Scope-tagged control
  commitments preserve global control replication without requiring unrelated
  realm plaintext. Signature facts remain separate from social authorization.
- 2026-09-13, Phase 3: implementation workers adding independent signed integration
  and property tests. No final gate, CLI delivery or production activation yet.

- 2026-09-13, Phase 3 join: maintained `vhalla-social` implements the signed
  protocol, borrowed control/projection views and complete archive. Independent
  signed tests cover controller forks, all social registers and historical
  contribution. `vhalla-social-store` implements exact-intent Unix publication,
  lifetime locking, monotonic history, bounded physical-copy reclamation and
  explicit recovery; 12 focused tests include 13 injected publication boundaries
  and a real subprocess lock test. Independent native source review found no
  blocker within its documented owner-controlled filesystem assumptions.
- 2026-09-13, adversarial resource join: two independent failing cases showed
  that quota exhaustion or staged-record reclassification could reject a valid
  revocation while preserving live authority. The repaired accounting retains
  bounded staging credit and derives capacity closure from the complete set.
  Structural control proof work is separate from history work. Both original
  regressions, 13 control tests and 14 archive tests pass. Per-owner versus global
  capacity status is explicit; committed history remains retained. All seven
  resource limits now contribute to the evaluation digest; 14 view tests pass.
- 2026-09-13, Phase 4: the optional local social CLI implements every selected
  operation, explicit scoped grant selection, owner atomic seal, ASCII JSON,
  bounded file exchange and recovery. Four enabled subprocess workflows and
  default-feature absence passed before the final file-open review fix. Review
  caught an import FIFO race; safe nonblocking/no-follow descriptor opening and
  descriptor metadata checks replace pathname-only assumptions. Additional
  pending-intent and path regressions precede the integration gate.
- 2026-09-13, cross-layer boundary: two new steel-thread tests pass through real
  pure paired-session handshakes, reordered social records, fresh-session replay
  rejection and content-ID deduplication. The outer relay key differs from the
  inner owner key. A signed chat wrapper cannot validate an inner forgery or enter
  the host-effect kind. A compiler test rejects passing social `VerifiedRecord`
  to `RemoteRequest::from_verified`; a native custodian test passes exact-primary
  and acknowledgement-key rejection without exporting private keys.
- 2026-09-13, portability: the maintained social crate, all three social spikes
  and portrait library compile for `wasm32-unknown-unknown` using the retained
  official Rust 1.97.1 compiler/sysroot. The initial Homebrew-only attempt lacked
  the target and failed; using the already installed WASM toolchain resolved it.
  Portrait release tests pass. These are compile/native results, not a claim of
  social browser runtime, cross-target byte parity or embedded performance.
- 2026-09-13, portrait/reference continuation: integration preparation overlaps
  final social validation to avoid a second full repository build. The gallery
  now records compact grayscale family collisions separately from full SVG
  diversity; release-active atom/output assertions protect the fixed grammar.
  Actual browser review at desktop and 390px mobile checked dark/light/grayscale
  and 16/24/32/64px presentation. Layout wraps correctly; tiny family cues remain
  weak and human recognition is still a promotion gate. The temporary tab/server
  and viewport override were cleaned up. No maintained portrait or WebRTC patch
  activation is implied.

- 2026-09-13, integration provenance: the exact `intro.rs` source and bounded
  interactive root-help guard from independently reviewed checkpoint
  `af7ebd5d3ed442a9f63aefac962e1a85a387cd59` (0thernet, “Add compact Vhalla identity
  intro to interactive help”) were incorporated while preserving social dispatch
  and the 64-argument bound. Its original PTY/pipe evidence is retained by that
  task; this integration runs the complete current CLI gate. Marketing remains
  in the separate site worktree.
- 2026-09-13, final acceptance pass: added a bounded owner timeline query so a
  profile can enumerate its reposts without already knowing target IDs. It
  preserves exact reviewed revision references and original attribution; it
  adds no storage, remote subscription or chronological consensus rule. Final
  timeline review/tests are required before the aggregate gate.

## Integration evidence — 2026-09-13

The bounded implementation is complete. Independent review approved the final
source and signed timeline tests after correcting the revocation/quota failures,
missing-history and committed-cohort errors, native import FIFO race and stale
design wording. The final owner timeline discovers profile posts/replies and
reposts by owner ID alone, preserving exact source revisions, attribution,
conflicts, missing context, and stable pagination. No public networking, private
social publication, automatic controller recovery or economic authority is enabled.

The local aggregate completed **119 commands**, all passing: workspace formatting,
**166 workspace tests**, **15 doc/compiler-boundary tests**, strict all-feature
Clippy, default CLI identity/social isolation, all top-level prototype checks,
native checkpoint persistence, nested browser fixture checks, portrait generation
and XML/goldens, 11 retained-reference integrity hashes, complete lock audit and
Wordcell validation. The final social source also passed the WASM compile after
timeline integration. The release portrait test and native custodian check passed
separately. A literal two-owner README walkthrough produced two thread posts,
one committed follower and eligible appreciation of one; its owned fixture was
removed after verification. The extra CLI recovery fixture uses independently
encoded exact signed intent and proves blocked operations, exact recovery, and
valid subsequent history. It is included in the passing aggregate.

`cargo-audit 0.22.2` checked **37 lockfiles** against RustSec database commit
`b50980aad8b8f14f77e25a97b32dd94bf008b0af`: zero vulnerabilities. The existing
`paste 1.0.15` / `RUSTSEC-2024-0436` maintenance advisory remains in the network
workspace/interop dependency graph, including the retained transport fixture;
no social dependency introduces it. No new third-party package version was added
to the workspace lock. Optional Unix `libc` is used only for safe descriptor-open
flags; JSON parsing and SHA-256 in CLI tests are dev-only existing dependencies.

The managed repository baseline is current for Oompa local efficiency 0.4.6.
Wordcell percolation was inspected, meaningful prose links were retained, and
refresh/check passes; its one historical contextual-orphan advisory is unrelated
to the new social plans. The commit containing this record carries the delivery
SHA; its exact GitHub Rust/security checks are the final remote delivery gate.
No release, migration, website deployment or risky adapter activation belongs to
this source delivery. Runtime browser parity, embedded memory/latency,
large-population portrait recognition and public transport remain separately
listed promotion work, not hidden completed claims.

The staged-diff check exposed mandatory single-space blank context lines inside
the immutable native repair patch. A path-specific `.gitattributes` setting
disables only end-of-line whitespace checking for that one hash-verified patch;
all other whitespace rules and source paths remain checked. Artifact integrity
continues to verify its exact original SHA-256, rather than rewriting the patch.
