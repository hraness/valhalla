# Owner / agent lifecycle spike

Disposable pure Rust model for vhalla (valhalla), excluded from the maintained
workspace. No wire parser, network, private publication, storage, account recovery
activation, or host effects. It uses real Ed25519 strict signatures and SHA-256,
with fixed synthetic test keys, `no_std + alloc`, and no unsafe code.

## Decisions falsified or supported

* **One key does not prove one owner.** Two jointly signed bindings reuse an
  agent key with different owners. Hashing owner-bound immutable genesis plus
  incarnation nonce produces distinct `AgentId`s and immutable attribution.
* **Sequence cutoffs are insufficient.** A signed sibling with equal sequence
  passes the abandoned `sequence <= cutoff` predicate. Exact scoped hash ancestry
  excludes it. Each accepted post must match owner, agent, grant and public-realm
  scope, with a complete authenticated prefix. Missing dependencies remain pending.
* **Historical evidence and current eligibility differ.** Owner seals commit an
  exact accepted history of all scoped social operations, including follows and
  reactions. The contribution cohort is only the post/revision subset of that
  history. Unsealed messages and preferences are provisional. Claimed timestamps
  never establish historical eligibility. Current grants use a supplied evaluation
  time; expiry/revocation/retirement do not delete sealed historical evidence.
  Selective commitment still permits selection bias; this is not a claim about all
  work an owner or its agents ever produced.
  Missing sealed heads/ancestors set a separate `history_incomplete` flag, even
  while current grant authority remains complete. A missing cohort is never
  presented as complete zero contribution.
* **Owner preferences outlive ephemeral delegates.** Sealed follows and reactions
  remain authenticated owner-state inputs after agent expiry, grant revocation or
  incarnation retirement. A newly enrolled delegate can explicitly supersede those
  exact retained operations. Its grant-local stream starts again at sequence zero;
  owner-register causality is carried separately in the signed payload. The test
  proves lifecycle retention and the signed cross-incarnation references; actual
  register conflict/reduction semantics remain the independent reducer's concern.
* **Grant revocation and incarnation retirement differ.** A revoked grant cannot
  return. A new explicit grant may renew an active incarnation; retirement prevents
  new grants to that incarnation. Replayed records never reopen authority.
* **Owner control is hash linked.** A valid rotation needs old-controller signature
  and new-key acknowledgement. Descendants require the new controller. Competing
  valid children freeze current projections. All authenticated control branches
  retain historical commitment evidence; a fork makes its current interpretation
  disputed rather than deleting evidence. This distinction needs UI review.
* **Admission is checked against current state.** Private, non-clone admission
  tokens carry a snapshot marker and grant ID; every recheck reconstructs current
  eligibility. A later fork/revocation invalidates cached use.
* **Recovery evidence needs declared authority.** A separate signed recovery transcript
  binds the owner, exact selected frontier and new key. No recovery key means no
  implicit fallback. Signature-valid recovery evidence still cannot activate
  recovery in the chosen public-v1 contract; `activate_recovery` always returns
  `RecoveryDisabled` without mutating control, retirement or cohort state.

## Resolved v1 recovery fork: planned rotation only

Choose explicit unavailability over an implicit newest-epoch or first-seen rule.
Planned rotation requires both controllers; an unresolved valid control fork
remains frozen. Key loss has no network recovery in v1. An offline predeclared
recovery key is tested as evidence in this prototype, not an activated v1 feature.

The executable counterexample constructs two observationally identical cases:
legitimate owner/agent records signed before compromise but withheld, and new
records forged after compromise using the old keys and backdated claimed times.
The exact payload IDs and deterministic signatures are identical. Retaining all
old-key commitments admits both cases; accepting only a named known cutoff drops
both unseen cases. An algorithm given those same authenticated inputs cannot
recover their actual creation time. Merely adding a hash-linked recovery stream
does not supply the missing historical witness.

A future recovery version must explicitly choose a trusted cutoff/witness and
state the loss of automatic attribution for legitimate unseen work. Alternatively
it can retain ambiguous historical evidence while quarantining its interpretation.
It must separately specify how an independently signed recovery stream supersedes
old controllers/grants, resolves its own forks, preserves already committed
evidence and survives rollback. Those promises are not smuggled into v1.

## Bounds and limitations

Each fact collection has a 64-object cap and each seal at most eight sorted,
unique heads. The model performs bounded history traversal; limits are experimental,
not production memory/performance budgets. Controls with missing predecessors or
invalid signatures cannot select authority. Signature variants are retained so an
invalid signature cannot poison a later valid payload ID. Capacity exhaustion is
explicit. There is no peer admission/fairness policy, compaction or DoS qualification.

The `scope` digest represents a **public realm** in this model. It is not encryption
or proof of private membership. Private publication/import must remain disabled
until separate privacy adapters are qualified. Owner genesis is supplied local
configuration; validating account discovery/pins is outside this experiment.

Bindings commit the exact owner control head used for first enrollment. After a
rotation, only the new controller can sign a new binding at that head; stale-head
and old-controller bindings cannot obtain a first grant. Later grants to an
already enrolled active incarnation retain its immutable original binding.
Control action schema parsing/canonical wire vectors, full recovery application,
storage rollback resistance, prospective retraction/revision cohorts, and a model
oracle independent of the Rust implementation remain promotion gates. Neither
`View` nor `Admission` converts into a host capability.
The typed follow/reaction payload fixtures have no production schema validator;
operation-specific grant capabilities and register parent/target checks belong
to the future adapter join, not the public-realm digest alone.

## Focused checks

Run via the installed host scheduler, using the full manifest path:

```text
cargo fmt --manifest-path prototypes/social-lifecycle/Cargo.toml --check
cargo test --manifest-path prototypes/social-lifecycle/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/social-lifecycle/Cargo.toml --all-targets --locked --offline -- -D warnings
```

The generated test permutes controls, duplicates delivery and varies evaluation
time. Regression tests exercise equal-sequence forks, wrong scopes/signers,
invalid-signature poisoning, late dependencies, monotonic sealed evidence,
renew/revoke/retire replay, controller rotation and cached admission after forks.
Semantic-invalid control actions are excluded before detecting forks; missing
binding dependencies produce an explicit incomplete view and prevent current
admission until resolved. Compile-fail doctests fence admission fabrication and
cloning.
