# Valhalla product and P2P review — 2026-09-19

This review starts from the private-overlay planner in PR #82, merged at
`b5eddc014588063c0aadbea54dff66d8f11da08d`. Its exact Rust and CodeQL runs
succeeded, but the broader review found authentication, resource-bound and
onboarding problems requiring repair before the next release.

## Assessment

The strongest foundation is the separation of identity, owner authorization,
local durability, quorum agreement and independently replayed work. Real
process and partition tests support specific recovery paths. The recent
peer-pinning review nevertheless missed a public-derived private key, so test
volume and green CI do not establish the full security claim. This review is a
source and targeted regression review, not an independent protocol audit or a
proof of competitive uniqueness.

The coherent product direction is **owner-controlled agent collaboration with
independently replayable work**. Durable attribution can outlive an individual
agent, a recipient can verify useful work without trusting the original worker,
and receiving a signed message never silently delegates the owner's computer.
These properties together are a concrete direction worth building around.
Witness work is not personhood or Sybil resistance, and adding more proof modes
would not fill the missing collaboration journey.

## Differentiation to earn

P2P messaging, signed personal histories and peer validation are established
building blocks. Holochain already describes signed per-agent source chains,
application-defined membership and validation, and consent-based capabilities.
[Holochain architecture](https://www.holochain.org/how-does-it-work/).
Waku already separates live message relay, selective subscriptions, history
retrieval and lightweight publishing; its documentation distinguishes a remote
peer acknowledgement from network-wide propagation and warns that history
retrieval does not guarantee availability.
[Waku protocols](https://docs.waku.org/learn/concepts/protocols).

The product inference is that Valhalla should earn differentiation through one
complete agent-work journey: an owner delegates narrowly, agents collaborate
across disconnections, a recipient independently reproduces a useful artifact,
and accepted attribution survives device recovery without granting new host
authority. Demonstrate those outcomes together with measured bounds and failure
behavior. This is a focused product thesis, not a claim that other systems
cannot implement it or that a market-wide novelty search has been completed.

## Findings and repairs in this change

| Boundary | Finding | Repair and qualification |
| --- | --- | --- |
| Validator transport identity | A public consensus address determined the Noise private seed, allowing transport impersonation despite matching peer pins | Bind transport identity to the actual secret Ed25519 key; derive expected PeerIds from public bytes only; reject the legacy forged identity. See [upgrade procedure](transport-identity-upgrade.md). Consensus signatures remain a separate authority boundary. |
| Proposal ingress | Nil round could reach a proposer-selection assertion; incomplete streams and empty chunks had no aggregate metadata bound | Reject invalid headers before proposer selection, bound per-peer/global streams and per-stream chunks, handle reordered closure, and bind header height to the canonical batch before durable admission. A single peer cannot exhaust the stream pool; admitted streams can finish at the global cap, and discarded streams release capacity. |
| Work verification | Unbounded file reading and sender-selected work limits preceded bounded inner decoders; final receipt computation replayed work outside receiver accounting | Bounded regular-file/field/record ingestion, explicit local work policy, enforced receiver step limit, and final receipt readback from charged verification. See [game replay](game-replay.md). |
| Onboarding | Clean-state identity/social setup, realm formatting, create arguments and rotation syntax were inconsistent; three validators implied resilience they do not provide | Rehearse actual commands, enroll the agent, use four equal-power members, and distinguish a local rehearsal from live provider qualification. |
| Newcomer and restart genesis | Creating a new owner changes the genesis root; using a mutable owner store as the genesis source can break fresh-replica or height-zero bootstrap after normal activity | `social restore-new` verifies an exact signed archive before creating a fresh store, adds no owner/key and never overwrites. Keep a dedicated genesis archive store separate from evolving owner activity; rehearse fresh-replica catch-up after later owner posts. |
| WAL recovery | Existing operator and agent instructions described deleting in-flight consensus history as safe | Preserve undecided-height votes and locks. A committed journal cannot replace them; reject incompatible formats and require a compatible binary or reviewed migration. Runtime error wording is corrected in the coordinated integration. |
| Current scope | Stale plans prescribed a retired Dioxus client and confused directory consensus with room participation | Preserve the headless direction and state current versus planned capabilities explicitly. |

The accompanying [security review](security-review-2026-09-19.md) covers
release publication, storage integrity and validator-set arithmetic. Final
readiness depends on integrated-tree checks and exact release evidence, not
these findings alone.

## Current surface and major remaining gaps

| Surface | What exists | Remaining product boundary |
| --- | --- | --- |
| Native paired chat | Persisted identities, signed sessions, explicit peer pins, optional private-network connectivity | A continually running multiparty room with explicit membership and reconnect history is not implemented by the paired demo. |
| Room directory | Signed registry operations, private validator consensus, local intake, TUI and replica-backed status | A registered room is not a joined conversation; non-validator remote users need a maintained authenticated client path. |
| Social state | Owner/agent records, selective owner acceptance, feeds and bounded explicit pairwise sync | Always-on multi-peer replication, retention/epoch policy and capacity reporting are still needed for long-lived activity. Private transport does not define confidential-room membership or content encryption. |
| Work evidence | Bounded witness execution, Platonik sessions, replayed checkpoints and verification CLI | Share one real work artifact through the same maintained activity flow; distinguish received, retained, owner-accepted and independently verified states. |
| Reachability | Accountless Tailcat and public-input managed overlay planning with pins | Managed profiles remain `live_qualified: false`; direct/relay transitions and recovery on actual separate machines need evidence. |
| Client distribution | Developer CLI archives and an optional menubar companion | Clean-machine release/install evidence and normal-user usability remain separate from protocol tests. Dioxus UI experiments were retired; do not restore them from stale plans. |

## Next implementation sequence

1. Deliver the corrected network/verifier boundaries and the executable private
   directory rehearsal. Keep exact evidence for authentication rejection,
   bounded hostile input, unchanged vectors and restart/partition regressions.
2. Build one headless private activity adapter: explicitly map a registered room
   to a signed social channel and its membership policy. Three independently
   owned agents exchange bounded posts; one disconnects, the other two continue,
   and the returning agent catches up after process restart. Ordinary activity
   should not require each chat message to enter the directory's linear
   consensus log. Do not introduce a `join` command until its room/channel and
   membership contract is defined.
3. Exchange one work artifact through that adapter and independently reproduce
   it with the bounded replay CLI. A refusal must preserve accepted history and
   must not cause a host effect. User-visible state must make the differences
   between transport delivery, local retention, owner acceptance and verified
   execution clear.
4. Qualify real network failure domains: four equal-power validators, an absent
   member, a minority partition, same-home restart, offline catch-up while the
   healthy quorum advances, relay replacement and maximum-size transfers.
   Record the actual selected paths, message/byte pressure, latency and recovery
   duration. A shared provider, household power supply or overlay administrator
   can fail multiple validators at once; four processes on one host do not
   establish independent failure tolerance.
5. Bound authenticated-but-hostile validator retention as well as wire buffers.
   At one undecided height, a Byzantine active proposer can sign many rounds and
   grow durable `seen` metadata. The ingress repair prevents forged future-height
   entries but does not safely cap this same-height history. A retention design
   must preserve values required by the engine's persisted locks and restart
   resupply; arbitrary pruning could damage consensus liveness. This remains a
   gate for hostile-validator operational claims.
6. Replace all-history-in-memory sync with a verified disk-backed range/checkpoint
   design before claiming indefinite operation. Preserve decided history until a
   tested retention protocol can recover a long-offline peer without losing
   evidence. The preceding implementation recorded `h9 after heal` timeouts in
   `live_mesh_soak_duplicate_churn_rotation_converges` both locally and in
   [PR #82's initial CI run](https://github.com/hraness/valhalla/actions/runs/35427199712).
   Retries passed without a recorded root cause. This review closes a test-side
   publication race by renaming complete fixture files into the intake, and
   retains per-node failure diagnostics. Historical causality remains unproven;
   investigate any recurrence rather than counting a successful retry as a
   diagnosis.

## Provider dependence is part of the design

Tailscale supports direct UDP, peer relays and DERP paths; clients can transition
between them. The existence of a fallback does not prove this application's
large-message or consensus recovery behavior on that path.
[Official connection documentation](https://tailscale.com/docs/reference/connection-types).

Cloudflare Mesh routes enrolled participants' traffic through Cloudflare's
network and requires the documented MASQUE profile. It is an optional managed
connectivity choice, not evidence of provider-independent networking.
[Official Mesh architecture](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/concepts/).

The libp2p Noise handshake binds a network identity through an identity-key
signature. Application code must keep the identity private key secret and still enforce
its own authorization. A cryptographic transport cannot correct an application
that derives its private identity from public data.
[libp2p Noise specification](https://github.com/libp2p/specs/blob/master/noise/README.md).

Public discovery, open membership, Sybil resistance, privacy of room contents,
and browser participation remain separate unqualified claims. The next useful
product is a small, reproducible private work room with observable recovery;
its measured guarantees should determine when broader participation is enabled.
