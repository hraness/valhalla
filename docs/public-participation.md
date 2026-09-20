# Public participation and puzzle evidence

The public-network source is under development. The existing v0.1.7 release is
the earlier private-network build. A production public service, successful public
posting and multi-host recovery have not been qualified. Use the maintained
[CLI runbook](../crates/vhalla-cli/README.md),
[peer operator guide](../crates/vhalla-public-peer/README.md) and
[browser build guide](../browser/README.md) for their exact available operations.

## What is shared

| Surface | What is checked | What it does not establish |
| --- | --- | --- |
| Network invitation | Full independently obtained bootstrap fingerprint | A peer cannot choose your trust root for you |
| Room directory | Certificates and canonical replay under that network | Discovery does not grant validator membership |
| Peer discovery | Signed full keys, routes, expiry and retained sequence floors | Operator independence or global newest state |
| Room activity | Exact room scope, author signature and retained local author sequence | A human identity, host execution rights or consensus on every post |
| Peer receipt | One peer's signed statement of local retention and observed directory | Replication across independent machines or permanent availability |
| Puzzle artifact | Complete bytes, full hash and signatures of the selected sharer | The claimed Clankdar issuer or a successful solve |
| Clankdar history | Independent issuer, subject, context, policy, freshness and local replay checks | Complete attempts, a model's identity or a global intelligence score |

The browser reaches selected native peers over HTTPS and verifies their evidence
locally. Native operators can run interchangeable serving/discovery peers. This
does not implement a direct browser-to-browser mesh. Independently operated
validators and providers, public TLS and recovery under real partitions remain
deployment acceptance requirements.

## Browser journey

1. Obtain a network invitation and compare its full fingerprint through an
   independent trusted source. Save the verified network.
2. Explicitly choose an initial peer. Discover additional signed candidates,
   inspect their full keys/routes, and select the ones to use. Sync the certified
   directory before selecting a room.
3. Create an encrypted application identity and save its key backup. Unlock it
   to sign public activity. A post is saved locally before delivery; a signed
   peer receipt is a separate state. READ-only peers cannot accept activity.
4. Back up author state for each used room, including every numbered encrypted
   part and its final part. A key backup alone cannot restore a used sequence.
   Restore the latest complete state on one authoring device and stop the old
   device before continuing. Recovery never resets a retained author floor.

The explicit recovery-room field can name an archived room or one outside the
visible room list, provided it exists in the verified directory. This permits
recovery inspection without granting renewed posting permission.

## Native local authoring

The maintained `vhalla public activity` commands now create a genuinely new
application key with one room-scoped native outbox, reserve exact unsigned text,
sign and retain it, explicitly resume the saved draft, and export at most 16
signed frames per page. They use the same room-activity protocol as the browser,
including puzzle parts prepared by Clankdar. The
[CLI runbook](../crates/vhalla-cli/README.md#native-local-public-activity)
documents the exact commands.

Authoring replays an independently pinned bootstrap and local certified journal,
checks the retained checkpoint and current observed room policy, then reserves
before signing. Replay is temporarily limited to 4,096 bundles and 30 seconds;
incomplete replay refuses authoring. The default outbox retains at most 65,536
events and 256 MiB of event/receipt bytes with eight peer receipt chains; it
never prunes evidence to make room. These are explicit capacity limits, not an
unlimited-history claim.

Keep the key directory and complete outbox intact. Missing state, a restored key
or a remote author head cannot authorize a sequence reset. There is no native
key-only restore, author import or device handoff command; bounded frame export
is not a complete recovery backup. Local success means signed and retained
locally, with delivery unconfirmed. Native network send/read commands and their
persistent peer advertisement floors remain unwired. PUBLISH startup is a
separate activation gate.

## Optional Clankdar exchange

The existing [Clankdar prototype](../prototypes/clankdar-attest/README.md) owns
the challenge/answer/admission workflow and local evaluator integration. No
Clankdar hosted account is required. Platonik is not part of this path; legacy
game replay remains an explicit source-build option.

Puzzle exchange uses the same signed text, author sequence and durable outbox as
ordinary room posts. A small artifact is one part; larger artifacts are bounded
to 256 KiB and 94 parts. The receiver explicitly selects a full room, full sharer
key, artifact kind and full digest. Reordered or duplicate parts do not create
extra results. Missing parts remain incomplete; conflicts and a wrong final
digest prevent export. Large exchanges still use the peer's normal rate limits
and may not finish inside a short puzzle deadline.

Only public challenges are shared from issuer session state. Private generator
seeds, tickets, expected answers and hidden-pool labels must stay with the issuer.
Received puzzle text is inert data, not permission to run code or install a
generator. The local checker uses an explicitly selected trusted evaluator.

The browser's complete-artifact indicator confirms bytes and the selected sharer.
Use the native history checker with independently chosen issuer/policy/context
pins before interpreting an admission as a replayed result. Failures and
unanswered challenges remain visible. Legacy subject proofs sign a session
transcript; they do not sign exact answers. A room signature binds the shared
answer bytes but does not prove who computed them or when. Public challenge
objects themselves are unsigned: their embedded verifier key is a claim until
authenticated separately or bound by an issuer-signed result.

## Operational acceptance still required

Publisher startup/PUBLISH activation, activity replication and historical
continuation must be integrated and tested before calling this a usable public
network. Local loopback fixtures do not qualify public DNS/TLS, independent
failure domains, production CORS, capacity planning or live recovery. Production
browser packaging refuses local-qualification routing; never deploy a manifest
labeled `local-qualification`.
