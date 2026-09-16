# vhalla-botcaptcha

Botcaptcha witness mode over [`vhalla-witness`](../vhalla-witness/README.md):
the signed challenge and response, the verified challenge that is this crate's
only source of run capabilities and receipt bindings, the one-use window, and
the verifier that replays a witness and admits it once.

Read the [witness platform plan](../../kb/plans/valhalla-witness-platform.md)
for the design and the [games plan](../../kb/plans/valhalla-botcaptcha-ledger-games.md)
for the field names this crate keeps verbatim.

## What a valid witness proves

`WitnessVerifier::verify_response` re-derives every fact before it admits:
issuer signature and context, time window, manifest identity, subject
signature, the response's binding to the challenge, the candidate programs,
a full replay under a fresh capability, a bit-exact receipt comparison, the
work contract, and finally one-use consumption keyed by the dedup scope
`issuer_key || challenge_id || subject_key`. A `VerifiedWitness` therefore
proves that this subject key produced bounded, replayable work on this task for
this challenge, once.

It proves nothing else. It is never identity, personhood, safety, or host
authority; it cannot enter `RemoteRequest::from_verified`; and it may only
remove a rate limit, award a badge by its reward digest, or qualify an event for
a game session under a policy that decides those things separately.

## Boundaries

- `no_std` plus `alloc`; dependencies are `ed25519-dalek`, `sha2`,
  `vhalla-core`, and `vhalla-witness`.
- The clock and entropy are injected: `ChallengeIssuer::issue` takes
  `entropy` and `now`, and every verifier call takes `now`.
- The one-use window is volatile. A restarted verifier restores it durably or
  starts with a fresh `started_at`, which refuses every earlier challenge. Two
  verifier instances sharing an issuer key need a shared durable ledger, which
  is outside this crate.
- Nothing executes network-supplied code; programs are data interpreted by
  `vhalla-witness` under its static bounds and the verifier's allowance.
- Hashcash mode is reserved (`Algorithm::Hashcash`) and not implemented here.
