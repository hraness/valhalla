# Bounded retrieval model and native fixture

The throwaway S5 model for vhalla (valhalla) lets a chosen provider return sorted exact
post/revision IDs, never trusted snippets, scores, actor claims or a completeness
flag. Four providers may each contribute one response of at most 32 hints / 2,053
bytes. Errors, timeouts and duplicate hints consume attempts or work. Input frame
bounds must also be enforced by the eventual transport before allocation.

Six unit/property tests establish codec bounds, canonical order, deterministic
deduplication, termination after malformed responses, and separation of candidate
fetch credit from control credit. The poisoned-reference test uses a model local
set: it is **not** proof of signature or social/control verification. The model
itself implements no transport, network timeout or maintained-archive fairness;
the separate native fixture below exercises the maintained protocol.

Decision: use a bounded optional candidate adapter, then hydrate candidates through
ordinary signed archive exchange and reapply the current local query. Peer omission
means unknown coverage, even after every selected peer has responded. Retry is a
new explicit bounded round. Never automatically dial an endpoint returned in a
hint. Search responses have no authority to schedule tools, subscribe or read
private preferences. Private queries disclose their text to selected providers.

The existing social archive already exchanges control/dependency closure with
separate reserves. Preserve that route instead of writing an ad hoc search-record
importer. D6 must test actual paired transport, invalid signatures and late control;
this model cannot qualify a public service. A capped archive is not an unrestricted
set-union CRDT: convergence requires delivery of the same evidence within the
declared resource policy. A peer cannot prove it returned every matching post.

The original pure model's six tests passed before the native fixture was added.
Its library still has no runtime dependencies.

## Actual paired native fixture

`tests/native.rs` uses the maintained `vhalla-retrieval` protocol over the existing
`vhalla-native::Listener` and `send_message` adapter. Two OS-generated application
identities occupy separate mode-0700 temporary directories. Each transfer opens a
fresh loopback QUIC connection and paired signed session with exact full-key pins.
The receiver keeps polling until the sender has its signed transport acknowledgment;
dropping both endpoints releases sockets and identity locks before fixture cleanup.
The request nonce comes from OS entropy. No new transport or public listener is
implemented here. Both endpoints run within one test process; this fixture does
not independently qualify process restart behavior.

The fixture sends actual request/response bytes through those sessions and checks:

- request peer and outer-room mismatch, plus a response request-nonce mismatch,
  cannot mutate the local archive;
- an authenticated malicious response with a poisoned exact hint and corrupted
  inner signature reaches ordinary bounded archive ingestion and cannot produce
  an authored search result;
- subsequent valid pages hydrate owner/agent/control closure and the exact signed
  faceted post, retaining duplicate/failure accounting;
- local owner filters still apply after hydration; poisoned IDs remain unresolved
  and network completeness remains false;
- a late provisional writer event becomes rejected after a subsequently delivered
  owner revocation, while previously sealed history remains queryable and no
  canonical evidence is erased.

Public deterministic seeds sign only the social test corpus. Actual paired
transport identities and request nonce use OS entropy. The original model's
four-peer fairness properties and this one-provider loopback fixture prove
different things; neither establishes public-network availability, honest
providers, browser transport or indefinite archive capacity.

```sh
/Users/bg/.bun/bin/hra-host-run --mode=shared --lane=compute --label=valhalla-retrieval-native-fixture -- /bin/sh /Users/bg/Documents/Codex/valhalla/prototypes/social-retrieval/verify-native.sh
```

`verify-native.sh` runs standalone formatting, the six pure tests plus the actual
native test, and strict all-target Clippy. Unix-only dev dependencies reuse versions
already present in the maintained workspace lock; product dependencies stay empty.

Qualification: independently reviewed source passed the scheduled `verify-native.sh`
on 2026-09-13 (Darwin arm64, Rust 1.97.1): six pure tests, the actual paired native
test (0.69 seconds), formatting and strict all-target Clippy. The native test uses
real loopback sockets and signed session acknowledgments; this receipt does not
qualify public routing, browser transport or multi-process restart behavior.
