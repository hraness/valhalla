# CodeQL source review — 22 September 2026

The saved PR #85 alert set contains **364 distinct open alerts across 60 files**:
363 `rust/hard-coded-cryptographic-value` (security severity critical) and one
`rust/cleartext-logging` (high). Source review found no confirmed exploitable
vulnerability in these reported locations: 356 alerts concern deliberately
synthetic test/fixture inputs; eight are data-flow false positives described
below. This is a source-triage conclusion, not a green CodeQL gate, an alert
dismissal, or a complete security audit.

The execution-boundary split is 344 alerts in test-only modules/targets
(including the logging alert), 14 in explicit examples/qualification fixtures,
and six in production paths. No classification remains unresolved for the
saved locations. This conclusion does not qualify examples for production use.

## Scope and reproducibility

- All alert instances identify `refs/pull/85/head`, commit
  `dbef8ee6e9f2053e373cab5fed0591d751cc3ca9`, CodeQL 2.27.0, Rust build mode `none`.
- Input: four saved API pages at
  `/private/tmp/valhalla-review-codeql-20260922.json`; 364 unique alert IDs with no
  duplicate IDs. SHA-256: `8dec3592933c1b03adab858a9f581dcd23b7b1155a1c583a9e365fee08c3e1e9`.
- Read each reported expression and its enclosing function/module against
  `git show dbef8ee6e9f2053e373cab5fed0591d751cc3ca9:PATH`. Checked the exact parent
  `cfg` declarations for source test modules, Cargo integration/example target
  boundaries, and upstream data flow for non-test buffers and the log.
- All 60 alerted files are byte-identical between that commit and the recovered
  working tree at review time. Numbers below refer to that immutable commit;
  other current-tree changes require their own current-head CodeQL analysis.
- No builds/tests were run for this review. No source, query configuration,
  suppression, alert state, or API metadata was changed. The CodeQL check remains
  failed until the repository's supported triage/disposition process accepts the
  evidence and the applicable current-head gate passes.

## Non-fixture data-flow findings

| Reference | Alert and exact source | Verifiable rationale |
| --- | --- | --- |
| R1 | #266, `browser/src/transport.rs:91` | Lines 89–97 allocate a zeroed output buffer, fill all 32 bytes via Web Crypto `get_random_values_with_u8_array`, propagate errors, and only then return. The initializer is not an emitted fixed challenge. |
| R2 | #268, `crates/vhalla-browser-vault/src/lib.rs:248` | Lines 240–264 take salt/nonce as parameters; all envelope fields are filled before return. Salt and nonce overwrite their slices at 250–251. Encryption at 255–260 uses `XNonce::from_slice(&nonce)`, not the zeroed envelope. The documented caller contract is fresh CSPRNG inputs (230–239); the browser creation path fills seed/salt/nonce independently and propagates failures at `browser/src/bin/worker.rs:133–156`. |
| R3 | #430, `crates/vhalla-public-protocol/src/activity.rs:638`; #437, `.../discovery.rs:301`; #444, `.../response.rs:514` | These are hex decoder output buffers. Activity 634–642 and response 510–518 require 64 input bytes and overwrite all 32 output slots from 32 byte pairs, failing on invalid nibbles. Discovery 293–305 requires 64 lowercase hex ASCII bytes and writes every slot with parsed input. No initial zero survives a successful decode merely because of buffer initialization. |
| R4 | #16, `crates/vhalla-session/src/lib.rs:232` | HELLO omits a responder challenge on wire; unsigned encoding 195–204 omits this field. Decode 221–248 uses zero solely as the absent-field representation and validates actual challenges. `Pending::respond` 329–350 validates the supplied nonce and replaces the field at 338 before emitting RESPONSE. Session establishment 366–396 only hashes RESPONSE/CONFIRM packets, both requiring their nonzero responder nonce. |
| R5 | #405, `crates/vhalla-public-peer/examples/browser_fixture/discovery.rs:27` | Example-only output buffer: lines 26–34 `read_exact` all 32 bytes from `/dev/urandom`, propagate I/O failure, reject an all-zero result, then return. No hard-coded request nonce. |
| R6 | #146, `crates/vhalla-rooms-node/src/unix/tests.rs:468` | `measurement_report` is a `tokio::test` at 411 in a `cfg(test)` module. `cert` is a `usize` from `bundle.field(0).unwrap().len()` at 466. The log prints height, certificate byte count and bundle byte count; it does not print certificate contents, keys, credentials or private payload. |

## Intentional example boundaries

- **E1 — IndexedDB qualification:** `continuity_indexeddb` and
  `private_custody_indexeddb` are separate Cargo examples requiring
  `continuity-qualification` / `private-custody-qualification`, with their fixture
  modules compiled only for WASM. Their headers identify synthetic-only work,
  without a product route or user import. The custody journey uses a known public
  account seed and public fixture passwords to test replacement and wrong-account
  refusal; deterministic salt/nonce pairs are part of that fixture. These values
  must not be promoted into a product account path.
- **E2 — frozen vectors:** `game_session_vectors` explicitly describes constant
  keys, salts and nonces as the means to regenerate checked-in protocol vectors.
  The flagged salt belongs to that example target, not the runtime session API.
- **E3 — local generated history:** the replay performance, browser fixture and
  room-activity performance example targets construct synthetic rooms through
  fixture helpers. Fixed integer arguments become deterministic record nonces.
  The replay benchmark has no validators/listeners; the browser fixture explicitly
  requires a fresh home and loopback listeners and warns against live-network use;
  the activity benchmark imports the test `common` module. They are intentional
  public fixture values, not production entropy defaults.

## Complete location inventory

Each entry is `source line (#alert ID)`. Repeated lines denote separate reported
values, not duplicate alerts. Parent boundary paths are relative to the crate
named in the first column. Every saved alert appears exactly once below.

| Source file | Exact reported lines and alert IDs | Enclosing boundary and classification evidence |
| --- | --- | --- |
| `browser/src/transport.rs` | 91 (#266) | Production; R1. |
| `crates/vhalla-botcaptcha/tests/hashcash.rs` | 187 (#213) | Cargo integration-test target (`tests/`); Negative cross-mode proof input. |
| `crates/vhalla-botcaptcha/tests/python_vectors.rs` | 53 (#212) | Cargo integration-test target (`tests/`); Cross-language frozen vector. |
| `crates/vhalla-browser-storage/examples/continuity_indexeddb/fixture.rs` | 209 (#394) | WASM example `continuity_indexeddb.rs:4–6`; Cargo feature gate at Cargo.toml:66–68. Synthetic fixture; E1. |
| `crates/vhalla-browser-storage/examples/private_custody_indexeddb/journey.rs` | 20 (#289), 21 (#290), 22 (#291), 269 (#292), 269 (#293), 304 (#294), 304 (#295) | WASM example `private_custody_indexeddb.rs:6–8`; Cargo feature gate at Cargo.toml:58–60. Synthetic passwords, salt and nonce; E1. |
| `crates/vhalla-browser-storage/src/native/continuity/tests.rs` | 96 (#309), 103 (#310), 264 (#311), 264 (#312), 292 (#313), 308 (#314) | `src/native/continuity.rs:12–13`, `cfg(test)`; deterministic continuity fixture. |
| `crates/vhalla-browser-storage/src/native/tests.rs` | 340 (#251), 370 (#252), 377 (#253), 391 (#254), 512 (#283), 642 (#284), 645 (#285) | `src/native/mod.rs:17–18`, `cfg(test)`; receipt/restart fixtures. |
| `crates/vhalla-browser-storage/src/outbox/continuity/tests.rs` | 216 (#315), 221 (#316), 230 (#317), 252 (#318), 263 (#319), 277 (#320), 287 (#321), 290 (#322), 308 (#323), 310 (#324), 312 (#325), 346 (#326), 349 (#327), 359 (#328), 382 (#329), 407 (#330), 413 (#331), 418 (#332), 451 (#333), 478 (#334), 490 (#335), 523 (#447), 528 (#448), 535 (#449), 540 (#450), 546 (#451), 557 (#452), 571 (#453), 582 (#454), 593 (#455), 597 (#456), 605 (#457) | `src/outbox/continuity.rs:14–15`, `cfg(test)`; fixed challenge IDs for continuity/retry cases. |
| `crates/vhalla-browser-storage/src/outbox/delivery/tests.rs` | 66 (#239), 89 (#267), 103 (#240), 141 (#241), 161 (#242), 165 (#243), 184 (#244), 194 (#245), 203 (#246), 208 (#247), 215 (#248), 282 (#249), 306 (#250) | `src/outbox/delivery.rs:300–301`, `cfg(test)`; receipt, scope, retry and corruption fixtures. |
| `crates/vhalla-browser-storage/src/outbox/tests.rs` | 342 (#255) | `src/outbox.rs:366–367`, `cfg(test)`; publicly defined vault fixture password. |
| `crates/vhalla-browser-vault/src/backup.rs` | 226 (#269), 238 (#270) | Same file:206–207, inline `cfg(test)` module; frozen vector and alternate nonce. |
| `crates/vhalla-browser-vault/src/lib.rs` | 248 (#268) | Production; R2. |
| `crates/vhalla-browser-vault/src/tests.rs` | 4 (#256), 108 (#257), 146 (#258), 198 (#259), 199 (#260), 200 (#271), 211 (#272), 212 (#273) | `src/lib.rs:297–298`, `cfg(test)`; public vector passwords and invalid/boundary password inputs. |
| `crates/vhalla-cli/src/public_activity/network/tests.rs` | 224 (#395), 302 (#396), 305 (#397) | `src/public_activity/network.rs:486–488`, `cfg(test)`; fake network response challenge substitution. |
| `crates/vhalla-cli/src/public_activity/recovery/tests.rs` | 28 (#445) | `src/public_activity/recovery.rs:197–199`, `cfg(test)`; synthetic room fixture. |
| `crates/vhalla-cli/src/public_discovery/http.rs` | 478 (#274), 479 (#275), 505 (#276), 518 (#277), 529 (#278), 580 (#279), 664 (#280) | Same file:445–446, inline `cfg(test)` module; cancelled/malformed/canonical request tests. |
| `crates/vhalla-cli/tests/public_activity.rs` | 95 (#261) | Cargo integration-test target (`tests/`); Synthetic room fixture. |
| `crates/vhalla-cli/tests/public_discovery.rs` | 169 (#281) | Cargo integration-test target (`tests/`); Local discovery startup/restart fixture. |
| `crates/vhalla-cli/tests/public_serve.rs` | 228 (#262), 234 (#263), 241 (#282), 243 (#264), 252 (#265), 368 (#336), 373 (#398), 400 (#399), 402 (#400), 417 (#337), 610 (#338), 678 (#339) | Cargo integration-test target (`tests/`); Local signed-request/restart/HTTP fixtures. |
| `crates/vhalla-game-platonik/examples/game_session_vectors.rs` | 47 (#214) | Cargo example; lines 1–8 explicitly require fixed values for frozen reproducible session vectors; E2. |
| `crates/vhalla-game-platonik/tests/session.rs` | 338 (#215) | Cargo integration-test target (`tests/`); Synthetic live game bind/reveal fixture. |
| `crates/vhalla-game-platonik/tests/settlement.rs` | 63 (#216), 315 (#217), 393 (#218) | Cargo integration-test target (`tests/`); Synthetic game settlement/cancel/replacement fixtures. |
| `crates/vhalla-game-platonik/tests/spike3.rs` | 716 (#219) | Cargo integration-test target (`tests/`); Synthetic fuel-bound game fixture. |
| `crates/vhalla-identity/tests/private_storage.rs` | 160 (#340), 161 (#401), 162 (#402), 167 (#341), 168 (#403), 169 (#404), 199 (#342) | Cargo integration-test target (`tests/`); Public password/salt/nonce fixtures for cross-adapter re-encryption. |
| `crates/vhalla-native/src/connection.rs` | 851 (#85), 861 (#86), 931 (#93), 970 (#94), 1106 (#87) | Same file:620–621, inline `cfg(test)` module; invitation scope, owner, expiry and refusal tests. |
| `crates/vhalla-native/src/spent.rs` | 389 (#210), 478 (#211) | Same file:353–354, inline `cfg(test)` module; zero rejection and tag-derived nonce model. |
| `crates/vhalla-public-client/examples/replay_performance.rs` | 272 (#343) | Cargo example, Unix module at 6–7; real APIs with synthetic `fixture` input, no listeners/validators; E3. |
| `crates/vhalla-public-peer/examples/browser_fixture.rs` | 254 (#344), 322 (#345) | Cargo example, Unix module at 23–24; lines 1–16 explicitly local public test data, new home and loopback; E3. |
| `crates/vhalla-public-peer/examples/browser_fixture/discovery.rs` | 27 (#405) | Example-only module via `browser_fixture.rs:19–21`; buffer filled from OS randomness; R5. |
| `crates/vhalla-public-peer/src/unix/activity/tests.rs` | 92 (#346), 229 (#406), 259 (#407), 430 (#408), 483 (#409), 492 (#410) | `src/unix/activity.rs:552–553`, `cfg(test)`; synthetic room and HTTP framing fixtures. |
| `crates/vhalla-public-peer/src/unix/continuity/tests.rs` | 173 (#347), 185 (#348), 209 (#349), 234 (#350), 246 (#351), 261 (#352), 300 (#353), 311 (#413), 322 (#354), 336 (#355), 359 (#356), 369 (#357), 376 (#358), 397 (#359), 415 (#360), 442 (#361), 465 (#362), 541 (#363), 581 (#364), 601 (#365), 607 (#366), 661 (#367), 706 (#368) | `src/unix/continuity.rs:545–546`, `cfg(test)`; deterministic request contexts and retry cases. |
| `crates/vhalla-public-peer/src/unix/discovery/tests.rs` | 29 (#411), 81 (#412), 518 (#414), 558 (#415), 591 (#416) | `src/unix/discovery.rs:1074–1075`, `cfg(test)`; challenge/listing fixtures. |
| `crates/vhalla-public-peer/src/unix/renewal/tests.rs` | 14 (#417) | `src/unix/renewal.rs:819–820`, `cfg(test)`; fixed advertisement request helper. |
| `crates/vhalla-public-peer/src/unix/tests.rs` | 129 (#418) | `src/unix.rs:675–676`, `cfg(test)`; fixed request helper. |
| `crates/vhalla-public-protocol/src/activity.rs` | 638 (#430) | Production; R3. |
| `crates/vhalla-public-protocol/src/activity/tests.rs` | 6 (#419), 9 (#420), 10 (#421), 12 (#422), 14 (#423), 30 (#424), 66 (#425), 67 (#426), 68 (#427), 69 (#428), 79 (#429) | `src/activity.rs:684–685`, `cfg(test)`; canonical framing, zero refusal, proof binding and limits. |
| `crates/vhalla-public-protocol/src/discovery.rs` | 301 (#437) | Production; R3. |
| `crates/vhalla-public-protocol/src/discovery/tests.rs` | 26 (#431), 53 (#432), 64 (#433), 96 (#434), 136 (#435), 173 (#436) | `src/discovery.rs:1159–1160`, `cfg(test)`; challenge/hashcash/decoder fixtures. |
| `crates/vhalla-public-protocol/src/response.rs` | 514 (#444) | Production; R3. |
| `crates/vhalla-public-protocol/src/response/tests.rs` | 6 (#438), 31 (#439), 51 (#440), 78 (#441), 143 (#442), 160 (#443) | `src/response.rs:556–557`, `cfg(test)`; fixed request, zero rejection and proof binding. |
| `crates/vhalla-retrieval/src/tests.rs` | 136 (#70), 174 (#71), 220 (#72), 323 (#73), 328 (#74), 511 (#201), 528 (#202), 538 (#203), 545 (#204) | `src/lib.rs:508–509`, `cfg(test)`; hydration/proof/challenge substitution and replay fixtures. |
| `crates/vhalla-room-activity-store/examples/performance.rs` | 93 (#369) | Cargo example, Unix module at 10–11; imports test common module at 6–8, synthetic new history; E3. |
| `crates/vhalla-room-activity-store/src/continuity/tests.rs` | 59 (#371) | `src/continuity/mod.rs:1402–1403`, `cfg(test)`; synthetic stored-room helper. |
| `crates/vhalla-room-activity-store/src/tests.rs` | 54 (#372) | `src/unix.rs:913–915`, `cfg(test)`; synthetic stored-room helper. |
| `crates/vhalla-room-activity/tests/activity.rs` | 228 (#370) | Cargo integration-test target (`tests/`); Synthetic room fixture using `tests/common`. |
| `crates/vhalla-rooms-app/src/tests.rs` | 128 (#139), 210 (#140), 226 (#141), 229 (#142) | `src/lib.rs:901–902`, `cfg(all(test, unix))`; deterministic consensus fixture. |
| `crates/vhalla-rooms-node/src/unix/seen_tests.rs` | 76 (#238) | `src/unix.rs:2860–2861`, `cfg(test)`; `batch` fixture, not production nonce generation. |
| `crates/vhalla-rooms-node/src/unix/tests.rs` | 468 (#146), 667 (#182), 680 (#183), 699 (#184), 790 (#185), 806 (#223), 822 (#187), 907 (#188), 918 (#189), 1229 (#190), 1243 (#191), 1261 (#192), 1527 (#193), 1541 (#194), 1560 (#195), 1571 (#196), 1747 (#197), 2062 (#198), 2197 (#164), 2200 (#165), 2291 (#199), 2382 (#167), 2385 (#168), 2392 (#169) | `src/unix.rs:2854–2855`, `cfg(test)`; deterministic consensus fixtures; #146 is R6. |
| `crates/vhalla-rooms-store/src/tests.rs` | 186 (#105), 213 (#106), 223 (#107), 233 (#108), 243 (#233), 254 (#234), 396 (#235), 418 (#236), 421 (#237), 469 (#109), 519 (#110), 525 (#111), 539 (#112), 1076 (#390), 1148 (#391), 1203 (#392), 1237 (#393) | `src/unix.rs:889–891`, `cfg(test)`; deterministic creation/candidate helpers for recovery cases. |
| `crates/vhalla-rooms/tests/calibration.rs` | 263 (#116), 275 (#117) | Cargo integration-test target (`tests/`); Synthetic room demand/rate-limit fixtures. |
| `crates/vhalla-rooms/tests/public_activity_policy.rs` | 28 (#373), 124 (#374), 153 (#375), 165 (#376), 169 (#377), 181 (#378), 185 (#379), 195 (#380), 209 (#381), 211 (#382), 243 (#383), 260 (#384), 262 (#385), 288 (#386), 295 (#387), 303 (#388), 342 (#389) | Cargo integration-test target (`tests/`); Synthetic policy/revision/authority fixtures. |
| `crates/vhalla-rooms/tests/registry.rs` | 22 (#95), 61 (#96), 66 (#97), 79 (#98), 100 (#99), 105 (#100), 128 (#101), 192 (#102), 312 (#231), 328 (#232), 350 (#103), 385 (#104), 403 (#113), 454 (#114), 473 (#115), 542 (#180) | Cargo integration-test target (`tests/`); Synthetic creation/update/restore fixtures. |
| `crates/vhalla-session/src/invitation.rs` | 258 (#80), 286 (#81), 318 (#83), 378 (#84) | Same file:235–236, inline `cfg(test)` module; round-trip, tamper, zero-rejection and property tests. |
| `crates/vhalla-session/src/lib.rs` | 232 (#16) | Production; R4. |
| `crates/vhalla-session/src/spent_nonce.rs` | 136 (#88), 137 (#89), 149 (#90), 151 (#91), 152 (#92) | Same file:94–95, inline `cfg(test)` module; repeated/zero/capacity nonce tests. |
| `crates/vhalla-session/tests/sessions.rs` | 58 (#8), 58 (#9), 102 (#10), 103 (#11), 110 (#12), 110 (#13), 117 (#14), 117 (#15), 130 (#17), 131 (#18), 137 (#19), 142 (#20), 142 (#21), 155 (#22), 156 (#23), 157 (#24), 162 (#25), 167 (#26), 168 (#27), 170 (#28), 180 (#29), 184 (#30), 190 (#31), 197 (#32), 201 (#33), 208 (#34), 229 (#35), 239 (#36), 240 (#37), 245 (#38), 250 (#39), 250 (#40), 259 (#41), 259 (#42), 272 (#43), 272 (#44), 312 (#45), 321 (#46), 336 (#47), 350 (#48), 368 (#49), 369 (#50), 376 (#51) | Cargo integration-test target (`tests/`); Deterministic handshake/challenge tests, including zero rejection and replay resistance. |
| `crates/vhalla-social/tests/archive.rs` | 93 (#52), 127 (#53), 159 (#54), 317 (#55), 391 (#56), 562 (#57), 707 (#58) | Cargo integration-test target (`tests/`); Synthetic genesis/control/recovery fixtures. |
| `crates/vhalla-steel-thread/tests/social.rs` | 105 (#59), 128 (#60), 151 (#61) | Cargo integration-test target (`tests/`); Synthetic paired-session relay/restart/authentication fixtures. |
| `prototypes/module-transfer/src/lib.rs` | 156 (#1), 165 (#2), 168 (#3), 172 (#4), 179 (#5), 186 (#6), 196 (#7) | Same file:139–140, inline `cfg(test)` module; replay/expiry fixture. Workspace excludes `prototypes/*`. |
| `prototypes/social-lifecycle/src/lib.rs` | 674 (#62), 695 (#63), 696 (#64), 804 (#65), 1158 (#66), 1193 (#67), 1194 (#68), 1214 (#69) | Same file:657–658, inline `cfg(test)` module; synthetic owner/agent control fixtures. Workspace excludes `prototypes/*`. |

## Disposition limit

Keep the exact alert IDs and rationale attached to any supported triage action.
Do not blanket-exclude test/example directories or suppress the entire rule:
production-callsite regressions and accidental fixture promotion still need
coverage. The buffer/log cases above have specific data-flow evidence; the
fixture cases have explicit execution boundaries. A later source change or a
new alert must be evaluated on its own evidence. No claim is made about physical
storage-full behavior, independent-device qualification, deployment safety, or
other readiness gates by this alert review.
