# Two-Mac private-room qualification handoff

This is an **unexecuted runbook**, not a qualification receipt. Apply the
[operational qualification baseline](operational-qualification.md); this checklist
adds the concrete two-Mac deployment and return packet. It authorizes no remote
access, service installation, sleep, logout or reboot by itself. Use newly created
synthetic custody only. Preserve failed runs and never delete state to regain a
budget, cursor, grant or ratchet.

## Freeze the candidate and prepare Mac B

Complete these fields before starting. Placeholders are deliberate; do not infer
an SSH destination, installed release, executable or artifact from a filename.

| Selection | Required value |
| --- | --- |
| Run identifier and UTC start | `<RUN_ID>`, `<UTC>` |
| Source | `<CANDIDATE_SHA>`, clean/dirty status, `Cargo.lock` SHA-256; record any patch hash if dirty |
| Mac A / Mac B | Pseudonyms, macOS version/build, architecture; no serial numbers needed |
| CLI on each Mac | `<ABS_VHALLA_A>`, `<ABS_VHALLA_B>`, binary SHA-256, target/toolchain/build flags including `experimental-private` |
| Browser artifact | `<ABS_PRODUCTION_DIST>`, `artifact.json` SHA-256, `purpose: production`, recorded asset size/hash verification |
| Browser and transport | Browser version/executable; selected Tailcat version, executable/hash and reviewed command syntax |
| Private working directories | `<ABS_RUN_A>`, `<ABS_RUN_B>`: new directories, mode `0700`, files `0600` |
| Fixed endpoints | Relay A `127.0.0.1:9473`; TLS forward B `127.0.0.1:19473`; gateway B `http://127.0.0.1:8790` |

Safe preparation handoff to the second-Mac operator:

> Inspect only until the candidate and ports are agreed. Return `sw_vers`,
> `uname -m`, available disk space, browser version, and resolved paths/versions
> for the selected CLI, Node, OpenSSL and Tailcat. Confirm whether ports 19473
> and 8790 are free without stopping any occupant. Inspect Remote Login and
> report the selected SSH user/destination and public host-key fingerprint.
> When the operator's setup instruction authorizes Remote Login, enable it only
> for that selected user; never request a password or private key in chat.
> Do not install Valhalla services, copy an existing account/browser profile,
> or alter power settings. Receive only the approved candidate binary and production browser
> assets initially. Report their hashes before activation. Any SSH host/user or
> file-transfer method remains `<AGREED_PRIVATE_CHANNEL>`, not an assumed target.

Record source identity from the candidate checkout with `git rev-parse HEAD`,
`git status --porcelain` and `shasum -a 256 Cargo.lock`. On each Mac use
`shasum -a 256 /absolute/vhalla /absolute/production-dist/artifact.json` with
the agreed paths. A different architecture may require a distinct binary hash;
record its same-source build provenance rather than claiming binary equality.
Both Macs must use clients from the coordinated candidate: mixed-version
control forwarding is not qualified.

The maintained build and packaging commands are in the
[browser guide](../browser/README.md#explicit-local-host-private-sync) and
[CLI guide](../crates/vhalla-cli/README.md#local-encrypted-private-room-files-experimental-private).
Reuse matching local receipts; do not silently rebuild during a device run.
If a build or local harness must run, use the repository's installed host
scheduler and its prescribed compute/browser-auth lane. The maintained harnesses
below are **same-machine baselines**, not remote orchestrators:

```sh
node browser/tools/qualify_private_delivery.mjs /ABS/PRODUCTION_DIST /ABS/CHROMIUM /ABS/NEW_LOCAL_RECEIPT /ABS/VHALLA /ABS/OPENSSL
node browser/tools/qualify_private_panel.mjs /ABS/PRODUCTION_DIST /ABS/CHROMIUM /ABS/OTHER_NEW_LOCAL_RECEIPT --production
```

There is currently no maintained harness that drives this entire two-physical-Mac
journey. Execute the following operator steps and retain individual observations;
do not label a local harness receipt as a two-Mac pass.

## Establish separate roles and fixed routes

Use the exact [local-host procedure](local-host.md) on Mac A:

```sh
/ABS/VHALLA_A private-host init /ABS/RUN_A/host --listen 127.0.0.1:9473 --tls-name relay.valhalla.invalid --executable /ABS/VHALLA_A
/ABS/VHALLA_A private-host add-credential /ABS/RUN_A/host
/ABS/VHALLA_A private-host status /ABS/RUN_A/host
/ABS/VHALLA_A private-host serve /ABS/RUN_A/host
```

The last command stays in its owned foreground terminal. Init creates credentials
1 and 2; the additional credential is 3. Assign 1 to native owner A, 2 to native
member B, and 3 exclusively to gateway B. Create separate account/device custody
for those native clients and the browser member; a relay credential does not
grant room membership. Never copy a live room store or browser profile.

Privately provision B with the non-secret connection descriptor/CA and only its
assigned client tokens. Keep CA/server private keys and the Tailcat saved key on
A. Tokens, browser capability, secret contact offers and Tailcat capability
address must not enter the returned evidence packet or chat transcript.

The maintained [Tailcat wiring](local-host.md#explicit-tailcat-wiring) currently
documents pinned v0.7.0. With that reviewed version, generate a new saved key once
on A and run only the relay port:

```sh
/ABS/TAILCAT_A genkey --key=/ABS/RUN_A/host/tailcat.private.json --fixed-region
/ABS/TAILCAT_A --key=/ABS/RUN_A/host/tailcat.private.json serve 9473
```

On B, substitute the privately obtained capability address locally:

```sh
/ABS/TAILCAT_B forward --bind=127.0.0.1 PRIVATE_TAILCAT_ADDRESS 19473:9473
```

Keep the fixed port and saved key across retries. An occupied port is a refusal,
not permission to stop an unrelated process. After a Tailcat server restart,
explicitly restarting B's exact forward may be necessary; automatic recovery is
not qualified. No SSH, exec, exit-node or wildcard service is needed.

Create B's gateway config from the maintained
[schema](../crates/vhalla-cli/src/private_gateway/README.md): `listen` is
`127.0.0.1:8790`, `upstream.addr` is `127.0.0.1:19473`, upstream TLS name/CA and
namespace match A, `token_file` selects credential 3, and `assets_dir` selects
the frozen production artifact. Generate an independent browser capability;
do not reuse any TLS token. Keep config and credentials owner-private. Then:

```sh
/ABS/VHALLA_B private-gateway serve /ABS/RUN_B/gateway.json
```

The browser imports the documented private connection profile with exact origin
`http://127.0.0.1:8790`, the selected namespace, its separate capability and trusted
initial cursor. It never receives the upstream TLS token. Preserve the same
browser profile and origin for every reopen; do not use random-port browsing.
`private-host status HOME --probe` and `private-gateway status CONFIG --probe`
check their respective listeners only, not end-to-end delivery.

## Admit synthetic participants and exercise the path

1. Create native accounts with `identity init NEW_ACCOUNT` and follow the CLI's
   exact `create → offer → offer-inspect → import → request → accept → join`
   [confidential admission sequence](../crates/vhalla-cli/README.md#one-confidential-offer-encrypted-request-and-response).
   Independently compare the intended public account keys. Transfer bootstrap
   files through the agreed confidential channel; retain operation IDs and
   validity endpoints for exact retries.
2. Admit a separately created browser account through the production panel's
   corresponding confidential offer/request/response flow. Retain its `.vhroom`
   locator before initialization. For this initial test, admit all three devices
   while the selected mailbox is still empty and use initial cursor `0`.
   A later join needs an owner-approved boundary after older traffic drains;
   if that trusted boundary cannot be established, mark the late-join case
   **BLOCKED**, never guess a cursor or copy an old device.
3. Follow the [agent delivery guide](cli-agents.md#local-hosting-and-persistent-tls-delivery)
   for each native profile: A selects `127.0.0.1:9473`, B selects
   `127.0.0.1:19473`; each uses its own context, credential and new delivery
   directory. Run `private delivery-init ID ROOM --config PROFILE` once.
   Its selected profile becomes v2. Use a fresh explicit grant/claim per launch
   and the documented `private agent-serve ID ROOM --grant GRANT --delivery PROFILE`.
   If an existing agent client is used, declare its actual provider/model and
   synthetic-only disclosure; this is not an OS containment test.
4. Verify the native five-tool interface and send unique synthetic case text A→B,
   B→A, browser→A and A→browser. Record sender outbox sequence/ciphertext digest,
   relay retention position and recipient inbox sequence separately. Choose
   **Sync now** explicitly in the browser until bounded work resolves. Record
   verified device claims when present without equating them to human reading.
5. Confirm that B receives the encrypted control for browser admission through
   normal delivery. An old native grant must close at a changed roster; obtain a
   new grant after reviewing it. Browser roster review must similarly require
   fresh consent. Do not manually inject a control to call automatic forwarding
   successful. An explicit control-file fallback is a separate result.

## Bounded failure and recovery checklist

Use a new output name for every CLI observation. `private delivery-status ID ROOM
--config PROFILE --out FILE` and `--stream control` expose native retained progress
while its agent is stopped. Do not open a second writer against a live custodian.

| Case | Action and required observation |
| --- | --- |
| Wrong TLS identity/token/namespace | Use a separate diagnostic profile or `relay-scan` with its documented TLS arguments and a new scan directory. Record pin/token/namespace refusal and no successful authenticated operation; credential-release ordering has separate transport-test evidence. Healthy credential still progresses. Do not mutate a retained production profile. |
| Wrong browser authority/origin | Select a deliberately wrong capability or origin in the synthetic browser flow. Refusal preserves work and budgets; explicit unlock plus the correct retained profile may resume an authority refusal. Never clear IndexedDB to recover. |
| Offline receiver | Stop B's native agent and lock/close its browser; A queues a small numbered batch. Record retention without claiming reception. Reopen the original B custody, new native grant and same browser origin/profile; bounded catch-up yields one committed instance per ciphertext. |
| Relay/route outage | Stop only the owned A relay or B forward, queue one synthetic send, record pending/uncertain state and charged evidence. Restart the same process/config/key/port, retry exact bytes and compare digests. Never re-encrypt as a replacement. |
| Orderly restart | Ctrl-C the owned foreground gateway/relay, wait for exit/drain, restart exact commands. Verify duplicate submission retains its original position and cursor/attempt history does not decrease. Record gateway, relay and forward restarts separately. |
| Control ordering/revocation | Stop native custodians before owner CLI membership changes. Retain an older unsent message, make one explicit owner control, then prepare new text under the new roster. Verify older local message → control → newer message and review/regrant. Removal blocks future sends after application; retained history remains. |
| Independent custody | A second native writer refuses. A second browser tab cannot advance a stale ownership token. Preserve the original queue and observe the active owner rather than clearing locks. |
| Capacity/malformed transport | Use existing focused tests/local harness for deterministic exhaustion/corruption. Mark physical-device injection **NOT RUN** unless an isolated bounded fixture is separately prepared. Never fill the shared disk or modify real retained files. |

The browser has an eight-item deferred queue, four-item incoming pages and at most
two outgoing artifacts per sync. Native delivery also has finite queues, deadlines
and grants. An observed capacity/review stop is not evidence of unlimited liveness.
Published control custody missing under a v2 native profile must refuse; upgrade
must not recreate it. Namespace/generation rotation remains **GATED**:
`private-host rotate` refuses, and the
[rotation contract](private-rotation-contract.md) is design work, not a recovery command.

## Separately agree disruptive device cases

After the foreground cases pass, agree the exact device, time window, responsible
operator and recovery access before each sleep/wake, logout/login or reboot case.
Do not execute these remotely on assumption. Save synthetic custody and record
pre-fault digests/cursors first; check the same post-fault state and exact retry.

For login lifecycle, separately agree and use documented `private-host install`
and `private-gateway install` with their exact paths, then inspect their matching
status. Relay, gateway and Tailcat supervision are separate. A GUI LaunchAgent
does not promise service while logged out, before login or during sleep. Record
outage duration, whether forwarding required manual restart, and whether grants
expired. Grant expiry requires a new explicit grant, not deleted claims.

## Return packet and decision

Return one redacted `qualification.json` (or equivalent table) containing:

- Candidate SHA/dirty status/patch hash, lockfile hash, each CLI binary hash and
  build provenance, browser manifest hash and verification, tool/OS versions.
- Mac A/B role placement, selected local ports/origin, CA fingerprint, and
  credential **indices** assigned to each role; no tokens or private keys.
- Each case ID with `PASS`, `FAIL`, `BLOCKED` or `NOT RUN`, UTC start/end, exact
  observed fault boundary, process exit/result, expected versus observed outcome.
- Ciphertext/job digests, relay positions, inbox/outbox/control watermarks,
  retry/attempt evidence before and after; redact account/device identifiers and
  private scope metadata. No message bodies, contact offers, capability addresses,
  browser connection profiles, raw custody or identity backups.
- Local harness receipt hashes/paths, explicitly labeled same-machine; separate
  two-Mac observations, sleep/logout/reboot results, unresolved failures and
  cleanup readback. Keep raw synthetic evidence owner-private on its source Mac.

At closeout stop only owned foreground processes; uninstall only qualification
LaunchAgents that were explicitly installed, using their matching maintained
commands. Preserve synthetic custody and failed evidence for review. A pass names
the exact tested candidate and routes; unrun disruptive cases, gated rotation and
public-internet/independent-validator claims remain unqualified.

Source references: [native steel thread](../crates/vhalla-cli/tests/private_steel_thread.rs),
[native delivery regressions](../crates/vhalla-cli/tests/private_agent_delivery.rs),
[production browser delivery harness](../browser/tools/qualify_private_delivery.mjs),
[production panel harness](../browser/tools/qualify_private_panel.mjs), and the
linked maintained CLI, gateway and local-host guides above.
