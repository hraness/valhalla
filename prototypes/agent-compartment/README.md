# Room-lifetime agent compartment spike

This isolated prototype exercises two boundaries with synthetic content: an
actual macOS child denied application-file, network and subprocess access, and a
broker model requiring an exact provider/content grant. It has no production
dependency, live room connection, account key, model SDK, provider credential or
external inference call. It does not activate the private-room agent product.

## Architecture and authority

The trusted launcher owns a single child lifetime. It clears the child's
environment, closes other descriptors, and inherits only bounded stdin/stdout
framing and a diagnostic pipe. The child receives one explicitly selected
synthetic transcript. A four-byte big-endian length precedes each frame; the
broker requires nonblocking descriptors and refuses empty, oversized, truncated
and late frames. Full/partially full pipes retain the deadline across partial
writes and interrupted waits. Checks after readiness and final I/O withhold late
completion; a timed-out write may already have effects, so the launcher ends the
child instead of retrying the frame. Child CPU, descriptor
count and wall time are bounded; cleanup terminates only that task-created
process group.

`macos.sb` denies by default. It permits only the fixture executable and dynamic
loader inputs. Apple's installed `dyld-support.sb` supplies cryptex mappings and
root-directory reads required by the current loader; `/System/Library` and
`/usr/lib` are readable runtime inputs. The profile does not import the broad
`system.sb` application policy, grant home/room/temporary-directory access, or
grant network access, process forks or other executables. Initial execution
requires allowing the exact fixture binary; re-executing that same binary is
not excluded by this profile. Its broker authority still cannot change rooms.

`DisclosureBroker` binds its whole lifetime to full room, anchor, account,
device, epoch, roster and fresh session identifiers. Only its trusted constructor
installs the provider adapter and grant. The data-only disclosure method cannot
replace them. A grant binds an exact endpoint, model, processing policy and hash
of the complete immutable wire request, plus finite attempts and a monotonic
deadline. Changed content, provider or room context refuses before dispatch.
Expiry/revocation is checked again after an awaited adapter response and before
returning output. Failed or canceled attempts consume quota and end that broker's
grant, requiring trusted-host reconciliation. Room instructions cannot mint grants.

The adapters in the tests only return synthetic bytes. Revocation during a real
in-flight inference request would not retract input already sent to its provider.
This process-local model does not promise durable quotas, provider idempotency,
restart-safe external actions or deletion of remote conversation state.

## Run the bounded evidence

From the repository root, the policy/framing suite needs only Python's standard
library and works independently of macOS:

```sh
python3 -m unittest discover -s prototypes/agent-compartment -q
```

Actual OS qualification requires macOS, its installed `sandbox-exec`, and clang.
Use the installed host scheduler; substitute its resolved absolute path:

```sh
/Users/benguo/.bun/bin/hra-host-run --mode=shared --lane=mac-native \
  --label=valhalla-agent-compartment-probe -- \
  /usr/bin/python3 prototypes/agent-compartment/qualify_macos.py
```

The launcher compiles the controlled C probe in a fresh private temporary
directory, creates a synthetic canary and real loopback/Unix listeners, and
requires permission-denied results for canary read/write, TCP/Unix connection,
fork and external execution. Connection refusal alone does not pass: the
listeners are open and the child must receive `EPERM` or `EACCES`. The launcher
also verifies that neither listener received a connection and the canary remains
unchanged. It checks the pipe roundtrip and exact response before reporting
success. Unsupported platforms or startup/permission failures return a refusal;
there is no unsandboxed fallback. Optional `--diagnostics` prints at most 4096
bytes from this synthetic fixture's stderr and its exit status.

On 2026-09-22, macOS 26.5.2 passed all six actual denial probes and the inherited
pipe roundtrip. The policy/framing suite passed sixteen tests, including mocked
late readiness and final read/write deadline regressions. No provider calls or
machine-wide configuration changes occurred. An initial profile lacking dyld's
loader rules refused startup; importing only those installed loader rules made
the qualified probe runnable. This is host-specific evidence, not a general
sandbox escape proof or a qualification for arbitrary interpreters and agents.

## Promotion requirements

`sandbox-exec` is **deprecated** in Apple's installed manual. Apple's own
[Developer Technical Support explanation](https://developer.apple.com/forums/thread/661939)
states that custom sandbox profiles are not a supported third-party product API.
The supported product route is
[App Sandbox](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox),
configured by entitlements and appropriately signed helpers. Therefore this
backend stays an explicit experiment; it must not silently become production
containment or a fallback for a failed supported backend.

Before promotion, implement and qualify a supported signed helper boundary,
connect the trusted broker to `OwnedAgentRoomSession`, and bind authenticated IPC
to the exact child instance. Qualify the actual chosen agent/runtime, loader
exceptions, termination/cancellation, room changes and fresh provider
conversations. Add exact selected-content/full-destination export grants and
durable external-effect intent/reconciliation before exposing external actions.
Keep all room keys and store handles outside the child. A general-purpose agent
that already has ambient tools outside this process remains out of scope.
