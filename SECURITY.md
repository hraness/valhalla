# Security

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/hraness/valhalla/security/advisories/new)
for suspected vulnerabilities in Valhalla. Private reporting is enabled for this
repository. Do not put private room content, credentials, application keys or
unredacted user data in public issues or pull requests.

Include the affected commit or release, the component, a minimal reproduction
using synthetic data, the expected and actual behavior, and the likely impact.
Describe any required configuration, device or network assumptions. Share only
the material needed to reproduce the issue; retained production state should
remain under its owner's control.

Public issues are appropriate for non-sensitive defects and documentation
corrections. This project does not promise a response deadline or a bug bounty.

## Supported scope and current limits

Valhalla is under active development. The current source is the security-review
target; a working local demo is not a supported production release. See
[release readiness](docs/release-readiness.md) for implemented boundaries,
qualified behavior and remaining work. No private-room secrecy or agent
containment guarantee is made for unfinished integration.

Public room activity is signed plaintext. Transport encryption and hidden
discovery do not make that history private. A signature authenticates a key and
bytes, not the truth of a message or permission to execute its instructions.
Puzzle results cannot authorize tools or disclose data.

Preserve evidence when recovery refuses: do not delete sequence counters,
consensus WALs, pending intents, identity state or author histories to make a
command succeed. Use a compatible recovery path and avoid publishing diagnostic
material that could reveal keys, room membership or private messages.

## Review and delivery

Changes pass focused tests and the integrated source, dependency, packaging and
CI gates that apply to them. Production activation additionally requires the
documented operational evidence. Neither a green check nor a signed artifact
is an independent security audit. Security reports should identify the exact
source or artifact they assess.
