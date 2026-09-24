# Private rooms in a browser

The optional private-room client can use a hosted HTTPS gateway without a local
CLI or Tailcat installation. The browser creates and uses the account and room
device keys. The gateway serves the checked client assets and forwards encrypted
requests to one configured relay namespace. A gateway credential permits
transport; it does not admit a device to a room.

This source change does not establish a deployed service. Public certificate,
independent-device HTTPS, recovery and operational checks must pass for the
selected host before inviting production users.

## Deployment shape

Use a dedicated, stable application origin. The gateway serves both the client
and `/private-relay/v1` at that origin. Configure the browser profile as format 2
and the gateway as format 2; format 1 remains the explicit local-host path.
The [browser guide](../browser/README.md#explicit-private-sync) describes profile
selection. The [gateway guide](../crates/vhalla-cli/src/private_gateway/README.md) describes
host commands and both configuration formats.

The gateway terminates TLS itself and requires TLS 1.3, its configured DNS name
and HTTP/1.1. Select a host that can expose that TCP listener with the configured
public port. A provider's ordinary HTTP reverse proxy is not interchangeable
with this deployment: forwarded headers do not authorize remote plaintext or
change the selected origin. Do not disable the origin or TLS checks to fit a
hosting platform. A separately reviewed deployment mode is needed if the
provider requires TLS termination before the gateway.

The upstream relay has its own explicit CA, TLS name, credential and namespace.
Its retained mailbox needs persistent storage, one writer and a recovery plan.
Keep gateway client credentials, TLS keys and upstream credentials out of the
asset directory and source control. Use separate browser credentials for
independent clients; never give the upstream credential to a browser.

The existing marketing site can keep its current deployment. Hosting a copy of
the private UI there does not supply its same-origin gateway or migrate an
existing browser device.

## Configuration and renewal

The hosted gateway accepts one through 64 explicitly configured client entries.
Each entry has an independent random capability, stable administration ID,
expiry, revocation flag and per-client request, byte and concurrency limits.
Active credentials can have at most seven days remaining when loaded. Expired
or revoked entries are denied while other valid clients remain usable.

Credential renewal is explicit. Stop admission, drain the gateway, update its
private configuration and restart it with the checked artifact. Supply a changed
browser capability through the confidential profile handoff. Opening the retained
connection with corrected authority preserves pending ciphertext and charged
retry budgets. Locking a browser does not revoke a server credential. This
version does not promise instantaneous revocation of an already admitted request.

Gateway rate limits are process-local windows. They protect finite transport
work; they do not replace the relay's durable lifetime capacity. Restarting a
gateway or renewing a credential must not erase relay history or reset browser
delivery state. Monitor retained capacity and stop accepting new rooms before
the chosen namespace reaches its limit. Seamless mailbox migration remains
separate work.

Renew the HTTPS certificate before expiry through the same drained restart.
Verify the public DNS name, full browser-trusted chain and exact checked assets
after every deployment. A successful TCP connection or `status --probe` result
alone does not establish HTTPS identity, upstream access or message delivery.

## Browser state and trust

Keep the exact scheme, hostname and port. Browser storage belongs to that origin;
a new origin creates separate storage. Do not copy or restore old live sender
state to bypass a missing-store or revision refusal. An account-key backup alone
cannot restore a private-room ratchet. Read-only history archives and admitting
a fresh device have separate recovery procedures.

The app publisher is trusted to serve honest code. End-to-end encryption does
not protect browser keys from a malicious application update. Publish only
checked, hash-bound assets, control who can deploy them and retain artifact
identities for rollback review. A rollback is a code decision, not permission to
roll back browser or relay history.

Users explicitly select **Sync now**. Closing the browser, background suspension
or sleeping the device can pause progress. This release does not provide an
always-on browser participant. Credentials and membership remain separate, and
the owner still reviews the exact joining device.

## Required evidence for activation

- Record the exact source, native binary, production asset manifest, gateway
  configuration identity, certificate identity and host target.
- From an independent device with an ordinary browser trust store, create or
  join a synthetic room, exchange encrypted messages, and reopen retained state
  at the same HTTPS origin without any local helper.
- Exercise wrong origin, namespace and capability; expiry and revocation;
  competing tabs; relay outage; exact retry; and browser document restart.
  Keep unsuccessful runs and verify owned-process cleanup.
- Demonstrate the selected host's drained upgrade, unexpected restart,
  persistent mailbox recovery, credential and certificate renewal, and bounded
  resource behavior. Verify retained ciphertext and delivery counters survive.
- Establish health and capacity observations, actionable operator alerts and
  a recovery runbook. Complete the elapsed soak and applicable installed-device
  lifecycle checks in the production-readiness plan.

Synthetic certificates trusted only by a test browser can qualify protocol
behavior. They cannot establish public certificate issuance, deployment identity
or ordinary-user connectivity.
