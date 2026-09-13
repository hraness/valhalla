# Control-plane prototype

A tiny reference model separating durable authority from hostile execution-plane requests. Realm policies own capability grants, byte quotas, revocation, and request replay results; request payloads are opaque bytes and never mutate policy. Request IDs are bound to a request fingerprint and policy epoch, with a bounded replay cache, so conflicting reuse is rejected and policy changes are re-evaluated.

The request and policy digests use domain-separated SHA-256 only to make this
reference model's equality and audit boundaries explicit. This is not a
signature, persistence, a sandbox, or proof that an implementation cannot be
confused by prompt injection. Production code must authenticate requests and
persist an auditable state root.
