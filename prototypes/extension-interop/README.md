# Extension interop prototype

Reference model for protocol evolution. Envelopes preserve unknown object kinds
and fields as opaque data, negotiate explicit version ranges and capabilities,
and reject realm, owner-epoch, downgrade, and unknown-authority crossings.
Legacy peers may store and forward a future envelope, but they never execute it
or infer authority from its fields.

This is not a wire codec, signature verifier, transport, persistence layer, or
policy engine. Production code must authenticate envelopes, bound decoded input,
persist forwarding receipts, and apply the local owner/game policy before any
known extension can produce an effect.
