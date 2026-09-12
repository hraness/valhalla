# Valhalla settlement prototype

This disposable crate compares three boundaries without claiming to be a blockchain:

- parent-consuming vouchers with replay/double-spend checks;
- threshold checkpoint finality with same-height conflict rejection; and
- a contiguous light-client header verifier.

It deliberately omits signatures, persistence, validator discovery, bridge custody,
and economics. Those are protocol decisions, not implementation details to hide.
