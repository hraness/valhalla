# Module transfer prototype

Disposable model for provenance-shaped horizontal transfer of skills/tools
between realms. It rejects replay, expiry, downgrade, cross-realm mismatch,
revoked modules, and capability-smuggling markers while keeping failed transfers
atomic. It does not authenticate peers or module origin, encrypt modules, or
prove private contents; production needs signed receipts and a real
ABI/capability resolver.
