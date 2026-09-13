# Genome bundle prototype

Disposable model for canonical, content-addressed genome/proteome manifests, capability/import/resource admission, versioned upgrade, revocation, rollback, and organelle lifecycle receipts. Lifecycle receipts have an explicit bounded log and fail closed with a capacity error when it is full. It does not execute WASM, provide cryptographic signatures, or replace a sandbox; bundle and revocation registries are still in-memory reference state.
