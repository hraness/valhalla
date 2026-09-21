# Continuity receipt IndexedDB qualification

This optional synthetic fixture exercises the maintained receipt and author
outbox implementations in the **same** profile database. It is excluded unless
`continuity-qualification` is selected. It adds no product UI, listener, network
operation, signing capability, data migration, or receipt reset.

The existing `browser/tools/qualify_storage.mjs` runner creates an isolated
Chromium profile and distinct random namespaces for Window and dedicated worker.
Its strict durability interception, 20-second worker deadline, 45-second overall
deadline, and process cleanup are unchanged. The fixture retains its synthetic
damaged namespaces; it does not repair them or access user state.

```sh
cargo clippy --locked -p vhalla-browser-storage --example continuity_indexeddb --features continuity-qualification --target wasm32-unknown-unknown -- -D warnings
cargo build --locked -p vhalla-browser-storage --example continuity_indexeddb --features continuity-qualification --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/debug/examples/continuity_indexeddb.wasm --target web --out-name indexeddb_qualification --out-dir "$RUNNER_TEMP/vhalla-continuity-runtime"
node browser/tools/qualify_storage.mjs "$RUNNER_TEMP/vhalla-continuity-runtime" "$(command -v google-chrome)"
```

The source contains these fixed, bounded scenarios:

- Publish 33 signed local events through actual history initialization, author
  reservation, and finalization APIs. Preserve the exact v1 author/history bytes
  and a strictly signed, actually stored v1 delivery receipt at sequence one.
- Persist Status and exactly-32-frame Stage replies without changing retention.
  Retain a terminal admission statement separately; only two signed Evidence
  pages containing exactly the local 33 frames complete the retained prefix.
  Reopen between pages and compare original proof/body and physical record bytes.
- Refuse a stale nonce, bad signature, foreign room, and a prepared response from
  an older durable generation. Compare unchanged persisted bytes after refusal.
- Inject real IndexedDB quota/transaction abort and unsupported strict-durability
  behavior using the unchanged harness. Require `needs_reopen`, then load the
  exact surviving attempt and retry once. Reads succeed with writes denied.
- Drop a publication future before completion and verify actual transaction
  abort. Separately allow the real transaction to commit, confirm it through a
  later independent connection, then drop the unpolled caller future. Reopen
  reconciles the original signed record; replaying the stale candidate cannot
  duplicate it or move a head.
- Enforce immutable record and byte quotas; refuse changed limits, lost FORMAT,
  missing prior receipt prefixes, and a never-created source author. None of
  these paths may initialize/reset the author or silently recreate a session.
- In two separate fresh namespaces, prepare a receipt, then replace the actual
  source frame with different valid signed bytes or remove its author head.
  Publication and subsequent load refuse; both damaged source and receipt bytes
  remain unchanged by the refused operation.

All event keys and peer responses are deterministic **synthetic** signatures.
They exercise the real strict verifiers; they are not proof that a remote server
stored events. The synthetic history metadata and opaque bootstrap deliberately
do not establish a certified registry or current public policy. This fixture
qualifies the storage boundary only. IndexedDB strict transaction completion
does not prove physical disk durability, protection against eviction or coherent
same-origin rollback, consensus, or global delivery.

The gated `continuity_qualification` helper permits only bounded raw snapshots
and three named synthetic corruption cases. It is not linked by default or by
the public browser product. Runtime success must come from the generated
`indexeddb-receipt.json` reporting both Window and worker success; source review
or compilation alone is not that result.
