# Signed revision facets spike

Disposable D0/S1 evidence for vhalla (valhalla), not a maintained record codec or
an affiliation verifier. The library is `no_std + alloc`, forbids unsafe code,
and reuses the maintained social codec only for its unchanged structural fields.
All third-party package versions in this lockfile already occur in the root lock.

## Decision

Add `PostFaceted = 8` and `ReviseFaceted = 9` to the existing v1 operation vocabulary.
Keep v1 envelope magic, content-ID/signature domains, existing opcodes 0–7 and all
old bytes unchanged. Each new operation contains the corresponding old operation
fields followed by its own bounded facet array. An envelope v2 prototype costs
exactly the same bytes and solves no additional requirement here; reserve it for
a real envelope/signature/identity change. These assignments are proposed until
the coordinator freezes the maintained schema.

The ordinary fixture is 215 bytes as legacy v1 and 263 bytes with two facets under
either new-opcode v1 or envelope v2. A 4,096-byte revision with 16 superseded heads,
eight 48-byte tag keys and eight mention targets is 5,570 bytes, below the existing
8,192-byte complete-record ceiling. This is a maximum owner/sequence-zero revision
fixture; an agent actor adds 32 bytes and a predecessor adds another 32, yielding
5,634 bytes. The largest post layout is smaller than the revision's 512-byte heads.
These are serialized bounds, not total archive or allocator measurements.

Existing legacy decoders reject both candidate formats. D1 now extends the
maintained decoder to accept opcodes8/9, so the retained regression uses an
explicit frozen legacy-vocabulary adapter and additionally requires maintained
v1 facet verification to match the same golden ID. This gate shares unchanged
structural validation and is not an independently captured full legacy decoder. A following old-style
record can parse but still name an unsupported predecessor: unknown operations
cannot safely be skipped. Require an advertised faceted-post capability before
mixed-client publication, and an explicit author-selected legacy publication
mode before creating compatible history. Never strip facets from signed bytes,
re-sign history, synthesize a chain reset or claim that exporting a subset repairs
an already incompatible writer/control closure. Older clients may remain incomplete.

## Constructor and wire contract

`FacetedText::new(Text, Vec<Facet>)` is the validating constructor. Text and facets
stay private and immutable together; do not add an independently mutable facet
sidecar. Decode checks before returning signature evidence, and semantic authority
is a later separate social/control operation.

- UTF-8 byte offsets are big-endian `u16`, nonempty and on character boundaries.
- Input is already sorted with no overlap; foreign bytes are rejected, not sorted.
- At most 16 facets, 8 distinct typed mention recipients and 8 distinct tag keys.
- `Mention(OwnerId)` and `Mention(AgentId)` contain immutable 32-byte references.
  Type discriminants are 0 and 1; an ID alone proves neither existence nor owner.
- Mention labels begin `@`, include a following byte, and contain no ASCII bytes
  0x00–0x20 or 0x7f. Non-ASCII text remains inert display data. This fixed byte rule
  intentionally avoids implicit compiler-version Unicode acceptance tables.
- `Tag` discriminant 2 carries a `u8` byte length and canonical ASCII key. The exact
  signed span must contain `#` followed by matching case-insensitive source text.
- Tag grammar is `[a-z0-9_][a-z0-9_-]{0,47}`. Local authors normalize ASCII uppercase;
  received canonical keys must already be lowercase. No implicit Unicode folding.
- The facet list begins with a `u8` count. Empty lists are allowed and exact signed
  revisions replace the previous annotation set. Legacy revisions carry no facets;
  they must never inherit mentions/tags from earlier text.

A signature binds text, placement/reply/quote/revision references, actor, realm,
writer predecessor, and all facets together. Copying an old signature over a changed
recipient or changed text fails even if the new spans remain structurally valid.

`@alice` is not identity proof. The false-alias fixture deliberately admits that
label attached to another signed target, while the local address-book helper
rejects alias mismatch, missing names and duplicate matches. Render an author's
label as untrusted text with a separately resolved immutable identity. Resolving an
agent's owner and routing a notification require verified historical affiliation,
which this codec spike does not attempt. Mentions are never tool/wake authority.

## Unicode comparison

The current standard Cargo cache contains no `unicode-normalization` or
`unicode-casefold` package. No package was fetched or new production dependency
introduced. `compare-unicode.py` explicitly requires the locally available Unicode
16.0.0 Python database and records an exploratory `NFKC(CaseFold(NFKC(input)))`
comparison in `vectors/unicode-16-comparison.json`. This is **not** a claim to
implement Unicode's complete NFKC_Casefold mapping, which also handles default
ignorables. It is not the production protocol.

The pinned experiment combines composed/decomposed accents, folds `ß` with `ss`,
and combines fullwidth `Ｒust` with `Rust`. Turkish `İ` retains a combining dot;
Cyrillic `а` remains distinct from ASCII `a`. Rust lowercase alone neither normalizes
accents nor folds `ß`, and compiler-owned Unicode versions are not a wire contract.
Unicode support would require a specified form, pinned folding/normalization tables,
a bounded expansion rule and dependency/WASM size measurements. No Rust table-size
or speed claim is made without that implementation. ASCII is the selected small
first protocol; general Unicode text and fulltext search remain separate questions.

## Evidence and reproduction

All commands run from the repository root. The initial vector build and test
suite ran through `/Users/bg/.bun/bin/hra-host-run --mode=shared --lane=compute`;
subsequent focused pure Clippy/fmt checks run directly, as permitted by the
repository baseline. Broad/native/process/WASM work retains the scheduler. `cargo run --example vectors` initially generated candidate
fixtures; committed fixtures are now fixed regression vectors. Python independently
checks the framing, operation offset, SHA-256 IDs and unchanged legacy prefix.

```text
cargo fmt --manifest-path prototypes/social-facets/Cargo.toml -- --check
cargo test --manifest-path prototypes/social-facets/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/social-facets/Cargo.toml --all-targets --locked --offline -- -D warnings
python3 prototypes/social-facets/verify-vectors.py
python3 prototypes/social-facets/compare-unicode.py
```

Validation results (2026-09-13): fmt PASS; unit/property tests 12 PASS in 0.76s
after compilation; strict all-target Clippy PASS; independent golden check PASS;
pinned Unicode 16 comparison PASS. The suite contains 12 checks,
including four 256-case property tests for arbitrary UTF-8 spans, arbitrary bytes,
normalization idempotence and mutation resistance. It covers signatures across
revisions, both candidate formats, frozen legacy bytes, mixed-history rejection,
malformed bounds/order, distinct recipient/tag ceilings and alias spoofing.

The candidate decoder uses a clearly isolated temporary zero-signature legacy
frame to invoke only `SignedRecord::decode`; it never calls legacy verification
on that synthetic frame or returns it as evidence. It then strictly verifies the
actual complete candidate signature. Production should directly extend the shared
codec and avoid this throwaway reconstruction path.
