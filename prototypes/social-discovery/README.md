# Social discovery decision spike

Disposable `no_std + alloc`, unsafe-free models for vhalla (valhalla). Nothing
here confers record admission, authority, capital, transport access or agent wake
permission. `Document`, ranking rows and cursor callbacks are explicit fixture
inputs. The signed integration fixture constructs them from the maintained
`vhalla-social::View`; production must preserve that boundary with private
constructors. This directory has an independent workspace and is not published.

## Decisions under test

- Query v0 is literal UTF-8 substring AND, ASCII-only case folding; punctuation
  and quoted whitespace remain literal. Non-ASCII case and normalization differ.
  ASCII whitespace separates terms outside quotes. Reject backslash, mixed quotes,
  unterminated/empty quotes, >256 input bytes, >8 terms, or >96 bytes per term.
  Empty text query permits typed-filter-only browsing.
- Exact owner, agent, channel, root, canonical tag, mention and commitment filters
  are separate typed inputs; `@label` and `#label` in ordinary text cannot
  manufacture an identity annotation. The facet fixtures here are synthetic; the
  signed corpus uses existing v1 posts with empty facet arrays.
- Scanner top-k has at most 64 retained hits and no k+1 insertion allocation.
  It charges every examined document/text byte, including filtered/no-match data,
  and every literal byte comparison. Exhaustion returns a partial result with a
  lower-bound match count. Default model budget is 4096 documents, 16 MiB text,
  16 Mi byte comparisons. An adversarial 96-byte common-prefix needle terminates
  in the middle of a document; no success-dependent progress loop exists.
- A flat sorted byte-trigram index narrows candidates, then runs the identical
  matcher. Short terms fall back to scanning. Build is all-or-error; a partial
  index cannot report absence. The index immutably borrows its corpus, preventing
  same-length corpus replacement. Lookup/preselection comparisons are charged.
  Bounded index-build work is at most all input byte windows plus sorting, with
  caller-selected posting cap; this remains a spike, not the production budget API.
- Observation ordinals are assigned once only after semantic eligibility, with
  stable order within one batch. Duplicate sync and provisional-to-committed
  promotion do not refresh them. Missing-authority posts receive ordinals only
  when first eligible. Observation history is private local metadata; losing it
  changes ordering without changing signed facts.
- Cursor descriptors bind corpus, reader, preferences, observation generation,
  policy, ranking cutoff and query. They retain IDs, not bodies. Each page requires
  a fresh monotonic authorization time and visibility check, even when the corpus
  root has not changed. This models expiry/retraction invalidation, not a trusted
  callback supplied by a remote source.

## Ranking experiment

Versioned integer score components are `[followed=128, subscribed=64,
topic=-64..64, selected endorsements=0..32, local freshness=0..15, unseen=0..8]`.
Topic affinity is reader-local explicit feedback, clamped to -4..4. Repeated
exposure, retrieval, replies and public vote totals supply no implicit interest.
Each selected external endorser counts once, at most four. Self-endorsement and
unselected owners add zero. Same exact post/revision reached through several
repost routes merges source affinity and distinct selected endorsers. This merge
is order-independent; inconsistent canonical metadata is rejected.

Selection sorts deterministically, then keeps at most two posts per original
owner and one per root per page. A page can be short. These caps prevent one
fleet/root taking a whole page, but cheap independent owners still occupy
exploration candidates. This is an explicit limitation, not Sybil resistance.
Pure weights are behavioral defaults, not a claim of optimal human relevance.
The prototype caps total endorser processing at 1,048,576 attempts independently
of whether the endorse list yields eligible results. A production API should
accept already deduplicated selected-owner evidence under a smaller query budget.

Recommend no mandatory exploration slot in initial release: explicit source
preferences are predictable and deny Sybils a guaranteed slot. An opt-in wider
candidate mode can be compared later against actual reader utility. Mute/hide
is a prefilter; negative affinity lowers score but is not a substitute for mute.
Following and Discover must remain separate modes.

## Reproduction and measurement scope

```sh
cargo fmt --manifest-path prototypes/social-discovery/Cargo.toml -- --check
cargo test --manifest-path prototypes/social-discovery/Cargo.toml --locked --offline
cargo clippy --manifest-path prototypes/social-discovery/Cargo.toml --all-targets --locked --offline -- -D warnings
/Users/bg/.bun/bin/hra-host-run --mode=shared --lane=compute --label=valhalla-discovery-measure -- /bin/sh /Users/bg/Documents/Codex/valhalla/prototypes/social-discovery/measure.sh
```

Native benchmarks belong inside the host scheduler. `measure.sh` uses macOS
`time -l` for process peak RSS. It measures exactly 64/256/1024/4096 signed
records, with one genesis, 62 posts, and one Seal per 64-record group. Thus the
largest corpus has 3968 admitted posts, never 4096 posts plus hidden controls.
The 4096-record case is at capacity; committed history remains searchable while
current live authority is closed. No canonical evidence is evicted.

Report signing/snapshot creation, verified archive restoration, semantic view and
post construction, index build, query latency and vector payload separately.
Query figures average 20 repeated warm queries, not tail latency or a statistical
distribution. Index vector payload includes capacity but excludes allocator
metadata and build scratch. `PostView` inline bytes exclude nested allocations.
Document rows borrow text, so text bytes are not copied into the query corpus.
Peak RSS is the entire example process, including signing, serialized bytes,
archive, view, index, runtime and allocator retention; it is not isolated peak
query allocation. Embedded/WASM execution is not measured by native numbers.

## Results

The scheduled native release run completed on 2026-09-13 with exit 0: all eight
64/256/1024/4096-record by 256/4096-byte fixtures admitted their exact expected
signed corpus, and all four queries produced identical complete scan/index
results under the measurement budget. The console receipt was truncated; the
complete rows retained below are a subset of the measurements, not invented
values for the missing rows. A second receipt capture was not admitted, so the
missing intermediate rows remain an evidence gap.
The host was Darwin arm64 using Rust 1.97.1; compilation used the release profile.

All table times are microseconds. Query times average twenty warm queries using
the 64 Mi comparison measurement budget; the separate default 16 Mi coverage
flag was also checked. “Absent” means `zzzzzzzzz`; “phrase” means
`rust "proof budget"`.

| Signed records / post bytes | Posts | Sign + raw snapshot | Verified restore | View + posts | Index build | Phrase scan / index | Absent scan / index |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 / 256 | 62 | 2,641 | 3,272 | 506 | 669 | 9 / 12 | 20 / <1 |
| 1,024 / 4,096 | 992 | 61,980 | 67,814 | 8,489 | 83,705 | 249 / 304 | 5,191 / 4 |
| 4,096 / 4,096 | 3,968 | 249,384 | 293,178 | 47,965 | 330,294 | 858 / 1,092 | 19,098 / 17 |

| Signed records / post bytes | Text bytes | Signed snapshot bytes | Document descriptor capacity bytes | PostView inline capacity bytes | Index capacity bytes | Whole-process peak RSS bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 64 / 256 | 15,872 | 32,079 | 14,848 | 56,320 | 86,016 | receipt unavailable |
| 1,024 / 4,096 | 4,063,232 | 4,322,124 | 237,568 | 901,120 | 1,622,016 | 18,595,840 |
| 4,096 / 4,096 | 16,252,928 | 17,288,412 | 950,272 | 3,604,480 | 6,488,064 | 63,553,536 |

At the largest corpus, absent-term scanning required 16,838,208 byte comparisons;
the default budget correctly returned partial coverage instead of a complete
zero. The complete measurement used 19.098 ms; the index used 40 comparisons and
17 µs after a 330.294 ms build. A mixed common/short query, `owner 13`, took
17,378 / 18,001 µs (scan/index), while the two-byte query `é` used the scanner
fallback at 648 / 645 µs. Neither common matches nor short terms justify the
index here. Repeated selective queries may amortize its build, but this corpus
alone does not establish a portable memory or relevance tradeoff.

Keep the maintained scanner baseline and expose exhausted coverage. A future
optional index needs workload evidence, invalidation qualification and actual
WASM/embedded memory measurements. RSS above includes both strategies plus the
signing/archive/view lifecycle; it cannot be attributed to query allocation.
The prototype byte-comparison budget also differs from the maintained query's
additional metadata/scoring allowance. Native prototype latency does not measure
the maintained snapshot's complete end-to-end query cost.

`measure.sh OPTIONAL_NEW_RECEIPT_PATH` captures future full receipts and refuses
to overwrite an existing file. Run it through the same scheduler command above,
adding that output path after the script path.
