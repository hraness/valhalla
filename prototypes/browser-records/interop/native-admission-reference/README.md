# Native WebRTC admission reference

**Reference only; not activated.** This preserves the independently reviewed
disposable repair for `libp2p-webrtc` **0.10.0-alpha**. No Cargo patch, workspace
dependency, listener, browser deployment, or maintained adapter selects it.

The original [notes](admission-repair-notes.md), [results](admission-repair-results.json),
[source hashes](admission-repair-hashes.json), [patch](admission-repair.patch),
fixture manifest, and lockfile are preserved byte for byte. Historical absolute
paths identify the original run; they are not portable setup instructions.
[provenance.json](provenance.json) identifies the immutable registry archive and
VCS origin. `SHA256SUMS` checks the retained artifacts. The source's MIT notice is
reproduced in [LICENSE-MIT.upstream](LICENSE-MIT.upstream).

The historical gate passed **18 library tests** (six upstream and twelve new),
formatting, and strict library Clippy on the recorded Rust 1.97.1 toolchain.
Preservation additionally verified that the unchanged patch reconstructs both
recorded candidate source hashes from the immutable registry archive. The
eighteen tests were not rerun merely to retain these reference bytes.

## Portable reproduction

Use a **new disposable directory**, never the registry cache or maintained
Valhalla source. Obtain the exact archive from an existing Cargo cache or the
[immutable crate download](https://static.crates.io/crates/libp2p-webrtc/libp2p-webrtc-0.10.0-alpha.crate).
Its SHA-256 must be:

```text
f22c63271ed36da0385b8efb58dc4df9448720299a913f13147879c748620d6f
```

From this reference directory, substitute the archive path below. Preparation
requires Python 3.12+ and Git:

```sh
reference_dir="$PWD"
crate_archive=/absolute/path/to/libp2p-webrtc-0.10.0-alpha.crate
reproduction_dir=$(mktemp -d "${TMPDIR:-/tmp}/vhalla-admission.XXXXXX")
python3 - "$reference_dir" "$crate_archive" "$reproduction_dir" <<'PY'
from pathlib import Path
import hashlib, json, shutil, subprocess, sys, tarfile
reference, archive, target = map(Path, sys.argv[1:])
digest = lambda raw: hashlib.sha256(raw).hexdigest()
provenance = json.loads((reference / "provenance.json").read_text())
results = json.loads((reference / "admission-repair-results.json").read_text())
assert digest(archive.read_bytes()) == provenance["upstream"]["crate_sha256"]
for name, field in (("admission-repair.patch", "patch_sha256"),
                    ("Cargo.toml", "cargo_manifest_sha256"),
                    ("Cargo.lock", "cargo_lock_sha256")):
    assert digest((reference / name).read_bytes()) == results[field]
with tarfile.open(archive) as source:
    source.extractall(target, filter="data")
crate = target / "libp2p-webrtc-0.10.0-alpha"
for name, expected in provenance["upstream"]["pristine_source_sha256"].items():
    assert digest((crate / "src/tokio" / name).read_bytes()) == expected
# The diagnostic probe was removed before the original diff, leaving one LF.
mux = crate / "src/tokio/udp_mux.rs"
mux.write_bytes(mux.read_bytes() + b"\n")
for name, hashes in results["source_hashes"].items():
    assert digest((crate / "src/tokio" / name).read_bytes()) == hashes["baseline_sha256"]
patch = str(reference / "admission-repair.patch")
subprocess.run(["git", "apply", "--check", patch], cwd=crate, check=True)
subprocess.run(["git", "apply", patch], cwd=crate, check=True)
for name, hashes in results["source_hashes"].items():
    assert digest((crate / "src/tokio" / name).read_bytes()) == hashes["candidate_sha256"]
for name in ("Cargo.toml", "Cargo.lock"):
    shutil.copyfile(reference / name, crate / name)
print(crate)
PY
reproduction_crate="$reproduction_dir/libp2p-webrtc-0.10.0-alpha"
cargo fmt --manifest-path "$reproduction_crate/Cargo.toml" --check
cargo test --manifest-path "$reproduction_crate/Cargo.toml" --lib --features tokio --locked --offline -- --nocapture
cargo clippy --manifest-path "$reproduction_crate/Cargo.toml" --lib --features tokio --locked --offline -- -D warnings
```

Use the applicable host scheduler for native/process checks on managed Hraness
machines. Offline commands require the locked dependencies in the local cache;
a missing dependency is not a successful reproduction. Preserve the lock and
use an explicit dependency-fetch step when needed. Do not remove `--locked` or
substitute newer upstream versions. The manifest retains the historical reduced
dev-dependency selection and empty workspace. These commands do **not** claim
upstream standalone smoke/integration coverage.

The separately preserved `native-admission-probe.rs` is the original diagnostic
for an **unmodified** disposable crate. Do not append it to the repair candidate:
its retained-state assertion intentionally describes the upstream bug.

## Unqualified boundaries

The candidate bounds inspected reservation, connection, and address tables and
repairs tested cancellation/generation/writer/source-routing races. Packet
probes use owned loopback sockets, finite sends, and deadlines. There is no real
successful browser/native handshake against this patch, whole-process memory
or task bound, or proof that cancellation closes every upstream RTC/ICE/DTLS/SCTP
resource. Outbound unscoped cleanup, full RTC lifecycle custody, mixed-load
fairness, and stronger interleaving tests remain open. See the original notes
for complete limitations. Public activation stays blocked.

This nested reference lock is separate from the workspace and active interop
locks. Dependency auditing must explicitly include
`prototypes/browser-records/interop/native-admission-reference/Cargo.lock`.
