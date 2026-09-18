//! Corpus-seeded decoder fuzzing for `vhalla-game-platonik`, on the stable
//! toolchain and with no `cargo-fuzz`, no libFuzzer, and no nightly feature.
//!
//! Every harness is an ordinary `#[test]`. It loads the committed corpus of
//! one decoder from `corpus/<decoder>/*.hex`, checks that every seed decodes
//! and re-encodes to itself, then runs a deterministic mutation loop at a
//! fixed seed and a fixed iteration cap. Two properties are asserted on every
//! candidate:
//!
//! 1. the decoder never panics, whatever the bytes are, and
//! 2. the canonical law: when the decoder accepts, re-encoding the decoded
//!    value reproduces the input bytes exactly.
//!
//! The second is what makes a bounded decoder a canonical decoder. If it ever
//! fails, the offending input is printed as hex, so the failure is a bug
//! report against the crate rather than a patch here.
//!
//! Runs are deterministic: the generator is a fixed xorshift, the seed and the
//! iteration cap are compiled-in constants, and the corpus is committed. The
//! same tree produces the same candidates on every machine.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

/// Iterations each decoder harness runs after its corpus is checked.
pub const ITERATIONS: usize = 20_000;

/// A fixed xorshift64* generator. No entropy, no clock, no system source: the
/// whole point is that a failing candidate is reproducible from the seed.
#[derive(Clone, Copy, Debug)]
pub struct Rng(u64);

impl Rng {
    /// A generator at a fixed seed; zero is mapped away from the fixed point.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }
    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// The next byte.
    pub fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
    /// A value below `limit`; `0` when `limit` is zero.
    pub fn below(&mut self, limit: usize) -> usize {
        if limit == 0 {
            0
        } else {
            (self.next_u64() % limit as u64) as usize
        }
    }
}

/// The mutation operators. The plan names byte flips, truncation, extension,
/// insertion, and random bytes; there are no others, so the search space is
/// exactly what the decision record says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutation {
    /// Flip one bit of one byte.
    BitFlip,
    /// Replace one byte with a fresh random byte.
    ByteFlip,
    /// Cut the input short.
    Truncate,
    /// Append bytes past the end.
    Extend,
    /// Splice bytes into the middle.
    Insert,
    /// Overwrite a span with random bytes.
    RandomBytes,
}

const MUTATIONS: [Mutation; 6] = [
    Mutation::BitFlip,
    Mutation::ByteFlip,
    Mutation::Truncate,
    Mutation::Extend,
    Mutation::Insert,
    Mutation::RandomBytes,
];

/// Applies one mutation in place.
pub fn mutate(rng: &mut Rng, buffer: &mut Vec<u8>, how: Mutation) {
    match how {
        Mutation::BitFlip => {
            if buffer.is_empty() {
                buffer.push(rng.next_u8());
                return;
            }
            let at = rng.below(buffer.len());
            buffer[at] ^= 1 << (rng.below(8) as u32);
        }
        Mutation::ByteFlip => {
            if buffer.is_empty() {
                buffer.push(rng.next_u8());
                return;
            }
            let at = rng.below(buffer.len());
            buffer[at] = rng.next_u8();
        }
        Mutation::Truncate => {
            if buffer.is_empty() {
                return;
            }
            let keep = rng.below(buffer.len());
            buffer.truncate(keep);
        }
        Mutation::Extend => {
            let extra = 1 + rng.below(16);
            for _ in 0..extra {
                buffer.push(rng.next_u8());
            }
        }
        Mutation::Insert => {
            let at = rng.below(buffer.len() + 1);
            let extra = 1 + rng.below(4);
            let bytes: Vec<u8> = (0..extra).map(|_| rng.next_u8()).collect();
            buffer.splice(at..at, bytes);
        }
        Mutation::RandomBytes => {
            if buffer.is_empty() {
                buffer.push(rng.next_u8());
                return;
            }
            let at = rng.below(buffer.len());
            let span = 1 + rng.below((buffer.len() - at).min(32));
            for byte in &mut buffer[at..at + span] {
                *byte = rng.next_u8();
            }
        }
    }
}

/// The corpus directory of one decoder.
#[must_use]
pub fn corpus_dir(decoder: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(decoder)
}

/// Loads `corpus/<decoder>/*.hex` in sorted file-name order. Each file is one
/// hex string; `#` starts a comment line and whitespace is ignored.
///
/// # Panics
///
/// Panics when the directory is missing, empty, or holds bytes that are not
/// hex: a corpus is committed evidence, so a broken one is a test failure and
/// never a silently skipped harness.
#[must_use]
pub fn load_corpus(decoder: &str) -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir(decoder);
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus {} is unreadable: {e}", dir.display()))
        .map(|entry| entry.expect("a readable corpus entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "corpus {} is empty", dir.display());
    entries
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).expect("a readable corpus file");
            let mut hex = String::new();
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                hex.push_str(line);
            }
            let raw = vhalla_witness::vectors::unhex(&hex)
                .unwrap_or_else(|| panic!("corpus file {} is not hex", path.display()));
            let name = path
                .file_name()
                .expect("a named corpus file")
                .to_string_lossy()
                .into_owned();
            (name, raw)
        })
        .collect()
}

thread_local! {
    /// The candidate the current thread is decoding, so a panic names it.
    static CURRENT: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
}

static HOOK: Once = Once::new();

/// Installs a panic hook that prints the decoder and the exact candidate hex
/// before the usual message. A decoder panic is the first thing these
/// harnesses look for, and a panic without its input is not a bug report.
fn arm_reporting() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            CURRENT.with(|cell| {
                if let Some((decoder, hex)) = cell.borrow().as_ref() {
                    eprintln!("game-fuzz: decoder {decoder} was running on input {hex}");
                }
            });
            previous(info);
        }));
    });
}

/// What one harness did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Committed seeds replayed unmutated.
    pub seeds: usize,
    /// Mutated candidates decoded.
    pub iterations: usize,
    /// Candidates the decoder accepted.
    pub accepted: usize,
    /// Candidates the decoder refused.
    pub rejected: usize,
}

/// Runs one decoder's harness: every committed seed, then [`ITERATIONS`]
/// mutated candidates from a fixed seed.
///
/// `decode` is the decoder under test and `encode` re-encodes what it
/// produced. Accepting an input obliges the pair to satisfy the canonical law.
///
/// # Panics
///
/// Panics when a seed does not decode, when a decoded value does not
/// re-encode to its input, or when the decoder itself panics; the message
/// carries the decoder name and the candidate hex.
pub fn harness<T, E, D, N>(decoder: &str, seed: u64, decode: D, encode: N) -> Report
where
    D: Fn(&[u8]) -> Result<T, E>,
    N: Fn(&T) -> Vec<u8>,
{
    arm_reporting();
    let corpus = load_corpus(decoder);
    let mut report = Report {
        seeds: corpus.len(),
        ..Report::default()
    };
    let check = |raw: &[u8]| -> bool {
        CURRENT.with(|cell| {
            *cell.borrow_mut() = Some((decoder.to_string(), vhalla_witness::vectors::hex(raw)));
        });
        let accepted = match decode(raw) {
            Ok(value) => {
                let again = encode(&value);
                assert!(
                    again == raw,
                    "{decoder} broke the canonical law: input {} re-encoded to {}",
                    vhalla_witness::vectors::hex(raw),
                    vhalla_witness::vectors::hex(&again)
                );
                true
            }
            Err(_) => false,
        };
        CURRENT.with(|cell| *cell.borrow_mut() = None);
        accepted
    };
    // A corpus seed that does not decode is a broken corpus, not a finding.
    for (name, raw) in &corpus {
        assert!(
            check(raw),
            "{decoder} corpus seed {name} does not decode; regenerate the corpus"
        );
    }
    let mut rng = Rng::new(seed);
    for _ in 0..ITERATIONS {
        let (_, base) = &corpus[rng.below(corpus.len())];
        let mut candidate = base.clone();
        let rounds = 1 + rng.below(3);
        for _ in 0..rounds {
            let how = MUTATIONS[rng.below(MUTATIONS.len())];
            mutate(&mut rng, &mut candidate, how);
        }
        report.iterations += 1;
        if check(&candidate) {
            report.accepted += 1;
        } else {
            report.rejected += 1;
        }
    }
    report
}
