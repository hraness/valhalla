//! Bounded artifact assembly: the happy path over a 200,000-byte artifact in
//! order, out of order, with duplicates, and through the browser record
//! mapping; every refusal the plan's **Bounded artifacts** section names; the
//! 8 MiB, 128-block worst case inside the retained-bytes cap; and properties
//! over random sizes that any permutation with duplicates completes and any
//! single corrupted block never does.

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use vhalla_game_platonik::artifact::{
    block_from_records, join_records, split_block, Accepted, ArtifactAssembly, ArtifactError,
    ArtifactSlots, RecordError, MAX_RECORDS_PER_BLOCK, RECORD_BODY_LEN, RECORD_HEADER_LEN,
};
use vhalla_game_platonik::ids::{InnerArtifactId, InnerKind, SessionKey};
use vhalla_game_platonik::manifest::MAX_ARTIFACT_BYTES;
use vhalla_game_platonik::wire::{ArtifactManifest, ArtifactRequest, Block, BLOCK_LEN, MAX_BLOCKS};

const SESSION: SessionKey = SessionKey([7; 32]);
const OTHER_SESSION: SessionKey = SessionKey([8; 32]);
/// Four blocks: three full and an exact 3,392-byte remainder.
const ARTIFACT_LEN: usize = 200_000;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Deterministic pseudo-random bytes, so a test names an exact artifact.
fn artifact(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn manifest_of(bytes: &[u8]) -> ArtifactManifest {
    ArtifactManifest {
        id: InnerArtifactId {
            kind: InnerKind::FrameTraceV1,
            sha256: sha256(bytes),
        },
        total_len: bytes.len() as u64,
        block_len: BLOCK_LEN,
        blocks: bytes.chunks(BLOCK_LEN as usize).map(sha256).collect(),
        decompressed_len: bytes.len() as u64,
    }
}

fn request_of(manifest: &ArtifactManifest, max_bytes: u64) -> ArtifactRequest {
    ArtifactRequest {
        session: SESSION,
        id: manifest.id,
        max_bytes,
        nonce: [9; 32],
    }
}

fn blocks_of(manifest: &ArtifactManifest, bytes: &[u8]) -> Vec<Block> {
    let hash = manifest.hash();
    bytes
        .chunks(BLOCK_LEN as usize)
        .enumerate()
        .map(|(index, chunk)| Block {
            manifest: hash,
            index: index as u8,
            offset: index as u64 * u64::from(BLOCK_LEN),
            bytes: chunk.to_vec(),
        })
        .collect()
}

/// An artifact, its manifest, its request, and its blocks.
struct Fixture {
    bytes: Vec<u8>,
    manifest: ArtifactManifest,
    request: ArtifactRequest,
    blocks: Vec<Block>,
}

fn fixture(len: usize, seed: u64) -> Fixture {
    let bytes = artifact(len, seed);
    let manifest = manifest_of(&bytes);
    let request = request_of(&manifest, MAX_ARTIFACT_BYTES);
    let blocks = blocks_of(&manifest, &bytes);
    Fixture {
        bytes,
        manifest,
        request,
        blocks,
    }
}

impl Fixture {
    fn open(&self) -> ArtifactAssembly {
        ArtifactAssembly::open(&self.request, &self.manifest, 0, 1_000).unwrap()
    }
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn two_hundred_thousand_bytes_assemble_in_order() {
    let f = fixture(ARTIFACT_LEN, 1);
    assert_eq!(f.blocks.len(), 4, "three full blocks and a remainder");
    assert_eq!(f.blocks[3].bytes.len(), ARTIFACT_LEN - 3 * 65_536);
    let mut assembly = f.open();
    assert_eq!(assembly.block_count(), 4);
    assert_eq!(assembly.retained(), 0, "nothing is held before a block");
    for (step, block) in f.blocks.iter().enumerate() {
        let want = if step + 1 == f.blocks.len() {
            Accepted::Complete
        } else {
            Accepted::Stored
        };
        assert_eq!(assembly.accept(block, step as u64).unwrap(), want);
    }
    assert!(assembly.is_complete());
    assert_eq!(assembly.retained(), ARTIFACT_LEN as u64);
    assert_eq!(assembly.peak_retained(), ARTIFACT_LEN as u64);
    assert!(assembly.peak_retained() <= assembly.retained_cap());
    assert_eq!(
        assembly.hashes(),
        5,
        "one per block plus one over the whole"
    );
    assert_eq!(assembly.hashes(), assembly.max_hashes());
    println!(
        "artifact {} bytes, {} blocks, peak retained {} of a {} cap, {} SHA-256 invocations",
        f.bytes.len(),
        assembly.block_count(),
        assembly.peak_retained(),
        assembly.retained_cap(),
        assembly.hashes()
    );
    assert_eq!(assembly.take().unwrap(), f.bytes);
}

#[test]
fn blocks_out_of_order_and_duplicated_assemble_the_same_bytes() {
    let f = fixture(ARTIFACT_LEN, 2);
    let mut assembly = f.open();
    let order = [2_usize, 2, 0, 3, 0, 1];
    let mut completed = false;
    for (step, index) in order.into_iter().enumerate() {
        match assembly.accept(&f.blocks[index], step as u64).unwrap() {
            Accepted::Complete => completed = true,
            Accepted::Stored | Accepted::Duplicate => {}
            Accepted::Restart => panic!("no manifest changed"),
        }
    }
    assert!(completed);
    assert_eq!(
        assembly.hashes(),
        5,
        "a duplicate costs no SHA-256 invocation"
    );
    assert_eq!(assembly.take().unwrap(), f.bytes);
}

#[test]
fn a_duplicate_after_completion_is_refused_as_closed() {
    let f = fixture(ARTIFACT_LEN, 3);
    let mut assembly = f.open();
    for (step, block) in f.blocks.iter().enumerate() {
        assembly.accept(block, step as u64).unwrap();
    }
    assert_eq!(
        assembly.accept(&f.blocks[0], 10),
        Err(ArtifactError::Closed)
    );
}

#[test]
fn the_browser_record_mapping_delivers_the_same_blocks() {
    let f = fixture(ARTIFACT_LEN, 4);
    let mut assembly = f.open();
    let mut records_seen = 0;
    let mut widest_record = 0;
    for (step, block) in f.blocks.iter().enumerate() {
        let records = split_block(block).unwrap();
        assert!(records.len() <= MAX_RECORDS_PER_BLOCK);
        for (at, record) in records.iter().enumerate() {
            let body = record.len() - RECORD_HEADER_LEN;
            let last = at + 1 == records.len();
            assert!(
                body == RECORD_BODY_LEN || last,
                "only the final body is a remainder"
            );
            widest_record = widest_record.max(record.len());
        }
        records_seen += records.len();
        let rebuilt =
            block_from_records(block.manifest, block.index, block.offset, &records).unwrap();
        assert_eq!(&rebuilt, block, "the mapping is the identity on a block");
        assert_eq!(
            sha256(&rebuilt.bytes),
            f.manifest.blocks[usize::from(block.index)],
            "the block digest is unchanged by the mapping"
        );
        assembly.accept(&rebuilt, step as u64).unwrap();
    }
    assert!(assembly.is_complete());
    println!(
        "browser path: {records_seen} records, widest {widest_record} bytes, \
         peak retained {} plus one {} byte block buffer",
        assembly.peak_retained(),
        BLOCK_LEN
    );
    assert_eq!(assembly.take().unwrap(), f.bytes);
}

#[test]
fn an_empty_block_is_one_header_only_record() {
    let block = Block {
        manifest: manifest_of(&[]).hash(),
        index: 0,
        offset: 0,
        bytes: Vec::new(),
    };
    let records = split_block(&block).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].len(), RECORD_HEADER_LEN);
    assert_eq!(records[0][12..RECORD_HEADER_LEN], sha256(&[]));
    assert_eq!(join_records(&records).unwrap(), Vec::<u8>::new());
}

#[test]
fn a_zero_length_artifact_completes_at_opening() {
    let f = fixture(0, 5);
    let assembly = f.open();
    assert_eq!(assembly.block_count(), 0);
    assert!(assembly.is_complete());
    assert_eq!(assembly.hashes(), 1);
    assert_eq!(assembly.take().unwrap(), Vec::<u8>::new());
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_for_another_artifact_is_refused() {
    let f = fixture(ARTIFACT_LEN, 6);
    let mut manifest = f.manifest.clone();
    manifest.id.sha256[0] ^= 1;
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::IdMismatch
    );
    let mut manifest = f.manifest.clone();
    manifest.id.kind = InnerKind::PlatonikReceiptV1;
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::IdMismatch,
        "the kind is part of the id"
    );
}

#[test]
fn any_block_length_but_the_fixed_one_is_refused() {
    let f = fixture(ARTIFACT_LEN, 7);
    let mut manifest = f.manifest.clone();
    manifest.block_len = 32_768;
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::BlockLen
    );
}

#[test]
fn a_decompressed_length_mismatch_is_refused() {
    let f = fixture(ARTIFACT_LEN, 8);
    let mut manifest = f.manifest.clone();
    manifest.decompressed_len = f.bytes.len() as u64 * 160;
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::Compressed,
        "v1 carries no compression, so no expansion ratio is admissible"
    );
}

#[test]
fn a_total_above_the_request_or_above_eight_mebibytes_is_refused() {
    let f = fixture(ARTIFACT_LEN, 9);
    let tight = request_of(&f.manifest, (ARTIFACT_LEN - 1) as u64);
    assert_eq!(
        ArtifactAssembly::open(&tight, &f.manifest, 0, 10).unwrap_err(),
        ArtifactError::TooLarge
    );

    let bytes = artifact(0, 1);
    let huge = ArtifactManifest {
        id: InnerArtifactId {
            kind: InnerKind::PlatonikReceiptV1,
            sha256: sha256(&bytes),
        },
        total_len: MAX_ARTIFACT_BYTES + 1,
        block_len: BLOCK_LEN,
        blocks: vec![[0; 32]; MAX_BLOCKS + 1],
        decompressed_len: MAX_ARTIFACT_BYTES + 1,
    };
    let request = request_of(&huge, u64::MAX);
    assert_eq!(
        ArtifactAssembly::open(&request, &huge, 0, 10).unwrap_err(),
        ArtifactError::TooLarge,
        "Platonik's 32 MiB checkpoints and 64 MiB bundles are refused, never chunked further"
    );
}

#[test]
fn a_block_count_inconsistent_with_the_total_is_refused() {
    let f = fixture(ARTIFACT_LEN, 10);
    let mut manifest = f.manifest.clone();
    manifest.blocks.push([0; 32]);
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::BlockCount,
        "too many blocks for the declared total"
    );
    let mut manifest = f.manifest.clone();
    manifest.blocks.pop();
    assert_eq!(
        ArtifactAssembly::open(&f.request, &manifest, 0, 10).unwrap_err(),
        ArtifactError::BlockCount,
        "too few blocks for the declared total"
    );
}

#[test]
fn a_block_index_past_the_manifest_is_refused() {
    let f = fixture(ARTIFACT_LEN, 11);
    let mut assembly = f.open();
    let mut block = f.blocks[0].clone();
    block.index = 4;
    block.offset = 4 * u64::from(BLOCK_LEN);
    assert_eq!(assembly.accept(&block, 0), Err(ArtifactError::BlockIndex));
    assert_eq!(assembly.retained(), 0);
}

#[test]
fn a_wrong_offset_is_refused() {
    let f = fixture(ARTIFACT_LEN, 12);
    let mut assembly = f.open();
    let mut block = f.blocks[1].clone();
    block.offset += 1;
    assert_eq!(assembly.accept(&block, 0), Err(ArtifactError::BlockOffset));
    let mut block = f.blocks[1].clone();
    block.index = 2;
    assert_eq!(
        assembly.accept(&block, 0),
        Err(ArtifactError::BlockOffset),
        "an index moved away from its offset is refused before any hashing"
    );
    assert_eq!(assembly.hashes(), 0);
}

#[test]
fn a_wrong_block_digest_is_refused() {
    let f = fixture(ARTIFACT_LEN, 13);
    let mut assembly = f.open();
    let mut block = f.blocks[0].clone();
    block.bytes[100] ^= 0xFF;
    assert_eq!(assembly.accept(&block, 0), Err(ArtifactError::BlockDigest));
    assert_eq!(assembly.stored_blocks(), 0);
    assert_eq!(assembly.retained(), 0, "a refused block retains nothing");
    assert_eq!(assembly.hashes(), 1);
    assert_eq!(assembly.accept(&f.blocks[0], 1).unwrap(), Accepted::Stored);
}

#[test]
fn a_wrong_length_is_refused_for_a_full_block_and_for_the_final_one() {
    let f = fixture(ARTIFACT_LEN, 14);
    let mut assembly = f.open();
    let mut short = f.blocks[0].clone();
    short.bytes.truncate(1024);
    assert_eq!(assembly.accept(&short, 0), Err(ArtifactError::BlockLength));
    let mut long = f.blocks[3].clone();
    long.bytes.push(0);
    assert_eq!(
        assembly.accept(&long, 1),
        Err(ArtifactError::BlockLength),
        "the final block is the exact remainder"
    );
    let mut short_final = f.blocks[3].clone();
    short_final.bytes.pop();
    assert_eq!(
        assembly.accept(&short_final, 2),
        Err(ArtifactError::BlockLength)
    );
    assert_eq!(assembly.hashes(), 0, "a length is checked before a digest");
}

#[test]
fn a_changed_manifest_for_the_same_id_restarts_and_drops_everything() {
    let f = fixture(ARTIFACT_LEN, 15);
    let mut assembly = f.open();
    assembly.accept(&f.blocks[0], 0).unwrap();
    assert_eq!(assembly.retained(), ARTIFACT_LEN as u64);

    // Same artifact id and bytes, a different manifest: one block re-split at
    // a different, inadmissible block length would change nothing the receiver
    // can check, so the holder is simply speaking about another manifest.
    let mut changed = f.manifest.clone();
    changed.blocks[0][0] ^= 1;
    let restarted = Block {
        manifest: changed.hash(),
        ..f.blocks[1].clone()
    };
    assert_eq!(assembly.accept(&restarted, 1).unwrap(), Accepted::Restart);
    assert!(assembly.is_closed());
    assert_eq!(assembly.retained(), 0, "everything is dropped on a restart");
    assert_eq!(assembly.stored_blocks(), 0);
    assert_eq!(
        assembly.accept(&f.blocks[0], 2),
        Err(ArtifactError::Closed),
        "a restarted assembly never accepts again"
    );
    assert_eq!(assembly.take().unwrap_err(), ArtifactError::Closed);
}

#[test]
fn a_wrong_whole_artifact_digest_discards_the_artifact() {
    let bytes = artifact(ARTIFACT_LEN, 16);
    // Every block digest is honest; only the id the session committed to
    // disagrees, which is the only check that can catch a re-blocked artifact.
    let mut manifest = manifest_of(&bytes);
    manifest.id.sha256[31] ^= 1;
    let request = request_of(&manifest, MAX_ARTIFACT_BYTES);
    let blocks = blocks_of(&manifest, &bytes);
    let mut assembly = ArtifactAssembly::open(&request, &manifest, 0, 100).unwrap();
    for block in &blocks[..3] {
        assert_eq!(assembly.accept(block, 0).unwrap(), Accepted::Stored);
    }
    assert_eq!(
        assembly.accept(&blocks[3], 0),
        Err(ArtifactError::DigestMismatch)
    );
    assert!(assembly.is_closed());
    assert_eq!(assembly.retained(), 0);
    assert_eq!(assembly.hashes(), 5);
    assert_eq!(assembly.take().unwrap_err(), ArtifactError::Closed);
}

#[test]
fn blocks_after_the_step_deadline_are_refused() {
    let f = fixture(ARTIFACT_LEN, 17);
    let mut assembly = ArtifactAssembly::open(&f.request, &f.manifest, 4, 6).unwrap();
    assert_eq!(assembly.accept(&f.blocks[0], 5).unwrap(), Accepted::Stored);
    assert_eq!(
        assembly.accept(&f.blocks[1], 3),
        Err(ArtifactError::StepNotMonotone),
        "a step never goes backwards"
    );
    assert_eq!(assembly.accept(&f.blocks[1], 6).unwrap(), Accepted::Stored);
    assert_eq!(
        assembly.accept(&f.blocks[2], 7),
        Err(ArtifactError::DeadlinePassed)
    );
    assert!(assembly.is_closed());
    assert_eq!(assembly.retained(), 0, "the deadline frees every byte");
    assert_eq!(
        ArtifactAssembly::open(&f.request, &f.manifest, 5, 4).unwrap_err(),
        ArtifactError::Deadline
    );
}

#[test]
fn incomplete_bytes_are_never_yielded() {
    let f = fixture(ARTIFACT_LEN, 18);
    let mut assembly = f.open();
    assembly.accept(&f.blocks[0], 0).unwrap();
    assert_eq!(assembly.take().unwrap_err(), ArtifactError::NotComplete);
}

// ---------------------------------------------------------------------------
// Per-session and receiver-wide caps
// ---------------------------------------------------------------------------

#[test]
fn a_session_drives_one_assembly_at_a_time() {
    let f = fixture(ARTIFACT_LEN, 19);
    let mut slots = ArtifactSlots::new(4);
    slots
        .open(SESSION, &f.request, &f.manifest, 0, 100)
        .unwrap();
    assert_eq!(
        slots.open(SESSION, &f.request, &f.manifest, 0, 100),
        Err(ArtifactError::SessionBusy)
    );
    for (step, block) in f.blocks.iter().enumerate() {
        slots.accept(SESSION, block, step as u64).unwrap();
    }
    assert_eq!(
        slots.open(SESSION, &f.request, &f.manifest, 5, 100),
        Err(ArtifactError::SessionBusy),
        "a completed assembly holds its slot until the bytes are taken"
    );
    assert_eq!(slots.take(SESSION).unwrap(), f.bytes);
    assert!(slots.is_empty());
    assert_eq!(slots.peak_retained(), ARTIFACT_LEN as u64);
    slots
        .open(SESSION, &f.request, &f.manifest, 6, 100)
        .unwrap();
    assert_eq!(slots.len(), 1);
    assert_eq!(slots.take(SESSION).unwrap_err(), ArtifactError::NotComplete);
    slots.abort(SESSION).unwrap();
    assert!(slots.is_empty());
    assert_eq!(slots.take(SESSION).unwrap_err(), ArtifactError::NoAssembly);
}

#[test]
fn an_aborted_assembly_frees_its_session_at_once() {
    let f = fixture(ARTIFACT_LEN, 20);
    let mut slots = ArtifactSlots::new(2);
    slots
        .open(SESSION, &f.request, &f.manifest, 0, 100)
        .unwrap();
    slots.accept(SESSION, &f.blocks[0], 0).unwrap();
    let mut changed = f.manifest.clone();
    changed.blocks[1][0] ^= 1;
    let restarted = Block {
        manifest: changed.hash(),
        ..f.blocks[1].clone()
    };
    assert_eq!(
        slots.accept(SESSION, &restarted, 1).unwrap(),
        Accepted::Restart
    );
    assert!(slots.is_empty(), "the slot is free again");
    assert_eq!(slots.retained(), 0);
    slots
        .open(SESSION, &f.request, &f.manifest, 2, 100)
        .unwrap();
}

#[test]
fn the_receiver_wide_cap_refuses_one_assembly_too_many() {
    let f = fixture(ARTIFACT_LEN, 21);
    let mut slots = ArtifactSlots::new(1);
    assert_eq!(slots.max_concurrent(), 1);
    slots
        .open(SESSION, &f.request, &f.manifest, 0, 100)
        .unwrap();
    assert_eq!(
        slots.open(OTHER_SESSION, &f.request, &f.manifest, 0, 100),
        Err(ArtifactError::ReceiverFull)
    );
    assert_eq!(
        slots.accept(OTHER_SESSION, &f.blocks[0], 0),
        Err(ArtifactError::NoAssembly)
    );
    slots.abort(SESSION).unwrap();
    slots
        .open(OTHER_SESSION, &f.request, &f.manifest, 1, 100)
        .unwrap();
    assert_eq!(slots.len(), 1);
}

// ---------------------------------------------------------------------------
// The record mapping's own refusals
// ---------------------------------------------------------------------------

#[test]
fn record_sequences_are_checked_before_they_are_joined() {
    let f = fixture(ARTIFACT_LEN, 22);
    let records = split_block(&f.blocks[0]).unwrap();
    assert_eq!(records.len(), MAX_RECORDS_PER_BLOCK);

    assert_eq!(join_records(&[]).unwrap_err(), RecordError::Order);

    let mut short = records.clone();
    short.pop();
    assert_eq!(join_records(&short).unwrap_err(), RecordError::Order);

    let mut reordered = records.clone();
    reordered.swap(0, 1);
    assert_eq!(join_records(&reordered).unwrap_err(), RecordError::Order);

    let mut bad_magic = records.clone();
    bad_magic[3][0] = b'X';
    assert_eq!(join_records(&bad_magic).unwrap_err(), RecordError::Format);

    let mut bad_total = records.clone();
    bad_total[2][7] ^= 1;
    assert_eq!(join_records(&bad_total).unwrap_err(), RecordError::Total);

    let mut bad_digest = records.clone();
    bad_digest[5][12] ^= 1;
    assert_eq!(join_records(&bad_digest).unwrap_err(), RecordError::Digest);

    let mut mutated = records.clone();
    let last = mutated[7].len() - 1;
    mutated[7][last] ^= 0xFF;
    assert_eq!(
        join_records(&mutated).unwrap_err(),
        RecordError::Digest,
        "a mutated body never reaches the assembly"
    );

    let mut truncated = records.clone();
    truncated[4].truncate(RECORD_HEADER_LEN + 1);
    assert_eq!(join_records(&truncated).unwrap_err(), RecordError::Length);

    let mut oversize = f.blocks[0].clone();
    oversize.bytes.push(0);
    assert_eq!(split_block(&oversize).unwrap_err(), RecordError::Length);
}

// ---------------------------------------------------------------------------
// The 8 MiB worst case
// ---------------------------------------------------------------------------

#[test]
fn eight_mebibytes_in_a_hundred_and_twenty_eight_blocks_assemble_inside_the_cap() {
    let len = MAX_ARTIFACT_BYTES as usize;
    let f = fixture(len, 23);
    assert_eq!(f.blocks.len(), MAX_BLOCKS);
    assert!(f.blocks.iter().all(|b| b.bytes.len() == BLOCK_LEN as usize));
    let mut assembly = f.open();
    // Deliver every second block first, so half the artifact is held before
    // the gaps close: the retained-bytes ceiling has to hold throughout.
    let order: Vec<usize> = (0..MAX_BLOCKS)
        .step_by(2)
        .chain((1..MAX_BLOCKS).step_by(2))
        .collect();
    let mut peak = 0_u64;
    for (step, index) in order.into_iter().enumerate() {
        assembly.accept(&f.blocks[index], step as u64).unwrap();
        peak = peak.max(assembly.retained());
        assert!(assembly.retained() <= assembly.retained_cap());
    }
    assert!(assembly.is_complete());
    assert_eq!(assembly.hashes(), MAX_BLOCKS as u64 + 1);
    println!(
        "8 MiB worst case: {} blocks, peak retained {peak} bytes, cap {} bytes ({:.3} x), \
         {} SHA-256 invocations",
        MAX_BLOCKS,
        assembly.retained_cap(),
        peak as f64 / len as f64,
        assembly.hashes()
    );
    assert!(peak <= assembly.retained_cap());
    assert_eq!(assembly.take().unwrap(), f.bytes);
}

// ---------------------------------------------------------------------------
// Properties over random sizes
// ---------------------------------------------------------------------------

/// A deterministic permutation of `0..count`, with every index repeated once
/// so duplicates are always in the schedule.
fn schedule(count: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).chain(0..count).collect();
    let mut state = seed | 1;
    for at in (1..order.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        order.swap(at, (state % (at as u64 + 1)) as usize);
    }
    order
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Any delivery order, with every block sent twice, completes and yields
    /// the exact bytes.
    #[test]
    fn any_permutation_with_duplicates_completes(
        len in 0_usize..=300_000,
        seed in any::<u64>(),
    ) {
        let f = fixture(len, seed | 1);
        let mut assembly = f.open();
        let mut completed = f.blocks.is_empty();
        for (step, index) in schedule(f.blocks.len(), seed ^ 0x5A5A).into_iter().enumerate() {
            match assembly.accept(&f.blocks[index], step as u64) {
                Ok(Accepted::Complete) => completed = true,
                Ok(Accepted::Stored | Accepted::Duplicate) => {}
                Ok(Accepted::Restart) => prop_assert!(false, "no manifest changed"),
                Err(ArtifactError::Closed) => prop_assert!(completed),
                Err(error) => prop_assert!(false, "{error:?}"),
            }
            prop_assert!(assembly.retained() <= assembly.retained_cap());
        }
        prop_assert!(completed);
        prop_assert!(assembly.hashes() <= assembly.max_hashes());
        prop_assert_eq!(assembly.take().unwrap(), f.bytes);
    }

    /// One corrupted block, in any position of any delivery order, never
    /// completes: the block is refused and its index is never filled.
    #[test]
    fn a_single_corrupted_block_never_completes(
        len in 1_usize..=300_000,
        seed in any::<u64>(),
    ) {
        let f = fixture(len, seed | 1);
        let count = f.blocks.len();
        let corrupt = (seed as usize) % count;
        let at = (seed as usize / 7) % f.blocks[corrupt].bytes.len();
        let mut delivered = f.blocks.clone();
        delivered[corrupt].bytes[at] ^= 0xFF;
        let mut assembly = f.open();
        let mut order: Vec<usize> = (0..count).collect();
        order.rotate_left((seed as usize / 3) % count);
        for (step, index) in order.into_iter().enumerate() {
            match assembly.accept(&delivered[index], step as u64) {
                Ok(Accepted::Complete) => prop_assert!(false, "a corrupted block completed"),
                Ok(_) => prop_assert_ne!(index, corrupt),
                Err(ArtifactError::BlockDigest) => prop_assert_eq!(index, corrupt),
                Err(error) => prop_assert!(false, "{error:?}"),
            }
        }
        prop_assert!(!assembly.is_complete());
        prop_assert_eq!(assembly.stored_blocks(), count - 1);
        prop_assert_eq!(assembly.take().unwrap_err(), ArtifactError::NotComplete);
    }

    /// The record mapping is the identity on every block of every size, and
    /// leaves the block digest alone.
    #[test]
    fn the_record_mapping_round_trips_every_block(
        len in 0_usize..=300_000,
        seed in any::<u64>(),
    ) {
        let f = fixture(len, seed | 1);
        for block in &f.blocks {
            let records = split_block(block).unwrap();
            prop_assert!(records.len() <= MAX_RECORDS_PER_BLOCK);
            let bytes = join_records(&records).unwrap();
            prop_assert_eq!(&bytes, &block.bytes);
            prop_assert_eq!(
                sha256(&bytes),
                f.manifest.blocks[usize::from(block.index)]
            );
        }
    }
}
