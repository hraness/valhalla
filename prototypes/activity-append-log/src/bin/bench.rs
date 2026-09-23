//! Measured spike for the E-2 append-log layout: `bench NEW_HOME COUNT`.
//! Appends COUNT synthetic records through the real barrier path (log entry
//! sync, derived index write, alternating head slot sync), then reports
//! per-append p50/p95/p99, the exact F_FULLFSYNC-equivalent call count, and
//! retained file sizes. Signature verification is deliberately excluded —
//! the spike measures the durability barrier model, not admission cost.
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;
use valhalla_activity_append_log_prototype::{Store, MAX_PAGE};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: bench NEW_HOME COUNT".into());
    }
    let dir = Path::new(&args[0]);
    let count: u64 = args[1].parse().map_err(|_| "COUNT must be a number")?;
    if dir.exists() {
        return Err("home must not exist — evidence is never reused".into());
    }
    let mut store = Store::create(dir).map_err(|e| format!("create: {e:?}"))?;
    let base_syncs = store.sync_count();
    let mut samples = Vec::with_capacity(count as usize);
    let authors: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];
    let mut sequences = [0u64; 3];
    for i in 0..count {
        let a = (i % 3) as usize;
        sequences[a] += 1;
        let payload = vec![(i % 251) as u8; 512];
        let at = Instant::now();
        store
            .append(authors[a], sequences[a], &payload)
            .map_err(|e| format!("append {i}: {e:?}"))?;
        samples.push(at.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    let pick = |p: usize| samples[((samples.len() - 1) * p / 100).min(samples.len() - 1)];
    let wall = samples.iter().sum::<u64>();
    println!("appends\t{count}");
    println!("sync_calls\t{}", store.sync_count() - base_syncs);
    println!("append_p50_ns\t{}", pick(50));
    println!("append_p95_ns\t{}", pick(95));
    println!("append_p99_ns\t{}", pick(99));
    println!("append_max_ns\t{}", samples.last().copied().unwrap_or(0));
    println!("append_total_ns\t{wall}");
    // Exact retained retry: the last author-2 append again must reconcile,
    // not rewrite — same sequence, same bytes.
    let last_a2 = (0..count).rev().find(|i| i % 3 == 2).unwrap_or(0);
    let retried = store
        .append(authors[2], sequences[2], &vec![(last_a2 % 251) as u8; 512])
        .map_err(|e| format!("retry: {e:?}"))?;
    println!("retry_ordinal\t{}", retried.ordinal);
    let head = store.head();
    drop(store);
    // Cold reopen + recover + bounded page read.
    let at = Instant::now();
    let store = Store::open(dir).map_err(|e| format!("reopen: {e:?}"))?;
    println!("reopen_ns\t{}", at.elapsed().as_nanos());
    assert_eq!(store.head(), head);
    let at = Instant::now();
    let page = store
        .read_page(head.count.saturating_sub(MAX_PAGE as u64), MAX_PAGE)
        .map_err(|e| format!("page: {e:?}"))?;
    println!("read_page_ns\t{}\t{}", at.elapsed().as_nanos(), page.len());
    let mut logical = 0u64;
    let mut allocated = 0u64;
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let meta = entry
            .map_err(|e| e.to_string())?
            .metadata()
            .map_err(|e| e.to_string())?;
        logical += meta.len();
        allocated += meta.blocks() * 512;
    }
    println!("footprint_files\t{}", fs::read_dir(dir).unwrap().count());
    println!("footprint_logical_bytes\t{logical}");
    println!("footprint_allocated_bytes\t{allocated}");
    if let Err(e) = fs::remove_dir_all(dir) {
        eprintln!("cleanup failed (evidence retained): {e}");
    }
    Ok::<(), String>(())
}
