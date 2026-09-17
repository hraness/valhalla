//! Native timing of the hashing observer over the corpus and the worst case,
//! and the invariant that observation changes nothing.

use std::time::Instant;

use game_trace_cost::{run_corpus, trace, VECTORS};

#[test]
fn observation_changes_nothing_and_is_within_budget() {
    let rendering = run_corpus();
    assert!(!rendering.contains("error"), "{rendering}");
    let mut worst_ms = 0.0_f64;
    let mut worst = String::new();
    let mut total_frames = 0;
    let mut total_state = 0;
    let mut samples = Vec::new();
    for (name, text) in VECTORS {
        let mut best = f64::MAX;
        let mut traced = None;
        for _ in 0..3 {
            let start = Instant::now();
            let t = trace(text).unwrap();
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            best = best.min(elapsed);
            traced = Some(t);
        }
        let traced = traced.unwrap();
        total_frames += traced.frames;
        total_state += traced.state_bytes;
        samples.push(best);
        if best > worst_ms {
            worst_ms = best;
            worst = name.to_string();
        }
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
    println!(
        "hashed {total_frames} frames, {total_state} state bytes over {} vectors; p95 {p95:.2} ms; worst {worst} {worst_ms:.2} ms (best of 3, {} profile)",
        VECTORS.len(),
        if cfg!(debug_assertions) { "debug" } else { "release" }
    );
    if !cfg!(debug_assertions) {
        assert!(
            worst_ms <= 100.0,
            "native worst case {worst_ms:.2} ms exceeds 100 ms"
        );
    }
}
