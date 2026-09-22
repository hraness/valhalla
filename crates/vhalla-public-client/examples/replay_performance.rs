//! Certified journal generation and replay baseline using real portable APIs.
//! Usage: replay_performance ABSOLUTE_NEW_HOME 1000|10000|100000
//! No validators/listeners run. Empty certified batches keep application state
//! fixed: this measures a best-case history-length baseline, not busy-room load.
#![forbid(unsafe_code)]
#[cfg(unix)]
mod native {
    use ed25519_dalek::{Signer, SigningKey};
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    use vhalla_journal::{
        Bundle, BundleParts, FsStore, Journal, PublishedRange, MAX_PUBLISHED_PAGE_BYTES,
    };
    use vhalla_public_client::{Bootstrap, CertifiedClient, Validator, ValidatorActivation};
    use vhalla_rooms::{RoomUpdate, Slug, UpdateAction};
    use vhalla_rooms_consensus::{fixture, Batch, Frontier};
    use vhalla_rooms_node::{Address, PublicKey};
    type Result<T> = std::result::Result<T, String>;
    fn debug(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }
    fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(debug)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(debug)
    }
    fn certificate(height: u64, value: [u8; 32], keys: &[SigningKey]) -> Vec<u8> {
        let mut raw = b"VC2".to_vec();
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(&0u32.to_be_bytes());
        raw.extend_from_slice(&value);
        raw.extend_from_slice(&(keys.len() as u16).to_be_bytes());
        for key in keys {
            let address = Address::from_public_key(
                &PublicKey::from_bytes(key.verifying_key().to_bytes()).unwrap(),
            )
            .into_inner();
            let mut vote = b"RV1".to_vec();
            vote.push(1);
            vote.extend_from_slice(&height.to_be_bytes());
            vote.extend_from_slice(&0u32.to_be_bytes());
            vote.push(1);
            vote.extend_from_slice(&value);
            vote.extend_from_slice(&address);
            raw.extend_from_slice(&address);
            raw.extend_from_slice(&key.sign(&vote).to_bytes());
        }
        raw
    }
    fn bundle(
        batch: &Batch,
        next: Frontier,
        policy: [u8; 32],
        keys: &[SigningKey],
    ) -> Result<Bundle> {
        Bundle::new(BundleParts {
            certificate: certificate(next.height, batch.value_id(), keys),
            predecessor: batch.parent.commitment(),
            next: next.commitment(),
            batch: batch.encode(),
            value: batch.value_id().to_vec(),
            configuration: policy.to_vec(),
            control_record: next.control.to_vec(),
            debit_marker: next.value.to_vec(),
            height: next.height,
        })
        .map_err(debug)
    }
    struct Replay {
        count: u64,
        elapsed: Duration,
        budget_refused: bool,
        frontier: Frontier,
        last_bundle: [u8; 32],
    }
    fn replay(
        raw: &[u8],
        pin: [u8; 32],
        journal: &Journal<FsStore>,
        target: u64,
        expected_mid: (Frontier, [u8; 32]),
        cli_budget: bool,
        overall_deadline: Instant,
    ) -> Result<Replay> {
        let start = Instant::now();
        let limit = if cli_budget { 4096 } else { target };
        let deadline =
            overall_deadline.min(start + Duration::from_secs(if cli_budget { 30 } else { 1200 }));
        let mut client = CertifiedClient::new(Bootstrap::decode(raw, pin).map_err(debug)?, pin)
            .map_err(debug)?;
        let mut count = 0;
        let mut matched = false;
        let mut last_bundle = [0; 32];
        loop {
            // Same two explicit resource refusals as native Context::replay.
            if Instant::now() >= deadline || count >= limit {
                return Ok(Replay {
                    count,
                    elapsed: start.elapsed(),
                    budget_refused: true,
                    frontier: client.frontier(),
                    last_bundle,
                });
            }
            let old = client.frontier();
            let page = journal
                .read_published_range(PublishedRange {
                    after_height: old.height,
                    expected_predecessor: Some(old.commitment()),
                    max_bundles: (target - count).min(32).min(limit - count) as usize,
                    max_bytes: MAX_PUBLISHED_PAGE_BYTES,
                })
                .map_err(debug)?;
            if page.observed_head().height != target || page.bundles().is_empty() {
                return Err("synthetic journal changed/stalled".into());
            }
            for bundle in page.bundles() {
                if Instant::now() >= deadline {
                    return Ok(Replay {
                        count,
                        elapsed: start.elapsed(),
                        budget_refused: true,
                        frontier: client.frontier(),
                        last_bundle,
                    });
                }
                let candidate = client
                    .prepare(client.network_id(), bundle.bytes())
                    .map_err(debug)?;
                // Exact immutable bytes were read from the durable journal.
                client.commit_after_persist(candidate).map_err(debug)?;
                last_bundle = bundle.id();
                count += 1;
                if client.frontier().height == expected_mid.0.height {
                    if client.frontier() != expected_mid.0 || last_bundle != expected_mid.1 {
                        return Err("retained checkpoint mismatch".into());
                    }
                    matched = true;
                }
            }
            if count == target {
                if !matched
                    || client.frontier().commitment() != page.observed_head().next
                    || last_bundle != page.observed_head().bundle
                {
                    return Err("published final frontier mismatch".into());
                }
                let end = journal
                    .read_published_range(PublishedRange {
                        after_height: target,
                        expected_predecessor: Some(client.frontier().commitment()),
                        max_bundles: 1,
                        max_bytes: MAX_PUBLISHED_PAGE_BYTES,
                    })
                    .map_err(debug)?;
                if !end.bundles().is_empty() || end.observed_head() != page.observed_head() {
                    return Err("final journal snapshot changed".into());
                }
                return Ok(Replay {
                    count,
                    elapsed: start.elapsed(),
                    budget_refused: false,
                    frontier: client.frontier(),
                    last_bundle,
                });
            }
        }
    }
    fn footprint(path: &Path) -> Result<(u64, u64, u64)> {
        let mut out = (0, 0, 0);
        for item in fs::read_dir(path).map_err(debug)? {
            let path = item.map_err(debug)?.path();
            let metadata = path.symlink_metadata().map_err(debug)?;
            if metadata.is_symlink() {
                return Err("unexpected synthetic symlink".into());
            }
            if metadata.is_dir() {
                let sub = footprint(&path)?;
                out.0 += sub.0;
                out.1 += sub.1;
                out.2 += sub.2;
            } else if metadata.is_file() {
                out.0 += 1;
                out.1 += metadata.len();
                out.2 += metadata.blocks() * 512;
            } else {
                return Err("unexpected synthetic special file".into());
            }
        }
        Ok(out)
    }
    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() != 2 {
            return Err("usage: replay_performance ABSOLUTE_NEW_HOME 1000|10000|100000".into());
        }
        let home = PathBuf::from(&args[0]);
        if !home.is_absolute() {
            return Err("absolute new synthetic home required".into());
        }
        let count = match args[1].to_str() {
            Some("1000") => 1000,
            Some("10000") => 10_000,
            Some("100000") => 100_000,
            _ => return Err("explicit bounded count required".into()),
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .map_err(debug)?;
        let directory = File::open(&home).map_err(debug)?;
        directory.sync_all().map_err(debug)?;
        File::open(home.parent().ok_or("missing parent")?)
            .and_then(|f| f.sync_all())
            .map_err(debug)?;
        let deadline = Instant::now() + Duration::from_secs(1200);
        let mut scenario = fixture::scenario(1, 1);
        let keys: Vec<_> = (101..=104)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let bootstrap = Bootstrap::from_genesis(
            scenario.genesis.clone(),
            vec![ValidatorActivation {
                from: 1,
                validators: keys
                    .iter()
                    .map(|key| Validator {
                        public_key: key.verifying_key().to_bytes(),
                        power: 1,
                    })
                    .collect(),
            }],
        )
        .map_err(debug)?;
        let pin = bootstrap.pin();
        let raw = bootstrap.encode();
        let mut client = CertifiedClient::new(bootstrap, pin).map_err(debug)?;
        let journal = Journal::with_genesis(
            home.join("journal"),
            FsStore,
            client.frontier().commitment(),
        );
        write_new(&home.join("bootstrap.vhbootstrap"), &raw)?;
        let mut checkpoint = (client.frontier(), [0; 32]);
        let mut last_bundle = [0; 32];
        let mut total_bytes = 0;
        let mut output = String::from("metric\toperations\telapsed_ns\tbytes\n");
        let start = Instant::now();
        let mut source_cursor = 0;
        for height in 1..=count {
            if Instant::now() >= deadline {
                return Err("1200-second generation deadline; preserve partial journal".into());
            }
            let (evidence, records) = if height == 1 {
                let (evidence, records, _) = fixture::first_create(
                    &scenario.app,
                    &scenario.owners[0],
                    &mut scenario.sources,
                    &mut source_cursor,
                    "replay-performance-room",
                    1,
                );
                (evidence, records)
            } else if height == 2 {
                let room = scenario
                    .app
                    .registry()
                    .room(&Slug::new("replay-performance-room").map_err(debug)?)
                    .ok_or("missing fixture room")?;
                let update = RoomUpdate {
                    directory: scenario.genesis.directory,
                    realm: scenario.genesis.realm,
                    genesis: room.genesis(),
                    previous: room.head(),
                    owner: scenario.owners[0].id,
                    social_control: scenario.owners[0].head,
                    controller_key: scenario.owners[0].key.verifying_key().to_bytes(),
                    expires_at: 1_000_000_000_000,
                    nonce: [2; 32],
                    action: UpdateAction::SetPublicActivityPolicy {
                        network: client.network_id(),
                        enabled: true,
                    },
                }
                .sign_with_key(&scenario.owners[0].key)
                .map_err(debug)?;
                (vec![], vec![update.encode()])
            } else {
                (vec![], vec![])
            };
            let checked = scenario
                .app
                .prepare(height * 100, evidence, records, None)
                .map_err(debug)?;
            let bundle = bundle(
                checked.batch(),
                checked.next(),
                *scenario.genesis.policy.id().as_bytes(),
                &keys[..3],
            )?;
            let candidate = client
                .prepare(client.network_id(), bundle.bytes())
                .map_err(debug)?;
            journal.commit(&bundle).map_err(debug)?;
            client.commit_after_persist(candidate).map_err(debug)?;
            scenario.app.apply_locally(checked);
            if client.frontier() != scenario.app.frontier() {
                return Err("independent replay differs".into());
            }
            total_bytes += bundle.bytes().len() as u64;
            last_bundle = bundle.id();
            if height == count / 2 {
                checkpoint = (client.frontier(), bundle.id());
            }
            if height.is_multiple_of(1000) {
                eprintln!("certified generation {height}/{count}");
            }
        }
        output.push_str(&format!(
            "generate_sign_verify_journal_fsync\t{count}\t{}\t{total_bytes}\n",
            start.elapsed().as_nanos()
        ));
        let room = client
            .registry()
            .room(&Slug::new("replay-performance-room").map_err(debug)?)
            .ok_or("missing final fixture room")?;
        if !room
            .public_activity_policy()
            .is_some_and(|policy| room.allows_public_activity(&client.network_id(), policy.record))
        {
            return Err("fixture public policy missing".into());
        }
        let expected = client.frontier();
        drop(client);
        drop(scenario);
        let full = replay(&raw, pin, &journal, count, checkpoint, false, deadline)?;
        if full.budget_refused || full.frontier != expected || full.last_bundle != last_bundle {
            return Err("complete portable replay refused or diverged".into());
        }
        output.push_str(&format!(
            "genesis_decode_certified_disk_replay\t{}\t{}\t{total_bytes}\n",
            full.count,
            full.elapsed.as_nanos()
        ));
        let limited = replay(&raw, pin, &journal, count, checkpoint, true, deadline)?;
        if count > 4096 && !limited.budget_refused {
            return Err("CLI ceiling simulation unexpectedly passed".into());
        }
        output.push_str(&format!(
            "native_cli_budget_replay_{}\t{}\t{}\t0\n",
            if limited.budget_refused {
                "refused"
            } else {
                "complete"
            },
            limited.count,
            limited.elapsed.as_nanos()
        ));
        let start = Instant::now();
        for _ in 0..1000 {
            if Instant::now() >= deadline {
                return Err("qualification deadline; preserve synthetic output".into());
            }
            let page = journal
                .read_published_range(PublishedRange {
                    after_height: count,
                    expected_predecessor: Some(expected.commitment()),
                    max_bundles: 1,
                    max_bytes: MAX_PUBLISHED_PAGE_BYTES,
                })
                .map_err(debug)?;
            if !page.bundles().is_empty()
                || page.observed_head().height != count
                || page.observed_head().bundle != last_bundle
            {
                return Err("idle journal view mismatch".into());
            }
            std::hint::black_box(page);
        }
        output.push_str(&format!(
            "idle_published_tip_read\t1000\t{}\t0\n",
            start.elapsed().as_nanos()
        ));
        let (files, logical, allocated) = footprint(&home.join("journal"))?;
        output.push_str(&format!("retained_regular_files\t{files}\t0\t{logical}\nretained_allocated_bytes\t0\t0\t{allocated}\n"));
        write_new(&home.join("metrics.tsv"), output.as_bytes())?;
        directory.sync_all().map_err(debug)?;
        println!("{output}\npreserved-output {}", home.display());
        Ok(())
    }
}
#[cfg(unix)]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("replay performance: {error}; preserve synthetic evidence");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("replay_performance requires Unix journal persistence");
    std::process::exit(1);
}
