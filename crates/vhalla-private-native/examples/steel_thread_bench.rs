//! Reproducible synthetic private steel-thread measurement, not a load server.
//!
//! Two in-process cooperating-host drivers (A = room owner, B = member) exchange
//! application messages and member-acceptance receipts through one loopback
//! TLS relay, using the production kernel store, delivery queue, scan directory
//! and TLS service. Everything lives under one NEW private home on an ephemeral
//! `127.0.0.1:0` port; the installed host, its ports and launchd labels are never
//! touched. The application-only measurement loop derives from
//! `vhalla private agent-serve --delivery`; it does not qualify the controller's
//! encrypted-control merge or restored-marker recovery. Its cadence is a
//! command-line choice so the host policy and storage floor can be measured
//! separately.
//!
//! Usage:
//!   cargo run --release -p vhalla-private-native --features relay-tls \
//!     --example steel_thread_bench -- NEW_HOME 100|1000|10000 \
//!     [--cadence production|fast] [--idle SECONDS] [--deadline SECONDS] [--window N]
//!
//! Never reuses or deletes a home. Refuses 10,000 messages: two relay items per
//! acknowledged message exceed the fixed 4,096-item mailbox (`MAX_RELAY_ITEMS`).
#![forbid(unsafe_code)]

#[cfg(all(unix, feature = "relay-tls"))]
mod bench {
    use ed25519_dalek::SigningKey;
    use futures::executor::block_on;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, File},
        io::Write,
        net::{SocketAddr, TcpListener},
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use vhalla_private_kernel::{
        protocol::{Key, Validity},
        Context, Kernel, MemberAcceptance, MemberDraft, OperationId, OutboxKind, OwnerDraft,
        StorageKey,
    };
    use vhalla_private_native::{
        bridge::KernelStore,
        private_rooms::Limits as KernelLimits,
        relay::{
            delivery::{DeliveryStore, JobState, Limits as QueueLimits, RetryPolicy, TickBudget},
            net::{NetError, RelayToken, ScanDirectory, ScanFailure},
            tls::{self, Credential, Permissions, Service, ServiceLimits, TlsRelay},
            FileStore, Limits as RelayLimits, RelayItem, RelayKind, RelayNamespace,
            MAX_RELAY_ITEMS,
        },
    };

    type Result<T> = std::result::Result<T, String>;
    const TLS_NAME: &str = "relay.steel-thread-bench.invalid";
    const STAGES: usize = 6;
    const STAGE_NAMES: [&str; STAGES - 1] = [
        "queue_kernel_send",
        "queue_to_relay_retained",
        "relay_retained_to_b_applied",
        "b_applied_to_acceptance_retained",
        "acceptance_retained_to_a_recorded",
    ];

    fn debug(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }
    fn now_secs() -> Result<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs())
            .map_err(debug)
    }
    fn op(tag: u8, n: u64) -> OperationId {
        let mut bytes = [0; 16];
        bytes[0] = tag;
        bytes[8..].copy_from_slice(&n.to_be_bytes());
        OperationId::from_bytes(bytes).expect("nonzero operation id")
    }
    fn footprint(path: &Path) -> Result<(u64, u64, u64)> {
        let mut result = (0, 0, 0);
        for entry in fs::read_dir(path).map_err(debug)? {
            let entry = entry.map_err(debug)?;
            let metadata = entry.path().symlink_metadata().map_err(debug)?;
            if metadata.is_symlink() {
                return Err("unexpected symlink in synthetic output".into());
            }
            if metadata.is_dir() {
                let child = footprint(&entry.path())?;
                result.0 += child.0;
                result.1 += child.1;
                result.2 += child.2;
            } else if metadata.is_file() {
                result.0 += 1;
                result.1 += metadata.len();
                result.2 += metadata.blocks() * 512;
            } else {
                return Err("unexpected special file in synthetic output".into());
            }
        }
        Ok(result)
    }
    fn percentile(sorted: &[u64], p: usize) -> u64 {
        if sorted.is_empty() {
            return 0;
        }
        sorted[(sorted.len() - 1) * p / 100]
    }

    /// One tick's host policy. `production` is the exact cadence of
    /// `agent-serve`: a tick at most once per second with a two-second budget,
    /// one relay job per tick, one eight-item relay poll every five seconds and
    /// at most eight applied positions per tick. `fast` removes the waits and
    /// takes the largest bounded page/job counts, so the run is bound by
    /// storage barriers and transport instead of timers.
    #[derive(Clone, Copy)]
    struct Cadence {
        tick_interval: Duration,
        tick_budget: Duration,
        max_jobs: usize,
        poll_interval: Duration,
        page: usize,
        apply_per_tick: usize,
    }
    impl Cadence {
        const PRODUCTION: Self = Self {
            tick_interval: Duration::from_secs(1),
            tick_budget: Duration::from_secs(2),
            max_jobs: 1,
            poll_interval: Duration::from_secs(5),
            page: 8,
            apply_per_tick: 8,
        };
        const FAST: Self = Self {
            tick_interval: Duration::ZERO,
            tick_budget: Duration::from_secs(2),
            max_jobs: 64,
            poll_interval: Duration::ZERO,
            page: 64,
            apply_per_tick: 64,
        };
    }

    /// Per-message stage timestamps, nanoseconds since the run base. Memory is
    /// fixed at 48 bytes per message for the bounded run; nothing else is
    /// retained per message beyond the drivers' own commitment indexes.
    struct Timeline {
        base: Instant,
        marks: Mutex<Vec<[u64; STAGES]>>,
    }
    impl Timeline {
        fn mark(&self, ordinal: usize, stage: usize) {
            let at = self.base.elapsed().as_nanos() as u64;
            let mut marks = self.marks.lock().expect("timeline lock");
            if let Some(slot) = marks.get_mut(ordinal) {
                if slot[stage] == 0 {
                    slot[stage] = at.max(1);
                }
            }
        }
    }

    #[derive(Default)]
    struct Counters {
        ticks: u64,
        puts: u64,
        pages: u64,
        enqueues: u64,
        receives: u64,
        acceptances: u64,
        applied_markers: u64,
        outbox_reads: u64,
        scan_reopens: u64,
    }

    struct Certificates {
        root: Vec<u8>,
        config: Arc<rustls::ServerConfig>,
    }
    fn certificates() -> Result<Certificates> {
        let issuer_key = KeyPair::generate().map_err(debug)?;
        let mut issuer = CertificateParams::new(Vec::<String>::new()).map_err(debug)?;
        issuer.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = issuer.self_signed(&issuer_key).map_err(debug)?;
        let key = KeyPair::generate().map_err(debug)?;
        let mut params = CertificateParams::new(vec![TLS_NAME.to_owned()]).map_err(debug)?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&key, &issuer, &issuer_key)
            .map_err(debug)?;
        Ok(Certificates {
            root: issuer.der().to_vec(),
            config: tls::server_config(vec![leaf.der().to_vec()], key.serialize_der())
                .map_err(debug)?,
        })
    }
    fn credential(id: u8, token: RelayToken, namespace: RelayNamespace) -> Credential {
        Credential {
            id: [id; 16],
            tokens: vec![token],
            namespace,
            permissions: Permissions {
                put: true,
                page: true,
            },
            storage: RelayLimits {
                max_items: MAX_RELAY_ITEMS / 2,
                max_bytes: 512 * 1024 * 1024,
            },
            max_inflight: 8,
            requests_per_window: 50_000,
            bytes_per_window: 512 * 1024 * 1024,
        }
    }

    /// The in-process equivalent of one `agent-serve --delivery` host loop.
    struct Driver<'a> {
        name: &'static str,
        emit_acceptance: bool,
        context: Context,
        kernel: Kernel<KernelStore>,
        queue: DeliveryStore,
        relay: TlsRelay,
        namespace: RelayNamespace,
        scan_path: PathBuf,
        applied_path: PathBuf,
        applied_dir: File,
        outgoing: u64,
        applied: u64,
        // Commitments only: never a lifetime in-memory ciphertext history.
        echoes: BTreeMap<[u8; 32], u64>,
        originals: BTreeMap<[u8; 32], u64>,
        job_ordinal: BTreeMap<[u8; 32], usize>,
        seq_ordinal: BTreeMap<u64, usize>,
        next_poll: Instant,
        cadence: Cadence,
        timeline: &'a Timeline,
        counters: Counters,
        acked: usize,
        received: usize,
    }
    impl<'a> Driver<'a> {
        #[allow(clippy::too_many_arguments)]
        fn new(
            name: &'static str,
            emit_acceptance: bool,
            home: &Path,
            context: Context,
            kernel: Kernel<KernelStore>,
            relay: TlsRelay,
            namespace: RelayNamespace,
            cadence: Cadence,
            timeline: &'a Timeline,
        ) -> Result<Self> {
            let queue = DeliveryStore::create_new(
                home.join("jobs"),
                context,
                namespace,
                relay.endpoint_id(),
                QueueLimits {
                    max_jobs: MAX_RELAY_ITEMS,
                    max_bytes: 1024 * 1024 * 1024,
                },
                RetryPolicy {
                    max_attempts: 10,
                    initial_backoff_secs: 1,
                    max_backoff_secs: 60,
                },
            )
            .map_err(debug)?;
            let scan_path = home.join("scan");
            drop(ScanDirectory::open(&scan_path, namespace).map_err(debug)?);
            let applied_path = home.join("applied");
            let (applied_dir, _) =
                vhalla_custody::create_private_directory(&applied_path).map_err(debug)?;
            Ok(Self {
                name,
                emit_acceptance,
                context,
                kernel,
                queue,
                relay,
                namespace,
                scan_path,
                applied_path,
                applied_dir,
                outgoing: 0,
                applied: 0,
                echoes: BTreeMap::new(),
                originals: BTreeMap::new(),
                job_ordinal: BTreeMap::new(),
                seq_ordinal: BTreeMap::new(),
                next_poll: Instant::now(),
                cadence,
                timeline,
                counters: Counters::default(),
                acked: 0,
                received: 0,
            })
        }
        /// A's agent action: `private_prepare` + `private_queue` for one message.
        fn send(&mut self, ordinal: usize) -> Result<()> {
            let mut body = format!("{ordinal:08}:synthetic private steel-thread payload:");
            while body.len() < 256 {
                body.push_str("0123456789abcdef");
            }
            self.timeline.mark(ordinal, 0);
            let draft = self
                .kernel
                .prepare_message(body.as_bytes())
                .map_err(debug)?;
            let committed = block_on(self.kernel.send(op(1, ordinal as u64), &draft, now_secs()?))
                .map_err(debug)?;
            self.timeline.mark(ordinal, 1);
            self.seq_ordinal.insert(committed.sequence(), ordinal);
            Ok(())
        }
        /// One bounded host tick, mirroring `Driver::tick` in the CLI.
        fn tick(&mut self, idle_cadence: bool) -> Result<bool> {
            let cadence = if idle_cadence {
                Cadence::PRODUCTION
            } else {
                self.cadence
            };
            self.counters.ticks += 1;
            let mut worked = false;
            let deadline = Instant::now() + cadence.tick_budget;
            let now = now_secs()?;
            self.counters.outbox_reads += 1;
            let page = block_on(self.kernel.outbox(self.outgoing, cadence.page)).map_err(debug)?;
            for entry in &page.records {
                if let Some(artifact) = entry.artifact().filter(|a| {
                    matches!(
                        a.kind(),
                        OutboxKind::Application
                            | OutboxKind::Removal
                            | OutboxKind::OwnerUpdate
                            | OutboxKind::Succession
                    )
                }) {
                    let item = RelayItem::from_artifact(self.namespace, artifact).map_err(debug)?;
                    // Exact retries of an already queued receipt still commit once,
                    // exactly like the CLI host that re-reads its outbox each tick.
                    self.counters.enqueues += 1;
                    self.queue.enqueue(&item, now).map_err(debug)?;
                    self.echoes.insert(item.digest(), artifact.sequence());
                    if artifact.kind() == OutboxKind::Application {
                        self.originals.insert(
                            MemberAcceptance::ciphertext_commitment(artifact.bytes()),
                            artifact.sequence(),
                        );
                    }
                    if let Some(ordinal) = self.seq_ordinal.get(&artifact.sequence()) {
                        self.job_ordinal.insert(item.digest(), *ordinal);
                    }
                    worked = true;
                }
                self.outgoing = entry.sequence();
            }
            if Instant::now() >= deadline {
                return Ok(worked);
            }
            let report = self
                .queue
                .tick(
                    &mut self.relay,
                    now,
                    TickBudget {
                        max_jobs: cadence.max_jobs,
                        max_bytes: 4 * 1024 * 1024,
                        deadline,
                    },
                )
                .map_err(debug)?;
            for status in &report.jobs {
                self.counters.puts += 1;
                worked = true;
                if status.last_error == Some(NetError::Denied) {
                    return Err(format!("{}: relay denied the credential", self.name));
                }
                if status.state == JobState::Retained {
                    if let Some(ordinal) = self.job_ordinal.remove(&status.id) {
                        self.timeline
                            .mark(ordinal, if self.emit_acceptance { 4 } else { 2 });
                    }
                }
            }
            if self.outgoing < page.head || Instant::now() >= deadline {
                return Ok(worked);
            }
            // The CLI reopens the retained scan every tick; its guard carries a
            // 90-second absolute budget, so a lifetime handle is not an option.
            self.counters.scan_reopens += 1;
            let mut scan = match ScanDirectory::open(&self.scan_path, self.namespace) {
                Ok(scan) => scan,
                // A scan-budget timeout is transient: the production host ends
                // the tick and retries on the next one instead of failing the
                // run — same treatment as ScanFailure::Timeout below.
                Err(ScanFailure::Timeout) => return Ok(worked),
                Err(error) => return Err(format!("{}: scan open {error:?}", self.name)),
            };
            if Instant::now() >= self.next_poll {
                self.next_poll = Instant::now() + cadence.poll_interval;
                self.counters.pages += 1;
                match scan.scan_page_until(&self.relay, cadence.page, deadline) {
                    Ok(report) => worked |= report.scanned > 0,
                    Err(ScanFailure::Net(
                        NetError::Connect
                        | NetError::Timeout
                        | NetError::Capacity
                        | NetError::Unavailable,
                    )) => self.next_poll = Instant::now() + Duration::from_secs(30),
                    Err(ScanFailure::Timeout) => (),
                    Err(error) => return Err(format!("{}: scan {error:?}", self.name)),
                }
            }
            if Instant::now() >= deadline {
                return Ok(worked);
            }
            let positions: Vec<u64> = match scan.positions() {
                Ok(positions) => positions,
                Err(ScanFailure::Timeout) => return Ok(worked),
                Err(error) => return Err(format!("{}: scan positions {error:?}", self.name)),
            }
            .into_iter()
            .filter(|p| *p > self.applied)
            .take(cadence.apply_per_tick)
            .collect();
            for position in positions {
                if Instant::now() >= deadline {
                    break;
                }
                worked = true;
                let item = match scan.read(position) {
                    Ok(item) => item,
                    // Same transient-timeout policy as scan_page_until: leave
                    // the position unapplied; the next tick retries it.
                    Err(ScanFailure::Timeout) => break,
                    Err(error) => return Err(format!("{}: scan read {error:?}", self.name)),
                };
                let marker = self.applied_path.join(format!("{position:016x}.json"));
                if marker.symlink_metadata().is_ok() {
                    self.applied = position;
                    continue;
                }
                let mut state = "exact-local-outbox-echo";
                if !self.echoes.contains_key(&item.digest()) {
                    match item.kind() {
                        RelayKind::Outbox(OutboxKind::Application) => {
                            let now = now_secs()?;
                            self.counters.receives += 1;
                            let received = block_on(self.kernel.receive(item.payload(), now))
                                .map_err(|e| format!("{}: receive {e:?}", self.name))?;
                            state = "locally-received";
                            if MemberAcceptance::is_receipt(received.body()) {
                                state = "unmatched-receipt-content";
                                if let Some(sequence) =
                                    MemberAcceptance::claimed_ciphertext(received.body())
                                        .and_then(|h| self.originals.get(&h).copied())
                                {
                                    self.counters.outbox_reads += 1;
                                    let original = block_on(self.kernel.outbox(sequence - 1, 1))
                                        .map_err(debug)?;
                                    let original = original
                                        .records
                                        .first()
                                        .and_then(|r| r.artifact())
                                        .ok_or("missing original outbox record")?;
                                    if original.sequence() != sequence {
                                        return Err("outbox page mismatch".into());
                                    }
                                    if let Ok(Some(_claim)) =
                                        MemberAcceptance::verify(self.context, original, &received)
                                    {
                                        state = "recipient-device-claim";
                                        // The CLI records the claim only in RpcSession memory.
                                        if let Some(ordinal) = self.seq_ordinal.get(&sequence) {
                                            self.timeline.mark(*ordinal, 5);
                                        }
                                        self.acked += 1;
                                    }
                                }
                            } else if self.emit_acceptance {
                                let ordinal: usize = std::str::from_utf8(received.body())
                                    .ok()
                                    .and_then(|s| s.get(..8))
                                    .and_then(|s| s.parse().ok())
                                    .ok_or("unexpected message body")?;
                                self.timeline.mark(ordinal, 3);
                                self.received += 1;
                                let mut hash = Sha256::new();
                                hash.update(b"vhalla/host/receipt-operation/v1\0");
                                hash.update(self.context.device.as_bytes());
                                hash.update(MemberAcceptance::ciphertext_commitment(
                                    item.payload(),
                                ));
                                let digest: [u8; 32] = hash.finalize().into();
                                let operation = OperationId::from_bytes(
                                    digest[..16].try_into().map_err(debug)?,
                                )
                                .map_err(debug)?;
                                self.counters.acceptances += 1;
                                let receipt = block_on(self.kernel.issue_acceptance(
                                    operation,
                                    item.payload(),
                                    now,
                                ))
                                .map_err(debug)?;
                                let relay = RelayItem::from_artifact(self.namespace, &receipt)
                                    .map_err(debug)?;
                                self.counters.enqueues += 1;
                                self.queue.enqueue(&relay, now).map_err(debug)?;
                                self.echoes.insert(relay.digest(), receipt.sequence());
                                self.seq_ordinal.insert(receipt.sequence(), ordinal);
                                self.job_ordinal.insert(relay.digest(), ordinal);
                            }
                        }
                        _ => return Err("unexpected relay item kind".into()),
                    }
                }
                // Same barrier shape as the CLI's `applied::publish` (`files::write`).
                let mut file = vhalla_custody::create_private_file(&marker).map_err(debug)?;
                file.write_all(
                    format!(
                        "{{\"digest\":\"{}\",\"position\":\"{position}\",\"state\":\"{state}\"}}",
                        hex(&item.digest())
                    )
                    .as_bytes(),
                )
                .and_then(|_| file.sync_all())
                .and_then(|_| self.applied_dir.sync_all())
                .map_err(debug)?;
                self.counters.applied_markers += 1;
                self.applied = position;
            }
            Ok(worked)
        }
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    struct Homes {
        root: PathBuf,
        relay: PathBuf,
        a: PathBuf,
        b: PathBuf,
    }

    /// Per-call F_FULLFSYNC cost on this host: `sync_all` of a small private
    /// file and of its directory, repeated 32 times each. Every `sync_all` in
    /// these crates compiles to `fcntl(F_FULLFSYNC)` on Apple targets.
    fn calibrate(home: &Path) -> Result<(u64, u64)> {
        let path = home.join("calibration");
        let (dir, _) = vhalla_custody::create_private_directory(&path).map_err(debug)?;
        let mut file = vhalla_custody::create_private_file(&path.join("probe")).map_err(debug)?;
        let mut files = Vec::with_capacity(32);
        let mut dirs = Vec::with_capacity(32);
        for i in 0..32u8 {
            file.write_all(&[i; 4096]).map_err(debug)?;
            let start = Instant::now();
            file.sync_all().map_err(debug)?;
            files.push(start.elapsed().as_nanos() as u64);
            let start = Instant::now();
            dir.sync_all().map_err(debug)?;
            dirs.push(start.elapsed().as_nanos() as u64);
        }
        files.sort_unstable();
        dirs.sort_unstable();
        Ok((percentile(&files, 50), percentile(&dirs, 50)))
    }

    pub fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.len() < 2 {
            return Err("usage: steel_thread_bench NEW_HOME 100|1000|10000 [--cadence production|fast] [--idle SECONDS] [--deadline SECONDS] [--window N]".into());
        }
        let count: usize = match args[1].as_str() {
            "100" => 100,
            "1000" => 1000,
            "10000" => {
                return Err(format!(
                    "10000 messages need 20000 relay items; MAX_RELAY_ITEMS is {MAX_RELAY_ITEMS} and the per-credential cap is {}; refusing (policy limit, not a measurement)",
                    MAX_RELAY_ITEMS / 2
                ))
            }
            _ => return Err("explicit bounded count required".into()),
        };
        let mut cadence = Cadence::PRODUCTION;
        let mut cadence_name = "production";
        let mut idle = Duration::from_secs(60);
        let mut deadline = Duration::from_secs(600);
        let mut window = 8usize;
        let mut explicit_deadline = false;
        let mut rest = args[2..].iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or("flag needs a value")?;
            match flag.as_str() {
                "--cadence" => {
                    cadence = match value.as_str() {
                        "production" => Cadence::PRODUCTION,
                        "fast" => Cadence::FAST,
                        _ => return Err("cadence must be production or fast".into()),
                    };
                    cadence_name = if value == "fast" {
                        "fast"
                    } else {
                        "production"
                    };
                }
                "--idle" => idle = Duration::from_secs(value.parse().map_err(debug)?),
                "--deadline" => {
                    deadline = Duration::from_secs(value.parse().map_err(debug)?);
                    explicit_deadline = true;
                }
                "--window" => window = value.parse().map_err(debug)?,
                _ => return Err(format!("unknown flag {flag}")),
            }
        }
        if !explicit_deadline {
            // Production cadence moves about one message per second per hop.
            deadline = if cadence.tick_interval.is_zero() {
                Duration::from_secs(600)
            } else {
                Duration::from_secs(count as u64 * 3 + 300)
            } + idle;
        }
        if window == 0 || window > 64 {
            return Err("window must be 1..=64".into());
        }
        let home = vhalla_custody::absolute(Path::new(&args[0])).map_err(debug)?;
        let (root_dir, _) = vhalla_custody::create_private_directory(&home).map_err(debug)?;
        root_dir.sync_all().map_err(debug)?;
        let homes = Homes {
            root: home.clone(),
            relay: home.join("relay"),
            a: home.join("a"),
            b: home.join("b"),
        };
        for path in [&homes.relay, &homes.a, &homes.b] {
            vhalla_custody::create_private_directory(path).map_err(debug)?;
        }
        // A supervised process deadline: a stuck filesystem call cannot be
        // cancelled, so this exits the whole process with the partial metrics
        // already written by the last completed phase.
        let started = Instant::now();
        thread::spawn(move || {
            thread::sleep(deadline);
            eprintln!("steel_thread_bench: {deadline:?} deadline; preserve partial output");
            std::process::exit(3);
        });
        let mut output = String::from("metric\toperations\telapsed_ns\tbytes\n");
        let metric = |output: &mut String, name: &str, count: u64, elapsed: u64, bytes: u64| {
            output.push_str(&format!("{name}\t{count}\t{elapsed}\t{bytes}\n"));
        };
        let (ff_file, ff_dir) = calibrate(&home)?;
        metric(
            &mut output,
            "calibration_file_fullfsync_p50_ns",
            32,
            ff_file,
            4096,
        );
        metric(
            &mut output,
            "calibration_dir_fullfsync_p50_ns",
            32,
            ff_dir,
            0,
        );

        // Relay: one durable mailbox namespace and two client credentials.
        let namespace = RelayNamespace::from_bytes([0x5a; 32]).map_err(debug)?;
        let token_a = RelayToken::from_bytes([0xa1; 32]).map_err(debug)?;
        let token_b = RelayToken::from_bytes([0xb2; 32]).map_err(debug)?;
        let certs = certificates()?;
        let mailbox = homes.relay.join("mailbox");
        Service::initialize(
            FileStore::create_new(
                &mailbox,
                namespace,
                RelayLimits {
                    max_items: MAX_RELAY_ITEMS,
                    max_bytes: 1024 * 1024 * 1024,
                },
            )
            .map_err(debug)?,
        )
        .map_err(debug)?;
        let service = Service::new(
            FileStore::open(&mailbox, namespace).map_err(debug)?,
            certs.config.clone(),
            vec![
                credential(1, token_a, namespace),
                credential(2, token_b, namespace),
            ],
            ServiceLimits {
                max_connections: 16,
                request_timeout: Duration::from_secs(10),
                window: Duration::from_secs(1),
                requests_per_window: 100_000,
                bytes_per_window: 1024 * 1024 * 1024,
            },
        )
        .map_err(debug)?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(debug)?;
        let addr: SocketAddr = listener.local_addr().map_err(debug)?;
        let stop = Arc::new(AtomicBool::new(false));
        let relay_stop = stop.clone();
        let relay_thread = thread::spawn(move || service.serve_until(listener, None, relay_stop));
        let relay_a =
            TlsRelay::new(addr, TLS_NAME, certs.root.clone(), token_a, namespace).map_err(debug)?;
        let relay_b =
            TlsRelay::new(addr, TLS_NAME, certs.root.clone(), token_b, namespace).map_err(debug)?;

        // Two devices: A creates the room, B is invited and joins in-process
        // (the invitation itself is not a relay item in this fixture).
        let now = now_secs()?;
        let validity = Validity::new(now - 30, now + 86_400).map_err(debug)?;
        // Public synthetic account keys, never a user's identity.
        let account_a = SigningKey::from_bytes(&[0x11; 32]);
        let account_b = SigningKey::from_bytes(&[0x22; 32]);
        let key = |k: &SigningKey| Key::from_bytes(k.verifying_key().to_bytes()).map_err(debug);
        let draft = OwnerDraft::new(key(&account_a)?, validity).map_err(debug)?;
        let anchor = draft.anchor_request().sign(&account_a).map_err(debug)?;
        let enrollment = draft.enrollment_request().sign(&account_a).map_err(debug)?;
        let context_a = draft.context(&anchor).map_err(debug)?;
        let member = MemberDraft::new(
            anchor.verify().map_err(debug)?.scope(),
            anchor.clone(),
            enrollment.clone(),
            key(&account_b)?,
            validity,
            now,
        )
        .map_err(debug)?;
        let member_enrollment = member
            .enrollment_request()
            .sign(&account_b)
            .map_err(debug)?;
        let context_b = member.context();
        let kernel_limits = KernelLimits {
            max_records: 200_000,
            max_record_bytes: 1024 * 1024 * 1024,
        };
        let store_a = KernelStore::create_new(homes.a.join("kernel"), context_a, kernel_limits)
            .map_err(debug)?;
        let store_b = KernelStore::create_new(homes.b.join("kernel"), context_b, kernel_limits)
            .map_err(debug)?;
        let storage_a = StorageKey::from_secret([0x31; 32]).map_err(debug)?;
        let storage_b = StorageKey::from_secret([0x32; 32]).map_err(debug)?;
        let mut kernel_a =
            block_on(draft.create(store_a, &storage_a, enrollment, anchor, now)).map_err(debug)?;
        let mut kernel_b = block_on(member.initialize(store_b, &storage_b, member_enrollment, now))
            .map_err(debug)?;
        let package = block_on(kernel_b.key_package(op(9, 1), now)).map_err(debug)?;
        let invite =
            block_on(kernel_a.invite(op(9, 1), package.bytes(), validity, now)).map_err(debug)?;
        block_on(kernel_b.join(invite.bytes(), now)).map_err(debug)?;
        metric(
            &mut output,
            "setup_relay_devices_join",
            1,
            started.elapsed().as_nanos() as u64,
            0,
        );

        let timeline = Timeline {
            base: Instant::now(),
            marks: Mutex::new(vec![[0; STAGES]; count]),
        };
        let mut a = Driver::new(
            "A", false, &homes.a, context_a, kernel_a, relay_a, namespace, cadence, &timeline,
        )?;
        let mut b = Driver::new(
            "B", true, &homes.b, context_b, kernel_b, relay_b, namespace, cadence, &timeline,
        )?;
        let done = AtomicBool::new(false);
        let b_ticks = AtomicU64::new(0);
        let run_start = Instant::now();
        let run_result: Result<()> = thread::scope(|scope| {
            let b_worker = scope.spawn(|| -> Result<(Counters, Counters)> {
                let mut next_tick = Instant::now();
                while !done.load(Ordering::Acquire) {
                    if Instant::now() >= next_tick {
                        let worked = b.tick(false)?;
                        b_ticks.fetch_add(1, Ordering::Relaxed);
                        next_tick = Instant::now() + cadence.tick_interval;
                        if !worked && cadence.tick_interval.is_zero() {
                            thread::sleep(Duration::from_millis(2));
                        }
                    } else {
                        thread::sleep(
                            next_tick
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(50)),
                        );
                    }
                }
                let run_counters = std::mem::take(&mut b.counters);
                // Idle phase at production cadence.
                let idle_start = Instant::now();
                let mut next_tick = Instant::now();
                while idle_start.elapsed() < idle {
                    if Instant::now() >= next_tick {
                        b.tick(true)?;
                        next_tick = Instant::now() + Cadence::PRODUCTION.tick_interval;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Ok((run_counters, std::mem::take(&mut b.counters)))
            });
            let a_result = (|| -> Result<(Counters, Counters)> {
                let mut sent = 0usize;
                let mut progress = 0usize;
                let mut next_tick = Instant::now();
                while a.acked < count {
                    while sent < count && sent - a.acked < window {
                        a.send(sent)?;
                        sent += 1;
                    }
                    if Instant::now() >= next_tick {
                        let worked = a.tick(false)?;
                        next_tick = Instant::now() + cadence.tick_interval;
                        if !worked && cadence.tick_interval.is_zero() {
                            thread::sleep(Duration::from_millis(2));
                        }
                    } else {
                        thread::sleep(
                            next_tick
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(50)),
                        );
                    }
                    if a.acked > 0 && a.acked.is_multiple_of(100) && a.acked != progress {
                        progress = a.acked;
                        eprintln!("steel_thread progress {}/{count}", a.acked);
                    }
                    if b_worker.is_finished() {
                        return Err("B stopped before the run completed".into());
                    }
                }
                let run_counters = std::mem::take(&mut a.counters);
                done.store(true, Ordering::Release);
                let idle_start = Instant::now();
                let mut next_tick = Instant::now();
                while idle_start.elapsed() < idle {
                    if Instant::now() >= next_tick {
                        a.tick(true)?;
                        next_tick = Instant::now() + Cadence::PRODUCTION.tick_interval;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                Ok((run_counters, std::mem::take(&mut a.counters)))
            })();
            done.store(true, Ordering::Release);
            let (b_run, b_idle) = b_worker
                .join()
                .map_err(|_| "B worker panicked".to_owned())??;
            let (a_run, a_idle) = a_result?;
            let run_elapsed = run_start.elapsed();
            let marks = timeline.marks.lock().expect("timeline lock").clone();
            let mut stage_samples: Vec<Vec<u64>> =
                (0..STAGES - 1).map(|_| Vec::with_capacity(count)).collect();
            let mut round_trip = Vec::with_capacity(count);
            let mut first_start = u64::MAX;
            let mut last_ack = 0;
            for slot in &marks {
                if slot.contains(&0) {
                    return Err("a message is missing a stage timestamp".into());
                }
                for (stage, samples) in stage_samples.iter_mut().enumerate() {
                    samples.push(slot[stage + 1] - slot[stage]);
                }
                round_trip.push(slot[STAGES - 1] - slot[0]);
                first_start = first_start.min(slot[0]);
                last_ack = last_ack.max(slot[STAGES - 1]);
            }
            metric(
                &mut output,
                "acknowledged_messages_wall",
                count as u64,
                run_elapsed.as_nanos() as u64,
                0,
            );
            metric(
                &mut output,
                "first_queue_to_last_acceptance",
                count as u64,
                last_ack - first_start,
                0,
            );
            for (stage, samples) in stage_samples.iter_mut().enumerate() {
                samples.sort_unstable();
                for (suffix, p) in [("p50", 50), ("p95", 95), ("p99", 99), ("max", 100)] {
                    metric(
                        &mut output,
                        &format!("{}_{suffix}_ns", STAGE_NAMES[stage]),
                        1,
                        percentile(samples, p),
                        0,
                    );
                }
            }
            round_trip.sort_unstable();
            for (suffix, p) in [("p50", 50), ("p95", 95), ("p99", 99), ("max", 100)] {
                metric(
                    &mut output,
                    &format!("round_trip_{suffix}_ns"),
                    1,
                    percentile(&round_trip, p),
                    0,
                );
            }
            for (name, c) in [
                ("a_run", &a_run),
                ("b_run", &b_run),
                ("a_idle", &a_idle),
                ("b_idle", &b_idle),
            ] {
                output.push_str(&format!(
                    "{name}_counters\tticks={} puts={} pages={} enqueues={} receives={} acceptances={} applied_markers={} outbox_reads={} scan_reopens={}\t0\t0\n",
                    c.ticks, c.puts, c.pages, c.enqueues, c.receives, c.acceptances, c.applied_markers, c.outbox_reads, c.scan_reopens
                ));
            }
            output.push_str(&format!(
                "b_run_ticks\t{}\t0\t0\n",
                b_ticks.load(Ordering::Relaxed)
            ));
            metric(&mut output, "idle_phase_wall", 1, idle.as_nanos() as u64, 0);
            Ok(())
        });
        stop.store(true, Ordering::Release);
        let relay_result = relay_thread
            .join()
            .map_err(|_| "relay thread panicked".to_owned())?;
        run_result?;
        relay_result.map_err(debug)?;
        // Footprint after the run, excluded from operation timings.
        for (name, path) in [("relay", &homes.relay), ("a", &homes.a), ("b", &homes.b)] {
            let (files, logical, allocated) = footprint(path)?;
            output.push_str(&format!(
                "footprint_{name}\t{files}\t0\t{logical}\nfootprint_{name}_allocated\t0\t0\t{allocated}\n"
            ));
        }
        output.push_str(&format!(
            "cadence\t{cadence_name}\t0\t0\nwindow\t{window}\t0\t0\n"
        ));
        let mut file =
            vhalla_custody::create_private_file(&homes.root.join("metrics.tsv")).map_err(debug)?;
        file.write_all(output.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(debug)?;
        root_dir.sync_all().map_err(debug)?;
        println!("{output}");
        println!("preserved-output {}", homes.root.display());
        Ok(())
    }
}

#[cfg(all(unix, feature = "relay-tls"))]
fn main() {
    if let Err(error) = bench::run() {
        eprintln!("steel_thread_bench: {error}; preserve partial synthetic output");
        std::process::exit(1);
    }
}
#[cfg(not(all(unix, feature = "relay-tls")))]
fn main() {
    eprintln!("steel_thread_bench requires Unix and --features relay-tls");
    std::process::exit(1);
}
