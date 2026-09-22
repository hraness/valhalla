//! Reproducible synthetic native activity persistence measurement, not a load server.
//! Usage: cargo run --release -p vhalla-room-activity-store --example performance -- NEW_HOME 1000|10000|100000
//! Never reuses/deletes a home. Includes real signatures, verification and store syncs.
#![forbid(unsafe_code)]

#[cfg(unix)]
#[path = "../../vhalla-rooms/tests/common/mod.rs"]
mod common;

#[cfg(unix)]
mod native {
    use super::common;
    use ed25519_dalek::SigningKey;
    use std::{
        fs::File,
        io::Write,
        os::unix::fs::MetadataExt,
        path::Path,
        time::{Duration, Instant},
    };
    use vhalla_room_activity::{
        AdmissionContext, Content, EventClaims, EventId, RoomScope, SignedEvent, Text,
        UnsignedEvent,
    };
    use vhalla_room_activity_store::{Limits, Store, MAX_PAGE};
    use vhalla_rooms::{Applied, RoomUpdate, UpdateAction};
    use vhalla_social::{archive::Archive, control::ControlView};

    type Result<T> = std::result::Result<T, String>;
    fn debug(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }
    fn metric(output: &mut String, name: &str, count: u64, elapsed: Duration, bytes: u64) {
        output.push_str(&format!(
            "{name}\t{count}\t{}\t{bytes}\n",
            elapsed.as_nanos()
        ));
    }
    fn footprint(path: &Path) -> Result<(u64, u64, u64)> {
        let mut result = (0, 0, 0);
        for entry in std::fs::read_dir(path).map_err(debug)? {
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
    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() != 2 {
            return Err("usage: performance NEW_HOME 1000|10000|100000".into());
        }
        let count = match args[1].to_str() {
            Some("1000") => 1000,
            Some("10000") => 10_000,
            Some("100000") => 100_000,
            _ => return Err("explicit bounded count required".into()),
        };
        let home = vhalla_custody::absolute(Path::new(&args[0])).map_err(debug)?;
        let (directory, _) = vhalla_custody::create_private_directory(&home).map_err(debug)?;
        directory.sync_all().map_err(debug)?;
        File::open(home.parent().ok_or("missing parent")?)
            .and_then(|f| f.sync_all())
            .map_err(debug)?;
        let deadline = Instant::now() + Duration::from_secs(1200);
        let check = || {
            if Instant::now() >= deadline {
                Err("1200-second qualification deadline; preserve partial output".to_owned())
            } else {
                Ok(())
            }
        };
        let network = [7; 32];
        let mut archive = Archive::new(common::REALM, common::limits()).map_err(debug)?;
        let owner = common::beneficiary(&mut archive, 4);
        let (mut pool, mut registry) = common::sources(&mut archive, 90, 1);
        let grant = common::grant_create(&mut registry, &archive, &owner, 100);
        common::award_one(&mut registry, &mut archive, &mut pool[0], &owner, 200);
        let creation = common::creation(&owner, grant, grant, "performance-room", 1, 1, 13);
        let Applied::Created(room) =
            common::apply(&mut registry, &archive, &creation, 300).map_err(debug)?
        else {
            return Err("fixture room missing".into());
        };
        let record = RoomUpdate {
            directory: common::DIRECTORY,
            realm: common::REALM,
            genesis: room,
            previous: creation.id(),
            owner: owner.id,
            social_control: owner.head,
            controller_key: owner.key.verifying_key().to_bytes(),
            expires_at: common::EXPIRES,
            nonce: [14; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network,
                enabled: true,
            },
        }
        .sign_with_key(&owner.key)
        .and_then(|v| v.verify())
        .map_err(debug)?;
        registry
            .apply(&record, &ControlView::new(&archive, 400), 400)
            .map_err(debug)?;
        let scope = RoomScope {
            network,
            realm: common::REALM,
            directory: common::DIRECTORY,
            room,
        };
        let limits = Limits {
            max_events: count,
            max_history_bytes: count * 8192,
        };
        let key = SigningKey::from_bytes(&[42; 32]); // Public synthetic key, never a user's identity.
        let author = key.verifying_key().to_bytes();
        let mut output = String::from("metric\toperations\telapsed_ns\tbytes\n");
        let start = Instant::now();
        let mut store = Store::create(home.join("activity"), scope, limits).map_err(debug)?;
        metric(&mut output, "create_store", 1, start.elapsed(), 0);
        let mut previous = EventId::ZERO;
        let mut last = None;
        let mut signing = Duration::ZERO;
        let mut admitting = Duration::ZERO;
        let mut wire_bytes = 0;
        let mut samples = Vec::with_capacity(count as usize);
        let all = Instant::now();
        for sequence in 1..=count {
            check()?;
            let start = Instant::now();
            let event = UnsignedEvent::new(EventClaims {
                scope,
                policy: record.id(),
                author,
                sequence,
                previous,
                created_at: 500,
                content: Content::Text(
                    Text::new(
                        "synthetic public performance payload:0123456789abcdef0123456789abcd",
                    )
                    .map_err(debug)?,
                ),
            })
            .and_then(|v| v.sign_with_key(&key))
            .map_err(debug)?;
            let raw = event.encode();
            let event = SignedEvent::decode(&raw)
                .and_then(|v| v.verify())
                .map_err(debug)?;
            signing += start.elapsed();
            wire_bytes += raw.len() as u64;
            let start = Instant::now();
            // Mirror caller-side current-author read and per-call registry digest.
            // This single-threaded fixture owns its immutable registry throughout.
            let expected = store.author_head(author).map_err(debug)?;
            let context = AdmissionContext::new(network, &registry).map_err(debug)?;
            let stored = store
                .append(event, expected, &context, *context.registry_digest())
                .map_err(debug)?;
            let elapsed = start.elapsed();
            admitting += elapsed;
            samples.push(elapsed.as_nanos());
            if stored.cursor() != sequence || stored.reconciled() {
                return Err("unexpected fresh append result".into());
            }
            previous = stored.event().id();
            last = Some(stored.event().clone());
            if sequence.is_multiple_of(1000) {
                eprintln!("activity progress {sequence}/{count}");
            }
        }
        metric(
            &mut output,
            "append_end_to_end",
            count,
            all.elapsed(),
            wire_bytes,
        );
        metric(
            &mut output,
            "canonical_sign_decode_verify",
            count,
            signing,
            wire_bytes,
        );
        metric(
            &mut output,
            "author_read_context_append_fsync",
            count,
            admitting,
            store.pin().history_bytes(),
        );
        samples.sort_unstable();
        for (name, percentile) in [
            ("append_p50_ns", 50),
            ("append_p95_ns", 95),
            ("append_p99_ns", 99),
        ] {
            output.push_str(&format!(
                "{name}\t1\t{}\t0\n",
                samples[(samples.len() - 1) * percentile / 100]
            ));
        }
        let pin = store.pin();
        let head = store.author_head(author).map_err(debug)?;
        let context = AdmissionContext::new(network, &registry).map_err(debug)?;
        let start = Instant::now();
        for _ in 0..100 {
            check()?;
            let stored = store
                .append(
                    last.as_ref().unwrap().clone(),
                    head,
                    &context,
                    *context.registry_digest(),
                )
                .map_err(debug)?;
            if !stored.reconciled() || stored.cursor() != count || store.pin() != pin {
                return Err("retry changed history".into());
            }
        }
        metric(&mut output, "exact_retry", 100, start.elapsed(), 0);
        let start = Instant::now();
        for _ in 0..20 {
            check()?;
            drop(store);
            store = Store::open(home.join("activity"), scope, limits, Some(pin)).map_err(debug)?;
            if store.recovery_required().map_err(debug)?
                || store.author_head(author).map_err(debug)? != head
            {
                return Err("reopen mismatch".into());
            }
        }
        metric(
            &mut output,
            "reopen_and_verified_author_head",
            20,
            start.elapsed(),
            0,
        );
        let start = Instant::now();
        let mut cursor = 0;
        let mut seen = 0;
        let mut prior = EventId::ZERO;
        let mut pages = 0;
        while cursor < count {
            check()?;
            let page = store.read_page(cursor, MAX_PAGE).map_err(debug)?;
            if page.records().is_empty() || page.tip() != pin {
                return Err("page stopped or moved".into());
            }
            for record in page.records() {
                seen += 1;
                let claims = record.event().claims();
                if claims.sequence != seen
                    || claims.previous != prior
                    || claims.scope != scope
                    || claims.author != author
                {
                    return Err("paginated chain mismatch".into());
                }
                prior = record.event().id();
            }
            cursor = page.next_cursor();
            pages += 1;
        }
        if seen != count || prior != previous {
            return Err("missing history".into());
        }
        metric(
            &mut output,
            "paginate_verified_history",
            count,
            start.elapsed(),
            wire_bytes,
        );
        output.push_str(&format!("pagination_pages\t{pages}\t0\t0\n"));
        let start = Instant::now();
        for _ in 0..1000 {
            check()?;
            let page = store.read_page(count, MAX_PAGE).map_err(debug)?;
            if !page.records().is_empty() || page.tip() != pin {
                return Err("idle page mismatch".into());
            }
            std::hint::black_box(page);
        }
        metric(
            &mut output,
            "idle_empty_page_poll",
            1000,
            start.elapsed(),
            0,
        );
        let before = store.pin();
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(100));
        if store.pin() != before {
            return Err("idle mutated history".into());
        }
        metric(&mut output, "passive_idle_wall_only", 1, start.elapsed(), 0);
        drop(store);
        // This bounded reporting walk is excluded from operation timings. Core
        // reopen/page APIs never scan the complete store or retain all events.
        let (files, logical, allocated) = footprint(&home.join("activity"))?;
        output.push_str(&format!("retained_regular_files\t{files}\t0\t{logical}\nretained_allocated_bytes\t0\t0\t{allocated}\n"));
        let mut file =
            vhalla_custody::create_private_file(&home.join("metrics.tsv")).map_err(debug)?;
        file.write_all(output.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(debug)?;
        directory.sync_all().map_err(debug)?;
        println!("{output}");
        println!("preserved-output {}", home.display());
        Ok(())
    }
}
#[cfg(unix)]
fn main() {
    if let Err(error) = native::run() {
        eprintln!("performance: {error}; preserve partial synthetic output");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("performance requires Unix durable custody");
    std::process::exit(1);
}
