//! LOCAL TEST FIXTURE ONLY. Deterministic consensus/social signing seeds are
//! public test data; never use this bootstrap or its journal as a live network.
//! Native custody peer keys are freshly generated and are never printed.
//!
//! Usage: browser_fixture NEW_HOME [--create-only] [--public-posting]
//! The home must never already exist. HTTP listeners are fixed to loopback
//! 9781/9782 and require the separately operated test proxy. No TLS, DNS, public
//! networking or validators are activated here. By default both peers are READ.
//! --public-posting adds a second certified open room and fresh bounded activity
//! stores for BOTH rooms on BOTH peers, enabling local test-only POST endpoints.
//! --create-only never starts listeners, with or without --public-posting.
//! Posting uses five deterministic eligible support sources to fund both rooms,
//! so its bootstrap/pin differs from the one-room READ fixture.
//! No existing fixture home can be upgraded or reused.
//! Serving seeds both optional discovery registries through real loopback HTTP
//! challenge/work/registration; signed route metadata confers no extra authority.
#![forbid(unsafe_code)]

#[cfg(unix)]
#[path = "browser_fixture/discovery.rs"]
mod discovery;

#[cfg(unix)]
mod native {
    use ed25519_dalek::{Signer, SigningKey};
    use std::{ffi::OsString, fs::File, io::Write, path::Path, sync::Arc};
    use vhalla_identity::Identity;
    use vhalla_journal::{Bundle, BundleParts, FsStore, Journal};
    use vhalla_public_client::{Bootstrap, CertifiedClient, Validator, ValidatorActivation};
    use vhalla_public_peer::{
        ActivityConfig, ActivityRoomConfig, Config, ContinuityConfig, ContinuityRoomConfig,
        CorsOrigin, DiscoveryConfig, ManagedPeer,
    };
    use vhalla_public_protocol::{response::hex, Endpoint};
    use vhalla_room_activity::RoomScope;
    use vhalla_room_activity_store::continuity::{ContinuityLimits, ContinuityStore};
    use vhalla_room_activity_store::{Limits as ActivityLimits, Store as ActivityStore};
    use vhalla_rooms::{RoomUpdate, Slug, UpdateAction};
    use vhalla_rooms_consensus::{fixture, Batch, Frontier};
    use vhalla_rooms_node::{Address, PublicKey};

    fn error(message: impl std::fmt::Display) -> String {
        message.to_string()
    }
    fn debug_error(message: impl std::fmt::Debug) -> String {
        format!("{message:?}")
    }

    fn export(path: &Path, raw: &[u8]) -> Result<(), String> {
        let mut file = vhalla_custody::create_private_file(path).map_err(debug_error)?;
        file.write_all(raw)
            .and_then(|_| file.sync_all())
            .map_err(error)
    }

    // Independent canonical RV1/VC2 fixture construction. Admission uses the
    // real portable certificate verifier and application replay before commit.
    fn certificate(height: u64, value: [u8; 32], validators: &[SigningKey]) -> Vec<u8> {
        let round = 0u32;
        let mut raw = b"VC2".to_vec();
        raw.extend_from_slice(&height.to_be_bytes());
        raw.extend_from_slice(&round.to_be_bytes());
        raw.extend_from_slice(&value);
        raw.extend_from_slice(&(validators.len() as u16).to_be_bytes());
        for key in validators {
            let public =
                PublicKey::from_bytes(key.verifying_key().to_bytes()).expect("fixture key");
            let address = Address::from_public_key(&public).into_inner();
            let mut vote = b"RV1".to_vec();
            vote.push(1);
            vote.extend_from_slice(&height.to_be_bytes());
            vote.extend_from_slice(&round.to_be_bytes());
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
    ) -> Result<Bundle, String> {
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
        .map_err(debug_error)
    }

    fn publish(
        journal: &Journal<FsStore>,
        client: &mut CertifiedClient,
        bundle: &Bundle,
    ) -> Result<(), String> {
        let candidate = client
            .prepare(client.network_id(), bundle.bytes())
            .map_err(debug_error)?;
        journal.commit(bundle).map_err(debug_error)?;
        client
            .commit_after_persist(candidate)
            .map(|_| ())
            .map_err(debug_error)
    }

    fn options(args: &[OsString]) -> Result<(bool, bool), String> {
        let mut create_only = false;
        let mut public_posting = false;
        let usage = "usage: browser_fixture NEW_HOME [--create-only] [--public-posting]; NEW_HOME must not exist";
        if args.is_empty() || args.len() > 3 {
            return Err(usage.into());
        }
        for flag in &args[1..] {
            if flag == "--create-only" && !create_only {
                create_only = true;
            } else if flag == "--public-posting" && !public_posting {
                public_posting = true;
            } else {
                return Err(usage.into());
            }
        }
        Ok((create_only, public_posting))
    }

    // Waits for the journey's advance-policy trigger, then commits one owner
    // update disabling the lobby's public-activity policy on the shared
    // journal. A no-show trigger exits quietly; the room's earlier enabling
    // revision stays retained, which is exactly what the held-draft recovery
    // journey exercises.
    fn advance_policy(
        home: std::path::PathBuf,
        mut scenario: fixture::Scenario,
        mut client: CertifiedClient,
        journal: Journal<FsStore>,
        keys: Vec<SigningKey>,
        genesis: vhalla_rooms::RoomGenesisId,
        network: [u8; 32],
    ) -> Result<(), String> {
        let trigger = home.join("advance-policy");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        while !trigger.exists() {
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let _ = std::fs::remove_file(&trigger);
        let room = scenario
            .app
            .registry()
            .room_by_genesis(genesis)
            .ok_or("watched lobby room missing")?;
        let update = RoomUpdate {
            directory: scenario.genesis.directory,
            realm: scenario.genesis.realm,
            genesis,
            previous: room.head(),
            owner: scenario.owners[0].id,
            social_control: scenario.owners[0].head,
            controller_key: scenario.owners[0].key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [6; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network,
                enabled: false,
            },
        }
        .sign_with_key(&scenario.owners[0].key)
        .map_err(debug_error)?;
        let policy_record = update.id();
        let checked = scenario
            .app
            .prepare(500, vec![], vec![update.encode()], None)
            .map_err(debug_error)?;
        let next = bundle(
            checked.batch(),
            checked.next(),
            *scenario.genesis.policy.id().as_bytes(),
            &keys[..3],
        )?;
        publish(&journal, &mut client, &next)?;
        scenario.app.apply_locally(checked);
        export(
            &home.join("policy-advanced"),
            format!(
                "height {}\nfrontier {}\npolicy-record {}\n",
                client.frontier().height,
                hex(&client.frontier().commitment()),
                hex(policy_record.as_bytes())
            )
            .as_bytes(),
        )
    }

    pub fn run(args: Vec<OsString>) -> Result<(), String> {
        let (create_only, public_posting) = options(&args)?;
        let home = vhalla_custody::absolute(Path::new(&args[0])).map_err(debug_error)?;
        let (directory, _uid) = vhalla_custody::create_private_directory(&home).map_err(|e| {
            format!("fresh fixture home required; never reuse existing paths: {e:?}")
        })?;
        directory.sync_all().map_err(error)?;
        File::open(home.parent().ok_or("fixture parent missing")?)
            .and_then(|f| f.sync_all())
            .map_err(error)?;

        let keys: Vec<_> = (101..=104)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        // The second room costs four additional credits. Distinct eligible
        // support sources satisfy the existing per-source/epoch award rules;
        // no test bypass or policy weakening. READ genesis stays byte identical.
        let mut scenario = fixture::scenario(1, if public_posting { 5 } else { 1 });
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
        .map_err(debug_error)?;
        let pin = bootstrap.pin();
        let network = bootstrap.network_id();
        let bootstrap_raw = bootstrap.encode();
        let mut client = CertifiedClient::new(bootstrap, pin).map_err(debug_error)?;
        let journal = Journal::with_genesis(
            home.join("journal"),
            FsStore,
            client.frontier().commitment(),
        );
        let mut cursor = 0;
        let (evidence, records, grant) = fixture::first_create(
            &scenario.app,
            &scenario.owners[0],
            &mut scenario.sources,
            &mut cursor,
            "public-lobby",
            1,
        );
        let checked = scenario
            .app
            .prepare(100, evidence, records, None)
            .map_err(debug_error)?;
        let first = bundle(
            checked.batch(),
            checked.next(),
            *scenario.genesis.policy.id().as_bytes(),
            &keys[..3],
        )?;
        publish(&journal, &mut client, &first)?;
        scenario.app.apply_locally(checked);
        let room = scenario
            .app
            .registry()
            .room(&Slug::new("public-lobby").map_err(debug_error)?)
            .ok_or("fixture room missing")?;
        let genesis = room.genesis();
        let update = RoomUpdate {
            directory: scenario.genesis.directory,
            realm: scenario.genesis.realm,
            genesis,
            previous: room.head(),
            owner: scenario.owners[0].id,
            social_control: scenario.owners[0].head,
            controller_key: scenario.owners[0].key.verifying_key().to_bytes(),
            expires_at: 1_000_000,
            nonce: [2; 32],
            action: UpdateAction::SetPublicActivityPolicy {
                network,
                enabled: true,
            },
        }
        .sign_with_key(&scenario.owners[0].key)
        .map_err(debug_error)?;
        let policy_record = update.id();
        let checked = scenario
            .app
            .prepare(200, vec![], vec![update.encode()], None)
            .map_err(debug_error)?;
        let second = bundle(
            checked.batch(),
            checked.next(),
            *scenario.genesis.policy.id().as_bytes(),
            &keys[..3],
        )?;
        publish(&journal, &mut client, &second)?;
        scenario.app.apply_locally(checked);
        if client.frontier() != scenario.app.frontier()
            || !client
                .registry()
                .room_by_genesis(genesis)
                .is_some_and(|room| room.allows_public_activity(&network, policy_record))
        {
            return Err("fixture did not replay to certified public-open room".into());
        }
        // Extend only the explicitly selected new posting fixture. The default
        // READ bootstrap, two bundle bytes and metadata remain unchanged.
        let second_room = if public_posting {
            let (evidence, records) = fixture::next_create(
                &scenario.app,
                &scenario.owners[0],
                grant,
                &mut scenario.sources,
                &mut cursor,
                "public-workshop",
                3,
            );
            let checked = scenario
                .app
                .prepare(300, evidence, records, None)
                .map_err(debug_error)?;
            let third = bundle(
                checked.batch(),
                checked.next(),
                *scenario.genesis.policy.id().as_bytes(),
                &keys[..3],
            )?;
            publish(&journal, &mut client, &third)?;
            scenario.app.apply_locally(checked);
            let room = scenario
                .app
                .registry()
                .room(&Slug::new("public-workshop").map_err(debug_error)?)
                .ok_or("second fixture room missing")?;
            let second_genesis = room.genesis();
            let update = RoomUpdate {
                directory: scenario.genesis.directory,
                realm: scenario.genesis.realm,
                genesis: second_genesis,
                previous: room.head(),
                owner: scenario.owners[0].id,
                social_control: scenario.owners[0].head,
                controller_key: scenario.owners[0].key.verifying_key().to_bytes(),
                expires_at: 1_000_000,
                nonce: [4; 32],
                action: UpdateAction::SetPublicActivityPolicy {
                    network,
                    enabled: true,
                },
            }
            .sign_with_key(&scenario.owners[0].key)
            .map_err(debug_error)?;
            let second_policy = update.id();
            let checked = scenario
                .app
                .prepare(400, vec![], vec![update.encode()], None)
                .map_err(debug_error)?;
            let fourth = bundle(
                checked.batch(),
                checked.next(),
                *scenario.genesis.policy.id().as_bytes(),
                &keys[..3],
            )?;
            publish(&journal, &mut client, &fourth)?;
            scenario.app.apply_locally(checked);
            if client.frontier() != scenario.app.frontier()
                || genesis == second_genesis
                || ![(genesis, policy_record), (second_genesis, second_policy)]
                    .iter()
                    .all(|(room, policy)| {
                        client
                            .registry()
                            .room_by_genesis(*room)
                            .is_some_and(|room| room.allows_public_activity(&network, *policy))
                    })
            {
                return Err(
                    "fixture did not replay to two distinct certified public-open rooms".into(),
                );
            }
            export(&home.join("height-3.vhbundle"), third.bytes())?;
            export(&home.join("height-4.vhbundle"), fourth.bytes())?;
            Some((second_genesis, second_policy))
        } else {
            None
        };
        export(&home.join("bootstrap.vhbootstrap"), &bootstrap_raw)?;
        export(
            &home.join("bootstrap.pin"),
            format!("{}\n", hex(&pin)).as_bytes(),
        )?;
        export(&home.join("height-1.vhbundle"), first.bytes())?;
        export(&home.join("height-2.vhbundle"), second.bytes())?;
        let mut metadata=format!("fixture local-test-only-public-consensus-and-social-seeds\nbootstrap-file {}\nbootstrap-pin {}\nnetwork-id {}\nheight {}\nfrontier {}\nroom-slug public-lobby\nroom-genesis {}\npublic-policy-record {}\nallowed-origin http://127.0.0.1:8789\n",home.join("bootstrap.vhbootstrap").display(),hex(&pin),hex(&network),client.frontier().height,hex(&client.frontier().commitment()),hex(genesis.as_bytes()),hex(policy_record.as_bytes()));
        if let Some((second_genesis, second_policy)) = second_room {
            metadata.push_str(&format!("public-posting local-test-only\nsecond-room-slug public-workshop\nsecond-room-genesis {}\nsecond-public-policy-record {}\n", hex(second_genesis.as_bytes()), hex(second_policy.as_bytes())));
        }
        let mut peers = Vec::new();
        for (name, port) in [("peer-a", 9781), ("peer-b", 9782)] {
            let peer_home = home.join(name);
            let (peer_directory, _) =
                vhalla_custody::create_private_directory(&peer_home).map_err(debug_error)?;
            drop(Identity::create_new(peer_home.join("key")).map_err(debug_error)?);
            let endpoint = Endpoint::parse(&format!("https://{name}.vhalla.dev:443/vhalla/v1"))
                .map_err(debug_error)?;
            let state = peer_home.join("state");
            let config = Config {
                bootstrap_file: home.join("bootstrap.vhbootstrap"),
                bootstrap_pin: pin,
                identity_dir: peer_home.join("key"),
                journal_dir: home.join("journal"),
                advertisement_file: state.join("advertisement"),
                public_endpoint: endpoint.clone(),
                allowed_origin: CorsOrigin::loopback_development(
                    "127.0.0.1:8789".parse().map_err(error)?,
                )
                .map_err(error)?,
                listen: format!("127.0.0.1:{port}").parse().map_err(error)?,
            };
            let peer = if let Some((second_genesis, _)) = second_room {
                let limits = ActivityLimits {
                    max_events: 10_000,
                    max_history_bytes: 64 * 1024 * 1024,
                };
                let mut rooms = Vec::new();
                for room in [genesis, second_genesis] {
                    let store_dir = peer_home.join(format!("activity-{}", hex(room.as_bytes())));
                    let scope = RoomScope {
                        network,
                        realm: scenario.genesis.realm,
                        directory: scenario.genesis.directory,
                        room,
                    };
                    drop(ActivityStore::create(&store_dir, scope, limits).map_err(debug_error)?);
                    rooms.push(ActivityRoomConfig {
                        room,
                        directory: store_dir,
                        limits,
                    });
                }
                ManagedPeer::create_with_activity(config, &state, ActivityConfig { rooms })
            } else {
                ManagedPeer::create(config, &state)
            }
            .map_err(error)?;
            let peer = Arc::new(peer);
            peer.enable_discovery(DiscoveryConfig {
                directory: peer_home.join("discovery"),
                create_new: true,
            })
            .map_err(error)?;
            let advertisement = std::fs::read(state.join("advertisement")).map_err(error)?;
            export(&home.join(format!("{name}.vhad")), &advertisement)?;
            export(
                &home.join(format!("{name}.invitation.txt")),
                format!("{}\n", hex(&advertisement)).as_bytes(),
            )?;
            metadata.push_str(&format!("{name}-key {}\n{name}-endpoint {}\n{name}-listen 127.0.0.1:{port}\n{name}-advertisement {}\n{name}-invitation {}\n",hex(&peer.application_key()),endpoint.as_str(),home.join(format!("{name}.vhad")).display(),home.join(format!("{name}.invitation.txt")).display()));
            peer_directory.sync_all().map_err(error)?;
            peers.push(peer);
        }
        // A third, explicitly continuity-mode peer: immutable v2 stores for the
        // same two rooms, never mixing with the legacy activity services above.
        if let Some((second_genesis, _)) = second_room {
            let peer_home = home.join("peer-c");
            let (peer_directory, _) =
                vhalla_custody::create_private_directory(&peer_home).map_err(debug_error)?;
            drop(Identity::create_new(peer_home.join("key")).map_err(debug_error)?);
            let endpoint =
                Endpoint::parse("https://peer-c.vhalla.dev:443/vhalla/v1").map_err(debug_error)?;
            let state = peer_home.join("state");
            let config = Config {
                bootstrap_file: home.join("bootstrap.vhbootstrap"),
                bootstrap_pin: pin,
                identity_dir: peer_home.join("key"),
                journal_dir: home.join("journal"),
                advertisement_file: state.join("advertisement"),
                public_endpoint: endpoint.clone(),
                allowed_origin: CorsOrigin::loopback_development(
                    "127.0.0.1:8789".parse().map_err(error)?,
                )
                .map_err(error)?,
                listen: "127.0.0.1:9783".parse().map_err(error)?,
            };
            let limits = ContinuityLimits {
                history: ActivityLimits {
                    max_events: 10_000,
                    max_history_bytes: 64 * 1024 * 1024,
                },
                max_stage_slots: 8,
                max_stage_events: 4096,
                max_stage_bytes: 4 * 1024 * 1024,
                stage_ttl_seconds: 3600,
            };
            let mut rooms = Vec::new();
            for room in [genesis, second_genesis] {
                let store_dir = peer_home.join(format!("continuity-{}", hex(room.as_bytes())));
                let scope = RoomScope {
                    network,
                    realm: scenario.genesis.realm,
                    directory: scenario.genesis.directory,
                    room,
                };
                drop(ContinuityStore::create(&store_dir, scope, limits).map_err(debug_error)?);
                rooms.push(ContinuityRoomConfig {
                    room,
                    directory: store_dir,
                    limits,
                });
            }
            let peer =
                ManagedPeer::create_with_continuity(config, &state, ContinuityConfig { rooms })
                    .map_err(error)?;
            let peer = Arc::new(peer);
            peer.enable_discovery(DiscoveryConfig {
                directory: peer_home.join("discovery"),
                create_new: true,
            })
            .map_err(error)?;
            let advertisement = std::fs::read(state.join("advertisement")).map_err(error)?;
            export(&home.join("peer-c.vhad"), &advertisement)?;
            export(
                &home.join("peer-c.invitation.txt"),
                format!("{}\n", hex(&advertisement)).as_bytes(),
            )?;
            metadata.push_str(&format!("peer-c-key {}\npeer-c-endpoint {}\npeer-c-listen 127.0.0.1:9783\npeer-c-advertisement {}\npeer-c-invitation {}\n",hex(&peer.application_key()),endpoint.as_str(),home.join("peer-c.vhad").display(),home.join("peer-c.invitation.txt").display()));
            peer_directory.sync_all().map_err(error)?;
            peers.push(peer);
        }
        export(&home.join("metadata.txt"), metadata.as_bytes())?;
        directory.sync_all().map_err(error)?;
        print!("{metadata}");
        std::io::stdout().flush().map_err(error)?;
        if create_only {
            println!("fixture-status generated-no-listeners");
            return Ok(());
        }
        // Posting journeys may revoke the lobby's public-activity policy
        // mid-run: a NEW_HOME/advance-policy trigger file commits one more
        // certified bundle on the shared journal, then policy-advanced marks
        // completion. A failure writes policy-advance-failed instead. Peers
        // re-read the journal per request, so the new revision propagates on
        // the next browser sync without any fixture restart.
        if public_posting {
            let watch_home = home.clone();
            std::thread::spawn(move || {
                if let Err(failed) = advance_policy(
                    watch_home.clone(),
                    scenario,
                    client,
                    journal,
                    keys,
                    genesis,
                    network,
                ) {
                    let _ = std::fs::write(watch_home.join("policy-advance-failed"), failed);
                }
            });
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(error)?;
        let outcome = runtime.block_on(async move {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(error)?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .map_err(error)?;
            let (stop_a, stopped_a) = tokio::sync::oneshot::channel();
            let (stop_b, stopped_b) = tokio::sync::oneshot::channel();
            let (stop_c, stopped_c) = tokio::sync::oneshot::channel();
            let a = peers[0].clone().bind().await.map_err(error)?;
            let b = peers[1].clone().bind().await.map_err(error)?;
            let bound_c = match peers.get(2) {
                Some(peer) => Some(peer.clone().bind().await.map_err(error)?),
                None => None,
            };
            let has_c = bound_c.is_some();
            println!("fixture-status serving-loopback-only");
            std::io::stdout().flush().map_err(error)?;
            let a = a.run(async {
                let _ = stopped_a.await;
            });
            let b = b.run(async {
                let _ = stopped_b.await;
            });
            let c = async {
                match bound_c {
                    Some(bound) => {
                        bound
                            .run(async {
                                let _ = stopped_c.await;
                            })
                            .await
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::pin!(a, b, c);
            let seed_peers = peers.clone();
            let mut setup = tokio::task::spawn_blocking(move || {
                crate::discovery::register(&seed_peers[0], &seed_peers[1], 1)?;
                crate::discovery::register(&seed_peers[1], &seed_peers[0], 0)
            });
            let mut setup_error = None;
            let early = tokio::select! {
                result=&mut a=>Some((0,result)), result=&mut b=>Some((1,result)),
                result=&mut c=>Some((2,result)),
                _=terminate.recv()=>None, _=interrupt.recv()=>None,
                result=&mut setup=> {
                    match result.map_err(error).and_then(|r| r) {
                        Ok(()) => {
                            if public_posting {
                                println!("fixture-status discovery-ready-both-publishing-peers");
                            } else {
                                println!("fixture-status discovery-ready-both-read-peers");
                            }
                            std::io::stdout().flush().map_err(error)?;
                            tokio::select! {
                                result=&mut a=>Some((0,result)), result=&mut b=>Some((1,result)),
                                result=&mut c=>Some((2,result)),
                                _=terminate.recv()=>None, _=interrupt.recv()=>None,
                            }
                        }
                        Err(error) => { setup_error = Some(error); None }
                    }
                }
            };
            let _ = stop_a.send(());
            let _ = stop_b.send(());
            let _ = stop_c.send(());
            match early {
                Some((0, result)) => {
                    let _ = b.await;
                    if has_c {
                        let _ = c.await;
                    }
                    result.map_err(error)?;
                }
                Some((1, result)) => {
                    let _ = a.await;
                    if has_c {
                        let _ = c.await;
                    }
                    result.map_err(error)?;
                }
                Some((_, result)) => {
                    let _ = a.await;
                    let _ = b.await;
                    result.map_err(error)?;
                }
                None => {
                    a.await.map_err(error)?;
                    b.await.map_err(error)?;
                    if has_c {
                        c.await.map_err(error)?;
                    }
                }
            }
            println!("fixture-status stopped");
            if let Some(error) = setup_error {
                return Err(error);
            }
            Ok::<(), String>(())
        });
        runtime.shutdown_timeout(std::time::Duration::from_secs(15));
        outcome
    }

    #[cfg(test)]
    mod tests {
        use super::options;
        use std::ffi::OsString;

        #[test]
        fn posting_opt_in_preserves_create_only_and_refuses_ambiguous_flags() {
            for (args, expected) in [
                (vec!["new-home"], (false, false)),
                (vec!["new-home", "--create-only"], (true, false)),
                (vec!["new-home", "--public-posting"], (false, true)),
                (
                    vec!["new-home", "--create-only", "--public-posting"],
                    (true, true),
                ),
                (
                    vec!["new-home", "--public-posting", "--create-only"],
                    (true, true),
                ),
            ] {
                assert_eq!(
                    options(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).unwrap(),
                    expected
                );
            }
            for args in [
                vec![],
                vec!["new-home", "--unknown"],
                vec!["new-home", "--create-only", "--create-only"],
                vec!["new-home", "--public-posting", "--public-posting"],
            ] {
                assert!(
                    options(&args.into_iter().map(OsString::from).collect::<Vec<_>>()).is_err()
                );
            }
        }
    }
}

#[cfg(unix)]
fn main() {
    if let Err(error) = native::run(std::env::args_os().skip(1).collect()) {
        eprintln!("browser fixture: {error}; preserve any partial fixture artifacts");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("browser_fixture requires native Unix custody and loopback sockets");
    std::process::exit(1);
}
