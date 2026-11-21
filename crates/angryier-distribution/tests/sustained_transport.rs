use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use angryier_distribution::contracts::{
    BranchDecision, BranchPoint, CampaignManifest, CampaignSpec, ContractError, Digest, ExplorationLimits, NamedDigest,
    Successor, WorkUnit,
};
use angryier_distribution::transport::{
    MAX_FRAME_BYTES, Message, RemoteStatus, TcpError, TcpServer, TcpSession, Transport, TransportError, WIRE_VERSION,
};
use angryier_types::FidelityProfile;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn manifest() -> TestResult<CampaignManifest> {
    Ok(CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(b"binary"),
        architecture: "x86_64".into(),
        entry_pc: 0x400000,
        semantic_version: "engine-v1".into(),
        semantic_profile_digest: Digest::of(b"profile"),
        script_digest: Digest::of(b"script"),
        policy_digest: Digest::of(b"policy"),
        inputs: vec![NamedDigest {
            name: "stdin".into(),
            digest: Digest::of(b"input"),
        }],
        stubs: vec![NamedDigest {
            name: "load_mem".into(),
            digest: Digest::of(b"stub"),
        }],
        solver_version: "solver-v1".into(),
        solver_policy_digest: Digest::of(b"solver policy"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 1000,
            max_path_steps: 500,
            max_active_states: 8,
            max_path_depth: 1000,
            max_loop_visits: 1000,
            max_solver_millis: 1000,
            max_wall_millis: 1000,
            max_ram_bytes: 1000,
            max_disk_bytes: 1000,
            max_trace_bytes: 1000,
        },
    })?)
}
fn transport(manifest: CampaignManifest, epoch: u64, local: &str, peer: &str) -> TestResult<Transport> {
    Ok(Transport::new(
        manifest,
        epoch,
        local.into(),
        HashMap::from([(peer.into(), [0x42; 32])]),
    )?)
}
fn deep_work(m: &CampaignManifest, epoch: u64) -> TestResult<WorkUnit> {
    let mut w = WorkUnit::root(m, epoch)?;
    for visit in 0..100 {
        w.prefix.push(BranchDecision {
            branch: BranchPoint {
                branch_pc: 0x400000,
                visit_index: visit,
                false_target: 1,
                true_target: 2,
                prefix_constraints: visit,
                trace_digest: Digest::of(&visit.to_be_bytes()),
                predicate_digest: Digest::of(&[visit as u8]),
            },
            successor: if visit % 2 == 0 {
                Successor::False
            } else {
                Successor::True
            },
        });
    }
    Ok(w)
}

#[test]
fn roundtrip_complete_contract_and_status_across_partial_frames() -> TestResult<()> {
    let m = manifest()?;
    let work = deep_work(&m, 7)?;
    let mut client = transport(m.clone(), 7, "worker", "coordinator")?;
    let mut server = transport(m.clone(), 7, "coordinator", "worker")?;
    let messages = [
        Message::Manifest(Box::new(m)),
        Message::Work(work.clone()),
        Message::Status {
            work,
            status: RemoteStatus::Completed,
        },
    ];
    let wire: Vec<u8> = messages
        .iter()
        .map(|message| client.encode("coordinator", message))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    let mut received = Vec::new();
    for piece in wire.chunks(7) {
        received.extend(server.feed(piece)?);
    }
    assert_eq!(received.len(), messages.len());
    for (actual, expected) in received.iter().zip(messages) {
        assert_eq!(actual.sender, "worker");
        assert_eq!(actual.message, expected);
    }
    assert_eq!(server.finish(), Ok(()));
    assert_eq!(server.nonce_high_water("worker"), Some((0, 3)));
    Ok(())
}

#[test]
fn bounded_grant_and_outcome_frames_are_authenticated() -> TestResult<()> {
    let m = manifest()?;
    let work = WorkUnit::root(&m, 7)?;
    let mut coordinator = transport(m.clone(), 7, "coordinator", "worker")?;
    let mut worker = transport(m.clone(), 7, "worker", "coordinator")?;
    let grant = Message::Grant {
        work: work.clone(),
        payload: vec![1, 3, 5],
    };
    let frame = coordinator.encode("worker", &grant)?;
    assert_eq!(worker.feed(&frame)?[0].message, grant);
    let outcome = Message::Outcome {
        work,
        payload: vec![7, 11],
    };
    let reply = worker.encode("coordinator", &outcome)?;
    assert_eq!(coordinator.feed(&reply)?[0].message, outcome);
    assert_eq!(coordinator.feed(&reply), Err(TransportError::Replay));
    let mut altered = reply;
    let last_payload = altered.len() - 33;
    altered[last_payload] ^= 0x40;
    let mut fresh = transport(manifest()?, 7, "coordinator", "worker")?;
    assert_eq!(fresh.feed(&altered), Err(TransportError::InvalidMac));
    assert_eq!(
        worker.encode(
            "coordinator",
            &Message::Outcome {
                work: WorkUnit::root(&m, 7)?,
                payload: vec![0; MAX_FRAME_BYTES],
            }
        ),
        Err(TransportError::Oversize)
    );
    Ok(())
}

#[test]
fn reject_oversize_truncation_bad_mac_and_replay() -> TestResult<()> {
    let m = manifest()?;
    let mut client = transport(m.clone(), 7, "worker", "coordinator")?;
    let mut server = transport(m.clone(), 7, "coordinator", "worker")?;
    let frame = client.encode("coordinator", &Message::Work(WorkUnit::root(&m, 7)?))?;
    let mut oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
    oversized.extend_from_slice(b"tiny");
    assert_eq!(server.feed(&oversized), Err(TransportError::Oversize));
    assert_eq!(server.feed(&frame[..frame.len() - 1])?.len(), 0);
    assert_eq!(server.finish(), Err(TransportError::Truncated));
    let mut tampered = frame.clone();
    tampered[12] ^= 1;
    assert_eq!(server.feed(&tampered), Err(TransportError::InvalidMac));
    assert_eq!(server.feed(&frame)?.len(), 1);
    assert_eq!(server.feed(&frame), Err(TransportError::Replay));
    assert_eq!(server.finish(), Ok(()));
    let mut future = transport(m, 7, "coordinator", "worker")?;
    future.set_nonce_high_water("worker", 0, 1)?;
    assert_eq!(future.feed(&frame), Err(TransportError::Replay));
    Ok(())
}

#[test]
fn reject_unsupported_version_malformed_peer_and_unauthorized_peer() -> TestResult<()> {
    let m = manifest()?;
    let mut client = transport(m.clone(), 1, "worker", "coordinator")?;
    let mut server = transport(m.clone(), 1, "coordinator", "worker")?;
    assert_eq!(
        client.encode("unknown", &Message::Manifest(Box::new(m.clone()))),
        Err(TransportError::UnauthorizedPeer)
    );
    let frame = client.encode("coordinator", &Message::Manifest(Box::new(m)))?;
    let mut unsupported = frame.clone();
    unsupported[8..10].copy_from_slice(&(WIRE_VERSION + 1).to_be_bytes());
    assert_eq!(server.feed(&unsupported), Err(TransportError::UnsupportedVersion));
    let mut old = frame.clone();
    // A version-1 frame carries neither the version-2 handshake nor its digest
    // binding, so it must be rejected outright rather than interoperate.
    old[8..10].copy_from_slice(&(WIRE_VERSION - 1).to_be_bytes());
    assert_eq!(server.feed(&old), Err(TransportError::UnsupportedVersion));
    let mut unknown = frame.clone();
    // Header: length(4), magic(4), version(2), kind(1), nonce(8), epoch(8), digest(32), sender length(2).
    unknown[61..67].copy_from_slice(b"rogue_");
    assert_eq!(server.feed(&unknown), Err(TransportError::UnauthorizedPeer));
    let mut invalid = frame;
    invalid[4..8].copy_from_slice(b"BAD!");
    assert_eq!(server.feed(&invalid), Err(TransportError::Malformed));
    Ok(())
}

#[test]
fn reject_stale_epoch_and_changed_campaign_binary_or_semantics() -> TestResult<()> {
    let m = manifest()?;
    let mut sender = transport(m.clone(), 3, "worker", "coordinator")?;
    let mut receiver = transport(m.clone(), 4, "coordinator", "worker")?;
    let frame = sender.encode("coordinator", &Message::Work(WorkUnit::root(&m, 3)?))?;
    assert_eq!(receiver.feed(&frame), Err(TransportError::StaleEpoch));
    for changed in [
        {
            let mut spec = m.spec.clone();
            spec.binary_digest = Digest::of(b"different binary");
            CampaignManifest::seal(spec)?
        },
        {
            let mut spec = m.spec.clone();
            spec.semantic_version = "engine-v2".into();
            CampaignManifest::seal(spec)?
        },
    ] {
        let mut receiver = transport(changed, 3, "coordinator", "worker")?;
        assert_eq!(receiver.feed(&frame), Err(TransportError::CampaignMismatch));
    }
    let mut bad_work = WorkUnit::root(&m, 3)?;
    bad_work.contract_epoch = 2;
    assert_eq!(
        sender.encode("coordinator", &Message::Work(bad_work)),
        Err(TransportError::Contract(ContractError::StaleEpoch))
    );
    Ok(())
}

#[test]
fn no_unbounded_frame_allocation_or_compression_path() -> TestResult<()> {
    let m = manifest()?;
    let mut sender = transport(m.clone(), 1, "worker", "coordinator")?;
    let mut receiver = transport(m.clone(), 1, "coordinator", "worker")?;
    let frame = sender.encode("coordinator", &Message::Manifest(Box::new(m)))?;
    assert_eq!(receiver.feed(&frame[..2])?.len(), 0);
    assert_eq!(receiver.finish(), Err(TransportError::Truncated));
    let mut bomb = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec();
    bomb.extend(std::iter::repeat_n(0xFF, 10));
    assert_eq!(receiver.feed(&bomb), Err(TransportError::Oversize));
    // No compression flag or decompressor exists: an invalid kind is rejected.
    let mut compressed = frame;
    compressed[10] = 4;
    assert_eq!(receiver.feed(&compressed), Err(TransportError::InvalidMac));
    Ok(())
}

#[test]
fn tcp_client_server_roundtrip_preserves_full_work_and_nonces() -> TestResult<()> {
    let m = manifest()?;
    let work = deep_work(&m, 7)?;
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_manifest = m.clone();
    let server_work = work.clone();
    let server = thread::spawn(move || -> TestResult<_> {
        let mut session = listener.accept(transport(server_manifest, 7, "coordinator", "worker")?, "worker")?;
        assert_eq!(session.receive()?.message, Message::Work(server_work.clone()));
        assert_eq!(session.transport().nonce_high_water("worker"), Some((0, 1)));
        session.send(&Message::Status {
            work: server_work,
            status: RemoteStatus::Accepted,
        })?;
        Ok(session.into_transport().nonce_high_water("worker"))
    });
    let mut client = TcpSession::connect(addr, transport(m, 7, "worker", "coordinator")?, "coordinator")?;
    client.send(&Message::Work(work.clone()))?;
    assert_eq!(
        client.receive()?.message,
        Message::Status {
            work,
            status: RemoteStatus::Accepted
        }
    );
    assert_eq!(client.into_transport().nonce_high_water("coordinator"), Some((1, 1)));
    assert_eq!(server.join().map_err(|_| "server thread panicked")??, Some((1, 1)));
    Ok(())
}

#[test]
fn tcp_rejects_partial_oversized_and_unauthenticated_frames() -> TestResult<()> {
    let m = manifest()?;
    let frame = transport(m.clone(), 7, "worker", "coordinator")?
        .encode("coordinator", &Message::Work(WorkUnit::root(&m, 7)?))?;
    for (bytes, expected) in [
        (frame[..3].to_vec(), TransportError::Truncated),
        (
            ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes().to_vec(),
            TransportError::Oversize,
        ),
        (frame, TransportError::InvalidMac),
    ] {
        let listener = TcpServer::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_manifest = m.clone();
        let server = thread::spawn(move || -> TestResult<()> {
            let mut session = listener.accept(transport(server_manifest, 7, "coordinator", "worker")?, "worker")?;
            assert!(matches!(session.receive(), Err(TcpError::Protocol(error)) if error == expected));
            assert_eq!(session.transport().nonce_high_water("worker"), Some((0, 0)));
            Ok(())
        });
        let raw = TcpStream::connect(addr)?;
        let mut writer = raw.try_clone()?;
        let _client = TcpSession::from_stream(raw, transport(m.clone(), 7, "worker", "coordinator")?, "coordinator")?;
        for piece in bytes.chunks(3) {
            writer.write_all(piece)?;
        }
        writer.shutdown(Shutdown::Write)?;
        server.join().map_err(|_| "server thread panicked")??;
    }
    Ok(())
}

#[test]
fn tcp_wrong_pairwise_key_is_not_accepted() -> TestResult<()> {
    let m = manifest()?;
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_manifest = m.clone();
    let server = thread::spawn(move || -> TestResult<()> {
        let different_key = HashMap::from([("worker".to_string(), [0x33; 32])]);
        let receiver = Transport::new(server_manifest, 7, "coordinator".into(), different_key)?;
        assert!(matches!(
            listener.accept(receiver, "worker"),
            Err(TcpError::Protocol(TransportError::InvalidMac))
        ));
        Ok(())
    });
    assert!(matches!(
        TcpSession::connect(addr, transport(m, 7, "worker", "coordinator")?, "coordinator"),
        Err(TcpError::Protocol(TransportError::InvalidMac))
    ));
    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[test]
fn raw_tcp_rejects_non_loopback_without_connecting() -> TestResult<()> {
    assert!(matches!(
        TcpServer::bind("0.0.0.0:0"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(matches!(
        TcpServer::bind("[::]:0"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    assert!(matches!(
        TcpSession::connect(
            "192.0.2.1:9",
            transport(manifest()?, 7, "worker", "coordinator")?,
            "coordinator"
        ),
        Err(TcpError::InsecureEndpoint)
    ));
    Ok(())
}

#[test]
fn handshake_rejects_downgrade_truncation_epoch_semantics_and_role() -> TestResult<()> {
    let m = manifest()?;
    let legacy = transport(m.clone(), 7, "worker", "coordinator")?
        .encode("coordinator", &Message::Manifest(Box::new(m.clone())))?;
    for (bytes, expected) in [
        (legacy, TransportError::InvalidMac),
        (vec![1, 2, 3], TransportError::Truncated),
        (vec![4; 48], TransportError::Truncated),
    ] {
        let listener = TcpServer::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server_m = m.clone();
        let server = thread::spawn(move || -> TestResult<()> {
            assert!(
                matches!(listener.accept(transport(server_m, 7, "coordinator", "worker")?, "worker"), Err(TcpError::Protocol(error)) if error == expected)
            );
            Ok(())
        });
        let mut raw = TcpStream::connect(addr)?;
        raw.write_all(&bytes)?;
        raw.shutdown(Shutdown::Write)?;
        server.join().map_err(|_| "server thread panicked")??;
    }
    // Epoch and role mismatches still fail closed at the proof, because both
    // values are bound into the tag the peer must reproduce.
    for (epoch, local) in [(8, "worker"), (7, "rogue")] {
        let (client, server) = handshake_error(
            transport(m.clone(), epoch, local, "coordinator")?,
            transport(m.clone(), 7, "coordinator", "worker")?,
        )?;
        for error in [client, server] {
            assert!(
                matches!(error, Some(TcpError::Protocol(TransportError::InvalidMac))),
                "expected invalid MAC, got {error:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn partial_handshake_and_partial_frame_obey_absolute_deadline() -> TestResult<()> {
    use std::time::{Duration, Instant};
    let m = manifest()?;
    let fake = TcpListener::bind("127.0.0.1:0")?;
    let addr = fake.local_addr()?;
    let peer = thread::spawn(move || -> TestResult<()> {
        let (mut stream, _) = fake.accept()?;
        let mut nonce = [0; 32];
        stream.read_exact(&mut nonce)?;
        for byte in [3; 32] {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    });
    let start = Instant::now();
    assert!(matches!(
        TcpSession::connect_until(addr, transport(m.clone(), 7, "worker", "coordinator")?, "coordinator",
            start + Duration::from_millis(120)),
        Err(TcpError::Io(error)) if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    peer.join().map_err(|_| "peer thread panicked")??;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let peer = thread::spawn(move || -> TestResult<()> {
        let (mut raw, _) = listener.accept()?;
        let _session = TcpSession::from_stream(raw.try_clone()?, transport(m, 7, "coordinator", "worker")?, "worker")?;
        for byte in [0; 4] {
            if raw.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(60));
        }
        Ok(())
    });
    let start = Instant::now();
    let mut session = TcpSession::connect_until(
        addr,
        transport(manifest()?, 7, "worker", "coordinator")?,
        "coordinator",
        start + Duration::from_millis(150),
    )?;
    assert!(matches!(session.receive(), Err(TcpError::Io(error))
        if matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)));
    assert!(start.elapsed() < Duration::from_secs(1));
    peer.join().map_err(|_| "peer thread panicked")??;
    Ok(())
}

#[test]
fn captured_handshake_proof_cannot_be_replayed() -> TestResult<()> {
    let m = manifest()?;
    let fake = TcpListener::bind("127.0.0.1:0")?;
    let addr = fake.local_addr()?;
    let attacker = thread::spawn(move || -> TestResult<_> {
        let (mut stream, _) = fake.accept()?;
        let mut challenge = [0; 32];
        stream.read_exact(&mut challenge)?;
        stream.write_all(&[7; 32])?;
        // The peer campaign digest slot, then the client's proof, then a
        // placeholder that is not a valid proof over the fresh challenge.
        stream.write_all(&[0; 32])?;
        let mut proof = [0; 32];
        stream.read_exact(&mut proof)?;
        stream.write_all(&[0; 32])?;
        Ok((challenge, proof))
    });
    assert!(matches!(
        TcpSession::connect(addr, transport(m.clone(), 7, "worker", "coordinator")?, "coordinator"),
        Err(TcpError::Protocol(TransportError::InvalidMac))
    ));
    let (challenge, proof) = attacker.join().map_err(|_| "attacker thread panicked")??;
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server = thread::spawn(move || -> TestResult<()> {
        assert!(matches!(
            listener.accept(transport(m, 7, "coordinator", "worker")?, "worker"),
            Err(TcpError::Protocol(TransportError::InvalidMac))
        ));
        Ok(())
    });
    let mut raw = TcpStream::connect(addr)?;
    let mut fresh = [0; 32];
    raw.read_exact(&mut fresh)?;
    raw.write_all(&challenge)?;
    raw.write_all(&proof)?;
    // The captured challenge and proof occupy the nonce and digest slots of the
    // fresh session; the peer proof slot is not reproducible by the attacker.
    raw.write_all(&[0; 32])?;
    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[test]
fn reconnect_with_same_pairwise_key_rejects_old_session_frame() -> TestResult<()> {
    let m = manifest()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_m = m.clone();
    let server = thread::spawn(move || -> TestResult<_> {
        let (mut raw, _) = listener.accept()?;
        let _session = TcpSession::from_stream(
            raw.try_clone()?,
            transport(server_m, 7, "coordinator", "worker")?,
            "worker",
        )?;
        let mut header = [0; 4];
        raw.read_exact(&mut header)?;
        let mut captured = header.to_vec();
        let mut rest = vec![0; u32::from_be_bytes(header) as usize];
        raw.read_exact(&mut rest)?;
        captured.extend(rest);
        Ok(captured)
    });
    let mut client = TcpSession::connect(addr, transport(m.clone(), 7, "worker", "coordinator")?, "coordinator")?;
    client.send(&Message::Manifest(Box::new(m.clone())))?;
    let captured = server.join().map_err(|_| "server thread panicked")??;
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_m = m.clone();
    let server = thread::spawn(move || -> TestResult<()> {
        let mut session = listener.accept(transport(server_m, 7, "coordinator", "worker")?, "worker")?;
        assert!(matches!(
            session.receive(),
            Err(TcpError::Protocol(TransportError::InvalidMac))
        ));
        Ok(())
    });
    let raw = TcpStream::connect(addr)?;
    let mut writer = raw.try_clone()?;
    let _client = TcpSession::from_stream(raw, transport(m, 7, "worker", "coordinator")?, "coordinator")?;
    writer.write_all(&captured)?;
    server.join().map_err(|_| "server thread panicked")??;
    Ok(())
}

#[test]
fn duplicate_pairwise_keys_cannot_impersonate_another_peer() -> TestResult<()> {
    assert!(matches!(
        Transport::new(
            manifest()?,
            7,
            "coordinator".into(),
            HashMap::from([("worker-a".into(), [0x42; 32]), ("worker-b".into(), [0x42; 32])]),
        ),
        Err(TransportError::Malformed)
    ));
    Ok(())
}

/// Drive one loopback handshake to completion or failure and return each side's
/// error; `None` means that side negotiated the session.
fn handshake_error(client: Transport, server: Transport) -> TestResult<(Option<TcpError>, Option<TcpError>)> {
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server = thread::spawn(move || -> TestResult<Option<TcpError>> { Ok(listener.accept(server, "worker").err()) });
    let client = TcpSession::connect(addr, client, "coordinator").err();
    Ok((client, server.join().map_err(|_| "server thread panicked")??))
}

#[test]
fn matching_digest_connects_and_differing_digest_reports_campaign_mismatch() -> TestResult<()> {
    let m = manifest()?;
    let (client, server) = handshake_error(
        transport(m.clone(), 7, "worker", "coordinator")?,
        transport(m.clone(), 7, "coordinator", "worker")?,
    )?;
    assert!(client.is_none() && server.is_none(), "{client:?} {server:?}");
    // A lost or altered budget changes the sealed digest, so the peer holds a
    // different manifest while still proving possession of the shared key.
    let mut spec = m.spec.clone();
    spec.limits.max_wall_millis += 1;
    let differing = CampaignManifest::seal(spec)?;
    assert_ne!(differing.campaign_digest, m.campaign_digest);
    let (client, server) = handshake_error(
        transport(differing, 7, "worker", "coordinator")?,
        transport(m, 7, "coordinator", "worker")?,
    )?;
    for error in [client, server] {
        assert!(
            matches!(error, Some(TcpError::Protocol(TransportError::CampaignMismatch))),
            "expected campaign mismatch, got {error:?}"
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Tamper {
    PeerDigest,
    PeerProof,
}

/// Relay one handshake through a middlebox that flips a byte, proving the peer
/// digest is authenticated and never trusted as received.
fn tampered_handshake(m: &CampaignManifest, tamper: Tamper) -> TestResult<(Option<TcpError>, Option<TcpError>)> {
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_transport = transport(m.clone(), 7, "coordinator", "worker")?;
    let server = thread::spawn(move || -> TestResult<Option<TcpError>> {
        Ok(listener.accept(server_transport, "worker").err())
    });
    let proxy_listener = TcpListener::bind("127.0.0.1:0")?;
    let proxy_addr = proxy_listener.local_addr()?;
    let proxy = thread::spawn(move || -> TestResult<()> {
        let (mut worker, _) = proxy_listener.accept()?;
        let mut server = TcpStream::connect(addr)?;
        // Both sides open with nonce || campaign digest before either proof.
        let mut worker_hello = [0u8; 64];
        worker.read_exact(&mut worker_hello)?;
        let mut server_hello = [0u8; 64];
        server.read_exact(&mut server_hello)?;
        if matches!(tamper, Tamper::PeerDigest) {
            worker_hello[32] ^= 0x80;
        }
        server.write_all(&worker_hello)?;
        worker.write_all(&server_hello)?;
        let mut worker_tag = [0u8; 32];
        worker.read_exact(&mut worker_tag)?;
        if matches!(tamper, Tamper::PeerProof) {
            worker_tag[0] ^= 0x80;
        }
        server.write_all(&worker_tag)?;
        let mut server_tag = [0u8; 32];
        server.read_exact(&mut server_tag)?;
        worker.write_all(&server_tag)?;
        Ok(())
    });
    let client = TcpSession::connect(
        proxy_addr,
        transport(m.clone(), 7, "worker", "coordinator")?,
        "coordinator",
    );
    proxy.join().map_err(|_| "proxy thread panicked")??;
    let server_error = server.join().map_err(|_| "server thread panicked")??;
    Ok((client.err(), server_error))
}

#[test]
fn tampered_handshake_digest_or_proof_is_rejected_as_invalid_mac() -> TestResult<()> {
    let m = manifest()?;
    let (client, server) = tampered_handshake(&m, Tamper::PeerDigest)?;
    for error in [client, server] {
        assert!(
            matches!(error, Some(TcpError::Protocol(TransportError::InvalidMac))),
            "expected invalid MAC, got {error:?}"
        );
    }
    let (_, server) = tampered_handshake(&m, Tamper::PeerProof)?;
    assert!(
        matches!(server, Some(TcpError::Protocol(TransportError::InvalidMac))),
        "expected invalid MAC, got {server:?}"
    );
    Ok(())
}

#[test]
fn version_one_handshake_peer_cannot_negotiate_a_session() -> TestResult<()> {
    let m = manifest()?;
    let listener = TcpServer::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let server_m = m.clone();
    let server = thread::spawn(move || -> TestResult<Option<TcpError>> {
        Ok(listener
            .accept(transport(server_m, 7, "coordinator", "worker")?, "worker")
            .err())
    });
    let mut raw = TcpStream::connect(addr)?;
    // A version-1 peer offers a nonce and a proof that binds no campaign digest,
    // so the version-2 requester's proof cannot be reproduced: fail closed.
    raw.write_all(&[0x11; 32])?;
    let mut hello = [0u8; 64];
    raw.read_exact(&mut hello)?;
    raw.write_all(&[0x22; 32])?;
    raw.write_all(&[0x33; 32])?;
    let error = server.join().map_err(|_| "server thread panicked")??;
    assert!(
        matches!(error, Some(TcpError::Protocol(TransportError::InvalidMac))),
        "expected invalid MAC, got {error:?}"
    );
    Ok(())
}
