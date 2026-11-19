//! Run both roles from the SAME compiled example executable: the campaign pins
//! its executable SHA-256, so `angryier-campaign worker` is not interchangeable.
//!
//! Worker: `rust_api --role worker --binary FILE --build-id ID --key-file KEY`
//!         `--worker-id ID --addr 127.0.0.1:PORT` (PORT may be 0; read READY).
//! Coordinator: `rust_api --role coordinator --binary FILE --build-id ID`
//!              `--ledger FILE --peer ID@127.0.0.1:PORT@KEY` (1, 2, or 4 peers).
//! Raw TCP is plaintext; only connect to loopback, using independently secured
//! tunnels between hosts. Default mode is ELF; set `config.image_mode` to
//! `ImageMode::PeDriver` in BOTH roles below for the PE loader model, not
//! Windows execution/fidelity. Set `config.entry` and `config.symbolic_reg`
//! identically in both roles if overriding their defaults.
#![cfg(target_arch = "x86_64")]

use angryier_campaign::{Config, ImageMode, Peer, coordinate_with_evidence, serve};
use angryier_ledger::evidence::{PathDisposition, ReplayVerification};
use std::{collections::HashSet, env, net::SocketAddr, path::PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("rust_api: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut role = None;
    let mut binary = None;
    let mut ledger = None;
    let mut build_id = None;
    let mut key_file = None;
    let mut worker_id = None;
    let mut addr = None;
    let mut peers = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(option) = args.next() {
        let value = args.next().ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--role" => role = Some(value),
            "--binary" => binary = Some(PathBuf::from(value)),
            "--ledger" => ledger = Some(PathBuf::from(value)),
            "--build-id" => build_id = Some(value),
            "--key-file" => key_file = Some(PathBuf::from(value)),
            "--worker-id" => worker_id = Some(value),
            "--addr" => addr = Some(value.parse::<SocketAddr>()?),
            "--peer" => {
                let mut fields = value.splitn(3, '@');
                let id = fields.next().unwrap_or_default();
                let addr: SocketAddr = fields
                    .next()
                    .ok_or("--peer must be ID@LOOPBACK_ADDR@KEY_FILE")?
                    .parse()?;
                let key_file = fields
                    .next()
                    .filter(|path| !path.is_empty())
                    .ok_or("--peer must be ID@LOOPBACK_ADDR@KEY_FILE")?;
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b)) {
                    return Err("peer ID must be a non-empty alphanumeric, dot, dash, or underscore token".into());
                }
                if !addr.ip().is_loopback() || addr.port() == 0 {
                    return Err(format!("peer address must be a concrete loopback endpoint: {addr}").into());
                }
                peers.push(Peer {
                    id: id.into(),
                    addr,
                    key_file: key_file.into(),
                });
            }
            _ => return Err(format!("unknown option {option}").into()),
        }
    }
    let binary = binary.ok_or("--binary is required")?;
    let build_id = build_id.ok_or("--build-id is required")?;
    let (config, coordinator_addr, ledger) = match role.as_deref() {
        Some("worker") => {
            if ledger.is_some() || !peers.is_empty() {
                return Err("worker does not accept --ledger or --peer".into());
            }
            let addr = addr.ok_or("worker requires --addr")?;
            if !addr.ip().is_loopback() {
                return Err("worker --addr must be loopback".into());
            }
            let mut config = Config::defaults(binary, key_file.ok_or("worker requires --key-file")?, build_id);
            config.worker_id = worker_id.ok_or("worker requires --worker-id")?;
            // For PE, change this to ImageMode::PeDriver in BOTH roles.
            config.image_mode = ImageMode::Elf;
            return serve(&config, addr, 0);
        }
        Some("coordinator") => {
            if key_file.is_some() || worker_id.is_some() || addr.is_some() {
                return Err("coordinator accepts --peer, not --key-file, --worker-id or --addr".into());
            }
            if !matches!(peers.len(), 1 | 2 | 4) {
                return Err("provide exactly 1, 2, or 4 --peer triples".into());
            }
            let ids: HashSet<_> = peers.iter().map(|peer| &peer.id).collect();
            let addrs: HashSet<_> = peers.iter().map(|peer| peer.addr).collect();
            let keys: HashSet<_> = peers.iter().map(|peer| &peer.key_file).collect();
            if ids.len() != peers.len() || addrs.len() != peers.len() || keys.len() != peers.len() {
                return Err("peer IDs, addresses, and key-file paths must be distinct".into());
            }
            let ledger = ledger.ok_or("coordinator requires --ledger")?;
            let mut config = Config::defaults(binary, peers[0].key_file.clone(), build_id);
            let addr = peers[0].addr;
            config.peers = peers;
            // For PE, change this to ImageMode::PeDriver in BOTH roles.
            config.image_mode = ImageMode::Elf;
            (config, addr, ledger)
        }
        _ => return Err("--role must be worker or coordinator".into()),
    };
    let outcome = coordinate_with_evidence(&config, coordinator_addr, ledger)?;
    let report = &outcome.report;
    let witnessed_terminals = outcome
        .accepted_evidence
        .iter()
        .filter(|event| {
            event.delta.path.disposition == PathDisposition::Terminal
                && event
                    .delta
                    .path
                    .witness
                    .as_ref()
                    .is_some_and(|witness| matches!(witness.replay, ReplayVerification::Verified { .. }))
        })
        .count();
    println!("campaign report: {report:?}");
    println!("latest accepted evidence paths: {}", outcome.accepted_evidence.len());
    println!("replay-verified witnessed terminal paths: {witnessed_terminals}");
    if !report.complete_within_declared_bounds {
        return Err("campaign incomplete within declared bounds".into());
    }
    Ok(())
}
