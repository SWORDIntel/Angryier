use angryier_campaign::local::LocalRegister;
use angryier_campaign::worker_config::WorkerConfig;
use angryier_campaign::{Config, ImageMode, LocalCampaign, LocalConfig, LocalPolicy, Peer, Result, SymbolicRegister};
use angryier_ledger::evidence::{PathDisposition, ReplayVerification};
use angryier_ledger::sustained::Status;
use std::{
    env,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

struct Cli {
    role: String,
    config: Config,
    output: Option<PathBuf>,
    worker_binary: Option<PathBuf>,
    sign_key: Option<PathBuf>,
    ledger: Option<PathBuf>,
    addr: Option<SocketAddr>,
    connections: u64,
    policy: LocalPolicy,
    find: Vec<u64>,
    avoid: Vec<u64>,
    symbolic: Option<Vec<(LocalRegister, u16)>>,
    regs: Vec<(LocalRegister, u64)>,
    batch_ms: Option<u64>,
    run_ms: Option<u64>,
    /// Consumed inside `parse`: `config.entry` carries the resolved address.
    #[allow(dead_code)]
    root_symbol: Option<String>,
}

fn pc(value: &str) -> Result<u64> {
    let parsed = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    };
    Ok(parsed.map_err(|_| "PC requires an absolute u64 address (decimal or 0x hexadecimal)")?)
}

fn worker_config_path(args: &[String]) -> Result<Option<PathBuf>> {
    if args.first().is_some_and(|role| role == "worker") && args.get(1).is_some_and(|flag| flag == "--config") {
        if args.len() != 3 || args[2].is_empty() || args[2].starts_with("--") {
            return Err("worker --config requires exactly one FILE and no other flags".into());
        }
        return Ok(Some(PathBuf::from(&args[2])));
    }
    if args.iter().any(|arg| arg == "--config") {
        return Err("--config is only valid as worker --config FILE".into());
    }
    Ok(None)
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Cli> {
    let mut args = args.into_iter();
    let role = args.next().ok_or("expected worker, coordinator, or local-* command")?;
    let local = matches!(
        role.as_str(),
        "local-start" | "local-resume" | "local-status" | "local-advance" | "local-retry" | "local-run"
    );
    if !local && role != "worker" && role != "coordinator" && role != "worker-config" {
        return Err("expected worker, worker-config, coordinator, or local-* command".into());
    }
    let mut output = None;
    let mut worker_binary = None;
    let mut sign_key = None;
    let mut binary = None;
    let mut key_file = None;
    let mut build_id = None;
    let mut addr = None;
    let mut ledger = None;
    let mut progress_jsonl = None;
    let mut connections = 0;
    let mut worker_id = None;
    let mut peers = Vec::new();
    let mut image_mode = ImageMode::Elf;
    let mut entry = None;
    let mut symbolic_reg = SymbolicRegister::Rbx;
    let mut legacy_symbolic = false;
    let mut symbolic: Option<Vec<(LocalRegister, u16)>> = None;
    let mut regs = Vec::new();
    let mut limits = Config::defaults(PathBuf::new(), PathBuf::new(), String::new()).limits;
    let mut policy = LocalPolicy::ForkAll;
    let mut find = Vec::new();
    let mut avoid = Vec::new();
    let mut exclude_avoid = false;
    let mut batch_ms = None;
    let mut run_ms = None;
    let mut root_symbol = None;
    while let Some(flag) = args.next() {
        if flag == "--exclude-avoid" {
            if !local {
                return Err("--exclude-avoid is local-only".into());
            }
            exclude_avoid = true;
            continue;
        }
        let value = args.next().ok_or("each option requires a value")?;
        match flag.as_str() {
            "--binary" => binary = Some(PathBuf::from(value)),
            "--image-mode" if !local => image_mode = value.parse()?,
            "--symbolic-reg" => {
                if local && symbolic.is_some() {
                    return Err("--symbolic-reg cannot be mixed with --symbolic".into());
                }
                symbolic_reg = value.parse()?;
                legacy_symbolic = true;
            }
            "--symbolic" if local => {
                if legacy_symbolic {
                    return Err("--symbolic cannot be mixed with --symbolic-reg".into());
                }
                symbolic.get_or_insert_with(Vec::new).push((value.parse()?, 64));
            }
            "--reg" if local => {
                let (name, seed) = value.split_once('=').ok_or("--reg requires NAME=VALUE")?;
                regs.push((
                    name.parse()?,
                    pc(seed).map_err(|_| "--reg requires a u64 value (decimal or 0x hexadecimal)")?,
                ));
            }
            "--entry" if !local => {
                if root_symbol.is_some() {
                    return Err("--entry and --root-symbol are mutually exclusive".into());
                }
                entry = Some(pc(&value)?);
            }
            "--root-symbol" => {
                if entry.is_some() {
                    return Err("--entry and --root-symbol are mutually exclusive".into());
                }
                if value.is_empty() || value.starts_with('-') {
                    return Err("--root-symbol requires a symbol name".into());
                }
                root_symbol = Some(value);
            }
            "--key-file" if !local => key_file = Some(PathBuf::from(value)),
            "--worker-id" if !local => worker_id = Some(value),
            "--peer" if !local && role != "worker-config" => {
                let mut fields = value.splitn(3, '@');
                let id = fields.next().ok_or("expected --peer ID@LOOPBACK_ADDR@KEY_FILE")?;
                let address = fields.next().ok_or("expected --peer ID@LOOPBACK_ADDR@KEY_FILE")?;
                let file = fields.next().ok_or("expected --peer ID@LOOPBACK_ADDR@KEY_FILE")?;
                peers.push(Peer {
                    id: id.into(),
                    addr: address.parse()?,
                    key_file: PathBuf::from(file),
                });
            }
            "--build-id" => build_id = Some(value),
            "--listen" if !local => addr = Some(value.parse::<SocketAddr>()?),
            "--connect" if role == "coordinator" || role == "worker" => addr = Some(value.parse::<SocketAddr>()?),
            "--ledger" if role != "worker-config" => ledger = Some(PathBuf::from(value)),
            "--progress-jsonl" if !local && role != "worker-config" => progress_jsonl = Some(PathBuf::from(value)),
            "--output" if role == "worker-config" => output = Some(PathBuf::from(value)),
            "--worker-binary" if role == "worker-config" => worker_binary = Some(PathBuf::from(value)),
            "--sign-key" if role == "worker-config" => sign_key = Some(PathBuf::from(value)),
            "--connections" if !local => connections = value.parse::<u64>()?,
            "--policy" if local => {
                policy = match value.as_str() {
                    "fork-all" => LocalPolicy::ForkAll,
                    "rank-targets" => LocalPolicy::RankTargets { exclude_avoid: false },
                    _ => return Err("--policy requires fork-all or rank-targets".into()),
                }
            }
            "--find" if local => find.push(pc(&value)?),
            "--avoid" if local => avoid.push(pc(&value)?),
            "--batch-ms" if role == "local-run" => batch_ms = Some(value.parse()?),
            "--run-ms" if role == "local-run" => run_ms = Some(value.parse()?),
            "--max-steps" => limits.max_steps = value.parse()?,
            "--max-path-steps" => limits.max_path_steps = value.parse()?,
            "--max-active-states" => limits.max_active_states = value.parse()?,
            "--max-path-depth" => limits.max_path_depth = value.parse()?,
            "--max-loop-visits" => limits.max_loop_visits = value.parse()?,
            "--max-solver-ms" => limits.max_solver_millis = value.parse()?,
            "--max-wall-ms" => limits.max_wall_millis = value.parse()?,
            "--max-ram-bytes" => limits.max_ram_bytes = value.parse()?,
            "--max-disk-bytes" => limits.max_disk_bytes = value.parse()?,
            "--max-trace-bytes" => limits.max_trace_bytes = value.parse()?,
            _ => return Err(format!("unsupported option {flag}").into()),
        }
    }
    if role == "local-run" {
        let wall = limits.max_wall_millis;
        let batch = batch_ms.unwrap_or(5_000).min(wall);
        let run = run_ms.unwrap_or(wall);
        if batch == 0 || run == 0 || batch_ms.is_some_and(|value| value > wall) || run > wall {
            return Err("--batch-ms and --run-ms must be positive and at most --max-wall-ms".into());
        }
        batch_ms = Some(batch);
        run_ms = Some(run);
    }
    if exclude_avoid {
        policy = match policy {
            LocalPolicy::RankTargets { .. } => LocalPolicy::RankTargets { exclude_avoid: true },
            LocalPolicy::ForkAll => return Err("--exclude-avoid requires --policy rank-targets".into()),
        };
    }
    if role == "worker-config" && (worker_id.is_none() || key_file.is_none() || sign_key.is_none()) {
        return Err("worker-config requires --worker-id, --key-file, and --sign-key".into());
    }
    if role == "worker" && !peers.is_empty() {
        return Err("worker cannot specify coordinator --peer entries".into());
    }
    if role == "coordinator" && !peers.is_empty() && (addr.is_some() || key_file.is_some() || worker_id.is_some()) {
        return Err("--peer pool cannot mix with legacy --connect/--key-file/--worker-id".into());
    }
    let pool_addr = peers.first().map(|peer| peer.addr);
    let mut config = Config::defaults(
        binary.ok_or("--binary is required")?,
        key_file.unwrap_or_default(),
        build_id.ok_or("--build-id is required")?,
    );
    if let Some(id) = worker_id {
        config.worker_id = id;
    }
    config.image_mode = image_mode;
    config.entry = entry;
    if let Some(name) = &root_symbol {
        config.entry = Some(angryier_campaign::resolve_entry_symbol(&config, name)?);
    }
    config.symbolic_reg = symbolic_reg;
    config.peers = peers;
    config.limits = limits;
    config.progress_jsonl = progress_jsonl;
    if local && ledger.is_none() {
        return Err("--ledger is required".into());
    }
    let addr = if local {
        None
    } else {
        Some(
            addr.or(pool_addr)
                .ok_or("--listen (worker), --connect (legacy), or --peer (pool) required")?,
        )
    };
    if role == "worker-config" {
        if output.is_none() {
            return Err("worker-config requires --output".into());
        }
        if !addr.ok_or("--listen is required")?.ip().is_loopback() {
            return Err("worker listener must be loopback".into());
        }
    }
    Ok(Cli {
        role,
        config,
        output,
        worker_binary,
        sign_key,
        ledger,
        addr,
        connections,
        policy,
        find,
        avoid,
        symbolic,
        regs,
        batch_ms,
        run_ms,
        root_symbol,
    })
}

#[cfg(target_arch = "x86_64")]
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(target_arch = "x86_64")]
fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c <= '\u{1f}' => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(target_arch = "x86_64")]
fn print_local_evidence(campaign: &LocalCampaign, find: &[u64], avoid: &[u64]) {
    let latest: Vec<_> = campaign.cumulative_evidence().collect();
    for (kind, event) in latest
        .iter()
        .copied()
        .map(|event| ("evidence_latest", event))
        .chain(campaign.accepted_events().iter().map(|event| ("evidence_event", event)))
    {
        let path = &event.delta.path;
        let witness = path.witness.as_ref().and_then(|witness| {
            if let ReplayVerification::Verified { trace_digest } = witness.replay {
                Some(hex(&trace_digest))
            } else {
                None
            }
        });
        let witness = witness.map_or_else(|| "null".to_owned(), |digest| format!("\"{digest}\""));
        println!(
            "{{\"type\":\"{kind}\",\"path_id\":\"{}\",\"provenance_digest\":\"{}\",\"work_index\":{},\"attempt\":{},\"sequence\":{},\"replay_digest\":\"{}\",\"status\":\"{}\",\"disposition\":\"{}\",\"verified_trace_digest\":{witness}}}",
            hex(&path.path_id),
            hex(&path.provenance_digest),
            event.work_index,
            event.attempt,
            event.delta.sequence,
            hex(&event.replay_digest.0),
            json_escape(&format!("{:?}", event.status)),
            json_escape(&format!("{:?}", path.disposition)),
        );
    }
    for (kind, targets) in [("find", find), ("avoid", avoid)] {
        let mut targets = targets.to_vec();
        targets.sort_unstable();
        for target in targets {
            let observed = latest.iter().find(|event| {
                let path = &event.delta.path;
                matches!(event.status, Status::Completed)
                    && matches!(path.disposition, PathDisposition::Terminal)
                    && path.witness.as_ref().is_some_and(|witness| {
                        matches!(witness.replay, ReplayVerification::Verified { .. })
                            && witness.replay_trace.iter().any(|block| block.pc == target)
                    })
            });
            let path_id = observed.map_or_else(
                || "null".to_owned(),
                |event| format!("\"{}\"", hex(&event.delta.path.path_id)),
            );
            println!(
                "{{\"type\":\"target\",\"kind\":\"{kind}\",\"pc\":{target},\"observed\":{},\"path_id\":{path_id}}}",
                observed.is_some(),
            );
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RunExit {
    Complete,
    Partial,
}

#[cfg(target_arch = "x86_64")]
fn run_local_campaign(mut campaign: LocalCampaign, batch_ms: u64, run_ms: u64) -> Result<RunExit> {
    use std::io::Write as _;

    let deadline = Duration::from_millis(run_ms);
    let started = Instant::now();
    let mut previous = campaign.checked_report()?;
    let mut emitted = 0;
    for event in campaign.accepted_events() {
        println!(
            "{{\"type\":\"replayed_event_id\",\"work_index\":{},\"attempt\":{},\"sequence\":{},\"path_id\":\"{}\",\"replay_digest\":\"{}\"}}",
            event.work_index,
            event.attempt,
            event.delta.sequence,
            hex(&event.delta.path.path_id),
            hex(&event.replay_digest.0),
        );
        emitted += 1;
    }
    std::io::stdout().flush()?;
    if previous.complete_within_declared_bounds || previous.queued == 0 && previous.active == 0 {
        println!("{previous:?}");
        std::io::stdout().flush()?;
        return Ok(if previous.complete_within_declared_bounds {
            RunExit::Complete
        } else {
            RunExit::Partial
        });
    }
    loop {
        let remaining_ms = deadline.saturating_sub(started.elapsed()).as_millis();
        if remaining_ms == 0 {
            println!("{previous:?}");
            std::io::stdout().flush()?;
            return Ok(RunExit::Partial);
        }
        let timeout = Duration::from_millis(u128::from(batch_ms).min(remaining_ms) as u64);
        let outcome = campaign.advance(timeout)?;
        println!("{:?}", outcome.report);
        let events = campaign.accepted_events();
        for event in &events[emitted..] {
            println!(
                "{{\"type\":\"accepted_event_id\",\"work_index\":{},\"attempt\":{},\"sequence\":{},\"path_id\":\"{}\",\"replay_digest\":\"{}\"}}",
                event.work_index,
                event.attempt,
                event.delta.sequence,
                hex(&event.delta.path.path_id),
                hex(&event.replay_digest.0),
            );
        }
        let unchanged = outcome.steps == 0 && previous == outcome.report && emitted == events.len();
        emitted = events.len();
        std::io::stdout().flush()?;
        if outcome.report.complete_within_declared_bounds {
            return Ok(RunExit::Complete);
        }
        if outcome.report.queued == 0 && outcome.report.active == 0 || unchanged {
            return Ok(RunExit::Partial);
        }
        previous = outcome.report;
    }
}

fn run() -> Result<RunExit> {
    let args: Vec<_> = env::args().skip(1).collect();
    if let Some(path) = worker_config_path(&args)? {
        let (config, addr, connections, expected_image_sha256) = WorkerConfig::load(&path)?;
        #[cfg(target_arch = "x86_64")]
        angryier_campaign::serve_pinned(&config, addr, connections, &expected_image_sha256)?;
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (config, addr, connections, expected_image_sha256);
            angryier_campaign::unsupported_architecture()?;
        }
        return Ok(RunExit::Complete);
    }
    let Cli {
        role,
        config,
        output,
        worker_binary,
        sign_key,
        ledger,
        addr,
        connections,
        policy,
        find,
        avoid,
        symbolic,
        regs,
        batch_ms,
        run_ms,
        // Applied inside `parse`: `config.entry` is already resolved numeric.
        root_symbol: _,
    } = parse(args)?;
    #[cfg(target_arch = "x86_64")]
    match role.as_str() {
        "worker-config" => {
            let mut handoff = WorkerConfig::from_worker(&config, addr.ok_or("--listen is required")?, connections)?;
            if let Some(path) = worker_binary {
                handoff.set_worker_binary_path(path)?;
            }
            handoff.write_new(
                &output.ok_or("--output is required")?,
                &sign_key.ok_or("--sign-key is required")?,
            )?;
            Ok(RunExit::Complete)
        }
        "worker" => {
            angryier_campaign::serve(&config, addr.ok_or("distributed address required")?, connections)?;
            Ok(RunExit::Complete)
        }
        "coordinator" => {
            let report = angryier_campaign::coordinate(
                &config,
                addr.ok_or("distributed address required")?,
                ledger.ok_or("--ledger is required")?,
            )?;
            println!("{report:?}");
            if !report.complete_within_declared_bounds {
                return Err("campaign partial: unresolved owned work remains".into());
            }
            Ok(RunExit::Complete)
        }
        "local-start" | "local-resume" | "local-status" | "local-advance" | "local-retry" | "local-run" => {
            let timeout = Duration::from_millis(config.limits.max_wall_millis);
            let targets = (find.clone(), avoid.clone());
            let local_config = LocalConfig {
                campaign: config,
                ledger: ledger.ok_or("--ledger is required")?,
                policy,
                find,
                avoid,
                symbolic,
                regs,
            };
            let mut campaign = if role == "local-start" || role == "local-run" && !local_config.ledger.exists() {
                LocalCampaign::start(local_config)?
            } else {
                LocalCampaign::resume(local_config)?
            };
            if role == "local-run" {
                return run_local_campaign(
                    campaign,
                    batch_ms.ok_or("missing batch bound")?,
                    run_ms.ok_or("missing run bound")?,
                );
            }
            match role.as_str() {
                "local-advance" => {
                    let outcome = campaign.advance(timeout)?;
                    println!("{:?}", outcome.report);
                    print_local_evidence(&campaign, &targets.0, &targets.1);
                    if !outcome.report.complete_within_declared_bounds {
                        return Err("campaign partial: unresolved owned work remains".into());
                    }
                }
                "local-retry" => {
                    campaign.retry_deferred()?;
                    println!("{:?}", campaign.checked_report()?);
                    print_local_evidence(&campaign, &targets.0, &targets.1);
                }
                _ => {
                    println!("{:?}", campaign.checked_report()?);
                    print_local_evidence(&campaign, &targets.0, &targets.1);
                }
            }
            Ok(RunExit::Complete)
        }
        _ => unreachable!(),
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (
            role,
            config,
            addr,
            output,
            worker_binary,
            sign_key,
            ledger,
            connections,
            policy,
            find,
            avoid,
            symbolic,
            regs,
            batch_ms,
            run_ms,
        );
        angryier_campaign::unsupported_architecture()?;
        Ok(RunExit::Complete)
    }
}

fn main() {
    match run() {
        Ok(RunExit::Complete) => {}
        Ok(RunExit::Partial) => std::process::exit(2),
        Err(error) => {
            eprintln!("campaign: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn local_evidence_escapes_disposition_reason() {
        let reason = "Pending(Unknown(\"quote\\slash\nline\rreturn\ttab\u{0001}\"))";
        assert_eq!(
            format!(
                "{{\"status\":\"{}\",\"disposition\":\"{}\"}}",
                json_escape("Deferred"),
                json_escape(reason)
            ),
            "{\"status\":\"Deferred\",\"disposition\":\"Pending(Unknown(\\\"quote\\\\slash\\nline\\rreturn\\ttab\\u0001\\\"))\"}"
        );
    }

    fn parse_test(args: &[&str]) -> Result<Cli> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    /// Minimal ET_REL object with one executable `.text` byte and a defined
    /// `main` symbol, for `--root-symbol` resolution without the corpus.
    fn write_minimal_ko(dir: &std::path::Path, name: &str) -> std::io::Result<PathBuf> {
        use std::io::Write as _;
        let path = dir.join(name);
        let text = [0x90u8]; // nop
        let strtab = b"\0main\0";
        let names = b"\0.text\0.symtab\0.strtab\0";
        let mut symtab = Vec::new();
        let push = |v: &mut Vec<u8>, name: u32, info: u8, shndx: u16, value: u64, size: u64| {
            v.extend_from_slice(&name.to_le_bytes());
            v.push(info);
            v.push(0);
            v.extend_from_slice(&shndx.to_le_bytes());
            v.extend_from_slice(&value.to_le_bytes());
            v.extend_from_slice(&size.to_le_bytes());
        };
        push(&mut symtab, 0, 0, 0, 0, 0);
        push(&mut symtab, 1, 0x12, 1, 0, 0); // main GLOBAL FUNC in .text
        let mut body: Vec<u8> = Vec::new();
        let text_off = 64 + body.len();
        body.extend_from_slice(&text);
        let symtab_off = 64 + body.len();
        body.extend_from_slice(&symtab);
        let strtab_off = 64 + body.len();
        body.extend_from_slice(strtab);
        let names_off = 64 + body.len();
        body.extend_from_slice(names);
        let shoff = 64 + body.len();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"\x7fELF");
        out.extend_from_slice(&[2, 1, 1]);
        out.extend_from_slice(&[0u8; 9]);
        out.extend_from_slice(&1u16.to_le_bytes()); // ET_REL
        out.extend_from_slice(&62u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        out.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
        out.extend_from_slice(&shoff.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // e_shstrndx = names
        out.extend_from_slice(&body);
        let sh = |name: u32, kind: u32, flags: u64, off: u64, size: u64, link: u32, align: u64, entsize: u64| {
            let mut v = Vec::with_capacity(64);
            v.extend_from_slice(&name.to_le_bytes());
            v.extend_from_slice(&kind.to_le_bytes());
            v.extend_from_slice(&flags.to_le_bytes());
            v.extend_from_slice(&0u64.to_le_bytes());
            v.extend_from_slice(&off.to_le_bytes());
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&link.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&align.to_le_bytes());
            v.extend_from_slice(&entsize.to_le_bytes());
            v
        };
        out.extend_from_slice(&sh(0, 0, 0, 0, 0, 0, 0, 0));
        out.extend_from_slice(&sh(1, 1, 0x6, text_off as u64, text.len() as u64, 0, 16, 0));
        out.extend_from_slice(&sh(7, 2, 0, symtab_off as u64, symtab.len() as u64, 3, 8, 24));
        out.extend_from_slice(&sh(15, 3, 0, strtab_off as u64, strtab.len() as u64, 0, 1, 0));
        out.extend_from_slice(&sh(23, 3, 0, names_off as u64, names.len() as u64, 0, 1, 0));
        let mut file = std::fs::File::create(&path)?;
        file.write_all(&out)?;
        Ok(path)
    }

    #[test]
    fn root_symbol_resolves_and_conflicts_with_entry() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("angryier-root-symbol-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let ko = write_minimal_ko(&dir, "minimal.ko")?;
        let ko = ko.to_str().ok_or("temp path is not UTF-8")?;

        let cli = parse_test(&[
            "worker",
            "--binary",
            ko,
            "--worker-id",
            "w1",
            "--key-file",
            "k.key",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:9101",
            "--root-symbol",
            "main",
        ])?;
        assert_eq!(cli.root_symbol.as_deref(), Some("main"));
        assert_eq!(cli.config.entry, Some(0x0100_0000));

        let cli = parse_test(&[
            "local-run",
            "--binary",
            ko,
            "--build-id",
            "v1",
            "--ledger",
            "l.ledger",
            "--root-symbol",
            "main",
        ])?;
        assert_eq!(cli.config.entry, Some(0x0100_0000));

        let conflict = parse_test(&[
            "worker",
            "--binary",
            "a.ko",
            "--worker-id",
            "w1",
            "--key-file",
            "k.key",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:9101",
            "--entry",
            "0x1000",
            "--root-symbol",
            "init_module",
        ]);
        assert!(conflict.is_err(), "--entry with --root-symbol must fail");

        let reverse = parse_test(&[
            "worker",
            "--binary",
            "a.ko",
            "--worker-id",
            "w1",
            "--key-file",
            "k.key",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:9101",
            "--root-symbol",
            "init_module",
            "--entry",
            "0x1000",
        ]);
        assert!(reverse.is_err(), "--root-symbol with --entry must fail");
        Ok(())
    }

    #[test]
    fn local_run_bounds_are_cli_only_and_order_independent() -> Result<()> {
        let base = [
            "local-run",
            "--binary",
            "a.elf",
            "--ledger",
            "a.ledger",
            "--build-id",
            "v1",
        ];
        let defaults = parse_test(&base)?;
        assert_eq!(defaults.batch_ms, Some(5_000));
        assert_eq!(defaults.run_ms, Some(defaults.config.limits.max_wall_millis));
        let mut args = base.to_vec();
        args.extend(["--batch-ms", "100", "--run-ms", "400", "--max-wall-ms", "400"]);
        let cli = parse_test(&args)?;
        assert_eq!(cli.batch_ms, Some(100));
        assert_eq!(cli.run_ms, Some(400));
        assert_eq!(cli.config.limits.max_wall_millis, 400);
        let mut args = base.to_vec();
        args.extend(["--max-wall-ms", "200"]);
        let capped = parse_test(&args)?;
        assert_eq!(capped.batch_ms, Some(200));
        assert_eq!(capped.run_ms, Some(200));
        for extra in [
            ["--batch-ms", "0"],
            ["--run-ms", "0"],
            ["--batch-ms", "401"],
            ["--run-ms", "401"],
            ["--run-ms", "invalid"],
        ] {
            let mut args = base.to_vec();
            args.extend(["--max-wall-ms", "400"]);
            args.extend(extra);
            assert!(parse_test(&args).is_err(), "accepted {extra:?}");
        }
        for role in [
            "worker",
            "coordinator",
            "local-start",
            "local-resume",
            "local-advance",
            "local-status",
            "local-retry",
        ] {
            for flag in ["--batch-ms", "--run-ms"] {
                let mut args = base.to_vec();
                args[0] = role;
                args.extend([flag, "100"]);
                assert!(parse_test(&args).is_err(), "accepted {flag} for {role}");
            }
        }
        Ok(())
    }

    #[test]
    fn local_spec_and_limits_are_shared_across_controls() -> Result<()> {
        for role in [
            "local-start",
            "local-resume",
            "local-status",
            "local-advance",
            "local-retry",
            "local-run",
        ] {
            let cli = parse_test(&[
                role,
                "--binary",
                "a.elf",
                "--ledger",
                "a.ledger",
                "--build-id",
                "v1",
                "--policy",
                "rank-targets",
                "--find",
                "0x4010",
                "--find",
                "42",
                "--avoid",
                "0X4020",
                "--exclude-avoid",
                "--symbolic-reg",
                "rcx",
                "--max-steps",
                "17",
                "--max-wall-ms",
                "999",
            ])?;
            assert_eq!(cli.role, role);
            assert_eq!(cli.ledger, Some(PathBuf::from("a.ledger")));
            assert_eq!(cli.config.limits.max_steps, 17);
            assert_eq!(cli.config.limits.max_wall_millis, 999);
            assert_eq!(cli.config.symbolic_reg, SymbolicRegister::Rcx);
            assert_eq!(cli.policy, LocalPolicy::RankTargets { exclude_avoid: true });
            assert_eq!(cli.find, vec![0x4010, 42]);
            assert_eq!(cli.avoid, vec![0x4020]);
            assert!(cli.addr.is_none());
        }
        Ok(())
    }

    #[test]
    fn local_rejects_worker_flags_and_invalid_policy() {
        let base = [
            "local-start",
            "--binary",
            "a.elf",
            "--ledger",
            "a.ledger",
            "--build-id",
            "v1",
        ];
        for flag in [
            "--listen",
            "--connect",
            "--peer",
            "--key-file",
            "--sign-key",
            "--worker-id",
            "--connections",
            "--progress-jsonl",
            "--entry",
            "--image-mode",
        ] {
            let mut args = base.to_vec();
            args.extend([flag, "value"]);
            assert!(parse_test(&args).is_err(), "{flag} accepted for local command");
        }
        for args in [
            vec!["--exclude-avoid"],
            vec!["--policy", "unknown"],
            vec!["--find", "not-a-pc"],
        ] {
            let mut full = base.to_vec();
            full.extend(args);
            assert!(parse_test(&full).is_err());
        }
    }

    #[test]
    fn distributed_roles_still_require_network_and_reject_local_flags() -> Result<()> {
        let worker = parse_test(&[
            "worker",
            "--binary",
            "a.elf",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:1234",
        ])?;
        assert_eq!(worker.addr, Some("127.0.0.1:1234".parse()?));
        assert!(
            parse_test(&[
                "coordinator",
                "--binary",
                "a.elf",
                "--build-id",
                "v1",
                "--connect",
                "127.0.0.1:1234",
                "--policy",
                "fork-all"
            ])
            .is_err()
        );
        assert!(parse_test(&["worker", "--binary", "a.elf", "--build-id", "v1"]).is_err());
        Ok(())
    }

    #[test]
    fn worker_config_generator_accepts_worker_fields_and_sealed_limits() -> Result<()> {
        let cli = parse_test(&[
            "worker-config",
            "--binary",
            "a.elf",
            "--worker-id",
            "w1",
            "--key-file",
            "remote.key",
            "--sign-key",
            "local.key",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:9001",
            "--connections",
            "4",
            "--image-mode",
            "elf",
            "--entry",
            "0x1234",
            "--symbolic-reg",
            "rcx",
            "--max-steps",
            "1",
            "--max-path-steps",
            "2",
            "--max-active-states",
            "3",
            "--max-path-depth",
            "4",
            "--max-loop-visits",
            "5",
            "--max-solver-ms",
            "6",
            "--max-wall-ms",
            "7",
            "--max-ram-bytes",
            "8",
            "--max-disk-bytes",
            "9",
            "--max-trace-bytes",
            "10",
            "--worker-binary",
            "/remote/image.elf",
            "--output",
            "worker.toml",
        ])?;
        assert_eq!(cli.role, "worker-config");
        assert_eq!(cli.output, Some(PathBuf::from("worker.toml")));
        assert_eq!(cli.worker_binary, Some(PathBuf::from("/remote/image.elf")));
        assert_eq!(cli.sign_key, Some(PathBuf::from("local.key")));
        assert_eq!(cli.addr, Some("127.0.0.1:9001".parse()?));
        assert_eq!(cli.connections, 4);
        assert_eq!(cli.config.binary, PathBuf::from("a.elf"));
        assert_eq!(cli.config.key_file, PathBuf::from("remote.key"));
        assert_eq!(cli.config.worker_id, "w1");
        assert_eq!(cli.config.build_id, "v1");
        assert_eq!(cli.config.entry, Some(0x1234));
        assert_eq!(cli.config.symbolic_reg, SymbolicRegister::Rcx);
        let limits = cli.config.limits;
        assert_eq!(limits.max_steps, 1);
        assert_eq!(limits.max_path_steps, 2);
        assert_eq!(limits.max_active_states, 3);
        assert_eq!(limits.max_path_depth, 4);
        assert_eq!(limits.max_loop_visits, 5);
        assert_eq!(limits.max_solver_millis, 6);
        assert_eq!(limits.max_wall_millis, 7);
        assert_eq!(limits.max_ram_bytes, angryier_campaign::RamCap::Bytes(8));
        assert_eq!(limits.max_disk_bytes, 9);
        assert_eq!(limits.max_trace_bytes, 10);
        Ok(())
    }

    #[test]
    fn worker_config_rejects_missing_fields_foreign_flags_and_nonloopback() -> Result<()> {
        let base = [
            "worker-config",
            "--binary",
            "a.elf",
            "--worker-id",
            "w1",
            "--key-file",
            "remote.key",
            "--sign-key",
            "local.key",
            "--build-id",
            "v1",
            "--listen",
            "127.0.0.1:9001",
            "--output",
            "worker.toml",
        ];
        for missing in [
            "--binary",
            "--worker-id",
            "--key-file",
            "--sign-key",
            "--build-id",
            "--listen",
            "--output",
        ] {
            let mut args = base.to_vec();
            let index = args.iter().position(|arg| *arg == missing).ok_or("missing test flag")?;
            args.drain(index..index + 2);
            assert!(parse_test(&args).is_err(), "accepted missing {missing}");
        }
        for flag in ["--ledger", "--peer", "--progress-jsonl", "--connect"] {
            let mut args = base.to_vec();
            args.extend([flag, "value"]);
            assert!(parse_test(&args).is_err(), "accepted {flag}");
        }
        for listener in ["0.0.0.0:9001", "192.0.2.1:9001", "[::]:9001"] {
            let mut args = base.to_vec();
            let index = args
                .iter()
                .position(|arg| *arg == "--listen")
                .ok_or("missing listener")?;
            args[index + 1] = listener;
            assert!(parse_test(&args).is_err(), "accepted {listener}");
        }
        for role in ["worker", "coordinator", "local-start", "local-run"] {
            let mut args = base.to_vec();
            args[0] = role;
            assert!(parse_test(&args).is_err(), "accepted --output for {role}");
            let mut without_output = base[..base.len() - 2].to_vec();
            without_output[0] = role;
            without_output.extend(["--worker-binary", "/remote/image.elf"]);
            assert!(
                parse_test(&without_output).is_err(),
                "accepted --worker-binary for {role}"
            );
            let mut without_output = base[..base.len() - 2].to_vec();
            without_output[0] = role;
            without_output.extend(["--sign-key", "local.key"]);
            assert!(parse_test(&without_output).is_err(), "accepted --sign-key for {role}");
        }
        Ok(())
    }

    #[test]
    fn worker_config_load_dispatch_requires_exact_worker_form() -> Result<()> {
        let valid = ["worker", "--config", "worker.toml"].map(str::to_owned);
        assert_eq!(worker_config_path(&valid)?, Some(PathBuf::from("worker.toml")));
        for args in [
            vec!["worker", "--config"],
            vec!["worker", "--config", "--connections"],
            vec!["worker", "--config", "worker.toml", "--connections", "1"],
            vec!["worker", "--binary", "a.elf", "--config", "worker.toml"],
            vec!["coordinator", "--config", "worker.toml"],
            vec!["worker-config", "--config", "worker.toml"],
            vec!["local-run", "--config", "worker.toml"],
        ] {
            assert!(
                worker_config_path(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()).is_err(),
                "accepted {args:?}"
            );
        }
        assert!(worker_config_path(&["worker".into(), "--binary".into(), "a.elf".into()])?.is_none());
        Ok(())
    }
}
