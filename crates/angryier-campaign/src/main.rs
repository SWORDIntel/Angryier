use angryier_campaign::{Config, ImageMode, Peer, Result, SymbolicRegister};
use std::{env, net::SocketAddr, path::PathBuf};

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let role = args.next().ok_or("expected worker or coordinator")?;
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
    let mut limits = Config::defaults(PathBuf::new(), PathBuf::new(), String::new()).limits;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("each option requires a value")?;
        match flag.as_str() {
            "--binary" => binary = Some(PathBuf::from(value)),
            "--image-mode" => image_mode = value.parse()?,
            "--symbolic-reg" => symbolic_reg = value.parse()?,
            "--entry" => {
                let pc = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16)
                } else {
                    value.parse::<u64>()
                };
                entry = Some(pc.map_err(|_| "--entry requires an absolute u64 PC (decimal or 0x hexadecimal)")?);
            }
            "--key-file" => key_file = Some(PathBuf::from(value)),
            "--worker-id" => worker_id = Some(value),
            "--peer" => {
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
            "--listen" | "--connect" => addr = Some(value.parse::<SocketAddr>()?),
            "--ledger" => ledger = Some(PathBuf::from(value)),
            "--progress-jsonl" => progress_jsonl = Some(PathBuf::from(value)),
            "--connections" => connections = value.parse::<u64>()?,
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
    config.symbolic_reg = symbolic_reg;
    config.peers = peers;
    config.limits = limits;
    config.progress_jsonl = progress_jsonl;
    let addr = addr
        .or(pool_addr)
        .ok_or("--listen (worker), --connect (legacy), or --peer (pool) required")?;
    #[cfg(target_arch = "x86_64")]
    match role.as_str() {
        "worker" => angryier_campaign::serve(&config, addr, connections),
        "coordinator" => {
            let report = angryier_campaign::coordinate(&config, addr, ledger.ok_or("--ledger is required")?)?;
            println!("{report:?}");
            if !report.complete_within_declared_bounds {
                return Err("campaign partial: unresolved owned work remains".into());
            }
            Ok(())
        }
        _ => Err("expected worker or coordinator".into()),
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (role, config, addr, ledger, connections);
        angryier_campaign::unsupported_architecture()
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("campaign: {error}");
        std::process::exit(1);
    }
}
