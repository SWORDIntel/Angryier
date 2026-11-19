//! Standalone typed local campaign, without Lua, a worker pool, or a shell launcher.
//!
//! `cargo run -p angryier-campaign --example local_campaign -- --binary FILE
//!  --ledger FILE --build-id ID --policy fork-all` creates a new ledger;
//! repeat the SAME pinned options with `--resume` to reopen it. For v2 use
//! `--policy rank-targets` and optionally `--exclude-avoid`. Repeat `--find PC`,
//! `--avoid PC`, `--symbolic REG` and `--reg NAME=VALUE` as needed. Addresses
//! and seed values accept decimal or 0x hexadecimal. All ten `--max-*` limits
//! are sealed; supply identical values on resume. `--batch-ms` and `--total-ms`
//! bound this invocation and are not sealed; defaults are 1000 and 30000 ms.
//!
//! This example has a DIFFERENT executable identity from the angryier-campaign
//! CLI. Do not treat their ledgers as interchangeable: create and resume with
//! the same compiled executable and pinned specification. Lua ledgers are also
//! incompatible. Exit 0 means complete within declared bounds, 2 means partial
//! or uncertain, and 1 means a usage or execution error. Deferred work remains
//! deferred until explicitly retried through the typed API; it is never a
//! replay-verified terminal.

use angryier_campaign::local::LocalRegister;
use angryier_campaign::{Config, LocalCampaign, LocalConfig, LocalPolicy, RamCap, Result};
use std::{
    env,
    path::PathBuf,
    time::{Duration, Instant},
};

fn number(value: &str) -> Result<u64> {
    Ok(
        if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)?
        } else {
            value.parse()?
        },
    )
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run() -> Result<bool> {
    let mut binary = None;
    let mut ledger = None;
    let mut build_id = None;
    let mut resume = false;
    let mut exclude_avoid = false;
    let mut policy = LocalPolicy::ForkAll;
    let mut find = Vec::new();
    let mut avoid = Vec::new();
    let mut symbolic: Option<Vec<(LocalRegister, u16)>> = None;
    let mut regs = Vec::new();
    let mut config = Config::defaults(PathBuf::new(), PathBuf::new(), String::new());
    let mut batch_ms = 1000;
    let mut total_ms = 30_000;
    let mut args = env::args().skip(1);
    while let Some(option) = args.next() {
        match option.as_str() {
            "--resume" => {
                resume = true;
                continue;
            }
            "--exclude-avoid" => {
                exclude_avoid = true;
                continue;
            }
            _ => {}
        }
        let value = args.next().ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--binary" => binary = Some(PathBuf::from(value)),
            "--ledger" => ledger = Some(PathBuf::from(value)),
            "--build-id" => build_id = Some(value),
            "--policy" => {
                policy = match value.as_str() {
                    "fork-all" => LocalPolicy::ForkAll,
                    "rank-targets" => LocalPolicy::RankTargets { exclude_avoid: false },
                    _ => return Err("--policy requires fork-all or rank-targets".into()),
                }
            }
            "--find" => find.push(number(&value)?),
            "--avoid" => avoid.push(number(&value)?),
            "--symbolic" => symbolic.get_or_insert_with(Vec::new).push((value.parse()?, 64)),
            "--reg" => {
                let (name, seed) = value.split_once('=').ok_or("--reg requires NAME=VALUE")?;
                regs.push((name.parse()?, number(seed)?));
            }
            "--max-steps" => config.limits.max_steps = number(&value)?,
            "--max-path-steps" => config.limits.max_path_steps = number(&value)?,
            "--max-active-states" => config.limits.max_active_states = number(&value)?,
            "--max-path-depth" => config.limits.max_path_depth = number(&value)?,
            "--max-loop-visits" => config.limits.max_loop_visits = number(&value)?,
            "--max-solver-ms" => config.limits.max_solver_millis = number(&value)?,
            "--max-wall-ms" => config.limits.max_wall_millis = number(&value)?,
            "--max-ram-bytes" => config.limits.max_ram_bytes = RamCap::Bytes(number(&value)?),
            "--max-disk-bytes" => config.limits.max_disk_bytes = number(&value)?,
            "--max-trace-bytes" => config.limits.max_trace_bytes = number(&value)?,
            "--batch-ms" => batch_ms = number(&value)?,
            "--total-ms" => total_ms = number(&value)?,
            _ => return Err(format!("unsupported option {option}").into()),
        }
    }
    if batch_ms == 0 || total_ms == 0 {
        return Err("--batch-ms and --total-ms must be positive".into());
    }
    if exclude_avoid {
        policy = match policy {
            LocalPolicy::ForkAll => return Err("--exclude-avoid requires --policy rank-targets".into()),
            LocalPolicy::RankTargets { .. } => LocalPolicy::RankTargets { exclude_avoid: true },
        };
    }
    config.binary = binary.ok_or("--binary is required")?;
    config.build_id = build_id.ok_or("--build-id is required")?;
    let local = LocalConfig {
        campaign: config,
        ledger: ledger.ok_or("--ledger is required")?,
        policy,
        find,
        avoid,
        symbolic,
        regs,
    };
    let mut campaign = if resume {
        LocalCampaign::resume(local)?
    } else {
        LocalCampaign::start(local)?
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(total_ms))
        .ok_or("--total-ms exceeds the platform clock range")?;
    for event in campaign.accepted_events() {
        println!(
            "replayed path_id={} work_index={} attempt={} sequence={} replay_digest={} status={:?} disposition={:?}",
            hex(&event.delta.path.path_id),
            event.work_index,
            event.attempt,
            event.delta.sequence,
            hex(&event.replay_digest.0),
            event.status,
            event.delta.path.disposition
        );
    }
    let mut seen = campaign.accepted_events().len();
    let mut report = campaign.checked_report()?;
    while !report.complete_within_declared_bounds && (report.queued != 0 || report.active != 0) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let previous_report = report.clone();
        let previous_count = seen;
        let outcome = campaign.advance(remaining.min(Duration::from_millis(batch_ms)))?;
        for event in &campaign.accepted_events()[seen..] {
            println!(
                "accepted path_id={} work_index={} attempt={} sequence={} replay_digest={} status={:?} disposition={:?}",
                hex(&event.delta.path.path_id),
                event.work_index,
                event.attempt,
                event.delta.sequence,
                hex(&event.replay_digest.0),
                event.status,
                event.delta.path.disposition
            );
        }
        seen = campaign.accepted_events().len();
        report = outcome.report;
        println!("advance steps={} reason={:?}", outcome.steps, outcome.reason);
        if outcome.steps == 0 && report == previous_report && seen == previous_count {
            break;
        }
    }
    println!("report: {report:?}");
    if !report.complete_within_declared_bounds {
        eprintln!(
            "partial/uncertain: queued={} active={} deferred={} unknown={} failed={} (no deferred path is a verified terminal)",
            report.queued, report.active, report.deferred, report.unknown, report.failed
        );
    }
    Ok(report.complete_within_declared_bounds)
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("local_campaign: {error}");
            std::process::exit(1);
        }
    }
}
