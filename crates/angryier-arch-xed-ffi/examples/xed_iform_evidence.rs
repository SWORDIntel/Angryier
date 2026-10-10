//! Small batch XED runtime IFORM evidence tool.
//!
//! Reuses existing [`XedDecoder::decode_with_iform`] to consume newline-delimited
//! JSON records with stable input ID and hex bytes, and emits newline-delimited
//! JSON retaining input ID, input bytes, pinned decoder version, raw XED IFORM
//! name and value, and decode/error status.
//!
//! # Identity Rule
//!
//! Does not assign canonical IDs (such as ISANITY FormIdentity) or treat
//! engine-owned `form_id` as IFORM.

use angryier_arch_xed_ffi::XedDecoder;
use angryier_arch_xed_ffi::evidence::{PINNED_XED_VERSION, process_evidence_stream};
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

const USAGE: &str = "\
Usage: xed_iform_evidence [OPTIONS] [INPUT] [OUTPUT]

Batch XED runtime IFORM evidence tool.

Consumes newline-delimited JSON records specifying input IDs and instruction
hex bytes, decodes each instruction using XedDecoder::decode_with_iform(), and
emits newline-delimited JSON records with stable IDs, retained bytes, pinned
decoder version, raw XED IFORM name/value, and decode/error status.

Arguments:
  [INPUT]                  Optional input file path (default: stdin)
  [OUTPUT]                 Optional output file path (default: stdout)

Options:
  -i, --input <PATH>       Input file path containing newline-delimited JSON
  -o, --output <PATH>      Output file path for emitted newline-delimited JSON
  -a, --address <ADDR>     Default instruction address in hex or decimal (default: 0)
  -s, --summary            Print batch summary to stderr upon completion
  -h, --help               Print this help documentation
  -v, --version            Print tool and decoder version

Input schema (newline-delimited JSON, one record per line):
  {\"id\": \"<stable_id>\", \"bytes\": \"<hex_bytes>\", \"address\": <optional_addr>}

Output schema (newline-delimited JSON, one record per line):
  {\"id\":..., \"bytes\":\"...\", \"status\":\"ok\"|\"error\", \"decoder_version\":\"...\",
   \"iform_name\":\"...\"|null, \"iform_value\":...|null,
   \"raw_iform\":{\"name\":\"...\", \"value\":...}|null,
   \"length\":...|null, \"error\":\"...\"}
";

struct Config {
    input_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    default_address: u64,
    show_summary: bool,
}

fn parse_args() -> Result<Option<Config>, String> {
    let mut args = std::env::args().skip(1);
    let mut input_path = None;
    let mut output_path = None;
    let mut default_address = 0;
    let mut show_summary = false;
    let mut positionals = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-v" | "--version" => {
                println!("xed_iform_evidence 1.0.0 (decoder: {PINNED_XED_VERSION})");
                return Ok(None);
            }
            "-s" | "--summary" => {
                show_summary = true;
            }
            "-i" | "--input" => {
                let path = args.next().ok_or_else(|| "missing argument for --input".to_owned())?;
                input_path = Some(PathBuf::from(path));
            }
            "-o" | "--output" => {
                let path = args.next().ok_or_else(|| "missing argument for --output".to_owned())?;
                output_path = Some(PathBuf::from(path));
            }
            "-a" | "--address" => {
                let addr_str = args.next().ok_or_else(|| "missing argument for --address".to_owned())?;
                let trimmed = addr_str.trim();
                let parsed = if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                    u64::from_str_radix(stripped, 16).map_err(|e| format!("invalid hex address '{addr_str}': {e}"))?
                } else {
                    trimmed
                        .parse::<u64>()
                        .map_err(|e| format!("invalid address '{addr_str}': {e}"))?
                };
                default_address = parsed;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'. Run with --help for usage."));
            }
            other => {
                positionals.push(PathBuf::from(other));
            }
        }
    }

    if input_path.is_none() && !positionals.is_empty() {
        input_path = Some(positionals.remove(0));
    }
    if output_path.is_none() && !positionals.is_empty() {
        output_path = Some(positionals.remove(0));
    }
    if !positionals.is_empty() {
        return Err("unexpected extra positional arguments".to_owned());
    }

    Ok(Some(Config {
        input_path,
        output_path,
        default_address,
        show_summary,
    }))
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let config = match parse_args() {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return Ok(0),
        Err(err) => {
            eprintln!("error: {err}");
            return Ok(1);
        }
    };

    let decoder = XedDecoder::new();

    let reader: Box<dyn BufRead> = match config.input_path {
        Some(ref path) => {
            let file = File::open(path).map_err(|e| format!("failed to open input file '{}': {e}", path.display()))?;
            Box::new(BufReader::new(file))
        }
        None => Box::new(BufReader::new(io::stdin())),
    };

    let writer: Box<dyn Write> = match config.output_path {
        Some(ref path) => {
            let file =
                File::create(path).map_err(|e| format!("failed to create output file '{}': {e}", path.display()))?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(BufWriter::new(io::stdout())),
    };

    let stats = process_evidence_stream(&decoder, reader, writer, config.default_address)?;

    if config.show_summary {
        eprintln!(
            "[xed_iform_evidence] processed {} records ({} ok, {} errors)",
            stats.total, stats.ok, stats.errors
        );
    }

    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("fatal: {err}");
            std::process::exit(1);
        }
    }
}
