//! Read-only PE address and Windows minidump inspection CLI commands.
//! These are deliberately independent from native XED/Z3 symbolic execution,
//! so they can run even on machines without those native libraries.

use angryier_loader::addresses::{PeAddressMap, PeLocation};
use angryier_loader::minidump_file::MiniDumpFile;
use sha2::{Digest, Sha384};

/// Bounds for `capture-coverage`: overlay count, per-overlay bytes, and dump
/// re-read chunk size. All three exist so a malformed or hostile capture
/// directory cannot make this inspection command allocate without limit.
const MAX_OVERLAYS: usize = 4096;
const MAX_OVERLAY_BYTES: usize = 4096;
const DUMP_CHUNK: usize = 256;

fn number(text: &str) -> Result<u64, String> {
    let value = text.trim();
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid hexadecimal address: {text}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|_| format!("invalid unsigned integer: {text}"))
    }
}

fn length(text: Option<&String>, default: usize, max: usize) -> Result<usize, String> {
    let val = match text {
        Some(text) => usize::try_from(number(text)?).map_err(|_| "read length overflows usize".to_string())?,
        None => default,
    };
    if val > max {
        return Err(format!("requested length {val} exceeds maximum {max}"));
    }
    Ok(val)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

pub fn pe_address(args: &[String]) -> Result<String, String> {
    if !(2..=3).contains(&args.len()) {
        return Err("usage: angryier pe-address <image.exe> <VA> [length<=256]".to_string());
    }
    let file = std::fs::read(&args[0]).map_err(|error| format!("cannot open PE image: {error}"))?;
    let mapping = PeAddressMap::parse(&file).map_err(|error| format!("invalid PE image: {error:?}"))?;
    let va = number(&args[1])?;
    let len = length(args.get(2), 0, 256)?;
    let rva = mapping
        .va_to_rva(va)
        .map_err(|error| format!("VA not in image: {error:?}"))?;
    let location = mapping
        .locate_va(va)
        .map_err(|error| format!("unmapped VA: {error:?}"))?;
    let description = match location {
        PeLocation::Header { file_offset } => format!("header file_offset=0x{file_offset:x}"),
        PeLocation::Section { index, file_offset } => {
            let section = &mapping.sections()[index];
            format!("section={} file_offset=0x{file_offset:x}", section.name)
        }
        PeLocation::ZeroFill { index } => {
            format!(
                "section={} zero-fill (no original file bytes)",
                mapping.sections()[index].name
            )
        }
    };
    let mut output = format!(
        "image_base=0x{:x} va=0x{va:x} rva=0x{rva:x} {description}",
        mapping.image_base()
    );
    if len != 0 {
        let bytes = mapping
            .bytes_at_va(&file, va, len)
            .map_err(|error| format!("cannot read {len} bytes at VA: {error:?}"))?;
        output.push_str(&format!("\nbytes[{len}]={}", hex(bytes)));
    }
    Ok(output)
}

/// Resolve the PE import directory to source file/IAT VA evidence. Import
/// names are *metadata*, not evidence that a kernel/user API was executed.
pub fn pe_imports(args: &[String]) -> Result<String, String> {
    if !(1..=2).contains(&args.len()) {
        return Err("usage: angryier pe-imports <image.exe> [substring]".to_string());
    }
    use angryier_loader::{ImageLoader, Pe32Loader, PeImportKind};
    let bytes = std::fs::read(&args[0]).map_err(|e| format!("cannot open PE: {e}"))?;
    let map = PeAddressMap::parse(&bytes).map_err(|e| format!("PE address map: {e:?}"))?;
    let image = Pe32Loader::new()
        .load(&bytes)
        .map_err(|e| format!("PE import parse: {e}"))?;
    let imports = image.pe_imports().ok_or("not a PE image")?;
    let filter = args.get(1).map(|s| s.to_ascii_lowercase());
    let mut out = format!("image_base=0x{:x} imports={}\n", map.image_base(), imports.len());
    let mut displayed = 0usize;
    for entry in imports {
        let symbol = match &entry.kind {
            PeImportKind::Name(name) => name.clone(),
            PeImportKind::Ordinal(ordinal) => format!("#{ordinal}"),
        };
        let qualified = format!("{}!{}", entry.dll, symbol);
        if filter
            .as_ref()
            .is_some_and(|query| !qualified.to_ascii_lowercase().contains(query))
        {
            continue;
        }
        let slot = map
            .rva_to_va(entry.iat_rva)
            .map_err(|e| format!("IAT RVA overflow: {e:?}"))?;
        let offset = match map.locate_rva(entry.iat_rva) {
            Ok(PeLocation::Header { file_offset } | PeLocation::Section { file_offset, .. }) => {
                format!("0x{file_offset:x}")
            }
            Ok(PeLocation::ZeroFill { .. }) => "no-file-byte".to_string(),
            Err(_) => "unmapped".to_string(),
        };
        out.push_str(&format!(
            "slot=0x{slot:x} rva=0x{:x} file_offset={offset} import={qualified}\n",
            entry.iat_rva
        ));
        displayed += 1;
        if displayed > 100_000 {
            return Err("too many imports to display safely".to_string());
        }
    }
    out.push_str(&format!("shown={displayed}"));
    Ok(out)
}

pub fn minidump_read(args: &[String]) -> Result<String, String> {
    if args.len() != 3 {
        return Err("usage: angryier dump-read <capture.dmp> <VA> <length<=4096>".to_string());
    }
    let addr = number(&args[1])?;
    let len = length(args.get(2), 0, 4096)?;
    let mut dump = MiniDumpFile::open(&args[0]).map_err(|error| format!("cannot inspect dump: {error:?}"))?;
    let bytes = dump
        .read(addr, len)
        .map_err(|error| format!("requested memory is unavailable in dump: {error:?}"))?;
    Ok(format!(
        "captured va=0x{addr:x} length={} regions={} file_bytes={}\n{}",
        bytes.len(),
        dump.regions().len(),
        dump.file_size(),
        hex(&bytes)
    ))
}

/// One write-once capture produced by the external overlay adapter.
struct Overlay {
    label: String,
    address: u64,
    bytes: Vec<u8>,
    module: Option<String>,
    pid: Option<u64>,
    creation: Option<u64>,
}

fn json_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut search = 0;
    while let Some(found) = text[search..].find(&needle) {
        let after = search + found + needle.len();
        let rest = text[after..].trim_start();
        let rest = rest.strip_prefix(':')?.trim_start();
        if !rest.is_empty() {
            if let Some(body) = rest.strip_prefix('"') {
                let end = body.find('"')?;
                return Some(&body[..end]);
            }
            let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
            return Some(rest[..end].trim());
        }
        search = after;
    }
    None
}

fn describe_range(address: u64, length: usize) -> String {
    format!("va=0x{address:x} len={length}")
}

fn load_overlay(dir: &std::path::Path, label: String) -> Result<Overlay, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let address = json_value(&manifest, "address")
        .ok_or_else(|| format!("{}: missing address", manifest_path.display()))
        .and_then(number)?;
    let length = json_value(&manifest, "length")
        .ok_or_else(|| format!("{}: missing length", manifest_path.display()))
        .and_then(|raw| {
            usize::try_from(number(raw)?).map_err(|_| "declared length overflows usize".to_string())
        })?;
    if length == 0 || length > MAX_OVERLAY_BYTES {
        return Err(format!(
            "{}: declared length {length} outside 1..={MAX_OVERLAY_BYTES}",
            manifest_path.display()
        ));
    }
    let expected = json_value(&manifest, "sha384")
        .ok_or_else(|| format!("{}: missing sha384", manifest_path.display()))?;
    let data_file = json_value(&manifest, "data_file").unwrap_or("bytes.bin");
    let bytes_path = dir.join(data_file);
    let bytes = std::fs::read(&bytes_path)
        .map_err(|error| format!("cannot read {}: {error}", bytes_path.display()))?;
    if bytes.len() != length {
        return Err(format!(
            "{}: {} bytes on disk but manifest declares {length}",
            bytes_path.display(),
            bytes.len()
        ));
    }
    let actual = Sha384::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected.to_ascii_lowercase() {
        return Err(format!(
            "{}: sha384 {actual} does not match manifest {expected}",
            bytes_path.display()
        ));
    }
    Ok(Overlay {
        label,
        address,
        bytes,
        module: json_value(&manifest, "module").map(str::to_string),
        pid: json_value(&manifest, "pid").and_then(|raw| raw.parse().ok()),
        creation: json_value(&manifest, "creation_filetime").and_then(|raw| raw.parse().ok()),
    })
}

/// Compare two captured ranges. Returns `(overlap_length, first_divergence)`.
fn overlap(left: &Overlay, right: &Overlay) -> Option<(usize, Option<usize>)> {
    let start = left.address.max(right.address);
    let end = (left.address + left.bytes.len() as u64)
        .min(right.address + right.bytes.len() as u64);
    if start >= end {
        return None;
    }
    let offset = (start - left.address) as usize;
    let other = (start - right.address) as usize;
    let span = (end - start) as usize;
    let divergence = (0..span)
        .find(|index| left.bytes[offset + index] != right.bytes[other + index]);
    Some((span, divergence))
}

pub fn capture_coverage(args: &[String]) -> Result<String, String> {
    if args.is_empty() || args.len() > 2 {
        return Err(
            "usage: angryier capture-coverage <overlays-dir> [capture.dmp]".to_string(),
        );
    }
    let root = std::path::Path::new(&args[0]);
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    let mut directories = Vec::new();
    if root.join("manifest.json").is_file() {
        directories.push(root.to_path_buf());
    } else {
        let entries = std::fs::read_dir(root)
            .map_err(|error| format!("cannot list {}: {error}", root.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot list overlay entry: {error}"))?;
            let path = entry.path();
            if path.is_dir() && path.join("manifest.json").is_file() {
                directories.push(path);
            }
        }
        directories.sort();
    }
    if directories.is_empty() {
        return Err(format!(
            "no overlay manifest.json found under {}",
            root.display()
        ));
    }
    if directories.len() > MAX_OVERLAYS {
        return Err(format!(
            "{} overlays exceeds the {MAX_OVERLAYS} inspection limit",
            directories.len()
        ));
    }
    let mut overlays = Vec::with_capacity(directories.len());
    for path in &directories {
        let label = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        overlays.push(load_overlay(path, label)?);
    }

    let mut out = String::new();
    let total: usize = overlays.iter().map(|overlay| overlay.bytes.len()).sum();
    out.push_str(&format!(
        "overlays={} total_bytes={total} sha384=verified\n",
        overlays.len()
    ));
    for (index, overlay) in overlays.iter().enumerate() {
        out.push_str(&format!(
            "ovl[{index}] {:<28} {} module={} pid={} created={}\n",
            overlay.label,
            describe_range(overlay.address, overlay.bytes.len()),
            overlay.module.as_deref().unwrap_or("-"),
            overlay
                .pid
                .map_or_else(|| "-".to_string(), |pid| pid.to_string()),
            overlay
                .creation
                .map_or_else(|| "-".to_string(), |ticks| ticks.to_string()),
        ));
    }

    let mut divergent = 0_usize;
    for left in 0..overlays.len() {
        for right in (left + 1)..overlays.len() {
            if let Some((span, first)) = overlap(&overlays[left], &overlays[right]) {
                let start = overlays[left].address.max(overlays[right].address);
                match first {
                    None => out.push_str(&format!(
                        "overlap ovl[{left}]~ovl[{right}] va=0x{start:x} len={span} agree=true\n"
                    )),
                    Some(offset) => {
                        divergent += 1;
                        out.push_str(&format!(
                            "overlap ovl[{left}]~ovl[{right}] va=0x{start:x} len={span} \
                             agree=false first_divergence=0x{:x}\n",
                            start + offset as u64
                        ));
                    }
                }
            }
        }
    }

    let mut with_gap = 0_usize;
    if args.len() == 2 {
        let mut dump = MiniDumpFile::open(&args[1])
            .map_err(|error| format!("cannot inspect dump: {error:?}"))?;
        for (index, overlay) in overlays.iter().enumerate() {
            let mut identical = 0_usize;
            let mut differing: Option<u64> = None;
            let mut captured = 0_usize;
            let mut cursor = 0_usize;
            while cursor < overlay.bytes.len() {
                let span = DUMP_CHUNK.min(overlay.bytes.len() - cursor);
                match dump.read(overlay.address + cursor as u64, span) {
                    Ok(bytes) => {
                        captured += bytes.len();
                        for (offset, byte) in bytes.iter().enumerate() {
                            let at = cursor + offset;
                            if *byte == overlay.bytes[at] {
                                identical += 1;
                            } else if differing.is_none() {
                                differing = Some(overlay.address + at as u64);
                            }
                        }
                    }
                    Err(_) => {
                        // A dump gap and a divergence are distinct facts: only
                        // divergence over actually captured bytes is reported.
                    }
                }
                cursor += span;
            }
            if captured < overlay.bytes.len() {
                with_gap += 1;
            }
            out.push_str(&format!(
                "ovl[{index}] dump=covered:{captured}/{} identical={identical} divergent={} \
                 first_divergence={}\n",
                overlay.bytes.len(),
                if differing.is_some() {
                    captured - identical
                } else {
                    0
                },
                differing
                    .map_or_else(|| "-".to_string(), |address| format!("0x{address:x}")),
            ));
        }
        out.push_str(&format!(
            "dump regions={} file_bytes={} overlays_with_dump_gap={with_gap}\n",
            dump.regions().len(),
            dump.file_size(),
        ));
    }
    out.push_str(&format!("summary overlays={} divergent_overlaps={divergent}", overlays.len()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_hex_addresses_and_rejects_invalid_input() {
        assert_eq!(number("0x140404e10"), Ok(0x140404e10));
        assert_eq!(number("12345"), Ok(12345));
        assert!(number("-1").is_err());
        assert!(number("0xZZ").is_err());
        assert_eq!(length(Some(&"0x100".to_string()), 16, 256), Ok(256));
        assert!(length(Some(&"257".to_string()), 16, 256).is_err());
    }

    fn write_overlay(root: &std::path::Path, name: &str, address: u64, bytes: &[u8]) -> std::path::PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let digest = Sha384::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(dir.join("bytes.bin"), bytes).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            format!(
                "{{\"address\": \"0x{address:x}\", \"length\": {}, \"sha384\": \"{digest}\", \
                 \"data_file\": \"bytes.bin\", \"module\": \"unit.dll\", \"pid\": 42}}",
                bytes.len()
            ),
        )
        .unwrap();
        dir
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("angryier-capture-coverage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn json_value_reads_strings_numbers_and_survives_nested_keys() {
        let text = "{\"length\": 2048, \"module\": \"GUIUtils64.dll\", \"nested\": {\"length\": 7}}";
        assert_eq!(json_value(text, "length"), Some("2048"));
        assert_eq!(json_value(text, "module"), Some("GUIUtils64.dll"));
        assert_eq!(json_value(text, "absent"), None);
    }

    #[test]
    fn capture_coverage_verifies_hashes_and_reports_overlap_agreement() {
        let root = scratch("agree");
        write_overlay(&root, "a", 0x1000, &[1, 2, 3, 4, 5, 6, 7, 8]);
        write_overlay(&root, "b", 0x1004, &[5, 6, 7, 8, 9]);
        let report = capture_coverage(&[root.display().to_string()]).unwrap();
        assert!(report.contains("overlays=2 total_bytes=13 sha384=verified"), "{report}");
        assert!(report.contains("len=8 module=unit.dll pid=42"), "{report}");
        assert!(report.contains("overlap ovl[0]~ovl[1] va=0x1004 len=4 agree=true"), "{report}");
        assert!(report.ends_with("summary overlays=2 divergent_overlaps=0"));
    }

    #[test]
    fn capture_coverage_flags_divergent_overlap_and_is_order_independent() {
        let root = scratch("diverge");
        write_overlay(&root, "early", 0x2000, &[0xaa, 0xbb, 0xcc]);
        write_overlay(&root, "late", 0x2001, &[0x00, 0xcc]);
        let report = capture_coverage(&[root.display().to_string()]).unwrap();
        assert!(report.contains("agree=false first_divergence=0x2001"), "{report}");
        assert!(report.contains("divergent_overlaps=1"), "{report}");
    }

    #[test]
    fn capture_coverage_fails_closed_on_tampered_or_oversized_captures() {
        let tampered = scratch("tampered");
        let dir = write_overlay(&tampered, "one", 0x3000, &[9, 9, 9]);
        std::fs::write(dir.join("bytes.bin"), [9u8, 9, 8]).unwrap();
        let error = capture_coverage(&[tampered.display().to_string()]).unwrap_err();
        assert!(error.contains("does not match manifest"), "{error}");

        let oversized = scratch("oversized");
        let dir = write_overlay(&oversized, "big", 0x4000, &[0u8; 8]);
        let manifest = std::fs::read_to_string(dir.join("manifest.json"))
            .unwrap()
            .replace("\"length\": 8", "\"length\": 4097");
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
        let error = capture_coverage(&[oversized.display().to_string()]).unwrap_err();
        assert!(error.contains("outside 1..=4096"), "{error}");

        let empty = scratch("empty");
        assert!(capture_coverage(&[empty.display().to_string()]).is_err());
        assert!(capture_coverage(&[]).is_err());
        assert!(capture_coverage(&["a".to_string(), "b".to_string(), "c".to_string()]).is_err());
    }
}
