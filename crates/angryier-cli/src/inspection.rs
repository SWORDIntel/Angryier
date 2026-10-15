//! Read-only PE address and Windows minidump inspection CLI commands.
//! These are deliberately independent from native XED/Z3 symbolic execution,
//! so they can run even on machines without those native libraries.

use angryier_loader::addresses::{PeAddressMap, PeLocation};
use angryier_loader::minidump_file::MiniDumpFile;

fn number(text: &str) -> Result<u64, String> {
    let value = text.trim();
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid hexadecimal address: {text}"))
    } else {
        value.parse::<u64>().map_err(|_| format!("invalid unsigned integer: {text}"))
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
    let rva = mapping.va_to_rva(va).map_err(|error| format!("VA not in image: {error:?}"))?;
    let location = mapping.locate_va(va).map_err(|error| format!("unmapped VA: {error:?}"))?;
    let description = match location {
        PeLocation::Header { file_offset } => format!("header file_offset=0x{file_offset:x}"),
        PeLocation::Section { index, file_offset } => {
            let section = &mapping.sections()[index];
            format!("section={} file_offset=0x{file_offset:x}", section.name)
        }
        PeLocation::ZeroFill { index } => {
            format!("section={} zero-fill (no original file bytes)", mapping.sections()[index].name)
        }
    };
    let mut output = format!(
        "image_base=0x{:x} va=0x{va:x} rva=0x{rva:x} {description}",
        mapping.image_base()
    );
    if len != 0 {
        let bytes = mapping.bytes_at_va(&file, va, len)
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
    let bytes = std::fs::read(&args[0])
        .map_err(|e| format!("cannot open PE: {e}"))?;
    let map = PeAddressMap::parse(&bytes)
        .map_err(|e| format!("PE address map: {e:?}"))?;
    let image = Pe32Loader::new().load(&bytes)
        .map_err(|e| format!("PE import parse: {e}"))?;
    let imports = image.pe_imports().ok_or("not a PE image")?;
    let filter = args.get(1).map(|s| s.to_ascii_lowercase());
    let mut out = format!(
        "image_base=0x{:x} imports={}\n", map.image_base(), imports.len()
    );
    let mut displayed = 0usize;
    for entry in imports {
        let symbol = match &entry.kind {
            PeImportKind::Name(name) => name.clone(),
            PeImportKind::Ordinal(ordinal) => format!("#{ordinal}"),
        };
        let qualified = format!("{}!{}", entry.dll, symbol);
        if filter.as_ref().is_some_and(|query| !qualified.to_ascii_lowercase().contains(query)) {
            continue;
        }
        let slot = map.rva_to_va(entry.iat_rva)
            .map_err(|e| format!("IAT RVA overflow: {e:?}"))?;
        let offset = match map.locate_rva(entry.iat_rva) {
            Ok(PeLocation::Header { file_offset } | PeLocation::Section { file_offset, .. }) => {
                format!("0x{file_offset:x}")
            }
            Ok(PeLocation::ZeroFill { .. }) => "no-file-byte".to_string(),
            Err(_) => "unmapped".to_string(),
        };
        out.push_str(&format!("slot=0x{slot:x} rva=0x{:x} file_offset={offset} import={qualified}\n", entry.iat_rva));
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
    let mut dump = MiniDumpFile::open(&args[0])
        .map_err(|error| format!("cannot inspect dump: {error:?}"))?;
    let bytes = dump.read(addr, len)
        .map_err(|error| format!("requested memory is unavailable in dump: {error:?}"))?;
    Ok(format!(
        "captured va=0x{addr:x} length={} regions={} file_bytes={}\n{}",
        bytes.len(),
        dump.regions().len(),
        dump.file_size(),
        hex(&bytes)
    ))
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
}
