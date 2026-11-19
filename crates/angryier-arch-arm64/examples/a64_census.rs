//! Static decoder-acceptance census, not a proof of executable code or semantics.
//! Usage: a64_census LISTING [--fde-ranges FILE] [--data-ranges FILE]
//! FDE bounds mark code candidates only; explicit data annotations take priority.

use angryier_arch::Decoder;
use angryier_arch_arm64::{Arm64DecodeError, Arm64Decoder};
use angryier_types::TargetProfileId;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn hex(text: &str) -> io::Result<u64> {
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16)
        .map_err(|_| invalid(format!("invalid hexadecimal address: {text}")))
}

#[derive(Default, Debug)]
struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    fn new(mut ranges: Vec<(u64, u64)>, allow_overlap: bool) -> io::Result<Self> {
        ranges.sort_unstable();
        let mut normalized: Vec<(u64, u64)> = Vec::new();
        for (start, end) in ranges {
            if start >= end {
                return Err(invalid(format!("empty/reversed range {start:x}..{end:x}")));
            }
            if let Some(previous) = normalized.last_mut() {
                if start < previous.1 && !allow_overlap {
                    return Err(invalid("overlapping explicit data annotations"));
                }
                if start <= previous.1 {
                    previous.1 = previous.1.max(end);
                    continue;
                }
            }
            normalized.push((start, end));
        }
        Ok(Self(normalized))
    }

    fn contains(&self, start: u64, end: u64) -> bool {
        let index = self.0.partition_point(|range| range.0 <= start);
        index > 0 && self.0[index - 1].1 >= end
    }

    fn intersects(&self, start: u64, end: u64) -> bool {
        let index = self.0.partition_point(|range| range.1 <= start);
        self.0.get(index).is_some_and(|range| range.0 < end)
    }
}

fn fde_ranges(reader: impl BufRead) -> io::Result<Ranges> {
    let mut ranges = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if !fields.contains(&"FDE") {
            return Err(invalid(format!("FDE line {}: expected an FDE record", index + 1)));
        }
        let bounds: Vec<_> = fields.iter().filter_map(|field| field.strip_prefix("pc=")).collect();
        let [range] = bounds.as_slice() else {
            return Err(invalid(format!(
                "FDE line {}: expected exactly one pc= range",
                index + 1
            )));
        };
        let (start, end) = range
            .split_once("..")
            .ok_or_else(|| invalid(format!("FDE line {}: malformed bounds", index + 1)))?;
        ranges.push((hex(start)?, hex(end)?));
    }
    Ranges::new(ranges, true)
}

fn data_ranges(reader: impl BufRead) -> io::Result<Ranges> {
    let mut ranges = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(start), Some(end), Some(_evidence)) = (fields.next(), fields.next(), fields.next()) else {
            return Err(invalid(format!("data line {}: expected START END EVIDENCE", index + 1)));
        };
        ranges.push((hex(start)?, hex(end)?));
    }
    Ranges::new(ranges, false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
enum Provenance {
    KnownData,
    CodeCandidate,
    Unclassified,
}
const PROVENANCE_NAMES: [&str; 3] = ["known_data", "code_candidate", "unclassified"];
const LISTING_NAMES: [&str; 3] = ["named", "undefined", "directive"];

fn provenance(start: u64, end: u64, code: &Ranges, data: &Ranges) -> Provenance {
    if data.contains(start, end) {
        Provenance::KnownData
    } else if data.intersects(start, end) {
        // A partial data annotation must not turn the rest of a word into code.
        Provenance::Unclassified
    } else if code.contains(start, end) {
        Provenance::CodeCandidate
    } else {
        Provenance::Unclassified
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    total: u64,
    decoded: u64,
    unsupported: u64,
    truncated: u64,
}

impl Counts {
    fn record(&mut self, result: &Result<(), Arm64DecodeError>) {
        self.total += 1;
        match result {
            Ok(()) => self.decoded += 1,
            Err(Arm64DecodeError::Truncated { .. }) => self.truncated += 1,
            Err(_) => self.unsupported += 1,
        }
    }
}

#[derive(Default, Debug)]
struct Census {
    raw: Counts,
    by_provenance: [Counts; 3],
    by_listing: [[Counts; 3]; 3],
    raw_bytes: BTreeMap<u8, (u64, u32)>,
    candidate_mnemonics: BTreeMap<String, (u64, String)>,
    unclassified_mnemonics: BTreeMap<String, (u64, String)>,
}

fn analyze(reader: impl BufRead, code: &Ranges, data: &Ranges) -> io::Result<Census> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    let mut census = Census::default();
    for line in reader.lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next().and_then(|field| field.strip_suffix(':')) else {
            continue;
        };
        let Some(raw) = fields.next() else { continue };
        let (Ok(address), Ok(word)) = (hex(address), u32::from_str_radix(raw, 16)) else {
            continue;
        };
        let end = address
            .checked_add(4)
            .ok_or_else(|| invalid("instruction address overflows u64"))?;
        let mnemonic = fields.next().unwrap_or("<none>");
        let listing = if mnemonic == ".inst" || mnemonic == "<unknown>" {
            1
        } else if mnemonic.starts_with('.') || mnemonic == "<none>" {
            2
        } else {
            0
        };
        let origin = provenance(address, end, code, data);
        let result = decoder.decode(address, &word.to_le_bytes()).map(|_| ());
        census.raw.record(&result);
        census.by_provenance[origin as usize].record(&result);
        census.by_listing[origin as usize][listing].record(&result);
        if matches!(result, Err(Arm64DecodeError::UnsupportedEncoding { .. })) {
            let entry = census.raw_bytes.entry((word >> 24) as u8).or_insert((0, word));
            entry.0 += 1;
            if listing == 0 {
                let histogram = match origin {
                    Provenance::KnownData => continue,
                    Provenance::CodeCandidate => &mut census.candidate_mnemonics,
                    Provenance::Unclassified => &mut census.unclassified_mnemonics,
                };
                let entry = histogram
                    .entry(mnemonic.to_owned())
                    .or_insert((0, line.trim().to_owned()));
                entry.0 += 1;
            }
        }
    }
    Ok(census)
}

fn print_counts(label: &str, counts: Counts) {
    println!(
        "{label} total={} decoded={} unsupported={} truncated={}",
        counts.total, counts.decoded, counts.unsupported, counts.truncated
    );
}

fn print_mnemonics(label: &str, histogram: BTreeMap<String, (u64, String)>) {
    println!("{label} (listing mnemonics, not verified execution):");
    let mut entries: Vec<_> = histogram.into_iter().collect();
    entries.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(&b.0)));
    for (mnemonic, (count, sample)) in entries.into_iter().take(24) {
        println!("  {count:>8} {mnemonic:<12} {sample}");
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    listing: String,
    fde: Option<String>,
    data: Option<String>,
}

fn options(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let mut options = Options::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--fde-ranges" | "--data-ranges" => {
                let slot = if argument == "--fde-ranges" {
                    &mut options.fde
                } else {
                    &mut options.data
                };
                if slot.is_some() {
                    return Err(invalid(format!("duplicate {argument}")));
                }
                let value = args
                    .next()
                    .ok_or_else(|| invalid(format!("missing value for {argument}")))?;
                if value.starts_with('-') {
                    return Err(invalid(format!("missing value for {argument}")));
                }
                *slot = Some(value);
            }
            _ if !argument.starts_with('-') && options.listing.is_empty() => options.listing = argument,
            _ => return Err(invalid(format!("unexpected argument: {argument}"))),
        }
    }
    if options.listing.is_empty() {
        return Err(invalid(
            "usage: a64_census LISTING [--fde-ranges FILE] [--data-ranges FILE]",
        ));
    }
    Ok(options)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = options(std::env::args().skip(1))?;
    let code = match &options.fde {
        Some(path) => fde_ranges(BufReader::new(File::open(path)?))?,
        None => Ranges::default(),
    };
    let data = match &options.data {
        Some(path) => data_ranges(BufReader::new(File::open(path)?))?,
        None => Ranges::default(),
    };
    let census = analyze(BufReader::new(File::open(&options.listing)?), &code, &data)?;
    // Preserve the original raw summary, including words inside annotated data.
    println!(
        "total={} decoded={} unsupported={} truncated={}",
        census.raw.total, census.raw.decoded, census.raw.unsupported, census.raw.truncated
    );
    let mut histogram: Vec<_> = census.raw_bytes.into_iter().collect();
    histogram.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(a.0.cmp(&b.0)));
    println!("unsupported by top byte (raw listing, including data):");
    for (byte, (count, sample)) in histogram.into_iter().take(24) {
        println!("  {count:>8}  0x{byte:02x}  sample {sample:08x}");
    }
    println!(
        "provenance: FDE={} data_annotations={} (no evidence means unclassified)",
        options.fde.as_deref().unwrap_or("none"),
        options.data.as_deref().unwrap_or("none")
    );
    for (index, name) in PROVENANCE_NAMES.iter().enumerate() {
        print_counts(name, census.by_provenance[index]);
        for (listing, kind) in LISTING_NAMES.iter().enumerate() {
            print_counts(&format!("  {name}/{kind}"), census.by_listing[index][listing]);
        }
    }
    print_mnemonics("unsupported code-candidate mnemonics", census.candidate_mnemonics);
    print_mnemonics("unsupported unclassified mnemonics", census.unclassified_mnemonics);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn range_boundaries_partial_words_and_priority() -> io::Result<()> {
        let code = Ranges::new(vec![(0x10, 0x30)], true)?;
        let data = Ranges::new(vec![(0x18, 0x1c), (0x21, 0x23)], false)?;
        assert_eq!(provenance(0x10, 0x14, &code, &data), Provenance::CodeCandidate);
        assert_eq!(provenance(0x18, 0x1c, &code, &data), Provenance::KnownData);
        assert_eq!(provenance(0x1c, 0x20, &code, &data), Provenance::CodeCandidate);
        assert_eq!(provenance(0x20, 0x24, &code, &data), Provenance::Unclassified);
        assert_eq!(provenance(0x2e, 0x32, &code, &data), Provenance::Unclassified);
        assert_eq!(provenance(0x30, 0x34, &code, &data), Provenance::Unclassified);
        Ok(())
    }

    #[test]
    fn fde_ranges_normalize_overlapping_unsorted_bounds() -> io::Result<()> {
        let input = b"001 FDE cie=0 pc=18..20\n002 FDE cie=0 pc=10..1c\n003 FDE cie=0 pc=20..24\n";
        assert_eq!(fde_ranges(Cursor::new(input))?.0, vec![(0x10, 0x24)]);
        for input in [
            "FDE pc=20..20",
            "FDE pc=20..10",
            "FDE pc=x..20",
            "FDE pc=10000000000000000..20",
            "FDE",
            "CIE pc=10..20",
            "FDE pc=10..20 pc=30..40",
        ] {
            assert!(fde_ranges(Cursor::new(input)).is_err(), "{input}");
        }
        Ok(())
    }

    #[test]
    fn data_annotations_require_evidence_and_disjoint_valid_ranges() -> io::Result<()> {
        let input = b"# half-open byte ranges\n0x18 0x1c literal bytes\n10 14 string # note\n";
        assert_eq!(data_ranges(Cursor::new(input))?.0, vec![(0x10, 0x14), (0x18, 0x1c)]);
        for input in [
            "10 20",
            "10 10 evidence",
            "20 10 evidence",
            "x 20 evidence",
            "10 20 a\n18 24 b",
            "10 20 a\n10 20 b",
        ] {
            assert!(data_ranges(Cursor::new(input)).is_err(), "{input}");
        }
        Ok(())
    }

    #[test]
    fn raw_counts_and_evidence_buckets_are_independent() -> io::Result<()> {
        let listing = b"header\n  10: d503201f nop\n  14: 1e700020 .inst 0x1e700020 ; undefined\n  18: d503201f .word 0xd503201f\n  1c: 1e700020 fcvtms w0, d1\n  20: 1e700020 .inst 0x1e700020\n  24: d503201f nop\n  28: d503201f .inst 0xd503201f\n";
        let code = Ranges::new(vec![(0x10, 0x1c)], true)?;
        let data = Ranges::new(vec![(0x18, 0x1c)], false)?;
        let census = analyze(Cursor::new(listing), &code, &data)?;
        assert_eq!(
            census.raw,
            Counts {
                total: 7,
                decoded: 4,
                unsupported: 3,
                truncated: 0
            }
        );
        assert_eq!(census.by_provenance[0].total, 1);
        assert_eq!(census.by_provenance[0].decoded, 1); // accepting data is not code coverage
        assert_eq!(census.by_provenance[1].total, 2);
        assert_eq!(census.by_provenance[1].unsupported, 1);
        assert_eq!(census.by_provenance[2].total, 4);
        assert_eq!(census.by_listing[0][2].total, 1);
        assert_eq!(census.by_listing[1][1].total, 1);
        assert_eq!(census.by_listing[2][1].total, 2);
        assert_eq!(census.by_listing[2][1].decoded, 1); // an undefined label is not a data annotation
        assert_eq!(census.unclassified_mnemonics["fcvtms"].0, 1);
        assert!(census.candidate_mnemonics.is_empty());
        assert_eq!(
            census.by_provenance.iter().map(|counts| counts.total).sum::<u64>(),
            census.raw.total
        );
        assert_eq!(
            census
                .by_listing
                .iter()
                .flatten()
                .map(|counts| counts.total)
                .sum::<u64>(),
            census.raw.total
        );
        let no_evidence = analyze(Cursor::new(listing), &Ranges::default(), &Ranges::default())?;
        assert_eq!(no_evidence.raw, census.raw);
        assert_eq!(no_evidence.by_provenance[2], census.raw);
        Ok(())
    }

    #[test]
    fn word_end_overflow_is_an_error() {
        assert!(
            analyze(
                Cursor::new("fffffffffffffffc: d503201f nop"),
                &Ranges::default(),
                &Ranges::default()
            )
            .is_err()
        );
    }

    #[test]
    fn reader_errors_are_not_silently_dropped() {
        struct Broken;
        impl io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("broken"))
            }
        }
        impl BufRead for Broken {
            fn fill_buf(&mut self) -> io::Result<&[u8]> {
                Err(io::Error::other("broken"))
            }
            fn consume(&mut self, _: usize) {}
        }
        assert!(analyze(Broken, &Ranges::default(), &Ranges::default()).is_err());
        assert!(fde_ranges(Broken).is_err());
        assert!(data_ranges(Broken).is_err());
    }

    #[test]
    fn options_fail_closed_on_missing_unknown_or_duplicate_flags() -> io::Result<()> {
        let parsed = options(
            ["listing", "--fde-ranges", "fde", "--data-ranges", "data"]
                .map(String::from)
                .into_iter(),
        )?;
        assert_eq!(
            parsed,
            Options {
                listing: "listing".into(),
                fde: Some("fde".into()),
                data: Some("data".into())
            }
        );
        for args in [
            vec![],
            vec!["listing", "--fde-ranges"],
            vec!["listing", "--bogus"],
            vec!["listing", "other"],
            vec!["listing", "--data-ranges", "--fde-ranges", "fde"],
            vec!["listing", "--fde-ranges", "a", "--fde-ranges", "b"],
        ] {
            assert!(options(args.into_iter().map(String::from)).is_err());
        }
        Ok(())
    }
}
