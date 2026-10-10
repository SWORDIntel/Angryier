//! Batch XED runtime IFORM evidence extraction.
//!
//! This module provides a small, deterministic engine for consuming
//! newline-delimited JSON records specifying input IDs and instruction hex bytes,
//! decoding them with [`XedDecoder::decode_with_iform`], and emitting
//! newline-delimited JSON retaining input IDs, bytes, pinned decoder version,
//! raw XED IFORM symbolic name and numeric discriminant, and decode/error status.
//!
//! # Identity Boundary Rule
//!
//! Raw XED IFORMs are source-level enum tokens scoped to the pinned `xed-sys`
//! release. They are **not** ISANITY canonical IDs and must not be conflated with
//! Angryier's engine-owned `form_id` (which maps instruction classes).

use crate::XedDecoder;
use core::fmt::Write as FmtWrite;
use std::collections::HashSet;
use std::io::{BufRead, Write};

/// Pinned XED version string.
pub const PINNED_XED_VERSION: &str = "xed-sys 0.6.0+xed-2024.05.20";

/// Stable identifier retained from input records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawJsonId {
    /// String identifier (e.g. `"test-case-1"`).
    String(String),
    /// Numeric identifier (e.g. `42` or `1001`).
    Number(String),
    /// Boolean identifier.
    Boolean(bool),
    /// Null identifier.
    Null,
}

impl RawJsonId {
    /// Returns a string representation of the ID.
    pub fn as_str(&self) -> &str {
        match self {
            Self::String(s) => s.as_str(),
            Self::Number(s) => s.as_str(),
            Self::Boolean(true) => "true",
            Self::Boolean(false) => "false",
            Self::Null => "null",
        }
    }

    /// Renders the ID as a raw JSON token.
    pub fn to_json(&self) -> String {
        match self {
            Self::String(s) => escape_json_string(s),
            Self::Number(n) => n.clone(),
            Self::Boolean(true) => "true".to_owned(),
            Self::Boolean(false) => "false".to_owned(),
            Self::Null => "null".to_owned(),
        }
    }
}

impl From<&str> for RawJsonId {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for RawJsonId {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<u64> for RawJsonId {
    fn from(n: u64) -> Self {
        Self::Number(n.to_string())
    }
}

/// Escapes a string for valid, deterministic JSON output.
pub fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Errors occurring during batch evidence ingestion or processing.
#[derive(Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// JSON syntactic violation.
    InvalidJson(String),
    /// Missing required JSON field.
    MissingField(&'static str),
    /// Hex string contained non-hex character.
    InvalidHexChar(char),
    /// Byte input was empty.
    EmptyInput,
    /// Hex string had an odd number of nibbles.
    OddLengthHex(usize),
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidJson(msg) => write!(f, "JSON parse error: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field '{field}'"),
            Self::InvalidHexChar(c) => write!(f, "invalid hex character '{c}'"),
            Self::EmptyInput => write!(f, "cannot decode empty byte string"),
            Self::OddLengthHex(len) => write!(f, "odd number of hex digits ({len})"),
        }
    }
}

impl std::error::Error for EvidenceError {}

/// Parsed input record from a newline-delimited JSON stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceInputRecord {
    /// Stable input identifier.
    pub id: RawJsonId,
    /// Retained input hex string.
    pub bytes: String,
    /// Optional instruction address (defaults to configured stream address).
    pub address: Option<u64>,
}

impl EvidenceInputRecord {
    /// Parses an input record from a single JSON line.
    pub fn parse(line: &str) -> Result<Self, EvidenceError> {
        let mut parser = JsonParser::new(line);
        let value = parser.parse_value()?;
        parser.skip_whitespace();
        if parser.peek().is_some() {
            return Err(EvidenceError::InvalidJson("unexpected trailing characters".to_owned()));
        }

        let fields = match value {
            JsonValue::Object(fields) => fields,
            _ => return Err(EvidenceError::InvalidJson("root must be a JSON object".to_owned())),
        };

        let mut id = None;
        let mut bytes = None;
        let mut address = None;
        let mut saw_bytes_key = false;
        let mut saw_address_key = false;

        for (k, v) in fields {
            match k.as_str() {
                "id" => {
                    id = Some(match v {
                        JsonValue::String(s) => RawJsonId::String(s),
                        JsonValue::Number(n) => RawJsonId::Number(n),
                        JsonValue::Boolean(b) => RawJsonId::Boolean(b),
                        JsonValue::Null => RawJsonId::Null,
                        _ => return Err(EvidenceError::InvalidJson("'id' must be scalar".to_owned())),
                    });
                }
                "bytes" | "hex" | "hex_bytes" => {
                    if saw_bytes_key {
                        return Err(EvidenceError::InvalidJson(
                            "multiple byte input fields are not allowed".to_owned(),
                        ));
                    }
                    saw_bytes_key = true;
                    bytes = Some(match v {
                        JsonValue::String(s) => s,
                        _ => return Err(EvidenceError::InvalidJson("'bytes' must be a hex string".to_owned())),
                    });
                }
                "address" | "addr" => {
                    if saw_address_key {
                        return Err(EvidenceError::InvalidJson(
                            "multiple address fields are not allowed".to_owned(),
                        ));
                    }
                    saw_address_key = true;
                    address = match v {
                        JsonValue::Number(n) => n.parse::<u64>().ok(),
                        JsonValue::String(s) => {
                            let trimmed = s.trim();
                            if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                                u64::from_str_radix(stripped, 16).ok()
                            } else {
                                trimmed.parse::<u64>().ok()
                            }
                        }
                        _ => None,
                    };
                }
                _ => {}
            }
        }

        let id = id.ok_or(EvidenceError::MissingField("id"))?;
        let bytes = bytes.ok_or(EvidenceError::MissingField("bytes"))?;

        Ok(Self { id, bytes, address })
    }
}

/// Decode status indicator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeStatus {
    /// Instruction decoded successfully.
    Ok,
    /// Decode failed or was rejected.
    Error,
}

/// Raw source-level XED IFORM evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IformEvidence {
    /// Exact symbolic enumerant name (e.g. `"XED_IFORM_NOP_90"`).
    pub name: String,
    /// Raw XED iform discriminant value (e.g. `1735`).
    pub value: u32,
}

/// Complete output record emitted for each consumed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceOutputRecord {
    /// Retained input identifier.
    pub id: RawJsonId,
    /// Retained input hex bytes.
    pub bytes: String,
    /// Decode status (`ok` or `error`).
    pub status: DecodeStatus,
    /// Exact pinned XED decoder version.
    pub decoder_version: &'static str,
    /// Raw symbolic IFORM name if decode succeeded.
    pub iform_name: Option<String>,
    /// Raw numeric IFORM value if decode succeeded.
    pub iform_value: Option<u32>,
    /// Structured raw IFORM evidence.
    pub raw_iform: Option<IformEvidence>,
    /// Decoded instruction byte length if decode succeeded.
    pub length: Option<u8>,
    /// Error message if decode failed.
    pub error: Option<String>,
}

impl EvidenceOutputRecord {
    /// Renders this record as a deterministic newline-delimited JSON line.
    pub fn to_ndjson_line(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push('{');

        out.push_str("\"id\":");
        out.push_str(&self.id.to_json());

        out.push_str(",\"bytes\":");
        out.push_str(&escape_json_string(&self.bytes));

        out.push_str(",\"status\":");
        match self.status {
            DecodeStatus::Ok => out.push_str("\"ok\""),
            DecodeStatus::Error => out.push_str("\"error\""),
        }

        out.push_str(",\"decoder_version\":");
        out.push_str(&escape_json_string(self.decoder_version));

        out.push_str(",\"iform_name\":");
        if let Some(ref name) = self.iform_name {
            out.push_str(&escape_json_string(name));
        } else {
            out.push_str("null");
        }

        out.push_str(",\"iform_value\":");
        if let Some(val) = self.iform_value {
            let _ = write!(out, "{val}");
        } else {
            out.push_str("null");
        }

        out.push_str(",\"raw_iform\":");
        if let Some(ref iform) = self.raw_iform {
            out.push('{');
            out.push_str("\"name\":");
            out.push_str(&escape_json_string(&iform.name));
            out.push_str(",\"value\":");
            let _ = write!(out, "{}", iform.value);
            out.push('}');
        } else {
            out.push_str("null");
        }

        if let Some(len) = self.length {
            let _ = write!(out, ",\"length\":{len}");
        }

        if let Some(ref err) = self.error {
            out.push_str(",\"error\":");
            out.push_str(&escape_json_string(err));
        }

        out.push('}');
        out
    }
}

/// Parses hex strings into a byte vector.
///
/// Accepts standard hexadecimal strings, with optional `0x` prefix and
/// optional separating whitespace, commas, or underscores.
pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, EvidenceError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(EvidenceError::EmptyInput);
    }

    let tokens: Vec<&str> = trimmed
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '_')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if tokens.is_empty() {
        return Err(EvidenceError::EmptyInput);
    }

    let mut hex_digits = String::with_capacity(trimmed.len());
    for token in tokens {
        let clean = if let Some(stripped) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
            stripped
        } else {
            token
        };
        for c in clean.chars() {
            if c.is_ascii_hexdigit() {
                hex_digits.push(c);
            } else {
                return Err(EvidenceError::InvalidHexChar(c));
            }
        }
    }

    if hex_digits.is_empty() {
        return Err(EvidenceError::EmptyInput);
    }
    if !hex_digits.len().is_multiple_of(2) {
        return Err(EvidenceError::OddLengthHex(hex_digits.len()));
    }
    let mut bytes = Vec::with_capacity(hex_digits.len() / 2);
    let chars: Vec<char> = hex_digits.chars().collect();
    for chunk in chars.chunks(2) {
        let hi = chunk[0].to_digit(16).ok_or(EvidenceError::InvalidHexChar(chunk[0]))?;
        let lo = chunk[1].to_digit(16).ok_or(EvidenceError::InvalidHexChar(chunk[1]))?;
        bytes.push(((hi << 4) | lo) as u8);
    }
    Ok(bytes)
}

/// Processes a single input line, returning the evidence output record.
pub fn process_single_line(
    decoder: &XedDecoder,
    line: &str,
    line_number: usize,
    default_address: u64,
) -> EvidenceOutputRecord {
    let parsed = match EvidenceInputRecord::parse(line) {
        Ok(rec) => rec,
        Err(err) => {
            return EvidenceOutputRecord {
                id: RawJsonId::Number(line_number.to_string()),
                bytes: String::new(),
                status: DecodeStatus::Error,
                decoder_version: PINNED_XED_VERSION,
                iform_name: None,
                iform_value: None,
                raw_iform: None,
                length: None,
                error: Some(err.to_string()),
            };
        }
    };

    let address = parsed.address.unwrap_or(default_address);
    let raw_bytes = match parse_hex_bytes(&parsed.bytes) {
        Ok(b) => b,
        Err(err) => {
            return EvidenceOutputRecord {
                id: parsed.id,
                bytes: parsed.bytes,
                status: DecodeStatus::Error,
                decoder_version: PINNED_XED_VERSION,
                iform_name: None,
                iform_value: None,
                raw_iform: None,
                length: None,
                error: Some(err.to_string()),
            };
        }
    };

    match decoder.decode_with_iform(address, &raw_bytes) {
        Ok((decoded, iform)) => EvidenceOutputRecord {
            id: parsed.id,
            bytes: parsed.bytes,
            status: DecodeStatus::Ok,
            decoder_version: iform.xed_sys_version,
            iform_name: Some(iform.name.clone()),
            iform_value: Some(iform.value),
            raw_iform: Some(IformEvidence {
                name: iform.name,
                value: iform.value,
            }),
            length: Some(decoded.length),
            error: None,
        },
        Err(err) => EvidenceOutputRecord {
            id: parsed.id,
            bytes: parsed.bytes,
            status: DecodeStatus::Error,
            decoder_version: PINNED_XED_VERSION,
            iform_name: None,
            iform_value: None,
            raw_iform: None,
            length: None,
            error: Some(err.to_string()),
        },
    }
}

/// Statistics from a batch evidence run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatchStats {
    /// Total records encountered.
    pub total: usize,
    /// Successfully decoded records.
    pub ok: usize,
    /// Records with decode or ingestion errors.
    pub errors: usize,
}

/// Streams newline-delimited JSON records from a reader, decodes with XED,
/// and writes newline-delimited JSON output to a writer.
pub fn process_evidence_stream<R: BufRead, W: Write>(
    decoder: &XedDecoder,
    reader: R,
    mut writer: W,
    default_address: u64,
) -> Result<BatchStats, std::io::Error> {
    let mut stats = BatchStats::default();

    for (line_index, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        stats.total += 1;
        let record = process_single_line(decoder, trimmed, line_index + 1, default_address);
        if record.status == DecodeStatus::Ok {
            stats.ok += 1;
        } else {
            stats.errors += 1;
        }

        writer.write_all(record.to_ndjson_line().as_bytes())?;
        writer.write_all(b"\n")?;
    }

    writer.flush()?;
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Self-contained minimal JSON parser (no external crates required)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum JsonValue {
    String(String),
    Number(String),
    Boolean(bool),
    Null,
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

struct JsonParser<'a> {
    chars: core::str::Chars<'a>,
    peeked: Option<char>,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars(),
            peeked: None,
        }
    }

    fn peek(&mut self) -> Option<char> {
        if self.peeked.is_none() {
            self.peeked = self.chars.next();
        }
        self.peeked
    }

    fn next_char(&mut self) -> Option<char> {
        if let Some(c) = self.peeked.take() {
            Some(c)
        } else {
            self.chars.next()
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if matches!(c, ' ' | '\t' | '\n' | '\r') {
                let _ = self.next_char();
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue, EvidenceError> {
        self.skip_whitespace();
        match self.peek() {
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(EvidenceError::InvalidJson(format!("unexpected character '{c}'"))),
            None => Err(EvidenceError::InvalidJson("unexpected end of input".to_owned())),
        }
    }

    fn parse_string(&mut self) -> Result<String, EvidenceError> {
        let quote = self.next_char();
        if quote != Some('"') {
            return Err(EvidenceError::InvalidJson("expected opening quote".to_owned()));
        }
        let mut out = String::new();
        while let Some(c) = self.next_char() {
            match c {
                '"' => return Ok(out),
                '\\' => match self.next_char() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\x08'),
                    Some('f') => out.push('\x0C'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let code = self.parse_hex_quad()?;
                        let scalar = match code {
                            0xD800..=0xDBFF => {
                                if self.next_char() != Some('\\') || self.next_char() != Some('u') {
                                    return Err(EvidenceError::InvalidJson(
                                        "high surrogate missing low surrogate".to_owned(),
                                    ));
                                }
                                let low = self.parse_hex_quad()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err(EvidenceError::InvalidJson("invalid low surrogate".to_owned()));
                                }
                                0x1_0000 + (((code - 0xD800) << 10) | (low - 0xDC00))
                            }
                            0xDC00..=0xDFFF => {
                                return Err(EvidenceError::InvalidJson("unpaired low surrogate".to_owned()));
                            }
                            _ => code,
                        };
                        let ch = char::from_u32(scalar)
                            .ok_or_else(|| EvidenceError::InvalidJson("invalid unicode codepoint".to_owned()))?;
                        out.push(ch);
                    }
                    _ => return Err(EvidenceError::InvalidJson("invalid escape sequence".to_owned())),
                },
                c if (c as u32) < 0x20 => {
                    return Err(EvidenceError::InvalidJson(
                        "unescaped control character in string".to_owned(),
                    ));
                }
                c => out.push(c),
            }
        }
        Err(EvidenceError::InvalidJson("unterminated string".to_owned()))
    }

    fn parse_number(&mut self) -> Result<JsonValue, EvidenceError> {
        let mut num = String::new();
        if self.peek() == Some('-') {
            num.push('-');
            let _ = self.next_char();
        }
        match self.peek() {
            Some('0') => {
                num.push('0');
                let _ = self.next_char();
                if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    return Err(EvidenceError::InvalidJson("leading zero in number".to_owned()));
                }
            }
            Some('1'..='9') => {
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    let c = self
                        .next_char()
                        .ok_or_else(|| EvidenceError::InvalidJson("unexpected end of number".to_owned()))?;
                    num.push(c);
                }
            }
            _ => return Err(EvidenceError::InvalidJson("invalid number".to_owned())),
        }
        if self.peek() == Some('.') {
            num.push('.');
            let _ = self.next_char();
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err(EvidenceError::InvalidJson("fraction requires a digit".to_owned()));
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                let c = self
                    .next_char()
                    .ok_or_else(|| EvidenceError::InvalidJson("unexpected end of number".to_owned()))?;
                num.push(c);
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let exponent = self
                .next_char()
                .ok_or_else(|| EvidenceError::InvalidJson("unexpected end of number".to_owned()))?;
            num.push(exponent);
            if matches!(self.peek(), Some('+' | '-')) {
                let sign = self
                    .next_char()
                    .ok_or_else(|| EvidenceError::InvalidJson("unexpected end of number".to_owned()))?;
                num.push(sign);
            }
            if !self.peek().is_some_and(|c| c.is_ascii_digit()) {
                return Err(EvidenceError::InvalidJson("exponent requires a digit".to_owned()));
            }
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                let c = self
                    .next_char()
                    .ok_or_else(|| EvidenceError::InvalidJson("unexpected end of number".to_owned()))?;
                num.push(c);
            }
        }
        Ok(JsonValue::Number(num))
    }

    fn parse_hex_quad(&mut self) -> Result<u32, EvidenceError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = self
                .next_char()
                .and_then(|c| c.to_digit(16))
                .ok_or_else(|| EvidenceError::InvalidJson("invalid unicode escape".to_owned()))?;
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_bool(&mut self) -> Result<JsonValue, EvidenceError> {
        let mut token = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphabetic() {
                let _ = self.next_char();
                token.push(c);
            } else {
                break;
            }
        }
        match token.as_str() {
            "true" => Ok(JsonValue::Boolean(true)),
            "false" => Ok(JsonValue::Boolean(false)),
            _ => Err(EvidenceError::InvalidJson(format!("unknown token '{token}'"))),
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, EvidenceError> {
        let mut token = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_alphabetic() {
                let _ = self.next_char();
                token.push(c);
            } else {
                break;
            }
        }
        if token == "null" {
            Ok(JsonValue::Null)
        } else {
            Err(EvidenceError::InvalidJson(format!("unknown token '{token}'")))
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, EvidenceError> {
        let open = self.next_char();
        if open != Some('[') {
            return Err(EvidenceError::InvalidJson("expected '['".to_owned()));
        }
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            let _ = self.next_char();
            return Ok(JsonValue::Array(items));
        }
        loop {
            let val = self.parse_value()?;
            items.push(val);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    let _ = self.next_char();
                    self.skip_whitespace();
                }
                Some(']') => {
                    let _ = self.next_char();
                    break;
                }
                _ => return Err(EvidenceError::InvalidJson("expected ',' or ']' in array".to_owned())),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue, EvidenceError> {
        let open = self.next_char();
        if open != Some('{') {
            return Err(EvidenceError::InvalidJson("expected '{'".to_owned()));
        }
        let mut fields = Vec::new();
        let mut keys = HashSet::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            let _ = self.next_char();
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(EvidenceError::InvalidJson(format!("duplicate object key '{key}'")));
            }
            self.skip_whitespace();
            if self.next_char() != Some(':') {
                return Err(EvidenceError::InvalidJson("expected ':' after object key".to_owned()));
            }
            let val = self.parse_value()?;
            fields.push((key, val));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    let _ = self.next_char();
                    self.skip_whitespace();
                }
                Some('}') => {
                    let _ = self.next_char();
                    break;
                }
                _ => return Err(EvidenceError::InvalidJson("expected ',' or '}' in object".to_owned())),
            }
        }
        Ok(JsonValue::Object(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_byte_variants() {
        assert_eq!(parse_hex_bytes("90"), Ok(vec![0x90]));
        assert_eq!(parse_hex_bytes("0x90"), Ok(vec![0x90]));
        assert_eq!(parse_hex_bytes("48 89 c1"), Ok(vec![0x48, 0x89, 0xc1]));
        assert_eq!(parse_hex_bytes("0x48, 0x89, 0xc1"), Ok(vec![0x48, 0x89, 0xc1]));
        assert_eq!(parse_hex_bytes("48_89_C1"), Ok(vec![0x48, 0x89, 0xc1]));
    }

    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(parse_hex_bytes(""), Err(EvidenceError::EmptyInput));
        assert_eq!(parse_hex_bytes("9"), Err(EvidenceError::OddLengthHex(1)));
        assert_eq!(parse_hex_bytes("9g"), Err(EvidenceError::InvalidHexChar('g')));
    }

    #[test]
    fn parses_input_record_schema() {
        let rec = EvidenceInputRecord::parse(r#"{"id": "nop-1", "bytes": "90"}"#).expect("record should parse");
        assert_eq!(rec.id, RawJsonId::String("nop-1".to_owned()));
        assert_eq!(rec.bytes, "90");
        assert_eq!(rec.address, None);

        let rec_num = EvidenceInputRecord::parse(r#"{"id": 42, "bytes": "4889c1", "address": "0x4000"}"#)
            .expect("numeric id should parse");
        assert_eq!(rec_num.id, RawJsonId::Number("42".to_owned()));
        assert_eq!(rec_num.bytes, "4889c1");
        assert_eq!(rec_num.address, Some(0x4000));
    }

    #[test]
    fn parser_rejects_non_json_numbers_and_duplicate_fields() {
        for input in [
            r#"{"id": +1, "bytes": "90"}"#,
            r#"{"id": 01, "bytes": "90"}"#,
            r#"{"id": 1e+, "bytes": "90"}"#,
            r#"{"id": 1, "id": 2, "bytes": "90"}"#,
            r#"{"id": 1, "bytes": "90", "hex": "90"}"#,
            r#"{"id": 1, "bytes": "90", "address": 1, "addr": 1}"#,
        ] {
            assert!(
                EvidenceInputRecord::parse(input).is_err(),
                "accepted invalid JSON: {input}"
            );
        }
    }

    #[test]
    fn parser_rejects_invalid_unicode_and_raw_controls() {
        for input in [
            r#"{"id":"\uD800", "bytes":"90"}"#,
            r#"{"id":"\uDC00", "bytes":"90"}"#,
            r#"{"id":"\uD800\u0041", "bytes":"90"}"#,
            "{\"id\":\"raw\u{0001}control\",\"bytes\":\"90\"}",
        ] {
            assert!(
                EvidenceInputRecord::parse(input).is_err(),
                "accepted invalid JSON string: {input:?}"
            );
        }

        let valid_pair = EvidenceInputRecord::parse(r#"{"id":"\uD83D\uDE00", "bytes":"90"}"#)
            .expect("valid surrogate pair should decode");
        assert_eq!(valid_pair.id, RawJsonId::String("😀".to_owned()));
    }

    #[test]
    fn preserves_valid_numeric_id_token() {
        let rec =
            EvidenceInputRecord::parse(r#"{"id":1.25e+2,"bytes":"90"}"#).expect("valid numeric scalar ID should parse");
        assert_eq!(rec.id, RawJsonId::Number("1.25e+2".to_owned()));
        assert_eq!(rec.id.to_json(), "1.25e+2");
    }

    #[test]
    fn decodes_nop_evidence_deterministically() {
        let decoder = XedDecoder::new();
        let rec = process_single_line(&decoder, r#"{"id": "test_nop", "bytes": "90"}"#, 1, 0x1000);

        assert_eq!(rec.id, RawJsonId::String("test_nop".to_owned()));
        assert_eq!(rec.bytes, "90");
        assert_eq!(rec.status, DecodeStatus::Ok);
        assert_eq!(rec.decoder_version, PINNED_XED_VERSION);
        assert_eq!(rec.iform_name.as_deref(), Some("XED_IFORM_NOP_90"));
        assert_eq!(rec.iform_value, Some(1735));
        assert_eq!(
            rec.raw_iform,
            Some(IformEvidence {
                name: "XED_IFORM_NOP_90".to_owned(),
                value: 1735,
            })
        );
        assert_eq!(rec.length, Some(1));
        assert_eq!(rec.error, None);

        let ndjson = rec.to_ndjson_line();
        assert_eq!(
            ndjson,
            r#"{"id":"test_nop","bytes":"90","status":"ok","decoder_version":"xed-sys 0.6.0+xed-2024.05.20","iform_name":"XED_IFORM_NOP_90","iform_value":1735,"raw_iform":{"name":"XED_IFORM_NOP_90","value":1735},"length":1}"#
        );
    }

    #[test]
    fn decodes_mov_evidence() {
        let decoder = XedDecoder::new();
        let rec = process_single_line(&decoder, r#"{"id": "mov_64", "bytes": "48 89 c1"}"#, 1, 0x1000);

        assert_eq!(rec.status, DecodeStatus::Ok);
        assert_eq!(rec.iform_name.as_deref(), Some("XED_IFORM_MOV_GPRv_GPRv_89"));
        assert_eq!(rec.iform_value, Some(1560));
        assert_eq!(rec.length, Some(3));
    }

    #[test]
    fn records_decode_errors_cleanly() {
        let decoder = XedDecoder::new();
        let rec = process_single_line(&decoder, r#"{"id": "bad_bytes", "bytes": "0f 0f"}"#, 1, 0x1000);

        assert_eq!(rec.id, RawJsonId::String("bad_bytes".to_owned()));
        assert_eq!(rec.bytes, "0f 0f");
        assert_eq!(rec.status, DecodeStatus::Error);
        assert_eq!(rec.decoder_version, PINNED_XED_VERSION);
        assert_eq!(rec.iform_name, None);
        assert_eq!(rec.iform_value, None);
        assert_eq!(rec.raw_iform, None);
        assert_eq!(rec.length, None);
        assert!(rec.error.is_some());
    }

    #[test]
    fn processes_stream_batch_with_stats() {
        let decoder = XedDecoder::new();
        let input = r#"
{"id": "case1", "bytes": "90"}
{"id": "case2", "bytes": "4889c1"}
{"id": "case3", "bytes": "ffff"}
"#;
        let mut output = Vec::new();
        let stats = process_evidence_stream(&decoder, input.as_bytes(), &mut output, 0x1000)
            .expect("stream processing succeeded");

        assert_eq!(stats.total, 3);
        assert_eq!(stats.ok, 2);
        assert_eq!(stats.errors, 1);

        let lines: Vec<String> = String::from_utf8(output)
            .expect("output is utf8")
            .lines()
            .map(ToOwned::to_owned)
            .collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("\"iform_name\":\"XED_IFORM_NOP_90\""));
        assert!(lines[1].contains("\"iform_name\":\"XED_IFORM_MOV_GPRv_GPRv_89\""));
        assert!(lines[2].contains("\"status\":\"error\""));
    }
}
