//! Binary utilities, register name mappings, and disassembler for the Lua scripting API.

use mlua::{Lua, LuaString, Table, Value};

/// Maps a register name (case-insensitive) to its architectural register ID.
pub fn reg_by_name(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let gprs = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];
    if let Some(pos) = gprs.iter().position(|&n| n == lower) {
        return Some(angryier_arch_intel64::register_id::GPR_BASE + pos as u32);
    }
    // APX extended GPRs: r16 .. r31
    if let Some(stripped) = lower.strip_prefix('r')
        && let Ok(idx) = stripped.parse::<u32>()
        && (16..=31).contains(&idx)
    {
        return Some(angryier_arch_intel64::register_id::GPR_BASE + idx);
    }
    match lower.as_str() {
        "rip" => Some(angryier_arch_intel64::register_id::RIP.0),
        "rflags" | "flags" | "eflags" => Some(angryier_arch_intel64::register_id::RFLAGS.0),
        "fs_base" => Some(angryier_arch_intel64::register_id::FS_BASE.0),
        "gs_base" => Some(angryier_arch_intel64::register_id::GS_BASE.0),
        "ssp" => Some(angryier_arch_intel64::register_id::SSP.0),
        _ => None,
    }
}

/// Reverse-maps an architectural register ID to its canonical GPR or special register name.
pub fn name_by_reg(reg: u32) -> Option<&'static str> {
    let gprs = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
    ];
    let base = angryier_arch_intel64::register_id::GPR_BASE;
    if reg >= base && reg < base + 32 {
        return Some(gprs[(reg - base) as usize]);
    }
    if reg == angryier_arch_intel64::register_id::RIP.0 {
        return Some("rip");
    }
    if reg == angryier_arch_intel64::register_id::RFLAGS.0 {
        return Some("rflags");
    }
    if reg == angryier_arch_intel64::register_id::FS_BASE.0 {
        return Some("fs_base");
    }
    if reg == angryier_arch_intel64::register_id::GS_BASE.0 {
        return Some("gs_base");
    }
    if reg == angryier_arch_intel64::register_id::SSP.0 {
        return Some("ssp");
    }
    None
}

/// Installs binary manipulation and disassembler helpers into the `angry` table.
pub fn register_utils(lua: &Lua, lib: &Table) -> mlua::Result<()> {
    // angry.hex(bytes) -> "4889e5..."
    lib.set(
        "hex",
        lua.create_function(|_, bytes: LuaString| {
            let b_slice: &[u8] = &bytes.as_bytes();
            let mut out = String::with_capacity(b_slice.len() * 2);
            for b in b_slice {
                use std::fmt::Write;
                let _ = write!(out, "{:02x}", b);
            }
            Ok(out)
        })?,
    )?;

    // angry.unhex(hex_str) -> raw binary string
    lib.set(
        "unhex",
        lua.create_function(|lua, hex_str: String| {
            let clean = hex_str.trim().replace([' ', '\n', '\t', '_'], "");
            let clean = clean
                .strip_prefix("0x")
                .or_else(|| clean.strip_prefix("0X"))
                .unwrap_or(&clean);
            if !clean.len().is_multiple_of(2) {
                return Err(mlua::Error::external("unhex: hex string must have an even length"));
            }
            let mut bytes = Vec::with_capacity(clean.len() / 2);
            for chunk in clean.as_bytes().chunks(2) {
                let s =
                    std::str::from_utf8(chunk).map_err(|e| mlua::Error::external(format!("unhex: utf8 error: {e}")))?;
                let b = u8::from_str_radix(s, 16)
                    .map_err(|e| mlua::Error::external(format!("unhex: invalid hex character: {e}")))?;
                bytes.push(b);
            }
            lua.create_string(&bytes)
        })?,
    )?;

    // angry.pack64(integer) -> 8 bytes little-endian string
    lib.set(
        "pack64",
        lua.create_function(|lua, val: u64| lua.create_string(val.to_le_bytes()))?,
    )?;

    // angry.unpack64(bytes) -> integer
    lib.set(
        "unpack64",
        lua.create_function(|_, bytes: LuaString| {
            let b: &[u8] = &bytes.as_bytes();
            if b.len() < 8 {
                return Err(mlua::Error::external("unpack64: requires at least 8 bytes"));
            }
            let arr: [u8; 8] = b[..8]
                .try_into()
                .map_err(|_| mlua::Error::external("unpack64: slice conversion failed"))?;
            Ok(u64::from_le_bytes(arr))
        })?,
    )?;

    // angry.pack32(integer) -> 4 bytes little-endian string
    lib.set(
        "pack32",
        lua.create_function(|lua, val: u32| lua.create_string(val.to_le_bytes()))?,
    )?;

    // angry.unpack32(bytes) -> integer
    lib.set(
        "unpack32",
        lua.create_function(|_, bytes: LuaString| {
            let b: &[u8] = &bytes.as_bytes();
            if b.len() < 4 {
                return Err(mlua::Error::external("unpack32: requires at least 4 bytes"));
            }
            let arr: [u8; 4] = b[..4]
                .try_into()
                .map_err(|_| mlua::Error::external("unpack32: slice conversion failed"))?;
            Ok(u32::from_le_bytes(arr))
        })?,
    )?;

    // angry.disasm(bytes, [base_pc]) -> array of instruction tables
    #[cfg(feature = "xed")]
    lib.set(
        "disasm",
        lua.create_function(|lua, (bytes, pc): (LuaString, Option<u64>)| {
            let start_pc = pc.unwrap_or(0);
            let data: &[u8] = &bytes.as_bytes();
            let decoder = angryier_arch_xed_ffi::XedDecoder::new();
            let mut offset = 0;
            let result_tbl = lua.create_table()?;
            let mut idx = 1;

            while offset < data.len() {
                let slice = &data[offset..];
                let insn_pc = start_pc.wrapping_add(offset as u64);
                match angryier_arch::Decoder::decode(&decoder, insn_pc, slice) {
                    Ok(insn) => {
                        let len = insn.length as usize;
                        if len == 0 {
                            break;
                        }
                        let insn_tbl = lua.create_table()?;
                        insn_tbl.set("pc", insn.address)?;
                        insn_tbl.set("len", len)?;
                        insn_tbl.set("length", len)?;
                        insn_tbl.set("form_id", insn.form_id)?;
                        let insn_bytes = &slice[..len];
                        insn_tbl.set("bytes", lua.create_string(insn_bytes)?)?;
                        let mut hex_rep = String::with_capacity(len * 3);
                        for (i, b) in insn_bytes.iter().enumerate() {
                            if i > 0 {
                                hex_rep.push(' ');
                            }
                            use std::fmt::Write;
                            let _ = write!(hex_rep, "{:02x}", b);
                        }
                        insn_tbl.set("hex", hex_rep)?;
                        insn_tbl.set("operands_count", insn.operands.len())?;
                        result_tbl.set(idx, insn_tbl)?;
                        idx += 1;
                        offset += len;
                    }
                    Err(_) => {
                        let insn_tbl = lua.create_table()?;
                        insn_tbl.set("pc", insn_pc)?;
                        insn_tbl.set("len", 1)?;
                        insn_tbl.set("bytes", lua.create_string(&slice[..1])?)?;
                        insn_tbl.set("hex", format!("{:02x}", slice[0]))?;
                        insn_tbl.set("invalid", true)?;
                        result_tbl.set(idx, insn_tbl)?;
                        idx += 1;
                        offset += 1;
                    }
                }
            }
            Ok(result_tbl)
        })?,
    )?;

    Ok(())
}

/// Parses a Lua value (hex string, raw byte string, or sequence table of integers)
/// into a `Vec<u8>`.
pub fn parse_patch_bytes(data: Value) -> Result<Vec<u8>, mlua::Error> {
    match data {
        Value::String(s) => {
            let s_bytes = s.as_bytes();
            if let Ok(text) = std::str::from_utf8(&s_bytes) {
                let trimmed = text.trim();
                let clean = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                    .unwrap_or(trimmed)
                    .replace([' ', '\t'], "");
                if !clean.is_empty() && clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
                    let mut bytes = Vec::with_capacity(clean.len() / 2);
                    for chunk in clean.as_bytes().chunks(2) {
                        if let Ok(s) = std::str::from_utf8(chunk)
                            && let Ok(b) = u8::from_str_radix(s, 16)
                        {
                            bytes.push(b);
                        } else {
                            bytes.clear();
                            break;
                        }
                    }
                    if bytes.len() == clean.len() / 2 {
                        return Ok(bytes);
                    }
                }
            }
            Ok(s_bytes.to_vec())
        }
        Value::Table(t) => {
            let mut vec = Vec::new();
            for b in t.sequence_values::<u8>() {
                vec.push(b?);
            }
            Ok(vec)
        }
        _ => Err(mlua::Error::external(
            "patch: data must be a hex string, byte string, or table of bytes",
        )),
    }
}

/// Robustly parses a Lua value representing a 64-bit unsigned integer or address.
/// Accepts:
/// - `Value::Integer(i)`: signed 64-bit integer, cast to `u64` preserving bit pattern.
/// - `Value::Number(f)`: finite positive floating-point number, converted to `u64`.
/// - `Value::String(s)`: hex string (with or without `0x`/`0X` prefix) or decimal string.
pub fn parse_lua_u64(val: &Value) -> Option<u64> {
    match val {
        Value::Integer(i) => Some(*i as u64),
        Value::Number(f) if f.is_finite() && *f >= 0.0 && *f <= (u64::MAX as f64) => Some(*f as u64),
        Value::String(s) => {
            let s_bytes = s.as_bytes();
            let text = std::str::from_utf8(&s_bytes).ok()?.trim();
            let clean = text.replace(['_', ' '], "");
            if let Some(hex) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else if clean.chars().all(|c| c.is_ascii_digit()) {
                clean.parse::<u64>().ok()
            } else {
                u64::from_str_radix(&clean, 16).ok()
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lua_u64() {
        let lua = Lua::new();
        let val_int = Value::Integer(0x401000);
        assert_eq!(parse_lua_u64(&val_int), Some(0x401000));

        let val_neg = Value::Integer(-1);
        assert_eq!(parse_lua_u64(&val_neg), Some(u64::MAX));

        let val_float = Value::Number(4096.0);
        assert_eq!(parse_lua_u64(&val_float), Some(4096));

        let val_hex_str = Value::String(lua.create_string("0x401000").unwrap());
        assert_eq!(parse_lua_u64(&val_hex_str), Some(0x401000));

        let val_dec_str = Value::String(lua.create_string("12345").unwrap());
        assert_eq!(parse_lua_u64(&val_dec_str), Some(12345));

        let val_raw_hex = Value::String(lua.create_string("deadbeef").unwrap());
        assert_eq!(parse_lua_u64(&val_raw_hex), Some(0xdeadbeef));

        assert_eq!(parse_lua_u64(&Value::Nil), None);
    }
}
