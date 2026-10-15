#![forbid(unsafe_code)]

//! Comprehensive POSIX Libc string, memory, and character simulation procedures.

use crate::{SimProcedure, SimResult, SimState};
use super::heap::TrackedHeap;

// ---------------------------------------------------------------------------
// String Length & Comparison
// ---------------------------------------------------------------------------

/// `strlen(const char *s)`
pub struct StrlenProcedure;

impl SimProcedure for StrlenProcedure {
    fn name(&self) -> &'static str {
        "strlen"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let s = state.read_null_terminated_string(addr, 65536);
        SimResult::Return(s.len() as u64)
    }
}

/// `strcmp(const char *s1, const char *s2)`
pub struct StrcmpProcedure;

impl SimProcedure for StrcmpProcedure {
    fn name(&self) -> &'static str {
        "strcmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr1 = state.get_arg(0);
        let addr2 = state.get_arg(1);
        let s1 = state.read_null_terminated_string(addr1, 65536);
        let s2 = state.read_null_terminated_string(addr2, 65536);
        match s1.cmp(&s2) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

/// `strncmp(const char *s1, const char *s2, size_t n)`
pub struct StrncmpProcedure;

impl SimProcedure for StrncmpProcedure {
    fn name(&self) -> &'static str {
        "strncmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr1 = state.get_arg(0);
        let addr2 = state.get_arg(1);
        let n = state.get_arg(2) as usize;
        let mut s1 = state.read_null_terminated_string(addr1, n);
        let mut s2 = state.read_null_terminated_string(addr2, n);
        s1.truncate(n);
        s2.truncate(n);
        match s1.cmp(&s2) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

/// `strcasecmp(const char *s1, const char *s2)`
pub struct StrcasecmpProcedure;

impl SimProcedure for StrcasecmpProcedure {
    fn name(&self) -> &'static str {
        "strcasecmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr1 = state.get_arg(0);
        let addr2 = state.get_arg(1);
        let s1 = state.read_null_terminated_string(addr1, 65536);
        let s2 = state.read_null_terminated_string(addr2, 65536);
        let s1_lower: Vec<u8> = s1.iter().map(|b| b.to_ascii_lowercase()).collect();
        let s2_lower: Vec<u8> = s2.iter().map(|b| b.to_ascii_lowercase()).collect();
        match s1_lower.cmp(&s2_lower) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

/// `strncasecmp(const char *s1, const char *s2, size_t n)`
pub struct StrncasecmpProcedure;

impl SimProcedure for StrncasecmpProcedure {
    fn name(&self) -> &'static str {
        "strncasecmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr1 = state.get_arg(0);
        let addr2 = state.get_arg(1);
        let n = state.get_arg(2) as usize;
        let mut s1 = state.read_null_terminated_string(addr1, n);
        let mut s2 = state.read_null_terminated_string(addr2, n);
        s1.truncate(n);
        s2.truncate(n);
        let s1_lower: Vec<u8> = s1.iter().map(|b| b.to_ascii_lowercase()).collect();
        let s2_lower: Vec<u8> = s2.iter().map(|b| b.to_ascii_lowercase()).collect();
        match s1_lower.cmp(&s2_lower) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

// ---------------------------------------------------------------------------
// String Copying & Concatenation
// ---------------------------------------------------------------------------

/// `strcpy(char *dest, const char *src)`
pub struct StrcpyProcedure;

impl SimProcedure for StrcpyProcedure {
    fn name(&self) -> &'static str {
        "strcpy"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let mut bytes = state.read_null_terminated_string(src, 65536);
        bytes.push(0); // null terminator

        let mut next = state.clone();
        next.write_memory(dest, bytes);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `strncpy(char *dest, const char *src, size_t n)`
pub struct StrncpyProcedure;

impl SimProcedure for StrncpyProcedure {
    fn name(&self) -> &'static str {
        "strncpy"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let n = state.get_arg(2) as usize;

        let src_bytes = state.read_null_terminated_string(src, n);
        let mut buf = vec![0u8; n];
        let copy_len = src_bytes.len().min(n);
        buf[..copy_len].copy_from_slice(&src_bytes[..copy_len]);

        let mut next = state.clone();
        next.write_memory(dest, buf);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `strcat(char *dest, const char *src)`
pub struct StrcatProcedure;

impl SimProcedure for StrcatProcedure {
    fn name(&self) -> &'static str {
        "strcat"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);

        let dest_str = state.read_null_terminated_string(dest, 65536);
        let mut src_str = state.read_null_terminated_string(src, 65536);
        src_str.push(0);

        let write_addr = dest.saturating_add(dest_str.len() as u64);
        let mut next = state.clone();
        next.write_memory(write_addr, src_str);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `strncat(char *dest, const char *src, size_t n)`
pub struct StrncatProcedure;

impl SimProcedure for StrncatProcedure {
    fn name(&self) -> &'static str {
        "strncat"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let n = state.get_arg(2) as usize;

        let dest_str = state.read_null_terminated_string(dest, 65536);
        let mut src_str = state.read_null_terminated_string(src, n);
        src_str.truncate(n);
        src_str.push(0);

        let write_addr = dest.saturating_add(dest_str.len() as u64);
        let mut next = state.clone();
        next.write_memory(write_addr, src_str);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

// ---------------------------------------------------------------------------
// Memory Operations
// ---------------------------------------------------------------------------

/// `memcpy(void *dest, const void *src, size_t n)`
pub struct MemcpyProcedure;

impl SimProcedure for MemcpyProcedure {
    fn name(&self) -> &'static str {
        "memcpy"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let n = (state.get_arg(2) as usize).min(1024 * 1024);
        let bytes = state.read_bytes(src, n);

        let mut next = state.clone();
        next.write_memory(dest, bytes);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `memmove(void *dest, const void *src, size_t n)`
pub struct MemmoveProcedure;

impl SimProcedure for MemmoveProcedure {
    fn name(&self) -> &'static str {
        "memmove"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let n = (state.get_arg(2) as usize).min(1024 * 1024);
        let bytes = state.read_bytes(src, n);

        let mut next = state.clone();
        next.write_memory(dest, bytes);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `memset(void *s, int c, size_t n)`
pub struct MemsetProcedure;

impl SimProcedure for MemsetProcedure {
    fn name(&self) -> &'static str {
        "memset"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let val = (state.get_arg(1) & 0xff) as u8;
        let n = (state.get_arg(2) as usize).min(1024 * 1024);
        let bytes = vec![val; n];

        let mut next = state.clone();
        next.write_memory(dest, bytes);
        next.return_value = Some(dest);
        next.set_reg(0, dest);
        SimResult::Continue(next)
    }
}

/// `memcmp(const void *s1, const void *s2, size_t n)`
pub struct MemcmpProcedure;

impl SimProcedure for MemcmpProcedure {
    fn name(&self) -> &'static str {
        "memcmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s1_addr = state.get_arg(0);
        let s2_addr = state.get_arg(1);
        let n = (state.get_arg(2) as usize).min(1024 * 1024);

        let b1 = state.read_bytes(s1_addr, n);
        let b2 = state.read_bytes(s2_addr, n);

        match b1.cmp(&b2) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

/// `memchr(const void *s, int c, size_t n)`
pub struct MemchrProcedure;

impl SimProcedure for MemchrProcedure {
    fn name(&self) -> &'static str {
        "memchr"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let target = (state.get_arg(1) & 0xff) as u8;
        let n = (state.get_arg(2) as usize).min(1024 * 1024);

        let bytes = state.read_bytes(s_addr, n);
        for (i, &b) in bytes.iter().enumerate() {
            if b == target {
                return SimResult::Return(s_addr.saturating_add(i as u64));
            }
        }
        SimResult::Return(0)
    }
}

/// `memrchr(const void *s, int c, size_t n)`
pub struct MemrchrProcedure;

impl SimProcedure for MemrchrProcedure {
    fn name(&self) -> &'static str {
        "memrchr"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let target = (state.get_arg(1) & 0xff) as u8;
        let n = (state.get_arg(2) as usize).min(1024 * 1024);

        let bytes = state.read_bytes(s_addr, n);
        for (i, &b) in bytes.iter().enumerate().rev() {
            if b == target {
                return SimResult::Return(s_addr.saturating_add(i as u64));
            }
        }
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// Search & Substrings
// ---------------------------------------------------------------------------

/// `strchr(const char *s, int c)`
pub struct StrchrProcedure;

impl SimProcedure for StrchrProcedure {
    fn name(&self) -> &'static str {
        "strchr"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let target = (state.get_arg(1) & 0xff) as u8;
        let bytes = state.read_null_terminated_string(s_addr, 65536);

        for (i, &b) in bytes.iter().enumerate() {
            if b == target {
                return SimResult::Return(s_addr.saturating_add(i as u64));
            }
        }
        if target == 0 {
            return SimResult::Return(s_addr.saturating_add(bytes.len() as u64));
        }
        SimResult::Return(0)
    }
}

/// `strrchr(const char *s, int c)`
pub struct StrrchrProcedure;

impl SimProcedure for StrrchrProcedure {
    fn name(&self) -> &'static str {
        "strrchr"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let target = (state.get_arg(1) & 0xff) as u8;
        let bytes = state.read_null_terminated_string(s_addr, 65536);

        if target == 0 {
            return SimResult::Return(s_addr.saturating_add(bytes.len() as u64));
        }
        for (i, &b) in bytes.iter().enumerate().rev() {
            if b == target {
                return SimResult::Return(s_addr.saturating_add(i as u64));
            }
        }
        SimResult::Return(0)
    }
}

/// `strstr(const char *haystack, const char *needle)`
pub struct StrstrProcedure;

impl SimProcedure for StrstrProcedure {
    fn name(&self) -> &'static str {
        "strstr"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let haystack_addr = state.get_arg(0);
        let needle_addr = state.get_arg(1);

        let needle = state.read_null_terminated_string(needle_addr, 65536);
        if needle.is_empty() {
            return SimResult::Return(haystack_addr);
        }

        let haystack = state.read_null_terminated_string(haystack_addr, 65536);
        if needle.len() > haystack.len() {
            return SimResult::Return(0);
        }

        for i in 0..=(haystack.len() - needle.len()) {
            if haystack[i..i + needle.len()] == needle[..] {
                return SimResult::Return(haystack_addr.saturating_add(i as u64));
            }
        }
        SimResult::Return(0)
    }
}

/// `strspn(const char *s, const char *accept)`
pub struct StrspnProcedure;

impl SimProcedure for StrspnProcedure {
    fn name(&self) -> &'static str {
        "strspn"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let accept_addr = state.get_arg(1);

        let s = state.read_null_terminated_string(s_addr, 65536);
        let accept = state.read_null_terminated_string(accept_addr, 65536);

        let mut count = 0u64;
        for &b in &s {
            if accept.contains(&b) {
                count += 1;
            } else {
                break;
            }
        }
        SimResult::Return(count)
    }
}

/// `strcspn(const char *s, const char *reject)`
pub struct StrcspnProcedure;

impl SimProcedure for StrcspnProcedure {
    fn name(&self) -> &'static str {
        "strcspn"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let reject_addr = state.get_arg(1);

        let s = state.read_null_terminated_string(s_addr, 65536);
        let reject = state.read_null_terminated_string(reject_addr, 65536);

        let mut count = 0u64;
        for &b in &s {
            if !reject.contains(&b) {
                count += 1;
            } else {
                break;
            }
        }
        SimResult::Return(count)
    }
}

// ---------------------------------------------------------------------------
// String Duplication
// ---------------------------------------------------------------------------

/// `strdup(const char *s)`
pub struct StrdupProcedure {
    heap: TrackedHeap,
}

impl StrdupProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for StrdupProcedure {
    fn name(&self) -> &'static str {
        "strdup"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let src_addr = state.get_arg(0);
        let mut bytes = state.read_null_terminated_string(src_addr, 65536);
        bytes.push(0);

        let new_ptr = self.heap.allocate(bytes.len() as u64);
        let mut next = state.clone();
        next.write_memory(new_ptr, bytes);
        next.return_value = Some(new_ptr);
        next.set_reg(0, new_ptr);
        SimResult::Continue(next)
    }
}

/// `strndup(const char *s, size_t n)`
pub struct StrndupProcedure {
    heap: TrackedHeap,
}

impl StrndupProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for StrndupProcedure {
    fn name(&self) -> &'static str {
        "strndup"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let src_addr = state.get_arg(0);
        let n = state.get_arg(1) as usize;

        let mut bytes = state.read_null_terminated_string(src_addr, n);
        bytes.truncate(n);
        bytes.push(0);

        let new_ptr = self.heap.allocate(bytes.len() as u64);
        let mut next = state.clone();
        next.write_memory(new_ptr, bytes);
        next.return_value = Some(new_ptr);
        next.set_reg(0, new_ptr);
        SimResult::Continue(next)
    }
}

// ---------------------------------------------------------------------------
// Printing & Formatting
// ---------------------------------------------------------------------------

/// `sprintf(char *str, const char *format, ...)`
pub struct SprintfProcedure;

impl SimProcedure for SprintfProcedure {
    fn name(&self) -> &'static str {
        "sprintf"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let fmt_addr = state.get_arg(1);
        let fmt = state.read_null_terminated_string(fmt_addr, 4096);

        // Minimal literal-preserving format printer: copies format bytes
        let mut out = fmt;
        out.push(0);
        let len = (out.len() - 1) as u64;

        let mut next = state.clone();
        next.write_memory(dest, out);
        next.return_value = Some(len);
        next.set_reg(0, len);
        SimResult::Continue(next)
    }
}

/// `snprintf(char *str, size_t size, const char *format, ...)`
pub struct SnprintfProcedure;

impl SimProcedure for SnprintfProcedure {
    fn name(&self) -> &'static str {
        "snprintf"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let size = state.get_arg(1) as usize;
        let fmt_addr = state.get_arg(2);
        let fmt = state.read_null_terminated_string(fmt_addr, 4096);

        let out_len = fmt.len();
        if size > 0 {
            let mut buf = fmt;
            buf.truncate(size - 1);
            buf.push(0);
            let mut next = state.clone();
            next.write_memory(dest, buf);
            next.return_value = Some(out_len as u64);
            next.set_reg(0, out_len as u64);
            SimResult::Continue(next)
        } else {
            SimResult::Return(out_len as u64)
        }
    }
}

/// `puts(const char *s)`
pub struct PutsProcedure;

impl SimProcedure for PutsProcedure {
    fn name(&self) -> &'static str {
        "puts"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `fputs(const char *s, FILE *stream)`
pub struct FputsProcedure;

impl SimProcedure for FputsProcedure {
    fn name(&self) -> &'static str {
        "fputs"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let s_addr = state.get_arg(0);
        let s = state.read_null_terminated_string(s_addr, 65536);
        SimResult::Return(s.len() as u64)
    }
}

/// `putchar(int c)`
pub struct PutcharProcedure;

impl SimProcedure for PutcharProcedure {
    fn name(&self) -> &'static str {
        "putchar"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = state.get_arg(0) & 0xff;
        SimResult::Return(c)
    }
}

// ---------------------------------------------------------------------------
// Numeric Conversion
// ---------------------------------------------------------------------------

/// `atoi(const char *nptr)`
pub struct AtoiProcedure;

impl SimProcedure for AtoiProcedure {
    fn name(&self) -> &'static str {
        "atoi"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let bytes = state.read_null_terminated_string(addr, 64);
        let s = String::from_utf8_lossy(&bytes);
        let val: i32 = s.trim().parse().unwrap_or(0);
        SimResult::Return(val as u32 as u64)
    }
}

/// `atol(const char *nptr)`
pub struct AtolProcedure;

impl SimProcedure for AtolProcedure {
    fn name(&self) -> &'static str {
        "atol"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let bytes = state.read_null_terminated_string(addr, 64);
        let s = String::from_utf8_lossy(&bytes);
        let val: i64 = s.trim().parse().unwrap_or(0);
        SimResult::Return(val as u64)
    }
}

/// `atoll(const char *nptr)`
pub struct AtollProcedure;

impl SimProcedure for AtollProcedure {
    fn name(&self) -> &'static str {
        "atoll"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let bytes = state.read_null_terminated_string(addr, 64);
        let s = String::from_utf8_lossy(&bytes);
        let val: i64 = s.trim().parse().unwrap_or(0);
        SimResult::Return(val as u64)
    }
}

/// `strtol(const char *nptr, char **endptr, int base)`
pub struct StrtolProcedure;

impl SimProcedure for StrtolProcedure {
    fn name(&self) -> &'static str {
        "strtol"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let endptr = state.get_arg(1);
        let base = state.get_arg(2) as u32;

        let bytes = state.read_null_terminated_string(addr, 64);
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim();

        let radix = if base == 0 {
            if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else if trimmed.starts_with('0') && trimmed.len() > 1 {
                8
            } else {
                10
            }
        } else {
            base
        };

        let num_str = if radix == 16 && (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
            &trimmed[2..]
        } else {
            trimmed
        };

        let val = i64::from_str_radix(num_str, radix).unwrap_or(0);

        if endptr != 0 {
            let mut next = state.clone();
            let end_addr = addr.saturating_add(bytes.len() as u64);
            next.write_memory(endptr, end_addr.to_le_bytes().to_vec());
            next.return_value = Some(val as u64);
            next.set_reg(0, val as u64);
            SimResult::Continue(next)
        } else {
            SimResult::Return(val as u64)
        }
    }
}

/// `strtoul(const char *nptr, char **endptr, int base)`
pub struct StrtoulProcedure;

impl SimProcedure for StrtoulProcedure {
    fn name(&self) -> &'static str {
        "strtoul"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let endptr = state.get_arg(1);
        let base = state.get_arg(2) as u32;

        let bytes = state.read_null_terminated_string(addr, 64);
        let s = String::from_utf8_lossy(&bytes);
        let trimmed = s.trim();

        let radix = if base == 0 {
            if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                16
            } else if trimmed.starts_with('0') && trimmed.len() > 1 {
                8
            } else {
                10
            }
        } else {
            base
        };

        let num_str = if radix == 16 && (trimmed.starts_with("0x") || trimmed.starts_with("0X")) {
            &trimmed[2..]
        } else {
            trimmed
        };

        let val = u64::from_str_radix(num_str, radix).unwrap_or(0);

        if endptr != 0 {
            let mut next = state.clone();
            let end_addr = addr.saturating_add(bytes.len() as u64);
            next.write_memory(endptr, end_addr.to_le_bytes().to_vec());
            next.return_value = Some(val);
            next.set_reg(0, val);
            SimResult::Continue(next)
        } else {
            SimResult::Return(val)
        }
    }
}

// ---------------------------------------------------------------------------
// Character Classification & Conversion
// ---------------------------------------------------------------------------

/// `toupper(int c)`
pub struct ToupperProcedure;

impl SimProcedure for ToupperProcedure {
    fn name(&self) -> &'static str {
        "toupper"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(c.to_ascii_uppercase() as u64)
    }
}

/// `tolower(int c)`
pub struct TolowerProcedure;

impl SimProcedure for TolowerProcedure {
    fn name(&self) -> &'static str {
        "tolower"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(c.to_ascii_lowercase() as u64)
    }
}

/// `isalpha(int c)`
pub struct IsalphaProcedure;

impl SimProcedure for IsalphaProcedure {
    fn name(&self) -> &'static str {
        "isalpha"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if c.is_ascii_alphabetic() { 1 } else { 0 })
    }
}

/// `isdigit(int c)`
pub struct IsdigitProcedure;

impl SimProcedure for IsdigitProcedure {
    fn name(&self) -> &'static str {
        "isdigit"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if c.is_ascii_digit() { 1 } else { 0 })
    }
}

/// `isalnum(int c)`
pub struct IsalnumProcedure;

impl SimProcedure for IsalnumProcedure {
    fn name(&self) -> &'static str {
        "isalnum"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if c.is_ascii_alphanumeric() { 1 } else { 0 })
    }
}

/// `isspace(int c)`
pub struct IsspaceProcedure;

impl SimProcedure for IsspaceProcedure {
    fn name(&self) -> &'static str {
        "isspace"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if c.is_ascii_whitespace() { 1 } else { 0 })
    }
}

/// `isprint(int c)`
pub struct IsprintProcedure;

impl SimProcedure for IsprintProcedure {
    fn name(&self) -> &'static str {
        "isprint"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if (0x20..=0x7e).contains(&c) { 1 } else { 0 })
    }
}

/// `isxdigit(int c)`
pub struct IsxdigitProcedure;

impl SimProcedure for IsxdigitProcedure {
    fn name(&self) -> &'static str {
        "isxdigit"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let c = (state.get_arg(0) & 0xff) as u8;
        SimResult::Return(if c.is_ascii_hexdigit() { 1 } else { 0 })
    }
}
