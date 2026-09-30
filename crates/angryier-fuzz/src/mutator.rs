//! Hybrid fuzzing mutators: bit/byte flips, arithmetic, boundary values, havoc operations, and dictionary injection.

use crate::rng::FastRng;

/// Endianness for multi-byte arithmetic and boundary values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

/// Boundary/interesting 8-bit integer values.
pub const INTERESTING_8: [u8; 9] = [
    0,     // 0
    1,     // 1
    0xFF,  // -1
    0x7F,  // 127 (i8::MAX)
    0x80,  // -128 (i8::MIN)
    2,     // 2
    0xFE,  // -2
    16,    // 16
    32,    // 32
];

/// Boundary/interesting 16-bit integer values.
pub const INTERESTING_16: [u16; 9] = [
    0x0000, // 0
    0x0001, // 1
    0xFFFF, // -1
    0x7FFF, // 32767 (i16::MAX)
    0x8000, // -32768 (i16::MIN)
    0x00FF, // 255
    0x0100, // 256
    0xFFFE, // -2
    0x0002, // 2
];

/// Boundary/interesting 32-bit integer values.
pub const INTERESTING_32: [u32; 10] = [
    0x0000_0000, // 0
    0x0000_0001, // 1
    0xFFFF_FFFF, // -1
    0x7FFF_FFFF, // i32::MAX
    0x8000_0000, // i32::MIN
    0x0000_FFFF, // 65535
    0xFFFF_0000,
    0x0001_0000, // 65536
    0xFFFF_FFFE, // -2
    0x0000_0002, // 2
];

/// Default maximum input length (1 MiB).
pub const DEFAULT_MAX_INPUT_SIZE: usize = 1024 * 1024;

/// Flips a single bit at the given bit index.
pub fn flip_bit(buf: &mut [u8], bit_idx: usize) -> bool {
    let byte_pos = bit_idx / 8;
    let bit_pos = bit_idx % 8;
    if let Some(byte) = buf.get_mut(byte_pos) {
        *byte ^= 1 << bit_pos;
        true
    } else {
        false
    }
}

/// Flips two adjacent bits starting at the given bit index.
pub fn flip_two_bits(buf: &mut [u8], bit_idx: usize) -> bool {
    if bit_idx + 1 >= buf.len().saturating_mul(8) {
        return false;
    }
    let _ = flip_bit(buf, bit_idx);
    let _ = flip_bit(buf, bit_idx + 1);
    true
}

/// Flips four adjacent bits (a nibble) starting at the given bit index.
pub fn flip_four_bits(buf: &mut [u8], bit_idx: usize) -> bool {
    if bit_idx + 3 >= buf.len().saturating_mul(8) {
        return false;
    }
    for i in 0..4 {
        let _ = flip_bit(buf, bit_idx + i);
    }
    true
}

/// Flips all bits in a single byte (`^= 0xFF`).
pub fn flip_byte(buf: &mut [u8], byte_idx: usize) -> bool {
    if let Some(byte) = buf.get_mut(byte_idx) {
        *byte ^= 0xFF;
        true
    } else {
        false
    }
}

/// Flips all bits in two consecutive bytes.
pub fn flip_two_bytes(buf: &mut [u8], byte_idx: usize) -> bool {
    if byte_idx + 1 >= buf.len() {
        return false;
    }
    buf[byte_idx] ^= 0xFF;
    buf[byte_idx + 1] ^= 0xFF;
    true
}

/// Flips all bits in four consecutive bytes.
pub fn flip_four_bytes(buf: &mut [u8], byte_idx: usize) -> bool {
    if byte_idx + 3 >= buf.len() {
        return false;
    }
    for i in 0..4 {
        buf[byte_idx + i] ^= 0xFF;
    }
    true
}

/// Performs wrapping arithmetic addition/subtraction on an 8-bit integer.
pub fn arith_u8(buf: &mut [u8], byte_idx: usize, delta: i8) -> bool {
    if let Some(byte) = buf.get_mut(byte_idx) {
        *byte = (*byte as i8).wrapping_add(delta) as u8;
        true
    } else {
        false
    }
}

/// Performs wrapping arithmetic addition/subtraction on a 16-bit integer with endianness handling.
pub fn arith_u16(buf: &mut [u8], byte_idx: usize, delta: i16, endianness: Endianness) -> bool {
    if byte_idx + 1 >= buf.len() {
        return false;
    }
    let b0 = buf[byte_idx];
    let b1 = buf[byte_idx + 1];
    let val = match endianness {
        Endianness::Little => u16::from_le_bytes([b0, b1]),
        Endianness::Big => u16::from_be_bytes([b0, b1]),
    };
    let new_val = (val as i16).wrapping_add(delta) as u16;
    let out = match endianness {
        Endianness::Little => new_val.to_le_bytes(),
        Endianness::Big => new_val.to_be_bytes(),
    };
    buf[byte_idx] = out[0];
    buf[byte_idx + 1] = out[1];
    true
}

/// Performs wrapping arithmetic addition/subtraction on a 32-bit integer with endianness handling.
pub fn arith_u32(buf: &mut [u8], byte_idx: usize, delta: i32, endianness: Endianness) -> bool {
    if byte_idx + 3 >= buf.len() {
        return false;
    }
    let b0 = buf[byte_idx];
    let b1 = buf[byte_idx + 1];
    let b2 = buf[byte_idx + 2];
    let b3 = buf[byte_idx + 3];
    let val = match endianness {
        Endianness::Little => u32::from_le_bytes([b0, b1, b2, b3]),
        Endianness::Big => u32::from_be_bytes([b0, b1, b2, b3]),
    };
    let new_val = (val as i32).wrapping_add(delta) as u32;
    let out = match endianness {
        Endianness::Little => new_val.to_le_bytes(),
        Endianness::Big => new_val.to_be_bytes(),
    };
    buf[byte_idx..byte_idx + 4].copy_from_slice(&out);
    true
}

/// Replaces a byte with an 8-bit interesting boundary value.
pub fn insert_interest_u8(buf: &mut [u8], byte_idx: usize, val: u8) -> bool {
    if let Some(slot) = buf.get_mut(byte_idx) {
        *slot = val;
        true
    } else {
        false
    }
}

/// Replaces 2 bytes with a 16-bit interesting boundary value using the given endianness.
pub fn insert_interest_u16(buf: &mut [u8], byte_idx: usize, val: u16, endianness: Endianness) -> bool {
    if byte_idx + 1 >= buf.len() {
        return false;
    }
    let out = match endianness {
        Endianness::Little => val.to_le_bytes(),
        Endianness::Big => val.to_be_bytes(),
    };
    buf[byte_idx] = out[0];
    buf[byte_idx + 1] = out[1];
    true
}

/// Replaces 4 bytes with a 32-bit interesting boundary value using the given endianness.
pub fn insert_interest_u32(buf: &mut [u8], byte_idx: usize, val: u32, endianness: Endianness) -> bool {
    if byte_idx + 3 >= buf.len() {
        return false;
    }
    let out = match endianness {
        Endianness::Little => val.to_le_bytes(),
        Endianness::Big => val.to_be_bytes(),
    };
    buf[byte_idx..byte_idx + 4].copy_from_slice(&out);
    true
}

/// Inserts a slice of bytes into `buf` at `offset`.
pub fn block_insert(buf: &mut Vec<u8>, offset: usize, bytes_to_insert: &[u8]) {
    if bytes_to_insert.is_empty() {
        return;
    }
    let offset = offset.min(buf.len());
    buf.splice(offset..offset, bytes_to_insert.iter().copied());
}

/// Deletes up to `count` bytes from `buf` at `offset`, preserving at least 1 byte in `buf`.
pub fn block_delete(buf: &mut Vec<u8>, offset: usize, count: usize) -> bool {
    if buf.len() <= 1 || count == 0 || offset >= buf.len() {
        return false;
    }
    let max_deletable = buf.len() - 1;
    let actual_count = count.min(max_deletable);
    let end = (offset + actual_count).min(buf.len());
    if end > offset && (buf.len() - (end - offset)) >= 1 {
        buf.drain(offset..end);
        true
    } else {
        false
    }
}

/// Overwrites a slice of `buf` at `offset` with `replacement` bytes.
pub fn block_replace(buf: &mut [u8], offset: usize, replacement: &[u8]) -> usize {
    if offset >= buf.len() || replacement.is_empty() {
        return 0;
    }
    let available = buf.len() - offset;
    let to_copy = available.min(replacement.len());
    buf[offset..offset + to_copy].copy_from_slice(&replacement[..to_copy]);
    to_copy
}

/// Splices two seeds together at pseudo-random split points.
pub fn splice(seed_a: &[u8], seed_b: &[u8], rng: &mut FastRng) -> Vec<u8> {
    if seed_a.is_empty() && seed_b.is_empty() {
        return vec![0];
    }
    if seed_a.is_empty() {
        return seed_b.to_vec();
    }
    if seed_b.is_empty() {
        return seed_a.to_vec();
    }

    let split_a = rng.gen_range(0, seed_a.len());
    let split_b = rng.gen_range(0, seed_b.len());

    let mut result = Vec::with_capacity(split_a + (seed_b.len() - split_b));
    result.extend_from_slice(&seed_a[..split_a]);
    result.extend_from_slice(&seed_b[split_b..]);

    if result.is_empty() {
        result.push(seed_a[0]);
    }
    result
}

/// Injects a dictionary token by inserting it into `buf` at `offset`.
pub fn inject_token_insert(buf: &mut Vec<u8>, offset: usize, token: &[u8]) {
    block_insert(buf, offset, token);
}

/// Injects a dictionary token by overwriting `buf` at `offset`.
pub fn inject_token_overwrite(buf: &mut [u8], offset: usize, token: &[u8]) -> usize {
    block_replace(buf, offset, token)
}

/// Configurable hybrid fuzzing mutator.
#[derive(Clone, Debug)]
pub struct Mutator {
    pub rng: FastRng,
    pub dictionary: Vec<Vec<u8>>,
    pub max_input_size: usize,
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator {
    pub fn new() -> Self {
        Self {
            rng: FastRng::default(),
            dictionary: Vec::new(),
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
        }
    }

    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: FastRng::new(seed),
            dictionary: Vec::new(),
            max_input_size: DEFAULT_MAX_INPUT_SIZE,
        }
    }

    pub fn add_token(&mut self, token: Vec<u8>) {
        if !token.is_empty() && !self.dictionary.contains(&token) {
            self.dictionary.push(token);
        }
    }

    pub fn set_dictionary(&mut self, tokens: Vec<Vec<u8>>) {
        self.dictionary = tokens.into_iter().filter(|t| !t.is_empty()).collect();
    }

    pub fn dictionary(&self) -> &[Vec<u8>] {
        &self.dictionary
    }

    pub fn set_max_input_size(&mut self, size: usize) {
        self.max_input_size = size.max(1);
    }

    /// Randomly picks an endianness.
    fn random_endianness(&mut self) -> Endianness {
        if self.rng.gen_bool() {
            Endianness::Little
        } else {
            Endianness::Big
        }
    }

    /// Applies a single random mutation operation on `buf`.
    pub fn apply_random_mutation(&mut self, buf: &mut Vec<u8>, secondary: Option<&[u8]>) -> bool {
        if buf.is_empty() {
            buf.push(0);
            return true;
        }

        let num_strategies = if self.dictionary.is_empty() { 8 } else { 9 };
        let strategy = self.rng.gen_range(0, num_strategies);

        match strategy {
            0 => {
                // Bit flips (1, 2, or 4 bits)
                let sub = self.rng.gen_range(0, 3);
                let bit_len = buf.len().saturating_mul(8);
                if bit_len == 0 {
                    return false;
                }
                match sub {
                    0 => {
                        let bit = self.rng.gen_range(0, bit_len);
                        flip_bit(buf, bit)
                    }
                    1 => {
                        if bit_len < 2 {
                            flip_bit(buf, 0)
                        } else {
                            let bit = self.rng.gen_range(0, bit_len - 1);
                            flip_two_bits(buf, bit)
                        }
                    }
                    _ => {
                        if bit_len < 4 {
                            flip_bit(buf, 0)
                        } else {
                            let bit = self.rng.gen_range(0, bit_len - 3);
                            flip_four_bits(buf, bit)
                        }
                    }
                }
            }
            1 => {
                // Byte flips (1, 2, or 4 bytes)
                let sub = self.rng.gen_range(0, 3);
                match sub {
                    0 => {
                        let idx = self.rng.gen_range(0, buf.len());
                        flip_byte(buf, idx)
                    }
                    1 => {
                        if buf.len() < 2 {
                            flip_byte(buf, 0)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 1);
                            flip_two_bytes(buf, idx)
                        }
                    }
                    _ => {
                        if buf.len() < 4 {
                            flip_byte(buf, 0)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 3);
                            flip_four_bytes(buf, idx)
                        }
                    }
                }
            }
            2 => {
                // Arithmetic increments / decrements
                let width = self.rng.gen_range(0, 3);
                let endian = self.random_endianness();
                let delta = match self.rng.gen_range(0, 2) {
                    0 => 1 + (self.rng.next_u64() % 35) as i32,
                    _ => -((1 + (self.rng.next_u64() % 35)) as i32),
                };
                match width {
                    0 => {
                        let idx = self.rng.gen_range(0, buf.len());
                        arith_u8(buf, idx, delta as i8)
                    }
                    1 => {
                        if buf.len() < 2 {
                            let idx = self.rng.gen_range(0, buf.len());
                            arith_u8(buf, idx, delta as i8)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 1);
                            arith_u16(buf, idx, delta as i16, endian)
                        }
                    }
                    _ => {
                        if buf.len() < 4 {
                            let idx = self.rng.gen_range(0, buf.len());
                            arith_u8(buf, idx, delta as i8)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 3);
                            arith_u32(buf, idx, delta, endian)
                        }
                    }
                }
            }
            3 => {
                // Boundary interest values
                let width = self.rng.gen_range(0, 3);
                let endian = self.random_endianness();
                match width {
                    0 => {
                        let val = *self.rng.choose(&INTERESTING_8).unwrap_or(&0);
                        let idx = self.rng.gen_range(0, buf.len());
                        insert_interest_u8(buf, idx, val)
                    }
                    1 => {
                        let val = *self.rng.choose(&INTERESTING_16).unwrap_or(&0);
                        if buf.len() < 2 {
                            insert_interest_u8(buf, 0, val as u8)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 1);
                            insert_interest_u16(buf, idx, val, endian)
                        }
                    }
                    _ => {
                        let val = *self.rng.choose(&INTERESTING_32).unwrap_or(&0);
                        if buf.len() < 4 {
                            insert_interest_u8(buf, 0, val as u8)
                        } else {
                            let idx = self.rng.gen_range(0, buf.len() - 3);
                            insert_interest_u32(buf, idx, val, endian)
                        }
                    }
                }
            }
            4 => {
                // Block deletion (preserve at least 1 byte)
                if buf.len() > 1 {
                    let del_len = self.rng.gen_range(1, buf.len().min(32));
                    let offset = self.rng.gen_range(0, buf.len());
                    block_delete(buf, offset, del_len)
                } else {
                    false
                }
            }
            5 => {
                // Block insertion (random bytes or sub-slice duplicate)
                if buf.len() < self.max_input_size {
                    let ins_len = self.rng.gen_range(1, 17).min(self.max_input_size - buf.len());
                    let offset = self.rng.gen_range(0, buf.len() + 1);
                    if self.rng.gen_bool() && !buf.is_empty() {
                        // Clone an existing slice
                        let src_offset = self.rng.gen_range(0, buf.len());
                        let src_len = ins_len.min(buf.len() - src_offset);
                        let chunk = buf[src_offset..src_offset + src_len].to_vec();
                        block_insert(buf, offset, &chunk);
                    } else {
                        // Insert random bytes
                        let mut chunk = Vec::with_capacity(ins_len);
                        for _ in 0..ins_len {
                            chunk.push(self.rng.next_u8());
                        }
                        block_insert(buf, offset, &chunk);
                    }
                    true
                } else {
                    false
                }
            }
            6 => {
                // Block replacement
                let repl_len = self.rng.gen_range(1, buf.len().min(16) + 1);
                let offset = self.rng.gen_range(0, buf.len());
                let mut chunk = Vec::with_capacity(repl_len);
                for _ in 0..repl_len {
                    chunk.push(self.rng.next_u8());
                }
                block_replace(buf, offset, &chunk) > 0
            }
            7 => {
                // Splicing with secondary seed if available
                if let Some(sec) = secondary.filter(|s| !s.is_empty()) {
                    let spliced = splice(buf, sec, &mut self.rng);
                    if !spliced.is_empty() && spliced.len() <= self.max_input_size {
                        *buf = spliced;
                        return true;
                    }
                }
                // Fallback: byte flip
                let idx = self.rng.gen_range(0, buf.len());
                flip_byte(buf, idx)
            }
            _ => {
                // Dictionary token injection
                if !self.dictionary.is_empty() {
                    let token_idx = self.rng.gen_range(0, self.dictionary.len());
                    let token = match self.dictionary.get(token_idx) {
                        Some(t) => t.clone(),
                        None => return false,
                    };
                    if self.rng.gen_bool() && buf.len() + token.len() <= self.max_input_size {
                        let offset = self.rng.gen_range(0, buf.len() + 1);
                        inject_token_insert(buf, offset, &token);
                        true
                    } else {
                        let offset = self.rng.gen_range(0, buf.len());
                        inject_token_overwrite(buf, offset, &token) > 0
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Mutates the input seed, producing a new non-empty byte vector.
    pub fn mutate(&mut self, input: &[u8], secondary: Option<&[u8]>) -> Vec<u8> {
        let mut buf = if input.is_empty() {
            vec![0]
        } else {
            input.to_vec()
        };

        // Try up to 5 times to produce an altered input
        for _ in 0..5 {
            if self.apply_random_mutation(&mut buf, secondary) && buf != input && !buf.is_empty() {
                break;
            }
        }

        if buf.is_empty() {
            buf.push(0);
        }
        buf
    }

    /// Havoc stage: applies a sequence of multiple random mutations in place.
    pub fn havoc_mutate(&mut self, input: &[u8], secondary: Option<&[u8]>, steps: usize) -> Vec<u8> {
        let mut buf = if input.is_empty() {
            vec![0]
        } else {
            input.to_vec()
        };

        let count = steps.max(1);
        for _ in 0..count {
            let _ = self.apply_random_mutation(&mut buf, secondary);
        }

        if buf.is_empty() {
            buf.push(0);
        }
        buf
    }

    /// Generates a set of deterministic mutations:
    /// - all single-bit flips
    /// - all two-bit flips
    /// - all four-bit flips
    /// - all byte flips
    /// - arithmetic (+1, -1) on all bytes
    /// - boundary values at start of buffer
    pub fn deterministic_mutations(&self, input: &[u8]) -> Vec<Vec<u8>> {
        if input.is_empty() {
            return vec![vec![0]];
        }

        let mut out = Vec::new();
        let bit_count = input.len().saturating_mul(8);

        // 1. Bit flips (1-bit)
        for bit in 0..bit_count {
            let mut clone = input.to_vec();
            if flip_bit(&mut clone, bit) {
                out.push(clone);
            }
        }

        // 2. Bit flips (2-bit)
        if bit_count >= 2 {
            for bit in 0..bit_count - 1 {
                let mut clone = input.to_vec();
                if flip_two_bits(&mut clone, bit) {
                    out.push(clone);
                }
            }
        }

        // 3. Bit flips (4-bit)
        if bit_count >= 4 {
            for bit in 0..bit_count - 3 {
                let mut clone = input.to_vec();
                if flip_four_bits(&mut clone, bit) {
                    out.push(clone);
                }
            }
        }

        // 4. Byte flips (1-byte)
        for byte_idx in 0..input.len() {
            let mut clone = input.to_vec();
            if flip_byte(&mut clone, byte_idx) {
                out.push(clone);
            }
        }

        // 5. Arithmetic (+1, -1) on every byte
        for byte_idx in 0..input.len() {
            for &delta in &[1i8, -1i8] {
                let mut clone = input.to_vec();
                if arith_u8(&mut clone, byte_idx, delta) {
                    out.push(clone);
                }
            }
        }

        // 6. Boundary values at offset 0
        for &val8 in &INTERESTING_8 {
            let mut clone = input.to_vec();
            if insert_interest_u8(&mut clone, 0, val8) {
                out.push(clone);
            }
        }
        if input.len() >= 2 {
            for &val16 in &INTERESTING_16 {
                for endian in [Endianness::Little, Endianness::Big] {
                    let mut clone = input.to_vec();
                    if insert_interest_u16(&mut clone, 0, val16, endian) {
                        out.push(clone);
                    }
                }
            }
        }
        if input.len() >= 4 {
            for &val32 in &INTERESTING_32 {
                for endian in [Endianness::Little, Endianness::Big] {
                    let mut clone = input.to_vec();
                    if insert_interest_u32(&mut clone, 0, val32, endian) {
                        out.push(clone);
                    }
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitflip_mutations_work() {
        let mut buf = vec![0b0000_0000];
        assert!(flip_bit(&mut buf, 0));
        assert_eq!(buf[0], 0b0000_0001);

        assert!(flip_two_bits(&mut buf, 1));
        assert_eq!(buf[0], 0b0000_0111);

        assert!(flip_four_bits(&mut buf, 3));
        assert_eq!(buf[0], 0b0111_1111);

        assert!(!flip_bit(&mut buf, 8));
        assert!(!flip_two_bits(&mut buf, 7));
        assert!(!flip_four_bits(&mut buf, 5));
    }

    #[test]
    fn byteflip_mutations_work() {
        let mut buf = vec![0x00, 0x11, 0x22, 0x33];
        assert!(flip_byte(&mut buf, 0));
        assert_eq!(buf[0], 0xFF);

        assert!(flip_two_bytes(&mut buf, 1));
        assert_eq!(buf[1], 0xEE);
        assert_eq!(buf[2], 0xDD);

        assert!(flip_four_bytes(&mut buf, 0));
        assert_eq!(buf, vec![0x00, 0x11, 0x22, 0xCC]);

        assert!(!flip_two_bytes(&mut buf, 3));
        assert!(!flip_four_bytes(&mut buf, 1));
    }

    #[test]
    fn arithmetic_increments_and_decrements_work() {
        let mut buf = vec![10, 0, 0, 0];
        assert!(arith_u8(&mut buf, 0, 5));
        assert_eq!(buf[0], 15);
        assert!(arith_u8(&mut buf, 0, -20));
        assert_eq!(buf[0], 251); // 15 - 20 = -5 => 251

        let mut buf16 = vec![0x01, 0x00]; // 1 LE
        assert!(arith_u16(&mut buf16, 0, 1, Endianness::Little));
        assert_eq!(buf16, vec![0x02, 0x00]);
        assert!(arith_u16(&mut buf16, 0, -3, Endianness::Little));
        assert_eq!(buf16, vec![0xFF, 0xFF]); // 2 - 3 = -1 => 0xFFFF

        let mut buf16_be = vec![0x00, 0x01]; // 1 BE
        assert!(arith_u16(&mut buf16_be, 0, 1, Endianness::Big));
        assert_eq!(buf16_be, vec![0x00, 0x02]);

        let mut buf32 = vec![0x05, 0x00, 0x00, 0x00];
        assert!(arith_u32(&mut buf32, 0, 10, Endianness::Little));
        assert_eq!(buf32, vec![0x0F, 0x00, 0x00, 0x00]);
        assert!(arith_u32(&mut buf32, 0, 10, Endianness::Big));
        assert_eq!(buf32, vec![0x0F, 0x00, 0x00, 0x0A]);
    }

    #[test]
    fn boundary_interest_values_work() {
        let mut buf = vec![0x12, 0x34, 0x56, 0x78];
        assert!(insert_interest_u8(&mut buf, 0, 0x7F));
        assert_eq!(buf[0], 0x7F);

        assert!(insert_interest_u16(&mut buf, 1, 0x8000, Endianness::Little));
        assert_eq!(buf[1..3], [0x00, 0x80]);

        assert!(insert_interest_u32(&mut buf, 0, 0x7FFF_FFFF, Endianness::Big));
        assert_eq!(buf, [0x7F, 0xFF, 0xFF, 0xFF]);

        assert!(!insert_interest_u32(&mut buf, 1, 0, Endianness::Little));
    }

    #[test]
    fn havoc_block_operations_work() {
        let mut buf = vec![1, 2, 3, 4];
        block_insert(&mut buf, 2, &[99, 100]);
        assert_eq!(buf, vec![1, 2, 99, 100, 3, 4]);

        assert!(block_delete(&mut buf, 2, 2));
        assert_eq!(buf, vec![1, 2, 3, 4]);

        let mut single = vec![42];
        assert!(!block_delete(&mut single, 0, 1)); // Cannot delete single byte
        assert_eq!(single, vec![42]);

        let replaced = block_replace(&mut buf, 1, &[88, 89]);
        assert_eq!(replaced, 2);
        assert_eq!(buf, vec![1, 88, 89, 4]);
    }

    #[test]
    fn splicing_produces_non_empty_combination() {
        let mut rng = FastRng::new(42);
        let a = b"HELLO";
        let b = b"WORLD";
        let spliced = splice(a, b, &mut rng);
        assert!(!spliced.is_empty());
    }

    #[test]
    fn dictionary_token_injection_works() {
        let mut buf = vec![1, 2, 3, 4];
        let token = b"TOKEN";
        inject_token_insert(&mut buf, 1, token);
        assert_eq!(buf, vec![1, b'T', b'O', b'K', b'E', b'N', 2, 3, 4]);

        let overwritten = inject_token_overwrite(&mut buf, 0, b"ABC");
        assert_eq!(overwritten, 3);
        assert_eq!(&buf[0..3], b"ABC");
    }

    #[test]
    fn mutator_mutate_changes_input() {
        let mut mutator = Mutator::with_seed(12345);
        mutator.add_token(b"MAGIC".to_vec());
        let original = b"sample fuzz seed";
        let mutated = mutator.mutate(original, Some(b"secondary input"));
        assert!(!mutated.is_empty());
        assert_ne!(mutated, original);
    }

    #[test]
    fn havoc_mutate_applies_multiple_steps() {
        let mut mutator = Mutator::with_seed(999);
        let original = b"fuzz test input payload";
        let mutated = mutator.havoc_mutate(original, None, 10);
        assert!(!mutated.is_empty());
        assert_ne!(mutated, original);
    }

    #[test]
    fn deterministic_mutations_non_empty() {
        let mutator = Mutator::new();
        let input = b"ab";
        let results = mutator.deterministic_mutations(input);
        assert!(!results.is_empty());
        for res in results {
            assert!(!res.is_empty());
        }
    }
}
