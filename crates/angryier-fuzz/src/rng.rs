//! Fast, deterministic pseudo-random number generator.
//!
//! Implements SplitMix64 to provide high-quality pseudo-randomness with zero
//! dependencies and strict determinism for reproducible fuzz sessions.

#[derive(Clone, Debug)]
pub struct FastRng {
    state: u64,
}

impl Default for FastRng {
    fn default() -> Self {
        Self::new(0x9E37_79B9_7F4A_7C15)
    }
}

impl FastRng {
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    #[inline]
    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    #[inline]
    pub fn next_usize(&mut self) -> usize {
        self.next_u64() as usize
    }

    #[inline]
    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        let range = (max - min) as u64;
        min + (self.next_u64() % range) as usize
    }

    #[inline]
    pub fn gen_bool(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }

    #[inline]
    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> Option<&'a T> {
        if slice.is_empty() {
            None
        } else {
            let idx = (self.next_u64() as usize) % slice.len();
            slice.get(idx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence_matches() {
        let mut rng1 = FastRng::new(42);
        let mut rng2 = FastRng::new(42);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn zero_seed_defaults_gracefully() {
        let mut rng = FastRng::new(0);
        assert_ne!(rng.next_u64(), 0);
    }

    #[test]
    fn gen_range_within_bounds() {
        let mut rng = FastRng::new(12345);
        for _ in 0..1000 {
            let val = rng.gen_range(5, 15);
            assert!((5..15).contains(&val));
        }
    }

    #[test]
    fn gen_range_empty_or_inverted() {
        let mut rng = FastRng::new(123);
        assert_eq!(rng.gen_range(10, 10), 10);
        assert_eq!(rng.gen_range(10, 5), 10);
    }

    #[test]
    fn choose_selects_elements() {
        let mut rng = FastRng::new(999);
        let items = [10, 20, 30];
        let chosen = rng.choose(&items);
        assert!(chosen.is_some_and(|&v| items.contains(&v)));
        assert_eq!(rng.choose::<i32>(&[]), None);
    }
}
