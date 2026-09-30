//! Prefetch-and-decode speculation pipeline.
//!
//! `SpeculativeDecodePipeline` pre-decodes instructions along the statically
//! predicted next path while the current basic block executes. On a hit the
//! pre-decoded `DecodedInstruction` is served from the ring buffer without
//! touching the decoder; on a misprediction (the actual target diverges from
//! the predicted one) the buffer is flushed and the decoder is invoked for the
//! real target.
//!
//! # Predictor bias
//! The predictor uses CFG static successor edges: a `FallThrough` edge is
//! preferred when present (sequential bias), followed by the first non-return
//! static edge. Indirect jumps and returns have no static successor and stop
//! speculation at that block.
//!
//! # Bounded cache
//! The ring buffer is bounded at `RING_CAPACITY` slots. New entries evict the
//! oldest ones when the buffer is full (LRU-by-insertion).
//!
//! # Metrics
//! All counters are plain `u64` fields — no atomics are needed because the
//! pipeline is used by a single execution context.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_cfg::{Cfg, EdgeKind};
use angryier_types::Address;

/// Maximum number of pre-decoded instructions the ring buffer holds.
pub const RING_CAPACITY: usize = 256;

/// A single slot in the speculative ring buffer.
#[derive(Clone, Debug)]
pub struct RingSlot {
    /// The PC this instruction was decoded from.
    pub pc: Address,
    /// The decoded instruction itself.
    pub insn: DecodedInstruction,
}

/// A speculative decode pipeline backed by a bounded ring buffer and a
/// fall-through-biased CFG predictor.
///
/// # Usage
/// ```rust,ignore
/// let mut pipeline = SpeculativeDecodePipeline::new();
/// // warm the pipeline ahead of time
/// pipeline.prefetch_ahead(current_pc, &cfg, &decoder, &code, region_base, 8);
/// // fast path — returns the pre-decoded instruction on a hit
/// let insn = pipeline.poll_or_decode(current_pc, &decoder, bytes)?;
/// ```
#[derive(Debug, Default)]
pub struct SpeculativeDecodePipeline {
    /// Ring buffer keyed by PC -> slot index for fast look-up.
    index: BTreeMap<Address, usize>,
    /// Insertion-ordered queue for bounded capacity eviction (oldest first).
    ring: VecDeque<RingSlot>,

    // ── Metrics ─────────────────────────────────────────────────────────────
    /// Total calls to `poll_or_decode`.
    pub pipeline_queries: u64,
    /// Calls that found the instruction already in the ring buffer.
    pub pipeline_hits: u64,
    /// Calls that flushed the pipeline because the actual PC diverged from
    /// the predicted path.
    pub pipeline_flushes: u64,
    /// Running sum of `depth` values passed to `prefetch_ahead`, used to
    /// compute [`prefetch_depth_avg`](Self::prefetch_depth_avg).
    prefetch_depth_sum: u64,
    /// Number of `prefetch_ahead` calls made so far.
    prefetch_depth_count: u64,

    /// Last PC and instruction length queried through `poll_or_decode`.
    /// Used to distinguish sequential straight-line execution from branch mispredictions.
    last_exec: Option<(Address, u8)>,
}

impl SpeculativeDecodePipeline {
    /// Creates an empty pipeline with all metrics zeroed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of instructions currently in the pipeline ring buffer.
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Returns `true` if the pipeline ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Pre-decodes up to `depth` instructions along the CFG-predicted path
    /// starting from `current_pc`.
    ///
    /// Instructions that are already in the ring buffer are skipped (no
    /// re-decode). Instructions that cannot be decoded stop speculation at
    /// that point without returning an error.
    ///
    /// The predictor prefers intra-block straight-line instructions; at block
    /// terminators it prefers fall-through edges, followed by the first static
    /// non-return successor edge. Blocks with only indirect or return edges end
    /// speculation early.
    pub fn prefetch_ahead<D>(
        &mut self,
        current_pc: Address,
        cfg: &Cfg,
        decoder: &D,
        region: &[u8],
        region_base: Address,
        depth: usize,
    ) where
        D: Decoder,
    {
        self.prefetch_depth_sum = self.prefetch_depth_sum.saturating_add(depth as u64);
        self.prefetch_depth_count = self.prefetch_depth_count.saturating_add(1);

        let mut pc = current_pc;
        let mut remaining = depth;

        while remaining > 0 {
            // Skip PCs already cached in the ring buffer.
            if self.index.contains_key(&pc) {
                match self.next_predicted_pc(pc, cfg) {
                    Some(next) => {
                        pc = next;
                        remaining = remaining.saturating_sub(1);
                        continue;
                    }
                    None => break,
                }
            }

            // Decode from the memory region slice, falling back to CFG instruction if available.
            let insn = match region_slice(region, region_base, pc) {
                Some(bytes) => match decoder.decode(pc, bytes) {
                    Ok(insn) => insn,
                    Err(_) => {
                        if let Some(insn) = cfg
                            .blocks
                            .values()
                            .find_map(|b| b.instructions.iter().find(|i| i.address == pc).cloned())
                        {
                            insn
                        } else {
                            break;
                        }
                    }
                },
                None => {
                    if let Some(insn) = cfg
                        .blocks
                        .values()
                        .find_map(|b| b.instructions.iter().find(|i| i.address == pc).cloned())
                    {
                        insn
                    } else {
                        break;
                    }
                }
            };

            self.insert(pc, insn);

            match self.next_predicted_pc(pc, cfg) {
                Some(next) => pc = next,
                None => break,
            }
            remaining = remaining.saturating_sub(1);
        }
    }

    /// Pre-decodes up to `depth` instructions using pre-recovered CFG blocks,
    /// without requiring an explicit raw memory region slice.
    pub fn prefetch_ahead_from_cfg<D>(
        &mut self,
        current_pc: Address,
        cfg: &Cfg,
        decoder: &D,
        depth: usize,
    ) where
        D: Decoder,
    {
        self.prefetch_ahead(current_pc, cfg, decoder, &[], 0, depth);
    }

    /// Returns the pre-decoded instruction for `pc` when it is in the ring
    /// buffer (a *hit*), otherwise falls back to `decoder` (a *miss*).
    ///
    /// When execution diverged from the predicted path (a non-sequential branch
    /// to an uncached target while speculative instructions were buffered), the
    /// pipeline is flushed first (a *misprediction flush*). On a miss the freshly
    /// decoded instruction is also inserted into the ring buffer.
    ///
    /// Returns `Err(e)` only when the decoder itself fails on a miss.
    pub fn poll_or_decode<D>(
        &mut self,
        pc: Address,
        decoder: &D,
        bytes: &[u8],
    ) -> Result<DecodedInstruction, D::Error>
    where
        D: Decoder,
    {
        self.pipeline_queries = self.pipeline_queries.saturating_add(1);

        // Fast path: ring-buffer hit.
        if self.index.contains_key(&pc) {
            if let Some(slot) = self.ring.iter().find(|s| s.pc == pc).map(|s| s.insn.clone()) {
                self.pipeline_hits = self.pipeline_hits.saturating_add(1);
                self.last_exec = Some((pc, slot.length));
                return Ok(slot);
            }
            self.index.remove(&pc);
        }

        // Cache miss: check whether this is a branch misprediction.
        // Sequential straight-line execution (e.g. pc == last_pc + last_len) or
        // cold startup with an empty ring buffer is not a misprediction.
        // A divergence from the predicted path while buffered speculative instructions
        // exist triggers a pipeline flush.
        let is_sequential = match self.last_exec {
            Some((last_pc, last_len)) => pc == last_pc.wrapping_add(u64::from(last_len)),
            None => false,
        };

        if !self.ring.is_empty() && !is_sequential {
            self.flush();
            self.pipeline_flushes = self.pipeline_flushes.saturating_add(1);
        }

        // Slow path: decoder miss.
        let insn = decoder.decode(pc, bytes)?;
        self.insert(pc, insn.clone());
        self.last_exec = Some((pc, insn.length));
        Ok(insn)
    }

    /// Average `depth` argument passed across all `prefetch_ahead` calls, or
    /// `0.0` when no calls have been made yet.
    pub fn prefetch_depth_avg(&self) -> f64 {
        if self.prefetch_depth_count == 0 {
            0.0
        } else {
            self.prefetch_depth_sum as f64 / self.prefetch_depth_count as f64
        }
    }

    /// Flushes (clears) the ring buffer, the index, and execution tracking state.
    pub fn flush(&mut self) {
        self.ring.clear();
        self.index.clear();
        self.last_exec = None;
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Inserts `(pc, insn)` into the ring buffer, evicting the oldest entry
    /// when [`RING_CAPACITY`] is reached.
    fn insert(&mut self, pc: Address, insn: DecodedInstruction) {
        if self.index.contains_key(&pc) {
            if let Some(pos) = self.ring.iter().position(|s| s.pc == pc) {
                self.ring.remove(pos);
            }
        } else if self.ring.len() >= RING_CAPACITY
            && let Some(evicted) = self.ring.pop_front()
        {
            self.index.remove(&evicted.pc);
        }
        let idx = self.ring.len();
        self.ring.push_back(RingSlot { pc, insn });
        self.index.insert(pc, idx);
        self.rebuild_index();
    }

    /// Rebuilds `self.index` from `self.ring` after structural changes.
    fn rebuild_index(&mut self) {
        self.index.clear();
        for (i, slot) in self.ring.iter().enumerate() {
            self.index.insert(slot.pc, i);
        }
    }

    /// Selects the next PC along the predicted path from `pc` using CFG edges.
    ///
    /// Intra-block: steps to the next instruction within the basic block.
    /// Inter-block: priority is FallThrough edge > first static non-return edge > None.
    fn next_predicted_pc(&self, pc: Address, cfg: &Cfg) -> Option<Address> {
        let block = cfg
            .blocks
            .values()
            .find(|b| b.instructions.iter().any(|i| i.address == pc))?;

        let last_insn_addr = block.instructions.last()?.address;

        // Intra-block: if pc is not the terminator, advance straight-line within block.
        if pc != last_insn_addr
            && let Some(pos) = block.instructions.iter().position(|i| i.address == pc)
            && let Some(next_insn) = block.instructions.get(pos + 1)
        {
            return Some(next_insn.address);
        }

        // Inter-block: terminator reached. Search CFG successor edges.
        let mut fall_through: Option<Address> = None;
        let mut other: Option<Address> = None;

        for edge in &cfg.edges {
            if edge.from != last_insn_addr {
                continue;
            }
            match (edge.kind, edge.to) {
                (EdgeKind::FallThrough, Some(target)) => {
                    fall_through = Some(target);
                }
                (EdgeKind::Return | EdgeKind::IndirectJump | EdgeKind::IndirectCall, _) => {
                    // Non-predictable — graph exit.
                }
                (_, Some(target)) if other.is_none() => {
                    other = Some(target);
                }
                _ => {}
            }
        }

        fall_through.or(other)
    }
}

/// Returns the byte slice starting at `pc` within `region` mapped at
/// `region_base`, or `None` when `pc` is outside the region.
fn region_slice(region: &[u8], region_base: Address, pc: Address) -> Option<&[u8]> {
    let offset = pc.checked_sub(region_base).and_then(|o| usize::try_from(o).ok())?;
    region.get(offset..)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, InstructionModifiers, Operand, OperandKind, OperandVisibility, RelativeBranchOperand,
    };
    use angryier_cfg::{BasicBlock, CfgEdge};
    use angryier_semantics_intel64::forms;

    // ── Minimal test decoder ─────────────────────────────────────────────────

    /// A tiny decoder that understands `nop` (0x90), `ret` (0xC3), and `jnz` (0x75).
    #[derive(Debug)]
    struct MinimalDecoder;

    impl Decoder for MinimalDecoder {
        type Error = String;

        fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, String> {
            match bytes.first().copied() {
                Some(0x90) => Ok(DecodedInstruction {
                    address,
                    length: 1,
                    form_id: forms::NOP,
                    features: Vec::new(),
                    operands: Vec::new(),
                    modifiers: InstructionModifiers::default(),
                }),
                Some(0xC3) => Ok(DecodedInstruction {
                    address,
                    length: 1,
                    form_id: forms::RET,
                    features: Vec::new(),
                    operands: Vec::new(),
                    modifiers: InstructionModifiers::default(),
                }),
                Some(0x75) => {
                    let disp = bytes.get(1).copied().map(|b| i64::from(b as i8)).unwrap_or(0);
                    Ok(DecodedInstruction {
                        address,
                        length: 2,
                        form_id: forms::JNZ_REL32,
                        features: Vec::new(),
                        operands: vec![Operand {
                            index: 0,
                            width_bits: 32,
                            access: AccessKind::Read,
                            visibility: OperandVisibility::Explicit,
                            kind: OperandKind::RelativeBranch(RelativeBranchOperand {
                                displacement: disp,
                                displacement_width_bits: 8,
                            }),
                        }],
                        modifiers: InstructionModifiers::default(),
                    })
                }
                _ => Err(format!("unknown opcode at {address:#x}")),
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn linear_cfg(base: Address, n_nops: usize) -> (Cfg, Vec<u8>) {
        let mut code = vec![0x90u8; n_nops];
        code.push(0xC3);

        let decoder = MinimalDecoder;
        let mut insns = Vec::new();
        let mut cursor = base;
        for &byte in &code {
            let decoded = decoder.decode(cursor, &[byte]).unwrap();
            cursor = cursor.wrapping_add(u64::from(decoded.length));
            insns.push(decoded);
        }
        let end = cursor;

        let ret_addr = insns.last().unwrap().address;
        let block = BasicBlock {
            start: base,
            end,
            instructions: insns,
            terminator: EdgeKind::Return,
        };
        let mut blocks = BTreeMap::new();
        blocks.insert(base, block);

        let cfg = Cfg {
            entry: base,
            blocks,
            edges: vec![CfgEdge { from: ret_addr, to: None, kind: EdgeKind::Return }],
        };
        (cfg, code)
    }

    // ── Test: linear execution — high hit rate ───────────────────────────────

    #[test]
    fn linear_execution_high_hit_rate() {
        let base: Address = 0x1000;
        let n_nops = 8;
        let (cfg, code) = linear_cfg(base, n_nops);
        let decoder = MinimalDecoder;

        let mut pipeline = SpeculativeDecodePipeline::new();

        // Pre-warm the pipeline with depth = n_nops + 1 (covers all instructions).
        pipeline.prefetch_ahead(base, &cfg, &decoder, &code, base, n_nops + 1);

        // Execute each nop in order; all should be cache hits.
        let mut pc = base;
        for i in 0..n_nops {
            let offset = usize::try_from(pc - base).unwrap();
            let insn = pipeline.poll_or_decode(pc, &decoder, &code[offset..]).unwrap();
            assert_eq!(insn.address, pc, "instruction {i} address mismatch");
            pc = pc.wrapping_add(u64::from(insn.length));
        }

        // All `n_nops` nops should have been hits (prefetched before query).
        assert_eq!(pipeline.pipeline_queries, n_nops as u64);
        assert_eq!(pipeline.pipeline_hits, n_nops as u64, "expected all queries to be cache hits");
        assert_eq!(pipeline.pipeline_flushes, 0, "linear execution must not flush");
    }

    // ── Test: misprediction triggers flush ───────────────────────────────────

    #[test]
    fn misprediction_triggers_flush_and_fallback() {
        let code: Vec<u8> = vec![
            0x90,       // [0] 0x1000 nop
            0x75, 0x04, // [1] 0x1001 jnz +4 (target: 0x1003 + 4 = 0x1007)
            0x90,       // [3] 0x1003 nop (fall-through block)
            0xC3,       // [4] 0x1004 ret
            0x90, 0x90, // [5..6] padding
            0x90,       // [7] 0x1007 nop (taken block)
            0xC3,       // [8] 0x1008 ret
        ];
        let base: Address = 0x1000;
        let decoder = MinimalDecoder;

        // Block A: 0x1000..0x1003 (nop, jnz)
        let nop_a = decoder.decode(0x1000, &code[0..]).unwrap();
        let jnz = decoder.decode(0x1001, &code[1..]).unwrap();
        let block_a = BasicBlock {
            start: 0x1000,
            end: 0x1003,
            instructions: vec![nop_a, jnz],
            terminator: EdgeKind::ConditionalTaken,
        };
        // Block B (fall-through): 0x1003..0x1005
        let nop_b = decoder.decode(0x1003, &code[3..]).unwrap();
        let ret_b = decoder.decode(0x1004, &code[4..]).unwrap();
        let block_b = BasicBlock {
            start: 0x1003,
            end: 0x1005,
            instructions: vec![nop_b, ret_b],
            terminator: EdgeKind::Return,
        };
        // Block C (taken): 0x1007..0x1009
        let nop_c = decoder.decode(0x1007, &code[7..]).unwrap();
        let ret_c = decoder.decode(0x1008, &code[8..]).unwrap();
        let block_c = BasicBlock {
            start: 0x1007,
            end: 0x1009,
            instructions: vec![nop_c, ret_c],
            terminator: EdgeKind::Return,
        };

        let mut blocks = BTreeMap::new();
        blocks.insert(0x1000, block_a);
        blocks.insert(0x1003, block_b);
        blocks.insert(0x1007, block_c);

        let edges = vec![
            CfgEdge { from: 0x1001, to: Some(0x1003), kind: EdgeKind::FallThrough },
            CfgEdge { from: 0x1001, to: Some(0x1007), kind: EdgeKind::ConditionalTaken },
            CfgEdge { from: 0x1004, to: None, kind: EdgeKind::Return },
            CfgEdge { from: 0x1008, to: None, kind: EdgeKind::Return },
        ];

        let cfg = Cfg { entry: 0x1000, blocks, edges };

        let mut pipeline = SpeculativeDecodePipeline::new();

        // Pre-warm from block A; predictor will prefer fall-through (-> block B).
        pipeline.prefetch_ahead(0x1000, &cfg, &decoder, &code, base, 8);
        assert!(
            pipeline.index.contains_key(&0x1003),
            "fall-through path (block B) should be prefetched"
        );
        assert!(
            pipeline.index.contains_key(&0x1001),
            "intra-block instruction should be prefetched"
        );

        // Simulate executing nop at 0x1000 (hit expected).
        let insn = pipeline.poll_or_decode(0x1000, &decoder, &code[0..]).unwrap();
        assert_eq!(insn.address, 0x1000);
        assert_eq!(pipeline.pipeline_hits, 1);

        // Now simulate that the branch was actually *taken* (-> 0x1007), so
        // the pipeline predicted fall-through (0x1003) but we jump to 0x1007.
        let insn = pipeline.poll_or_decode(0x1007, &decoder, &code[7..]).unwrap();
        assert_eq!(insn.address, 0x1007);
        assert_eq!(pipeline.pipeline_flushes, 1, "misprediction must trigger a flush");
        // The instruction at 0x1007 is a miss (buffer was flushed).
        assert_eq!(pipeline.pipeline_hits, 1, "only the first query should have been a hit");
    }

    // ── Test: bounded queue depth and eviction ───────────────────────────────

    #[test]
    fn bounded_queue_evicts_oldest() {
        let decoder = MinimalDecoder;
        let base: Address = 0x2000;
        let n = RING_CAPACITY + 16;
        let code: Vec<u8> = vec![0x90u8; n + 1];

        let mut pipeline = SpeculativeDecodePipeline::new();

        for i in 0..n {
            let pc = base.wrapping_add(i as u64);
            pipeline
                .poll_or_decode(pc, &decoder, &code[i..])
                .unwrap();
        }

        assert!(
            pipeline.ring.len() <= RING_CAPACITY,
            "ring grew to {} (> RING_CAPACITY {})",
            pipeline.ring.len(),
            RING_CAPACITY
        );

        let oldest_evicted = base;
        assert!(
            !pipeline.index.contains_key(&oldest_evicted),
            "oldest entry should have been evicted from the ring"
        );
        let newest = base.wrapping_add((n - 1) as u64);
        assert!(
            pipeline.index.contains_key(&newest),
            "newest entry must still be in the ring"
        );

        assert_eq!(pipeline.ring.len(), pipeline.index.len(), "ring and index must be in sync");
    }

    // ── Test: prefetch_depth_avg metric ─────────────────────────────────────

    #[test]
    fn prefetch_depth_avg_is_correct() {
        let base: Address = 0x3000;
        let code = vec![0x90u8; 32];
        let (cfg, _) = linear_cfg(base, 16);
        let decoder = MinimalDecoder;

        let mut pipeline = SpeculativeDecodePipeline::new();
        pipeline.prefetch_ahead(base, &cfg, &decoder, &code, base, 4);
        pipeline.prefetch_ahead(base, &cfg, &decoder, &code, base, 8);
        pipeline.prefetch_ahead(base, &cfg, &decoder, &code, base, 12);

        let avg = pipeline.prefetch_depth_avg();
        let expected = (4.0 + 8.0 + 12.0) / 3.0;
        assert!(
            (avg - expected).abs() < 1e-9,
            "prefetch_depth_avg expected {expected} got {avg}"
        );
    }

    // ── Test: repeated linear execution — cache serves every instruction ──────

    #[test]
    fn repeated_execution_served_from_cache() {
        let base: Address = 0x4000;
        let n_nops = 4;
        let (cfg, code) = linear_cfg(base, n_nops);
        let decoder = MinimalDecoder;

        let mut pipeline = SpeculativeDecodePipeline::new();
        pipeline.prefetch_ahead(base, &cfg, &decoder, &code, base, n_nops + 1);

        for _pass in 0..3 {
            let mut pc = base;
            for _ in 0..n_nops {
                let offset = usize::try_from(pc - base).unwrap();
                let _ = pipeline.poll_or_decode(pc, &decoder, &code[offset..]).unwrap();
                pc = pc.wrapping_add(1);
            }
        }

        let expected_hits = (n_nops * 3) as u64;
        let expected_queries = expected_hits;
        assert_eq!(pipeline.pipeline_queries, expected_queries);
        assert_eq!(pipeline.pipeline_hits, expected_hits);
        assert_eq!(pipeline.pipeline_flushes, 0);
    }
}
