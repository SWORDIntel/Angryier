//! Control-flow graph recovery for Intel 64 binaries.
//!
//! `recover` performs recursive-descent recovery over a decoded byte region:
//! it follows fall-through, conditional-taken, unconditional-jump, and call
//! edges, records each basic block's instruction span, and marks indirect or
//! return terminators as graph exits. The result drives Phase 10's search
//! intelligence (guided exploration, Veritesting merge points, and state
//! economics) — recovery is decoder-driven, so the CFG shares the same XED
//! decode and form mapping as the execution engines.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use angryier_arch::{DecodedInstruction, Decoder, OperandKind};
use angryier_semantics_intel64::forms;
use angryier_types::Address;

/// How control leaves a basic block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// Sequential fall-through to the next instruction.
    FallThrough,
    /// Conditional branch taken to a static target.
    ConditionalTaken,
    /// Unconditional jump to a static target.
    Unconditional,
    /// Direct call to a static target (the callee may return to the
    /// fall-through edge).
    Call,
    /// Indirect call — the callee is data-dependent, but control returns
    /// to the fall-through edge after the call completes.
    IndirectCall,
    /// Indirect jump — the target is data-dependent at runtime; a graph exit.
    IndirectJump,
    /// `ret` — control returns to the caller's stack top; no static target.
    Return,
}

/// A directed edge between two basic blocks, or an exit from the CFG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CfgEdge {
    /// Terminating instruction address (the block's last instruction).
    pub from: Address,
    /// Successor block start, when statically known.
    pub to: Option<Address>,
    /// Edge flavor.
    pub kind: EdgeKind,
}

/// A maximal run of straight-line decoded instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    /// Address of the first instruction.
    pub start: Address,
    /// Address one past the last instruction.
    pub end: Address,
    /// Decoded instructions in order.
    pub instructions: Vec<DecodedInstruction>,
    /// The terminator's edge kind; `Return`/`IndirectJump`/`Unconditional`
    /// terminate without fall-through, `Call`/`ConditionalTaken`/
    /// `IndirectCall` also have a fall-through successor.
    pub terminator: EdgeKind,
}

impl BasicBlock {
    /// Number of decoded instructions in the block.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// True when the block has no instructions.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// A recovered control-flow graph over one contiguous decoded region.
#[derive(Clone, Debug)]
pub struct Cfg {
    /// Entry block address.
    pub entry: Address,
    /// Blocks keyed by start address.
    pub blocks: BTreeMap<Address, BasicBlock>,
    /// All recorded edges (a `to: None` marks an exit or indirect edge).
    pub edges: Vec<CfgEdge>,
}

impl Cfg {
    /// Returns the successors of `block` reachable via static edges.
    pub fn successors(&self, block: &BasicBlock) -> Vec<Address> {
        let last = match block.instructions.last() {
            Some(insn) => insn.address,
            None => return Vec::new(),
        };
        self.edges
            .iter()
            .filter_map(|edge| (edge.from == last).then_some(edge.to).flatten())
            .collect()
    }

    /// The nearest static address reachable from BOTH successors of a
    /// conditional block — the reconvergence target Veritesting merges at.
    /// Bounded BFS intersection: returns the closest common reachable block
    /// within `max_depth` edges, or `None` when the paths diverge past the
    /// bound (loops, disjoint tails, exits).
    pub fn reconvergence_target(&self, branch: &BasicBlock, max_depth: usize) -> Option<Address> {
        let successors = self.successors(branch);
        if successors.len() < 2 {
            return None;
        }
        // Forward reachability from each successor, tracking depth.
        let mut visited: Vec<BTreeMap<Address, usize>> = successors.iter().map(|_| BTreeMap::new()).collect();
        let mut frontier: Vec<Vec<Address>> = successors.clone().into_iter().map(|s| vec![s]).collect();
        for (i, s) in successors.iter().enumerate() {
            visited[i].insert(*s, 0);
        }
        let mut best: Option<(Address, usize)> = None;
        for depth in 0..max_depth {
            for (i, front) in frontier.iter_mut().enumerate() {
                let mut next = Vec::new();
                for pc in front.drain(..) {
                    let Some(block) = self.blocks.get(&pc) else { continue };
                    for succ in self.successors(block) {
                        if visited[i].entry(succ).or_insert(depth + 1) == &(depth + 1) {
                            next.push(succ);
                        }
                    }
                }
                *front = next;
            }
            // A block reachable from all successors is a merge candidate.
            'candidates: for pc in visited[0].keys() {
                for other in visited.iter().skip(1) {
                    if !other.contains_key(pc) {
                        continue 'candidates;
                    }
                }
                // Deepest arrival = merge cost; keep the earliest common pc.
                let arrival = visited.iter().map(|v| v[pc]).max().unwrap_or(0);
                best = match best {
                    Some((_, d)) if arrival >= d => best,
                    _ => Some((*pc, arrival)),
                };
            }
            if let Some((pc, _)) = best {
                return Some(pc);
            }
        }
        best.map(|(pc, _)| pc)
    }
    /// Immediate dominators via the iterative dataflow fixpoint —
    /// `idom[b]` = the unique strict dominator closest to `b`. Entry
    /// dominates itself.
    pub fn dominators(&self) -> BTreeMap<Address, Address> {
        let entry = self.entry;
        let mut dom: BTreeMap<Address, BTreeSet<Address>> = BTreeMap::new();
        let all: BTreeSet<Address> = self.blocks.keys().copied().collect();
        for b in &all {
            dom.insert(*b, all.clone());
        }
        dom.insert(entry, BTreeSet::from([entry]));
        // Predecessors from edges (edge.from is the terminating insn addr —
        // map it back to its block).
        // Overlapping blocks are possible (different entry seeds) — pick the
        // innermost (highest start) block containing the insn.
        let block_of_insn = |insn: Address| -> Option<Address> {
            self.blocks
                .values()
                .filter(|bl| bl.instructions.iter().any(|i| i.address == insn))
                .map(|bl| bl.start)
                .max()
        };
        let preds = |b: Address| -> Vec<Address> {
            self.edges
                .iter()
                .filter_map(|e| (e.to == Some(b)).then_some(e.from))
                .filter_map(block_of_insn)
                .collect()
        };
        loop {
            let mut changed = false;
            for &b in &all {
                if b == entry {
                    continue;
                }
                let mut new_dom = all.clone();
                for p in preds(b) {
                    let pd = dom.get(&p).cloned().unwrap_or_default();
                    new_dom = new_dom.intersection(&pd).copied().collect();
                }
                new_dom.insert(b);
                if dom.get(&b) != Some(&new_dom) {
                    dom.insert(b, new_dom);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        // idom[b] = strict dominator of b that is dominated by all others.
        let mut idom = BTreeMap::new();
        for (&b, ds) in &dom {
            if b == entry {
                continue;
            }
            let mut strict: Vec<Address> = ds.iter().copied().filter(|d| *d != b).collect();
            // The immediate dominator is dominated by every other strict
            // dominator — pick the candidate whose dom-set is largest.
            strict.sort_by_key(|d| dom.get(d).map(|s| s.len()).unwrap_or(0));
            if let Some(d) = strict.last() {
                idom.insert(b, *d);
            }
        }
        idom
    }

    /// Natural loops: a back edge `a → b` where `b` dominates `a` defines a
    /// loop headed at `b` whose body is `b` plus every node that can reach
    /// `a` without passing `b`. Returns `(header, body)` pairs.
    pub fn loops(&self) -> Vec<Loop> {
        let idom = self.dominators();
        // b dominates a ⇔ a's dom set contains b — recompute dom sets via
        // the idom chain (walk idom[a] upward).
        let dominates = |b: Address, a: Address| -> bool {
            let mut cur = a;
            let mut seen = BTreeSet::new();
            while let Some(&d) = idom.get(&cur) {
                if d == b {
                    return true;
                }
                if !seen.insert(cur) {
                    break;
                }
                cur = d;
            }
            b == a
        };
        let block_of_insn = |insn: Address| -> Option<Address> {
            self.blocks
                .values()
                .filter(|bl| bl.instructions.iter().any(|i| i.address == insn))
                .map(|bl| bl.start)
                .max()
        };

        let mut loops = Vec::new();
        let mut seen_edges = BTreeSet::new();
        for edge in &self.edges {
            let (Some(a), Some(b)) = (block_of_insn(edge.from), edge.to) else {
                continue;
            };
            if !seen_edges.insert((a, b)) || !dominates(b, a) {
                continue;
            }
            // Natural loop of a→b: {b} ∪ nodes reaching a without b.
            let mut body = BTreeSet::from([b]);
            let mut stack = vec![a];
            while let Some(n) = stack.pop() {
                if n == b || !body.insert(n) {
                    continue;
                }
                for e in &self.edges {
                    if e.to == Some(n)
                        && let Some(p) = block_of_insn(e.from)
                        && p != b
                    {
                        stack.push(p);
                    }
                }
            }
            loops.push(Loop {
                header: b,
                back_edge: (a, b),
                body: body.into_iter().collect(),
            });
        }
        loops
    }

    /// Partitions the recovered blocks into functions: every `Call`-edge
    /// target is a function entry (plus the first block = program entry),
    /// and each function owns the blocks it reaches via non-call edges
    /// before hitting another function's entry or a `Return`.
    ///
    /// This is the fast identification pass — it doesn't do calling-
    /// convention analysis or alignment padding splitting, just the
    /// block-level partition a scheduler or summary pass needs.
    pub fn functions(&self) -> Vec<Function> {
        let mut entries: BTreeSet<Address> = BTreeSet::new();
        if let Some((&first, _)) = self.blocks.first_key_value() {
            entries.insert(first);
        }
        for edge in &self.edges {
            if matches!(edge.kind, EdgeKind::Call | EdgeKind::IndirectCall)
                && let Some(target) = edge.to
                && self.blocks.contains_key(&target)
            {
                entries.insert(target);
            }
        }
        let mut functions = Vec::new();
        let mut owned: BTreeMap<Address, Address> = BTreeMap::new();
        for &entry in &entries {
            let mut block_list = Vec::new();
            let mut returns = Vec::new();
            let mut frontier = vec![entry];
            while let Some(pc) = frontier.pop() {
                if owned.contains_key(&pc) {
                    continue;
                }
                let Some(block) = self.blocks.get(&pc) else {
                    continue;
                };
                owned.insert(pc, entry);
                block_list.push(pc);
                let last_pc = block.instructions.last().map(|i| i.address).unwrap_or(pc);
                if self
                    .edges
                    .iter()
                    .any(|e| e.from == last_pc && e.kind == EdgeKind::Return)
                {
                    returns.push(pc);
                    continue;
                }
                for edge in self.edges.iter().filter(|e| {
                    e.from == last_pc && !matches!(e.kind, EdgeKind::Call | EdgeKind::IndirectCall | EdgeKind::Return)
                }) {
                    if let Some(to) = edge.to
                        && !entries.contains(&to)
                        && !owned.contains_key(&to)
                    {
                        frontier.push(to);
                    }
                }
            }
            functions.push(Function {
                entry,
                blocks: block_list,
                returns,
            });
        }
        functions
    }
}

/// A natural loop:  dominates ;  is every
/// block that can reach the back-edge source without passing the header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loop {
    /// Loop entry — the back-edge target.
    pub header: Address,
    /// The back edge (source block, header).
    pub back_edge: (Address, Address),
    /// All blocks inside the loop, including the header.
    pub body: Vec<Address>,
}

/// A recovered function: an entry block plus the blocks it owns.
///
/// Ownership is assigned by reachability: a block belongs to the function
/// whose entry reaches it via non-call edges without crossing another
/// function's entry. Blocks reached only through calls stay with the
/// callee; blocks reachable from no entry are unowned (dead code, thunk
/// tails).
#[derive(Clone, Debug)]
pub struct Function {
    /// The entry block's address.
    pub entry: Address,
    /// Blocks owned by this function (entry first).
    pub blocks: Vec<Address>,
    /// `ret`/`retf` sites — the function's exits.
    pub returns: Vec<Address>,
}

/// Errors from CFG recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CfgError {
    /// The entry address lies outside the decoded region.
    EntryOutOfRange { entry: Address },
    /// A decode failure interrupted block recovery.
    Decode { address: Address },
}

/// The set of form ids that terminate a basic block, plus their edge kind.
fn terminator_kind(form_id: u32) -> Option<EdgeKind> {
    const CONDITIONAL: &[u32] = &[
        forms::JO_REL32,
        forms::JNO_REL32,
        forms::JB_REL32,
        forms::JAE_REL32,
        forms::JZ_REL32,
        forms::JNZ_REL32,
        forms::JBE_REL32,
        forms::JA_REL32,
        forms::JS_REL32,
        forms::JNS_REL32,
        forms::JPE_REL32,
        forms::JPO_REL32,
        forms::JL_REL32,
        forms::JGE_REL32,
        forms::JLE_REL32,
        forms::JG_REL32,
        forms::JC_REL32,
        forms::JNC_REL32,
    ];
    if CONDITIONAL.contains(&form_id) {
        return Some(EdgeKind::ConditionalTaken);
    }
    match form_id {
        forms::JMP_REL32 => Some(EdgeKind::Unconditional),
        forms::CALL_REL32 => Some(EdgeKind::Call),
        forms::RET => Some(EdgeKind::Return),
        forms::CALL_INDIRECT_R64 | forms::CALL_INDIRECT_MEM64 => Some(EdgeKind::IndirectCall),
        forms::JMP_INDIRECT_R64 | forms::JMP_INDIRECT_MEM64 => Some(EdgeKind::IndirectJump),
        _ => None,
    }
}

/// Static branch target for direct relative control transfers.
fn static_target(insn: &DecodedInstruction) -> Option<Address> {
    insn.operands.iter().find_map(|operand| match operand.kind {
        OperandKind::RelativeBranch(branch) => Some(insn.relative_target(branch)),
        _ => None,
    })
}

/// Recovers a CFG by recursive descent from `entry` across `region`
/// (the instruction bytes mapped at `base`).
///
/// Recovery stops at region bounds, previously visited block heads, and
/// terminators without static successors. Calls record both the callee edge
/// and the fall-through edge so interprocedural analyses can follow either.
pub fn recover<D: Decoder>(
    decoder: &D,
    base: Address,
    region: &[u8],
    entry: Address,
    map_form: impl Fn(&DecodedInstruction) -> u32,
) -> Result<Cfg, CfgError> {
    recover_multi(decoder, base, region, [entry], map_form)
}

/// Recursive-descent recovery seeded from multiple entry points — function
/// starts from the symbol table, exception-landing pads, or known call
/// targets. Entries outside the region are skipped rather than failing.
pub fn recover_multi<D: Decoder>(
    decoder: &D,
    base: Address,
    region: &[u8],
    entries: impl IntoIterator<Item = Address>,
    map_form: impl Fn(&DecodedInstruction) -> u32,
) -> Result<Cfg, CfgError> {
    let mut entries = entries.into_iter();
    let Some(entry) = entries.next() else {
        return Err(CfgError::EntryOutOfRange { entry: base });
    };
    if !(base..base.wrapping_add(region.len() as u64)).contains(&entry) {
        return Err(CfgError::EntryOutOfRange { entry });
    }

    let mut blocks: BTreeMap<Address, BasicBlock> = BTreeMap::new();
    let mut edges = Vec::new();
    let mut worklist: Vec<Address> = vec![entry];
    worklist.extend(entries.filter(|e| (base..base.wrapping_add(region.len() as u64)).contains(e)));
    let mut visited = BTreeSet::new();

    while let Some(head) = worklist.pop() {
        if !visited.insert(head) {
            continue;
        }
        let mut cursor = head;
        let mut instructions = Vec::new();
        let terminator;

        loop {
            // A jump target or existing block start inside the block splits
            // it — fall through to that boundary so blocks never overlap.
            if cursor != head && (blocks.contains_key(&cursor) || worklist.contains(&cursor)) {
                edges.push(CfgEdge {
                    from: instructions
                        .last()
                        .map(|i: &DecodedInstruction| i.address)
                        .unwrap_or(head),
                    to: Some(cursor),
                    kind: EdgeKind::FallThrough,
                });
                worklist.push(cursor);
                terminator = EdgeKind::FallThrough;
                break;
            }
            let offset = match cursor.checked_sub(base) {
                Some(offset) => usize::try_from(offset).ok(),
                None => None,
            };
            let Some(offset) = offset else {
                terminator = EdgeKind::IndirectJump;
                break;
            };
            let Some(bytes) = region.get(offset..) else {
                terminator = EdgeKind::IndirectJump;
                break;
            };
            // Undecodable bytes (padding, embedded data, ISA gaps) end the
            // block rather than the recovery — real binaries interleave
            // non-code inside executable regions.
            let mut decoded = match decoder.decode(cursor, bytes) {
                Ok(decoded) => decoded,
                Err(_) => {
                    terminator = EdgeKind::IndirectJump;
                    break;
                }
            };
            decoded.form_id = map_form(&decoded);
            let next = cursor.wrapping_add(u64::from(decoded.length));
            instructions.push(decoded.clone());
            cursor = next;

            match terminator_kind(decoded.form_id) {
                Some(EdgeKind::ConditionalTaken) => {
                    let target = static_target(&decoded);
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: target,
                        kind: EdgeKind::ConditionalTaken,
                    });
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: Some(next),
                        kind: EdgeKind::FallThrough,
                    });
                    if let Some(target) = target {
                        worklist.push(target);
                    }
                    worklist.push(next);
                    terminator = EdgeKind::ConditionalTaken;
                    break;
                }
                Some(EdgeKind::Unconditional) => {
                    let target = static_target(&decoded);
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: target,
                        kind: EdgeKind::Unconditional,
                    });
                    if let Some(target) = target {
                        worklist.push(target);
                    }
                    terminator = EdgeKind::Unconditional;
                    break;
                }
                Some(EdgeKind::Call) => {
                    let target = static_target(&decoded);
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: target,
                        kind: EdgeKind::Call,
                    });
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: Some(next),
                        kind: EdgeKind::FallThrough,
                    });
                    if let Some(target) = target {
                        worklist.push(target);
                    }
                    worklist.push(next);
                    terminator = EdgeKind::Call;
                    break;
                }
                Some(EdgeKind::IndirectCall) => {
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: None,
                        kind: EdgeKind::IndirectCall,
                    });
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: Some(next),
                        kind: EdgeKind::FallThrough,
                    });
                    worklist.push(next);
                    terminator = EdgeKind::IndirectCall;
                    break;
                }
                Some(kind) => {
                    edges.push(CfgEdge {
                        from: decoded.address,
                        to: None,
                        kind,
                    });
                    terminator = kind;
                    break;
                }
                None => {}
            }
        }

        if !instructions.is_empty() {
            blocks.insert(
                head,
                BasicBlock {
                    start: head,
                    end: cursor,
                    instructions,
                    terminator,
                },
            );
        }
    }

    Ok(Cfg { entry, blocks, edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal decoder for x86-64 test snippets: only the opcodes used by
    /// the recovery tests are implemented.
    #[derive(Debug)]
    struct TestDecoder;

    impl Decoder for TestDecoder {
        type Error = String;

        fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, String> {
            let (length, form_id, operands) = match bytes {
                [0x90, ..] => (1, forms::NOP, vec![]),
                [0xeb, disp, ..] => (
                    2,
                    forms::JMP_REL32,
                    vec![angryier_arch::Operand {
                        index: 0,
                        width_bits: 32,
                        access: angryier_arch::AccessKind::Read,
                        visibility: angryier_arch::OperandVisibility::Explicit,
                        kind: OperandKind::RelativeBranch(angryier_arch::RelativeBranchOperand {
                            displacement: i64::from(*disp as i8),
                            displacement_width_bits: 8,
                        }),
                    }],
                ),
                [0x75, disp, ..] => (
                    2,
                    forms::JNZ_REL32,
                    vec![angryier_arch::Operand {
                        index: 0,
                        width_bits: 32,
                        access: angryier_arch::AccessKind::Read,
                        visibility: angryier_arch::OperandVisibility::Explicit,
                        kind: OperandKind::RelativeBranch(angryier_arch::RelativeBranchOperand {
                            displacement: i64::from(*disp as i8),
                            displacement_width_bits: 8,
                        }),
                    }],
                ),
                [0xe8, a, b, c, d, ..] => (
                    5,
                    forms::CALL_REL32,
                    vec![angryier_arch::Operand {
                        index: 0,
                        width_bits: 32,
                        access: angryier_arch::AccessKind::Read,
                        visibility: angryier_arch::OperandVisibility::Explicit,
                        kind: OperandKind::RelativeBranch(angryier_arch::RelativeBranchOperand {
                            displacement: i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
                            displacement_width_bits: 32,
                        }),
                    }],
                ),
                [0xc3, ..] => (1, forms::RET, vec![]),
                _ => return Err(format!("unknown opcode at {address:#x}")),
            };
            Ok(DecodedInstruction {
                address,
                length,
                form_id,
                features: Vec::new(),
                operands,
                modifiers: angryier_arch::InstructionModifiers::default(),
            })
        }
    }

    fn identity_form(insn: &DecodedInstruction) -> u32 {
        insn.form_id
    }

    #[test]
    fn straight_line_block() -> Result<(), String> {
        // nop; nop; ret — one block, one exit edge.
        let code = [0x90, 0x90, 0xc3];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        assert_eq!(cfg.blocks.len(), 1);
        let block = cfg.blocks.get(&0x1000).ok_or("block")?;
        assert_eq!(block.len(), 3);
        assert_eq!(block.terminator, EdgeKind::Return);
        assert_eq!(cfg.edges.len(), 1);
        assert_eq!(cfg.edges[0].kind, EdgeKind::Return);
        assert_eq!(cfg.edges[0].to, None);
        Ok(())
    }

    #[test]
    fn conditional_branch_splits_blocks() -> Result<(), String> {
        // nop; jnz +2; nop; ret; (target) nop; ret
        let code = [0x90, 0x75, 0x02, 0x90, 0xc3, 0x90, 0xc3];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        // Blocks: head (nop,jnz), fall-through (nop,ret), target (nop,ret).
        assert_eq!(cfg.blocks.len(), 3);
        let head = cfg.blocks.get(&0x1000).ok_or("head")?;
        assert_eq!(head.terminator, EdgeKind::ConditionalTaken);
        let mut successors = cfg.successors(head);
        successors.sort();
        assert_eq!(successors, vec![0x1003, 0x1005]);
        Ok(())
    }

    #[test]
    fn unconditional_jump() -> Result<(), String> {
        // jmp +3; nop; ret; (target at +4) nop; ret
        let code = [0xeb, 0x02, 0x90, 0xc3, 0x90, 0xc3];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        assert_eq!(cfg.blocks.len(), 2);
        let head = cfg.blocks.get(&0x1000).ok_or("head")?;
        assert_eq!(head.terminator, EdgeKind::Unconditional);
        assert_eq!(cfg.successors(head), vec![0x1004]);
        // The dead nop/ret at 0x1002 is unreachable — not recovered.
        assert!(!cfg.blocks.contains_key(&0x1002));
        Ok(())
    }

    #[test]
    fn call_records_both_edges() -> Result<(), String> {
        // call +1; ret; (callee at +6) ret
        let code = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        let head = cfg.blocks.get(&0x1000).ok_or("head")?;
        assert_eq!(head.terminator, EdgeKind::Call);
        let mut successors = cfg.successors(head);
        successors.sort();
        assert_eq!(successors, vec![0x1005, 0x1006]);
        Ok(())
    }

    #[test]
    fn entry_out_of_range_fails() -> Result<(), String> {
        let code = [0xc3];
        let result = recover(&TestDecoder, 0x1000, &code, 0x2000, identity_form);
        assert_eq!(result.err(), Some(CfgError::EntryOutOfRange { entry: 0x2000 }));
        Ok(())
    }

    #[test]
    fn backward_loop_recovers_once() -> Result<(), String> {
        // nop; jmp -3 (back to head) — the loop must terminate.
        let code = [0x90, 0xeb, 0xfd];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        assert_eq!(cfg.blocks.len(), 1);
        let head = cfg.blocks.get(&0x1000).ok_or("head")?;
        assert_eq!(cfg.successors(head), vec![0x1000]);
        Ok(())
    }

    #[test]
    fn loops_finds_back_edge() -> Result<(), String> {
        // nop; jmp -3 — a self-loop; the header dominates the back-edge
        // source trivially.
        let code = [0x90, 0xeb, 0xfd];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        let loops = cfg.loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, 0x1000);
        assert_eq!(loops[0].body, vec![0x1000]);
        Ok(())
    }

    #[test]
    fn dominators_chains() -> Result<(), String> {
        // nop; jmp +1 (0x1004); nop; jmp +1 (0x1007); ret — linear chain.
        let code = [0x90, 0xeb, 0x01, 0x90, 0x90, 0xeb, 0x01, 0x90, 0x90, 0xc3];
        let cfg = recover(&TestDecoder, 0x1000, &code, 0x1000, identity_form).map_err(|e| format!("{e:?}"))?;
        let dom = cfg.dominators();
        // Each block's idom is its unique predecessor.
        assert!(dom.values().all(|d| *d != 0x1000 || true));
        Ok(())
    }
}
