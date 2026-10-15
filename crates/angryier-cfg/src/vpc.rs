//! Virtual program counter (VPC) candidate identification for VM-aware CFG
//! analysis (PUSHAN-style, arXiv 2603.18355, informed by the
//! stuxnet147/Themida-Research VM internals notes).
//!
//! Code virtualizers (Themida, VMProtect) compile functions into an
//! interpreter: every handler block advances a *virtual program counter* —
//! a register holding the next virtual instruction's location — and
//! transfers control with a memory-indirect jump through a dispatch table.
//! `angryier-cfg`'s recovery records those jumps as unresolved
//! `EdgeKind::IndirectJump` exits, which stalls CFG recovery exactly where
//! the virtualized body begins. This module re-examines decoded blocks and
//! reports the registers that most plausibly hold the VPC, so a later
//! context-sensitive pass can key analysis locations by
//! `(native_pc, virtual_pc)` — the central PUSHAN idea: one interpreter
//! dispatch site (a fixed `native_pc`) stands for many virtualized program
//! locations (distinct `virtual_pc` values), so VPC candidates must be
//! re-evaluated per basic block, never once per function.
//!
//! Identification is structural register-tracking, not offset-based: the
//! Themida VM_CONTEXT is ~0x200 bytes with *randomized* member offsets
//! (Themida-Research), so no fixed context layout survives between builds —
//! only the dataflow shape of the dispatch is stable. Themida keeps one
//! stable VPC register across handler blocks (heuristic 3); VMProtect
//! rotates the dispatch register between registers (heuristic 4, weaker).
//!
//! Heuristics (confidence 0-100; when several hit the same
//! `(native_pc, register)` pair the maximum wins):
//!
//! 1. `DISPATCH_READ_CONFIDENCE` — the index register of a memory-indirect
//!    jump terminator, redefined inside the same block with no bounds check
//!    between the redefinition and the jump. The redefinition requirement is
//!    what separates a live dispatch chain (every handler recomputes its VPC
//!    before dispatching) from a compiler switch table, whose index arrives
//!    from outside the block; the bounds-check exclusion removes the
//!    remaining `cmp idx, bound; ja default; jmp [table + idx*8]` shape.
//! 2. `TABLE_LOAD_CHAIN_CONFIDENCE` — a register redefined by a load from a
//!    table that the same block then jumps *through* (`mov r, [table]`
//!    followed by `jmp *r` or `jmp [r + …]`): the handler-entry fetch.
//!    Lower than the dispatch read because the loaded register holds the
//!    handler entry materialized from the table — one step removed from the
//!    VPC value itself.
//! 3. `STABLE_VPC_CONFIDENCE` — Themida stable-VPC: the *same* register
//!    loaded-then-used-as-dispatch-index across multiple sibling blocks in
//!    address order (each block re-reads it from the VM_CONTEXT at its own
//!    randomized offset, then dispatches through the same table). Multiple
//!    independent blocks agreeing on one register is stronger evidence than
//!    any single-block read, hence the highest score.
//! 4. `VOLATILE_VPC_CONFIDENCE` — VMProtect volatile VPC: the dispatch
//!    register is *moved* between different registers across consecutive
//!    dispatch blocks (`mov r2, r1` in the later block, dispatch through
//!    `r1` then `r2`). Register rotation is also something ordinary
//!    register allocation produces, so this is the weakest signal.
//!
//! This module is compiled and exposed by `angryier-cfg`. Its candidates
//! are consumed by the opt-in `vm::inspect_native_cfg` report; they are not
//! automatically promoted to confirmed virtual-PC identities.

use std::collections::BTreeMap;

use angryier_arch::{
    AccessKind, DecodedInstruction, MemoryBase, MemoryIndex, MemoryOperand, OperandKind, RegisterId, RegisterView,
};
use angryier_semantics_intel64::forms;
use angryier_types::Address;

/// Minimum number of address-ordered sibling blocks that must independently
/// load-and-dispatch through the same register before the Themida
/// stable-VPC heuristic fires. Two already implies a repeated dispatch
/// chain rather than a one-off compiler switch.
pub const MIN_STABLE_VPC_SIBLINGS: usize = 2;

/// Heuristic 1: dispatch read — index register of a memory-indirect jump
/// terminator, redefined in-block, unguarded.
pub const DISPATCH_READ_CONFIDENCE: u8 = 85;
/// Heuristic 2: register redefined by a table load the same block jumps
/// through (handler-entry fetch).
pub const TABLE_LOAD_CHAIN_CONFIDENCE: u8 = 70;
/// Heuristic 3: Themida stable VPC — one register loaded-then-dispatched
/// across multiple sibling blocks in address order.
pub const STABLE_VPC_CONFIDENCE: u8 = 92;
/// Heuristic 4: VMProtect volatile VPC — dispatch register rotated between
/// registers across consecutive dispatch blocks.
pub const VOLATILE_VPC_CONFIDENCE: u8 = 40;

/// Terminator forms whose target is data-dependent through a register: the
/// VM dispatch read.
const DISPATCH_JUMP_FORMS: &[u32] = &[forms::JMP_INDIRECT_MEM64, forms::JMP_INDIRECT_R64];

/// `mov rN, [mem]` shapes: a register redefined by a table load.
const TABLE_LOAD_FORMS: &[u32] = &[
    forms::MOV_R64_MEM64,
    forms::MOV_R32_MEM32,
    forms::MOV_R16_MEM16,
    forms::MOV_R8_MEM8,
];

/// Register-to-register moves: the chain-of-custody shape of a volatile VPC
/// being handed to the next handler's working register.
const REGISTER_MOVE_FORMS: &[u32] = &[forms::MOV_R64_R64, forms::MOV_R32_R32];

/// Compare/test shapes a compiler emits to bounds-check a switch-table
/// index before the table jump. A VM dispatch never bounds-checks its VPC:
/// the index comes from (encrypted) bytecode and is trusted.
const BOUNDS_CHECK_FORMS: &[u32] = &[
    forms::CMP_R64_R64,
    forms::CMP_R64_IMM32,
    forms::CMP_R32_IMM8,
    forms::TEST_R64_R64,
];

/// A basic block offered to VPC identification.
///
/// `native_pc` is the block's first-instruction address — the `native_pc`
/// half of PUSHAN's `(native_pc, virtual_pc)` analysis-location key.
/// `instructions` are the decoded instructions in order; only the final
/// instruction may transfer control (it is the block terminator).
pub struct VpcBlock<'a> {
    /// Address of the block's first instruction.
    pub native_pc: Address,
    /// Instructions in address order; the last is the terminator.
    pub instructions: &'a [DecodedInstruction],
}

/// One register, at one native dispatch site, plausibly holding the VPC.
///
/// `table_base` is the statically resolved anchor of the dispatch (or, for
/// heuristic 2, defining-load) table when its memory operand is
/// RIP-relative or absolute; `None` when a register base hides it.
/// `confidence` is the winning 0-100 heuristic score for this
/// `(native_pc, register)` pair.
pub struct VpcCandidate {
    /// Native dispatch-site block address (PUSHAN's `native_pc` key half).
    pub native_pc: Address,
    /// Parent register plausibly holding the virtual program counter.
    pub register: RegisterId,
    /// Statically resolved dispatch-table anchor, when knowable.
    pub table_base: Option<Address>,
    /// Winning heuristic score, 0-100.
    pub confidence: u8,
}

/// Structural evidence extracted from one dispatch-terminated block.
struct DispatchSite {
    native_pc: Address,
    /// Register whose runtime value selects the dispatch target.
    register: RegisterId,
    /// Terminator is the memory-indexed form `jmp [base + r*scale + disp]`.
    memory_indexed: bool,
    /// Register the terminator jumps *through*: the target of `jmp *r`, or
    /// the base register of `jmp [r + …]` — heuristic 2's subject.
    jump_through: Option<RegisterId>,
    /// Statically resolved dispatch-table anchor of the terminator.
    table_base: Option<Address>,
    /// The dispatch register is redefined inside the block before the
    /// terminator.
    defined_in_block: bool,
    /// A bounds-check compare on the dispatch register sits between its
    /// last in-block definition and the terminator — compiler
    /// switch-table shape.
    bounds_guarded: bool,
    /// The defining instruction is a table load and the site is unguarded —
    /// heuristic 3's subject (Themida stable VPC).
    loaded_from_table: bool,
}

fn register_reads(instruction: &DecodedInstruction) -> Vec<RegisterView> {
    instruction
        .operands
        .iter()
        .filter(|operand| matches!(operand.access, AccessKind::Read | AccessKind::ReadWrite))
        .filter_map(|operand| match operand.kind {
            OperandKind::Register(view) => Some(view),
            _ => None,
        })
        .collect()
}

fn register_writes(instruction: &DecodedInstruction) -> Vec<RegisterView> {
    instruction
        .operands
        .iter()
        .filter(|operand| matches!(operand.access, AccessKind::Write | AccessKind::ReadWrite))
        .filter_map(|operand| match operand.kind {
            OperandKind::Register(view) => Some(view),
            _ => None,
        })
        .collect()
}

fn reads_register(instruction: &DecodedInstruction, register: RegisterId) -> bool {
    register_reads(instruction).iter().any(|view| view.parent == register)
}

fn writes_register(instruction: &DecodedInstruction, register: RegisterId) -> bool {
    register_writes(instruction).iter().any(|view| view.parent == register)
}

fn memory_operand(instruction: &DecodedInstruction) -> Option<MemoryOperand> {
    instruction.operands.iter().find_map(|operand| match operand.kind {
        OperandKind::Memory(mem) | OperandKind::AddressGeneration(mem) => Some(mem),
        _ => None,
    })
}

fn is_dispatch_jump(instruction: &DecodedInstruction) -> bool {
    DISPATCH_JUMP_FORMS.contains(&instruction.form_id)
}

/// The register whose value selects the dispatch target: the index register
/// of `jmp [base + r*scale + disp]`, or the target register of `jmp *r`.
/// Matching is on the parent register, so 32/64-bit views of the same
/// storage collapse (that is what `RegisterView` exists for).
fn dispatch_register(terminator: &DecodedInstruction) -> Option<RegisterView> {
    if terminator.form_id == forms::JMP_INDIRECT_MEM64 {
        match memory_operand(terminator)?.index {
            Some(MemoryIndex::Register(view)) => Some(view),
            _ => None,
        }
    } else if terminator.form_id == forms::JMP_INDIRECT_R64 {
        register_reads(terminator).into_iter().next()
    } else {
        None
    }
}

/// The register the terminator jumps *through* (heuristic 2's subject):
/// the target of `jmp *r`, or the base register of `jmp [r + …]`. The
/// *index* register is deliberately excluded here — that is heuristic 1's
/// subject.
fn jumped_through_register(terminator: &DecodedInstruction) -> Option<RegisterView> {
    if terminator.form_id == forms::JMP_INDIRECT_R64 {
        register_reads(terminator).into_iter().next()
    } else {
        match memory_operand(terminator)?.base {
            Some(MemoryBase::Register(view)) => Some(view),
            _ => None,
        }
    }
}

/// Statically resolved anchor of the table a memory operand addresses.
/// RIP-relative and absolute-displacement forms resolve; a register base
/// hides the table at static-analysis time. Wrapping mirrors
/// `DecodedInstruction::relative_target`.
fn table_anchor(instruction: &DecodedInstruction) -> Option<Address> {
    let memory = memory_operand(instruction)?;
    match memory.base {
        Some(MemoryBase::InstructionPointer { .. }) => Some(
            instruction
                .address
                .wrapping_add(u64::from(instruction.length))
                .wrapping_add_signed(memory.displacement),
        ),
        Some(MemoryBase::Register(_)) => None,
        // Absolute `[index*scale + disp]` table: the displacement is the anchor.
        None => Some(memory.displacement as u64),
    }
}

/// True when a bounds-check compare on `register` appears in
/// `body[after + 1..]` — the compiler switch-table guard.
fn bounds_guarded_between(body: &[DecodedInstruction], register: RegisterId, after: usize) -> bool {
    body[after + 1..]
        .iter()
        .any(|instruction| BOUNDS_CHECK_FORMS.contains(&instruction.form_id) && reads_register(instruction, register))
}

/// Position of the last instruction in `body` that redefines `register`
/// with a table-load form, if any.
fn table_load_defining(body: &[DecodedInstruction], register: RegisterId) -> Option<usize> {
    body.iter().rposition(|instruction| {
        TABLE_LOAD_FORMS.contains(&instruction.form_id) && writes_register(instruction, register)
    })
}

/// Heuristic 2 evidence: the register the terminator jumps *through* was
/// redefined by an unguarded table load in this same block — returns that
/// register together with the load's table anchor.
fn table_load_chain(body: &[DecodedInstruction], jump_through: RegisterId) -> Option<(RegisterId, Option<Address>)> {
    let load_pos = table_load_defining(body, jump_through)?;
    if bounds_guarded_between(body, jump_through, load_pos) {
        return None;
    }
    Some((jump_through, table_anchor(&body[load_pos])))
}

/// Extract dispatch evidence from a block, or `None` when the block does
/// not end in a register-mediated indirect jump.
fn analyze(block: &VpcBlock<'_>) -> Option<DispatchSite> {
    let terminator = block.instructions.last()?;
    if !is_dispatch_jump(terminator) {
        return None;
    }
    let register = dispatch_register(terminator)?.parent;
    let term_pos = block.instructions.len() - 1;
    let body = &block.instructions[..term_pos];
    let defined_pos = body.iter().rposition(|insn| writes_register(insn, register));
    let bounds_guarded = defined_pos.is_some_and(|pos| bounds_guarded_between(body, register, pos));
    let loaded_from_table =
        defined_pos.is_some_and(|pos| TABLE_LOAD_FORMS.contains(&block.instructions[pos].form_id) && !bounds_guarded);
    Some(DispatchSite {
        native_pc: block.native_pc,
        register,
        memory_indexed: terminator.form_id == forms::JMP_INDIRECT_MEM64,
        jump_through: jumped_through_register(terminator).map(|view| view.parent),
        table_base: table_anchor(terminator),
        defined_in_block: defined_pos.is_some(),
        bounds_guarded,
        loaded_from_table,
    })
}

fn record(
    ranked: &mut BTreeMap<(Address, RegisterId), (u8, Option<Address>)>,
    native_pc: Address,
    register: RegisterId,
    table_base: Option<Address>,
    confidence: u8,
) {
    let entry = ranked.entry((native_pc, register)).or_insert((0, None));
    entry.0 = entry.0.max(confidence);
    entry.1 = entry.1.or(table_base);
}

/// Identify VPC candidate registers across address-ordered dispatch blocks.
///
/// Returns one [`VpcCandidate`] per `(native_pc, register)` pair that any
/// heuristic flagged, sorted by `(native_pc, register)`, carrying the
/// maximum heuristic confidence that hit the pair. Each returned
/// `native_pc` is a dispatch site that PUSHAN-style analysis would key by
/// `(native_pc, virtual_pc)`; the paired `register` is where a
/// context-sensitive pass should read the `virtual_pc` from. Structural
/// only — no assumption is made about context-layout offsets, per the
/// Themida-Research VM_CONTEXT randomized-offset note.
pub fn identify_vpc_candidates(blocks: &[VpcBlock<'_>]) -> Vec<VpcCandidate> {
    let mut ranked: BTreeMap<(Address, RegisterId), (u8, Option<Address>)> = BTreeMap::new();

    let mut ordered: Vec<&VpcBlock<'_>> = blocks.iter().collect();
    ordered.sort_by_key(|block| block.native_pc);

    // Dispatch sites in address order (blocks without a register-mediated
    // indirect-jump terminator contribute nothing).
    let mut sites: Vec<(&VpcBlock<'_>, DispatchSite)> = Vec::new();
    for block in &ordered {
        if let Some(site) = analyze(block) {
            sites.push((block, site));
        }
    }

    for (block, site) in &sites {
        let term_pos = block.instructions.len() - 1;
        let body = &block.instructions[..term_pos];

        // (1) Dispatch read: the memory-indirect jump index register,
        // redefined in-block, with no bounds check guarding the jump —
        // the two exclusions that keep compiler switch tables out.
        if site.memory_indexed && site.defined_in_block && !site.bounds_guarded {
            record(
                &mut ranked,
                site.native_pc,
                site.register,
                site.table_base,
                DISPATCH_READ_CONFIDENCE,
            );
        }

        // (2) Table-load chain: a register redefined by a table load that
        // this block then jumps through — the handler-entry fetch.
        if let Some((jumped, anchor)) = site.jump_through.and_then(|jumped| table_load_chain(body, jumped)) {
            record(&mut ranked, site.native_pc, jumped, anchor, TABLE_LOAD_CHAIN_CONFIDENCE);
        }
    }

    // (3) Themida stable VPC: the same register loaded-then-used-as-index
    // across multiple sibling blocks in address order.
    let mut stable: BTreeMap<RegisterId, usize> = BTreeMap::new();
    for (_, site) in &sites {
        if site.loaded_from_table {
            *stable.entry(site.register).or_insert(0) += 1;
        }
    }
    for (register, count) in stable {
        if count < MIN_STABLE_VPC_SIBLINGS {
            continue;
        }
        for (_, site) in &sites {
            if site.register == register && site.loaded_from_table {
                record(
                    &mut ranked,
                    site.native_pc,
                    register,
                    site.table_base,
                    STABLE_VPC_CONFIDENCE,
                );
            }
        }
    }

    // (4) VMProtect volatile VPC: the dispatch register is moved between
    // different registers across consecutive dispatch blocks.
    for pair in sites.windows(2) {
        let (earlier, later) = (&pair[0].1, &pair[1].1);
        if earlier.register == later.register {
            continue;
        }
        let rotated = [pair[0].0.instructions, pair[1].0.instructions].iter().any(|body| {
            body.iter().any(|insn| {
                REGISTER_MOVE_FORMS.contains(&insn.form_id)
                    && reads_register(insn, earlier.register)
                    && writes_register(insn, later.register)
            })
        });
        if rotated {
            record(
                &mut ranked,
                earlier.native_pc,
                earlier.register,
                earlier.table_base,
                VOLATILE_VPC_CONFIDENCE,
            );
            record(
                &mut ranked,
                later.native_pc,
                later.register,
                later.table_base,
                VOLATILE_VPC_CONFIDENCE,
            );
        }
    }

    ranked
        .into_iter()
        .map(|((native_pc, register), (confidence, table_base))| VpcCandidate {
            native_pc,
            register,
            table_base,
            confidence,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // Tests activate once this module is wired into the crate
    // (`pub mod vpc;` in lib.rs); until then cargo never compiles this file.
    // Synthetic instruction construction mirrors the cfg lib.rs tests:
    // direct `DecodedInstruction` literals with stable `forms` IDs and
    // hand-laid-out addresses.

    use super::*;
    use angryier_arch::{
        InstructionModifiers, MemoryBase, MemoryOperand, Operand, OperandKind, OperandVisibility, RegisterView,
    };

    // Synthetic Intel 64 register file (standard encoding order).
    const RAX: RegisterId = RegisterId(0);
    const RCX: RegisterId = RegisterId(1);
    const RDX: RegisterId = RegisterId(2);
    const RBX: RegisterId = RegisterId(3);
    const RBP: RegisterId = RegisterId(5);
    const RSI: RegisterId = RegisterId(6);
    const R15: RegisterId = RegisterId(15);

    fn insn(form_id: u32, length: u8, operands: Vec<Operand>) -> DecodedInstruction {
        DecodedInstruction {
            address: 0,
            length,
            form_id,
            features: Vec::new(),
            operands,
            modifiers: InstructionModifiers::default(),
        }
    }

    fn reg_op(index: u8, width_bits: u16, access: AccessKind, register: RegisterId) -> Operand {
        Operand {
            index,
            width_bits,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(RegisterView::full(register, width_bits)),
        }
    }

    fn imm_op(index: u8, value: u64) -> Operand {
        Operand {
            index,
            width_bits: 32,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Immediate(angryier_arch::ImmediateOperand { value, signed: false }),
        }
    }

    fn mem_op(
        index: u8,
        width_bits: u16,
        access: AccessKind,
        base: Option<MemoryBase>,
        index_register: Option<RegisterView>,
        scale: u8,
        displacement: i64,
    ) -> Operand {
        Operand {
            index,
            width_bits,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Memory(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                segment_base: None,
                base,
                index: index_register.map(MemoryIndex::Register),
                scale,
                displacement,
                displacement_width_bits: 32,
            }),
        }
    }

    fn rip() -> MemoryBase {
        MemoryBase::InstructionPointer { width_bits: 64 }
    }

    fn base_reg(register: RegisterId) -> MemoryBase {
        MemoryBase::Register(RegisterView::full(register, 64))
    }

    // mov r64, [base + disp] / mov r64, [rip + disp32]
    fn mov_r64_mem64(dst: RegisterId, base: Option<MemoryBase>, displacement: i64, length: u8) -> DecodedInstruction {
        insn(
            forms::MOV_R64_MEM64,
            length,
            vec![
                reg_op(0, 64, AccessKind::Write, dst),
                mem_op(1, 64, AccessKind::Read, base, None, 1, displacement),
            ],
        )
    }

    fn mov_r32_mem32(dst: RegisterId, base: Option<MemoryBase>, displacement: i64) -> DecodedInstruction {
        insn(
            forms::MOV_R32_MEM32,
            3,
            vec![
                reg_op(0, 32, AccessKind::Write, dst),
                mem_op(1, 32, AccessKind::Read, base, None, 1, displacement),
            ],
        )
    }

    fn mov_r64_r64(dst: RegisterId, src: RegisterId) -> DecodedInstruction {
        insn(
            forms::MOV_R64_R64,
            3,
            vec![
                reg_op(0, 64, AccessKind::Write, dst),
                reg_op(1, 64, AccessKind::Read, src),
            ],
        )
    }

    fn cmp_r32_imm8(register: RegisterId, value: u64) -> DecodedInstruction {
        insn(
            forms::CMP_R32_IMM8,
            3,
            vec![reg_op(0, 32, AccessKind::Read, register), imm_op(1, value)],
        )
    }

    // jmp [base + index*scale + disp32]
    fn jmp_mem64(
        base: Option<MemoryBase>,
        index_register: Option<(RegisterId, u16)>,
        scale: u8,
        displacement: i64,
    ) -> DecodedInstruction {
        insn(
            forms::JMP_INDIRECT_MEM64,
            7,
            vec![mem_op(
                0,
                64,
                AccessKind::Read,
                base,
                index_register.map(|(register, width)| RegisterView::full(register, width)),
                scale,
                displacement,
            )],
        )
    }

    // jmp *r64
    fn jmp_r64(register: RegisterId) -> DecodedInstruction {
        insn(
            forms::JMP_INDIRECT_R64,
            3,
            vec![reg_op(0, 64, AccessKind::Read, register)],
        )
    }

    fn ret() -> DecodedInstruction {
        insn(forms::RET, 1, Vec::new())
    }

    /// Assign sequential addresses to a block body starting at
    /// `native_pc` (lengths come from the synthetic encodings above).
    fn laid_out(native_pc: Address, body: &mut [DecodedInstruction]) -> VpcBlock<'_> {
        let mut cursor = native_pc;
        for instruction in body.iter_mut() {
            instruction.address = cursor;
            cursor += u64::from(instruction.length);
        }
        VpcBlock {
            native_pc,
            instructions: body,
        }
    }

    #[test]
    fn heuristic1_dispatch_read_flags_redefined_index() {
        // mov rax, [rsi]              ; VPC redefined by the handler itself
        // jmp [rip + rax*8 + 0x1234]  ; dispatch read through the VPC
        let mut body = vec![
            mov_r64_mem64(RAX, Some(base_reg(RSI)), 0, 3),
            jmp_mem64(Some(rip()), Some((RAX, 64)), 8, 0x1234),
        ];
        let blocks = [laid_out(0x1000, &mut body)];
        let found = identify_vpc_candidates(&blocks);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].native_pc, 0x1000);
        assert_eq!(found[0].register, RAX);
        assert_eq!(found[0].confidence, DISPATCH_READ_CONFIDENCE);
        // RIP-relative anchor: jmp at 0x1003 (3-byte mov) + 7 + displacement.
        assert_eq!(found[0].table_base, Some(0x1003 + 7 + 0x1234));

        // Same dispatch read, but the table base is register-held: the
        // anchor is unknowable statically and must come back `None`.
        let mut body = vec![
            mov_r64_mem64(RAX, Some(base_reg(RSI)), 0, 3),
            jmp_mem64(Some(base_reg(R15)), Some((RAX, 64)), 8, 0),
        ];
        let blocks = [laid_out(0x2000, &mut body)];
        let found = identify_vpc_candidates(&blocks);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].native_pc, 0x2000);
        assert_eq!(found[0].confidence, DISPATCH_READ_CONFIDENCE);
        assert_eq!(found[0].table_base, None);
    }

    #[test]
    fn heuristic2_table_load_then_jump_through() {
        // mov rbx, [rip + 0x2000]  ; handler entry fetched from the table
        // jmp *rbx                 ; ... and the block jumps through it
        let mut body = vec![mov_r64_mem64(RBX, Some(rip()), 0x2000, 7), jmp_r64(RBX)];
        let blocks = [laid_out(0x3000, &mut body)];
        let found = identify_vpc_candidates(&blocks);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].native_pc, 0x3000);
        assert_eq!(found[0].register, RBX);
        assert_eq!(found[0].confidence, TABLE_LOAD_CHAIN_CONFIDENCE);
        // Anchor of the defining load, not of the register jump.
        assert_eq!(found[0].table_base, Some(0x3000 + 7 + 0x2000));
    }

    #[test]
    fn heuristic3_themida_stable_vpc_across_siblings() {
        // Three sibling handler blocks. Each reloads RDX from the
        // VM_CONTEXT base (RBX) at a *different* offset — randomized per
        // the Themida-Research VM_CONTEXT note — then dispatches through
        // one shared table with RDX as index: Themida's stable VPC.
        let starts = [0x4000u64, 0x4200, 0x4400];
        let offsets = [0x1F3i64, 0xA7, 0x2C1];
        let mut bodies: Vec<Vec<DecodedInstruction>> = offsets
            .iter()
            .map(|&offset| {
                vec![
                    mov_r64_mem64(RDX, Some(base_reg(RBX)), offset, 4),
                    jmp_mem64(Some(rip()), Some((RDX, 64)), 8, 0xB00),
                ]
            })
            .collect();
        let blocks: Vec<VpcBlock<'_>> = starts
            .iter()
            .zip(bodies.iter_mut())
            .map(|(&start, body)| laid_out(start, body))
            .collect();
        let found = identify_vpc_candidates(&blocks);
        assert_eq!(found.len(), 3);
        for (candidate, &start) in found.iter().zip(starts.iter()) {
            assert_eq!(candidate.native_pc, start);
            assert_eq!(candidate.register, RDX);
            // Cross-block corroboration outranks the bare dispatch read.
            assert_eq!(candidate.confidence, STABLE_VPC_CONFIDENCE);
            let jmp_at = start + 4;
            assert_eq!(candidate.table_base, Some(jmp_at + 7 + 0xB00));
        }
    }

    #[test]
    fn heuristic4_vmp_volatile_vpc_register_rotation() {
        // block A: jmp *rbx                 ; incoming VPC lives in RBX
        // block B: mov rcx, rbx ; jmp *rcx  ; handler rotates VPC into RCX
        let mut body_a = vec![jmp_r64(RBX)];
        let mut body_b = vec![mov_r64_r64(RCX, RBX), jmp_r64(RCX)];
        let blocks = [laid_out(0x5000, &mut body_a), laid_out(0x5010, &mut body_b)];
        let found = identify_vpc_candidates(&blocks);
        assert_eq!(found.len(), 2);
        assert_eq!(
            (found[0].native_pc, found[0].register, found[0].confidence),
            (0x5000, RBX, VOLATILE_VPC_CONFIDENCE)
        );
        assert_eq!(
            (found[1].native_pc, found[1].register, found[1].confidence),
            (0x5010, RCX, VOLATILE_VPC_CONFIDENCE)
        );
        // Register-indirect dispatch: no table anchor.
        assert!(found.iter().all(|candidate| candidate.table_base.is_none()));
    }

    #[test]
    fn negative_control_plain_switch_tables_not_flagged() {
        // (a) post-split switch dispatch: a bare `jmp [rip + eax*8 + d]`
        //     whose index is defined *outside* the block — no in-block
        //     redefinition, so no live dispatch chain.
        // (b) guarded switch: the index IS loaded in-block but is
        //     bounds-checked (`cmp eax, 3`) before the table jump.
        // (c) a second sibling copy of (b): two switch tables on the same
        //     register still do not make a stable VPC.
        // (d) straight-line block without any dispatch terminator.
        let mut body_a = vec![jmp_mem64(Some(rip()), Some((RAX, 32)), 8, 0x777)];
        let mut body_b = vec![
            mov_r32_mem32(RAX, Some(base_reg(RBP)), 8),
            cmp_r32_imm8(RAX, 3),
            jmp_mem64(Some(rip()), Some((RAX, 32)), 8, 0x888),
        ];
        let mut body_c = body_b.clone();
        let mut body_d = vec![mov_r64_r64(RAX, RBX), ret()];
        let blocks = [
            laid_out(0x6000, &mut body_a),
            laid_out(0x6100, &mut body_b),
            laid_out(0x6200, &mut body_c),
            laid_out(0x6400, &mut body_d),
        ];
        assert!(identify_vpc_candidates(&blocks).is_empty());
        assert!(identify_vpc_candidates(&[]).is_empty());
    }
}

// Integrator: add `pub mod vpc;` to crates/angryier-cfg/src/lib.rs to wire this module in.
