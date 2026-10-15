//! Themida dispatch-site classification and base-provenance analysis.
//!
//! Data-driven design: the 2026-10-15 census of the unpacked Sarin Advisor
//! image (`ADVISOR_SYMEX_SESSION_20261015/dispatch_census_report.md`,
//! 75M instructions swept across `.themida`/`.boot` at 95.9% decode rate)
//! measured what indirect dispatch actually looks like inside a commercial
//! VM protector — and it is NOT the compiler switch-table shape:
//!
//! * class b (PIE `mov e,[base+idx*s]; add e,base; jmp e`): **0 sites** —
//!   the MSVC switch idiom the CFG resolver targets is absent;
//! * class a (`jmp [base+idx*scale+disp]`): 60,430 sites, but only **1.4%**
//!   carry a discoverable `cmp idx,imm` bound and **0/200** sampled have a
//!   statically recoverable base — the base register is data-dependent;
//! * class a′ (`jmp [base+disp]`, no index): **540,992 sites — the dominant
//!   shape**: handler dispatch through a table hanging off a *context
//!   register*, exactly the Themida VM_CONTEXT model (randomized offsets,
//!   Themida-Research);
//! * class c (RIP slots — import/wrap trampolines): 16,772;
//! * class d (raw `jmp/call reg` — handler tail-jumps): 136,035.
//!
//! So static table resolution is nearly useless inside the VM; what IS
//! tractable statically is *classifying* every unresolved indirect exit by
//! where its base comes from. That classification is this module's product:
//! it turns `EdgeKind::IndirectJump` exits into annotated dispatch sites a
//! context-sensitive / VPC-aware pass (see [`crate::vpc`]) can consume —
//! a′ sites whose base tracks one stable context register are Themida's
//! handler dispatch (stable VPC); `d` sites fed by `pop` chains are
//! handler tail-jumps; `c` sites are the known import-wrap slots.
//!
//! Wiring (integrator): add `pub mod themida;` to `angryier-cfg/src/lib.rs`.

use angryier_arch::{
    AccessKind, DecodedInstruction, MemoryBase, MemoryIndex, OperandKind, RegisterId,
};

/// Dispatch shape of one indirect control-transfer site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchKind {
    /// `jmp/call [base + idx*scale + disp]` — census class a. The index is
    /// the virtual opcode; scale ∈ {1,2,4,8} all occur in the wild.
    Indexed { scale: u8, has_disp: bool },
    /// `jmp/call [base + disp]` with NO index — census class a′, the
    /// dominant Themida handler-dispatch shape (541k sites). The table
    /// hangs off the context register; `disp` is the (per-build random)
    /// VM_CONTEXT member offset.
    ContextTable { disp: i64 },
    /// `jmp/call [rip + disp]` — census class c: import/wrap trampoline
    /// slots; outside VM analysis (already modeled as wrap slots).
    RipSlot,
    /// `jmp/call reg` — census class d: handler tail-jumps and mutated
    /// computed branches; needs register-chain provenance.
    RegisterRaw,
}

/// Where the dispatch base register's value comes from, established by a
/// bounded backward walk over the block's instructions. Mirrors the census
/// base-def methodology (which measured: constant defs ~0%, clobbers via
/// mov/add/pop/xchg dominate) — provenance, not value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseProvenance {
    /// Defined by `mov reg, imm` / RIP-relative `lea` — statically known;
    /// the standard CFG resolver's territory, not the VM's.
    Constant,
    /// Loaded from another register that this block does not define —
    /// the *context register* candidate (VM_CONTEXT pointer). `depth`
    /// counts the in-block `mov reg,reg` hops walked to reach it.
    ContextRegister { source: RegisterId, depth: u8 },
    /// Pushed earlier and popped into the base register inside this block
    /// — a saved context restore (census saw `clobber:pop` ×10/200).
    PoppedFromStack,
    /// Defined by arithmetic on another register (`add/lea reg,[reg+…]`) —
    /// a *derived* context pointer (context + member offset).
    DerivedFrom { source: RegisterId },
    /// Rewritten by an instruction this analysis does not model.
    Clobbered,
    /// No defining instruction within the analysis window.
    NoLocalDef,
}

/// One classified indirect-transfer site.
#[derive(Clone, Debug)]
pub struct DispatchSite {
    pub native_pc: u64,
    pub kind: DispatchKind,
    /// Base-register provenance for memory-indirect sites (`None` for
    /// `RegisterRaw`, where [`DispatchSite::chain_register`] applies).
    pub base: Option<(RegisterId, BaseProvenance)>,
    /// For `RegisterRaw`: the jumped-through register.
    pub chain_register: Option<RegisterId>,
    /// Index register for `Indexed` sites — the virtual-opcode register
    /// and a direct [`crate::vpc`] candidate.
    pub index_register: Option<RegisterId>,
}

/// Instructions a dispatch site is analyzed against — the tail of a basic
/// block ending in the indirect transfer (order = execution order).
pub struct DispatchWindow<'a> {
    pub instructions: &'a [DecodedInstruction],
}

/// Maximum instructions walked backward from the terminator while chasing
/// base provenance. The census used ≤16 for base defs and ≤8 for the PIE
/// pair; 16 covers both without following whole handlers.
pub const PROVENANCE_WINDOW: usize = 16;

impl DispatchWindow<'_> {
    /// Classifies the window's final instruction (assumed to be the
    /// indirect `jmp`/`call` terminator). Fail-closed: an operand shape
    /// this module does not recognize yields `None`.
    pub fn classify(&self) -> Option<DispatchSite> {
        let term = self.instructions.last()?;
        let pc = term.address;
        let mem = term.operands.iter().find_map(|op| match op.kind {
            OperandKind::Memory(mem) | OperandKind::AddressGeneration(mem) => Some(mem),
            _ => None,
        });
        if let Some(mem) = mem {
            // RIP-relative: wrap slot, no base analysis.
            if matches!(mem.base, Some(MemoryBase::InstructionPointer { .. })) {
                return Some(DispatchSite {
                    native_pc: pc,
                    kind: DispatchKind::RipSlot,
                    base: None,
                    chain_register: None,
                    index_register: None,
                });
            }
            let (base_reg, prov) = match mem.base {
                Some(MemoryBase::Register(view)) => {
                    (view.parent, self.provenance(view.parent))
                }
                _ => return None,
            };
            let kind = match mem.index {
                Some(MemoryIndex::Register(_idx)) => DispatchKind::Indexed {
                    scale: mem.scale,
                    has_disp: mem.displacement != 0,
                },
                None if mem.displacement != 0 => DispatchKind::ContextTable { disp: mem.displacement },
                None => DispatchKind::ContextTable { disp: 0 },
                Some(MemoryIndex::Vsib { .. }) => return None,
            };
            let index_register = match mem.index {
                Some(MemoryIndex::Register(idx)) => Some(idx.parent),
                _ => None,
            };
            return Some(DispatchSite {
                native_pc: pc,
                kind,
                base: Some((base_reg, prov)),
                chain_register: None,
                index_register,
            });
        }
        // Raw register transfer.
        let reg = term.operands.iter().find_map(|op| match op.kind {
            OperandKind::Register(view) => Some(view.parent),
            _ => None,
        })?;
        Some(DispatchSite {
            native_pc: pc,
            kind: DispatchKind::RegisterRaw,
            base: None,
            chain_register: Some(reg),
            index_register: None,
        })
    }

    /// Backward provenance walk for `reg` over the window (terminator
    /// excluded — it only reads). Conservative at every step.
    fn provenance(&self, reg: RegisterId) -> BaseProvenance {
        let Some(last) = self.instructions.len().checked_sub(1) else {
            return BaseProvenance::NoLocalDef;
        };
        let mut depth: u8 = 0;
        let mut target = reg;
        for insn in self.instructions[..last].iter().rev().take(PROVENANCE_WINDOW) {
            match Self::defines(insn, target) {
                Def::Constant => return BaseProvenance::Constant,
                Def::From(other) => {
                    // Follow one mov-chain hop; a second hop costs depth,
                    // more than two is untracked context.
                    if other == target {
                        return BaseProvenance::ContextRegister { source: other, depth };
                    }
                    if depth >= 2 {
                        return BaseProvenance::ContextRegister { source: other, depth };
                    }
                    depth = depth.saturating_add(1);
                    target = other;
                }
                Def::Popped => return BaseProvenance::PoppedFromStack,
                Def::Derived(other) => return BaseProvenance::DerivedFrom { source: other },
                Def::ClobberedByUnmodeled => return BaseProvenance::Clobbered,
                Def::No => continue,
            }
        }
        if depth > 0 {
            BaseProvenance::ContextRegister { source: target, depth }
        } else {
            BaseProvenance::NoLocalDef
        }
    }

    /// How `insn` relates to `reg`'s definition. Only writes matter; a
    /// read of `reg` does not affect provenance.
    fn defines(insn: &DecodedInstruction, reg: RegisterId) -> Def {
        let writes_reg = insn.operands.iter().any(|op| {
            matches!(op.access, AccessKind::Write | AccessKind::ReadWrite)
                && matches!(op.kind, OperandKind::Register(v) if v.parent == reg)
        });
        if !writes_reg {
            return Def::No;
        }
        use angryier_semantics_intel64::forms;
        match insn.form_id {
            forms::MOV_R64_IMM64 | forms::MOV_R32_IMM32 | forms::LEA_R64_MEM => Def::Constant,
            forms::MOV_R64_R64 | forms::MOV_R32_R32 | forms::MOVZX_R64_R32 | forms::MOVSX_R64_R32 => {
                match register_source(insn) {
                    Some(src) => Def::From(src),
                    None => Def::ClobberedByUnmodeled,
                }
            }
            forms::ADD_R64_IMM32 => {
                if let Some(src) = register_source(insn) {
                    Def::Derived(src)
                } else {
                    Def::Derived(reg)
                }
            }
            forms::ADD_R64_R64 | forms::SUB_R64_R64 => match register_source(insn) {
                Some(src) => Def::Derived(src),
                None => Def::Derived(reg),
            },
            forms::POP_R64 => Def::Popped,
            _ => Def::ClobberedByUnmodeled,
        }
    }
}

/// Internal: the definition relation of one instruction to one register.
enum Def {
    Constant,
    From(RegisterId),
    Derived(RegisterId),
    Popped,
    ClobberedByUnmodeled,
    No,
}

fn register_source(insn: &DecodedInstruction) -> Option<RegisterId> {
    insn.operands.iter().find_map(|op| match op.kind {
        OperandKind::Register(view)
            if matches!(op.access, AccessKind::Read) =>
        {
            Some(view.parent)
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, ImmediateOperand, InstructionModifiers, MemoryOperand, Operand,
        OperandVisibility, RegisterView,
    };
    use angryier_semantics_intel64::forms;

    fn view(id: u32) -> RegisterView {
        RegisterView::full(RegisterId(id), 64)
    }

    fn reg_op(index: u8, id: u32, access: AccessKind) -> Operand {
        Operand {
            index,
            width_bits: 64,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(view(id)),
        }
    }

    fn insn(addr: u64, form: u32, operands: Vec<Operand>) -> DecodedInstruction {
        DecodedInstruction {
            address: addr,
            length: 3,
            form_id: form,
            features: Vec::new(),
            operands,
            modifiers: InstructionModifiers::default(),
        }
    }

    fn mem_op(index: u8, base: Option<u32>, idx: Option<u32>, scale: u8, disp: i64) -> Operand {
        Operand {
            index,
            width_bits: 64,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Memory(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                segment_base: None,
                base: base.map(|b| MemoryBase::Register(view(b))),
                index: idx.map(|i| MemoryIndex::Register(view(i))),
                scale,
                displacement: disp,
                displacement_width_bits: 32,
            }),
        }
    }

    fn rip_mem_op(disp: i64) -> Operand {
        Operand {
            index: 0,
            width_bits: 64,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Memory(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                segment_base: None,
                base: Some(MemoryBase::InstructionPointer { width_bits: 64 }),
                index: None,
                scale: 1,
                displacement: disp,
                displacement_width_bits: 32,
            }),
        }
    }

    fn imm(v: u64) -> Operand {
        Operand {
            index: 1,
            width_bits: 64,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Immediate(ImmediateOperand { value: v, signed: false }),
        }
    }

    #[test]
    fn context_table_dominant_shape() {
        // mov rbx, r14 (context ptr, no local def) ; jmp [rbx+0x38]
        let block = [
            insn(0x10, forms::MOV_R64_R64, vec![reg_op(0, 2, AccessKind::Write), reg_op(1, 0xE, AccessKind::Read)]),
            insn(0x13, forms::JMP_INDIRECT_MEM64, vec![mem_op(0, Some(2), None, 1, 0x38)]),
        ];
        let w = DispatchWindow { instructions: &block };
        let site = w.classify().expect("site");
        assert_eq!(site.kind, DispatchKind::ContextTable { disp: 0x38 });
        let (base, prov) = site.base.expect("base");
        assert_eq!(base, RegisterId(2));
        match prov {
            // r14 (0xE) is the context register candidate, one hop away.
            BaseProvenance::ContextRegister { source, depth } => {
                assert_eq!(source, RegisterId(0xE));
                assert!(depth <= 2);
            }
            other => panic!("expected ContextRegister, got {other:?}"),
        }
    }

    #[test]
    fn indexed_dispatch_reports_index_register() {
        // jmp [rbx + rax*8 + 0x10]
        let block = [insn(
            0x20,
            forms::JMP_INDIRECT_MEM64,
            vec![mem_op(0, Some(2), Some(0), 8, 0x10)],
        )];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        assert_eq!(
            site.kind,
            DispatchKind::Indexed { scale: 8, has_disp: true }
        );
        assert_eq!(site.index_register, Some(RegisterId(0)));
        // Base with no local def: context candidate too (weaker).
        assert!(matches!(
            site.base.expect("base").1,
            BaseProvenance::NoLocalDef
        ));
    }

    #[test]
    fn rip_slot_is_not_vm_dispatch() {
        let block = [insn(0x30, forms::JMP_INDIRECT_MEM64, vec![rip_mem_op(0x1234)])];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        assert_eq!(site.kind, DispatchKind::RipSlot);
        assert!(site.base.is_none());
    }

    #[test]
    fn constant_base_is_resolver_territory() {
        // mov rbx, 0x145000000 ; jmp [rbx+0x38] — statically resolvable:
        // classified as ContextTable shape but Constant provenance, so the
        // VM passes skip it and the static resolver owns it.
        let block = [
            insn(0x40, forms::MOV_R64_IMM64, vec![reg_op(0, 2, AccessKind::Write), imm(0x1_4500_0000)]),
            insn(0x43, forms::JMP_INDIRECT_MEM64, vec![mem_op(0, Some(2), None, 1, 0x38)]),
        ];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        assert!(matches!(site.base.expect("base").1, BaseProvenance::Constant));
    }

    #[test]
    fn popped_base_is_context_restore() {
        // push r15 ... pop rbx ; jmp [rbx+0x40]
        let block = [
            insn(0x50, forms::POP_R64, vec![reg_op(0, 2, AccessKind::Write)]),
            insn(0x53, forms::JMP_INDIRECT_MEM64, vec![mem_op(0, Some(2), None, 1, 0x40)]),
        ];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        assert!(matches!(site.base.expect("base").1, BaseProvenance::PoppedFromStack));
    }

    #[test]
    fn raw_register_transfer_reports_chain() {
        // mov rax, rbx ; jmp rax  (handler tail-jump)
        let block = [
            insn(0x60, forms::MOV_R64_R64, vec![reg_op(0, 0, AccessKind::Write), reg_op(1, 3, AccessKind::Read)]),
            insn(0x63, forms::JMP_INDIRECT_R64, vec![reg_op(0, 0, AccessKind::Read)]),
        ];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        assert_eq!(site.kind, DispatchKind::RegisterRaw);
        assert_eq!(site.chain_register, Some(RegisterId(0)));
    }

    #[test]
    fn derived_base_keeps_source() {
        // add rbx, 0x20 ; jmp [rbx+0x38] — context member pointer.
        let block = [
            insn(0x70, forms::ADD_R64_IMM32, vec![reg_op(0, 2, AccessKind::ReadWrite)]),
            insn(0x73, forms::JMP_INDIRECT_MEM64, vec![mem_op(0, Some(2), None, 1, 0x38)]),
        ];
        let site = DispatchWindow { instructions: &block }.classify().expect("site");
        match site.base.expect("base").1 {
            BaseProvenance::DerivedFrom { source } => assert_eq!(source, RegisterId(2)),
            other => panic!("expected DerivedFrom, got {other:?}"),
        }
    }
}

// Integrator note — exact wiring:
//   1. `pub mod themida;` in angryier-cfg/src/lib.rs
//   2. (optional bridge) in the IndirectJump post-pass, after a site stays
//      unresolved, call `DispatchWindow { instructions: &block.instructions
//      }.classify()` and record the site on the block/edge for the VPC pass.
