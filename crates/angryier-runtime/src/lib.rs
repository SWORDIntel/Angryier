#![forbid(unsafe_code)]

//! End-to-end pipeline glue wiring loader, decoder, semantics, IR lowering,
//! concrete interpreter, and SimProcedure dispatch.
//!
//! This crate owns the orchestration that connects previously-isolated
//! components into a single execution pipeline:
//!
//! ```text
//! Elf64Loader → Decoder → SemanticRegistry → SemanticBlockBuilder
//!             → SealedRichSemanticBlock → BasicSemanticLowerer → IrBlock
//!             → ConcreteInterpreter → SimProcedureRegistry
//! ```
//!
//! The runtime is generic over the decoder backend so it works with both
//! native XED (behind feature gates) and synthetic decoders for testing.

use std::collections::BTreeMap;

use angryier_arch::Decoder;
use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::{BasicSemanticLowerer, IrBlock};
use angryier_loader::{Elf64Loader, ImageLoader, LoadedImage};
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_models::{SimProcedureRegistry, SimResult, SimState};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, SemanticRegistry, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::Intel64CorpusRegistry;
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::{
    Address, BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};

/// Default stack size in bytes (64 KiB).
const STACK_SIZE: u64 = 0x1_0000;

/// Default stack base address (grows down from here).
const STACK_BASE: Address = 0x7fff_0000_0000;

/// Maximum x86-64 instruction length in bytes.
const MAX_INSN_LEN: usize = 15;

/// Errors produced by the runtime pipeline.
#[derive(Debug)]
pub enum RuntimeError {
    /// Loader failed to parse the image.
    Loader(angryier_loader::LoaderError),
    /// Decoder failed to decode instruction bytes.
    Decode(String),
    /// No semantic provider matched the decoded instruction.
    UnsupportedForm(u32),
    /// Semantic provider failed to emit a block.
    Semantic(String),
    /// IR lowering failed.
    Lowering(String),
    /// Concrete interpreter failed.
    Execution(String),
    /// Memory operation failed.
    Memory(String),
    /// Register operation failed.
    Register(String),
    /// SimProcedure dispatch failed.
    SimProcedure(String),
    /// Execution exceeded the step budget.
    StepLimitExceeded,
    /// Forking is not supported in concrete mode.
    ForkInConcreteMode,
    /// No executable segment was found in the loaded image.
    NoExecutableSegment,
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loader(e) => write!(f, "loader error: {e:?}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::UnsupportedForm(form) => write!(f, "no semantic provider for form {form:#x}"),
            Self::Semantic(e) => write!(f, "semantic error: {e}"),
            Self::Lowering(e) => write!(f, "lowering error: {e}"),
            Self::Execution(e) => write!(f, "execution error: {e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            Self::Register(e) => write!(f, "register error: {e}"),
            Self::SimProcedure(e) => write!(f, "simproc error: {e}"),
            Self::StepLimitExceeded => write!(f, "step limit exceeded"),
            Self::ForkInConcreteMode => write!(f, "fork encountered in concrete mode"),
            Self::NoExecutableSegment => write!(f, "no executable segment in image"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Outcome of a single execution step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// One instruction was decoded, lowered, and executed.
    Stepped {
        pc: Address,
        next_pc: Address,
        length: u8,
        form_id: u32,
    },
    /// A SimProcedure was dispatched at this address.
    SimProcedure { address: Address, name: String },
    /// Execution terminated (return instruction or exit).
    Terminated { pc: Address },
    /// A trap was raised.
    Trap { pc: Address, vector: u32 },
}

/// Summary of a completed run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummary {
    pub steps: u64,
    pub final_pc: Address,
    pub simproc_dispatches: u64,
    pub terminated: bool,
}

/// A loaded process with execution state.
pub struct Process {
    pub image_id: ImageId,
    pub target_profile: TargetProfileId,
    pub entry: Address,
    pub state: ExecutionState<PersistentRegisters, PersistentMemory>,
    pub block_cache: BTreeMap<Address, IrBlock>,
    pub simproc_hooks: BTreeMap<Address, String>,
    pub next_block_id: u64,
    pub step_count: u64,
    pub simproc_dispatches: u64,
    pub terminated: bool,
}

impl Process {
    /// Registers a SimProcedure hook at a specific address.
    pub fn hook_simproc(&mut self, address: Address, name: &str) {
        self.simproc_hooks.insert(address, name.to_string());
    }

    /// Reads the current program counter (RIP).
    pub fn pc(&self) -> Result<Address, RuntimeError> {
        let bytes = self
            .state
            .registers
            .read(register_id::RIP.0)
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Writes the program counter (RIP).
    fn write_pc(&mut self, pc: Address) -> Result<(), RuntimeError> {
        self.state.registers = self
            .state
            .registers
            .write(register_id::RIP.0, &pc.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        Ok(())
    }

    /// Reads a register as u64.
    pub fn read_register(&self, register: u32) -> Result<u64, RuntimeError> {
        let bytes = self
            .state
            .registers
            .read(register)
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(u64::from_le_bytes(buf))
    }
}

/// The end-to-end execution pipeline, generic over the decoder backend.
pub struct Runtime<D: Decoder> {
    pub decoder: D,
    pub registry: Intel64CorpusRegistry,
    pub lowerer: BasicSemanticLowerer,
    pub interpreter: ConcreteInterpreter<PersistentRegisters, PersistentMemory>,
    pub simprocs: SimProcedureRegistry,
    pub semantic_version: SemanticVersion,
    pub target_profile: TargetProfileId,
    pub context: SemanticContext,
}

impl<D: Decoder> Runtime<D> {
    /// Creates a new runtime with the given decoder, semantic version, and target profile.
    pub fn new(decoder: D, semantic_version: SemanticVersion, target_profile: TargetProfileId) -> Self {
        Self {
            decoder,
            registry: Intel64CorpusRegistry::new(semantic_version),
            lowerer: BasicSemanticLowerer,
            interpreter: ConcreteInterpreter::new(),
            simprocs: SimProcedureRegistry::with_stubs(),
            semantic_version,
            target_profile,
            context: SemanticContext {
                semantic_version,
                target_profile,
                fidelity: FidelityProfile::Prove,
                vector_representation: VectorRepresentation::HybridLazy,
                tile_representation: TileRepresentation::LazyChunked,
                floating_point_policy: FloatingPointPolicy::SmtFpPreferred,
            },
        }
    }

    /// Loads an ELF64 image from raw bytes and creates a Process.
    pub fn load_elf(&self, bytes: &[u8]) -> Result<Process, RuntimeError> {
        let loader = Elf64Loader::new();
        let image = loader.load(bytes).map_err(RuntimeError::Loader)?;
        self.load_image(image)
    }

    /// Creates a Process from an already-loaded image.
    pub fn load_image(&self, image: LoadedImage) -> Result<Process, RuntimeError> {
        if image.target_profile != self.target_profile {
            return Err(RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat));
        }

        // Convert loader segments to memory regions.
        let mut regions: Vec<MemoryRegion> = Vec::with_capacity(image.segments.len() + 1);
        for seg in &image.segments {
            let size = u64::try_from(seg.bytes.len())
                .map_err(|_| RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat))?;
            regions.push(MemoryRegion {
                object: angryier_types::ObjectId(0),
                base: seg.address,
                size,
                readable: seg.readable,
                writable: seg.writable,
                executable: seg.executable,
            });
        }

        // Add a stack region.
        regions.push(MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: STACK_BASE - STACK_SIZE,
            size: STACK_SIZE,
            readable: true,
            writable: true,
            executable: false,
        });

        let mut memory = PersistentMemory::new(regions).map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // Load segment bytes into memory.
        for seg in &image.segments {
            if seg.bytes.is_empty() {
                continue;
            }
            memory = memory
                .load_concrete(seg.address, &seg.bytes)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        }

        // Initialize registers with Intel64 canonical widths.
        let reg_file = Intel64RegisterFile::canonical();
        let widths: Vec<(u32, usize)> = reg_file
            .architectural_registers
            .iter()
            .map(|(reg, bits)| {
                let bytes = usize::from(*bits).div_ceil(8);
                (reg.0, bytes)
            })
            .collect();
        let mut registers =
            PersistentRegisters::from_widths(widths).map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Set RIP to entry point.
        registers = registers
            .write(register_id::RIP.0, &image.entry.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Set RSP to top of stack region (aligned to 16 bytes).
        let stack_top = STACK_BASE & !0xF;
        registers = registers
            .write(register_id::GPR_BASE + 4, &stack_top.to_le_bytes()) // RSP = GPR 4
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Zero RFLAGS.
        registers = registers
            .write(register_id::RFLAGS.0, &0u64.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        let state = ExecutionState {
            id: StateId(0),
            parent: None,
            target_profile: image.target_profile,
            registers,
            memory,
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        };

        Ok(Process {
            image_id: image.id,
            target_profile: image.target_profile,
            entry: image.entry,
            state,
            block_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            next_block_id: 0,
            step_count: 0,
            simproc_dispatches: 0,
            terminated: false,
        })
    }

    /// Executes a single instruction at the current PC.
    pub fn step(&self, process: &mut Process) -> Result<StepOutcome, RuntimeError> {
        if process.terminated {
            return Ok(StepOutcome::Terminated { pc: process.pc()? });
        }

        let pc = process.pc()?;

        // Check for SimProcedure hooks.
        if let Some(name) = process.simproc_hooks.get(&pc).cloned() {
            return self.dispatch_simproc(process, pc, &name);
        }

        // Read instruction bytes from memory.
        let bytes = process
            .state
            .memory
            .read(pc, MAX_INSN_LEN)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        let raw: Vec<u8> = bytes
            .iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => *v,
                ByteValue::Symbolic(_) => 0,
            })
            .collect();
        if raw.is_empty() {
            return Err(RuntimeError::Decode("no bytes at PC".into()));
        }

        // Decode.
        let decoded = self
            .decoder
            .decode(pc, &raw)
            .map_err(|e| RuntimeError::Decode(format!("{e:?}")))?;

        // Resolve semantic provider.
        let resolution = self
            .registry
            .resolve(&decoded, self.semantic_version)
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Find the provider by rule_id.
        let provider = self
            .registry
            .providers()
            .iter()
            .find(|p| p.rule_id() == resolution.rule_id)
            .ok_or(RuntimeError::UnsupportedForm(decoded.form_id))?;

        // Emit semantic block.
        let mut builder = SemanticBlockBuilder::new(self.semantic_version);
        provider
            .emit(&self.context, &decoded, &mut builder)
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Seal the block.
        let sealed = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Build BlockValidityKey.
        let block_id = BlockId(process.next_block_id);
        process.next_block_id += 1;

        let code_versions = process
            .state
            .memory
            .code_version_guards_for_range(pc, usize::from(decoded.length))
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        let validity_key = BlockValidityKey {
            image: process.image_id,
            block: block_id,
            address: pc,
            semantic_version: self.semantic_version,
            target_profile: self.target_profile,
            code_versions,
        };

        // Lower to IR.
        let ir_block = self
            .lowerer
            .lower_with_decode(&sealed, &validity_key, &decoded)
            .map_err(|e| RuntimeError::Lowering(format!("{e:?}")))?;

        // Cache the block.
        process.block_cache.insert(pc, ir_block.clone());

        // Execute.
        let (new_state, outcome) = self
            .interpreter
            .execute_block(&process.state, &ir_block, ExecutionMode::Concrete)
            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;

        process.state = new_state;
        process.step_count += 1;

        let length = decoded.length;
        let form_id = decoded.form_id;

        match outcome {
            ExecutionOutcome::Continue { next_pc, .. } => {
                process.write_pc(next_pc)?;
                Ok(StepOutcome::Stepped {
                    pc,
                    next_pc,
                    length,
                    form_id,
                })
            }
            ExecutionOutcome::Fork { .. } => Err(RuntimeError::ForkInConcreteMode),
            ExecutionOutcome::Terminated { .. } => {
                process.terminated = true;
                Ok(StepOutcome::Terminated { pc })
            }
            ExecutionOutcome::Trap { vector, .. } => {
                process.terminated = true;
                Ok(StepOutcome::Trap { pc, vector })
            }
        }
    }

    /// Runs execution for up to `max_steps` instructions.
    pub fn run(&self, process: &mut Process, max_steps: u64) -> Result<RunSummary, RuntimeError> {
        while !process.terminated && process.step_count < max_steps {
            let _ = self.step(process)?;
        }
        if !process.terminated && process.step_count >= max_steps {
            return Err(RuntimeError::StepLimitExceeded);
        }
        Ok(RunSummary {
            steps: process.step_count,
            final_pc: process.pc()?,
            simproc_dispatches: process.simproc_dispatches,
            terminated: process.terminated,
        })
    }

    /// Dispatches a SimProcedure at the given address.
    fn dispatch_simproc(
        &self,
        process: &mut Process,
        address: Address,
        name: &str,
    ) -> Result<StepOutcome, RuntimeError> {
        // Bridge ExecutionState → SimState.
        let mut sim_state = SimState::new();

        // Copy GPRs (RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7).
        for index in 0u32..8 {
            let reg_id = register_id::GPR_BASE + index;
            if let Ok(val) = process.state.registers.read(reg_id) {
                let mut buf = [0u8; 8];
                let len = val.len().min(8);
                buf[..len].copy_from_slice(&val[..len]);
                sim_state.set_reg(u64::from(index), u64::from_le_bytes(buf));
            }
        }

        let result = self
            .simprocs
            .apply_by_name(name, &sim_state)
            .ok_or_else(|| RuntimeError::SimProcedure(format!("unknown procedure: {name}")))?;

        process.simproc_dispatches += 1;

        match result {
            SimResult::Return(val) => {
                // Write return value to RAX (GPR 0).
                process.state.registers = process
                    .state
                    .registers
                    .write(register_id::GPR_BASE, &val.to_le_bytes())
                    .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

                // Advance PC past the call instruction (simulate return).
                // For hooked stubs, we advance by 1 byte as a minimal convention.
                let next_pc = address.wrapping_add(1);
                process.write_pc(next_pc)?;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
            SimResult::Exit => {
                process.terminated = true;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
            SimResult::Continue(_) => {
                // For continue results, advance PC by 1.
                let next_pc = address.wrapping_add(1);
                process.write_pc(next_pc)?;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
        }
    }
}

/// Loads an ELF64 file from disk.
pub fn load_elf_file(path: &str) -> Result<Vec<u8>, RuntimeError> {
    std::fs::read(path).map_err(|_| RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{DecodedInstruction, InstructionModifiers};

    /// A synthetic decoder that maps byte patterns to known instructions.
    /// This lets us test the full pipeline without requiring native XED.
    #[derive(Debug, Clone)]
    struct SyntheticDecoder {
        forms: BTreeMap<u8, (u32, u8)>,
    }

    impl SyntheticDecoder {
        fn new() -> Self {
            let mut forms = BTreeMap::new();
            // Map specific opcodes to (form_id, length).
            // 0x90 = NOP (form NOP2, length 1)
            // 0xC3 = RET (form RET, length 1)
            forms.insert(0x90, (angryier_semantics_intel64::forms::NOP2, 1));
            forms.insert(0xC3, (angryier_semantics_intel64::forms::RET, 1));
            Self { forms }
        }
    }

    impl Decoder for SyntheticDecoder {
        type Error = String;

        fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
            if bytes.is_empty() {
                return Err("empty input".into());
            }
            let opcode = bytes[0];
            let (form_id, length) = self
                .forms
                .get(&opcode)
                .copied()
                .ok_or_else(|| format!("unknown opcode: {opcode:#x}"))?;

            Ok(DecodedInstruction {
                address,
                length,
                form_id,
                features: Vec::new(),
                operands: Vec::new(),
                modifiers: InstructionModifiers::default(),
            })
        }
    }

    /// Builds a minimal synthetic ELF64 image with given code bytes.
    fn build_elf(code: &[u8]) -> Vec<u8> {
        // We use the real Elf64Loader, so we need a valid ELF64 header.
        // Build a minimal statically-linked ELF64 with one executable segment.
        use angryier_loader::INTEL64_TARGET_PROFILE;

        let segment_base = 0x400000u64;

        // ELF64 header (64 bytes) + program header (56 bytes) = 120 bytes.
        // Code starts at offset 120.
        let header_len = 64usize;
        let phdr_len = 56usize;
        let code_offset = header_len + phdr_len;
        // Pad to page boundary so instruction reads (up to 15 bytes) don't
        // run past the mapped segment.
        let min_size = code_offset + code.len() + MAX_INSN_LEN;
        let total_size = min_size.next_multiple_of(0x1000);

        // Entry point is at the code, not the ELF header.
        let entry = segment_base + code_offset as u64;

        let mut buf = vec![0u8; total_size];

        // ELF header.
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little-endian
        buf[6] = 1; // EV_CURRENT
        buf[7] = 0; // SYSV ABI
        buf[8..16].copy_from_slice(&[0u8; 8]); // padding

        // e_type = ET_EXEC (2)
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = EM_X86_64 (62)
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version = 1
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        buf[24..32].copy_from_slice(&entry.to_le_bytes());
        // e_phoff = 64
        buf[32..40].copy_from_slice(&(64u64).to_le_bytes());
        // e_shoff = 0
        buf[40..48].copy_from_slice(&0u64.to_le_bytes());
        // e_flags = 0
        buf[48..52].copy_from_slice(&0u32.to_le_bytes());
        // e_ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize = 56
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum = 1
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        // e_shentsize = 0
        buf[58..60].copy_from_slice(&0u16.to_le_bytes());
        // e_shnum = 0
        buf[60..62].copy_from_slice(&0u16.to_le_bytes());
        // e_shstrndx = 0
        buf[62..64].copy_from_slice(&0u16.to_le_bytes());

        // Program header (PT_LOAD).
        // p_type = PT_LOAD (1)
        buf[64..68].copy_from_slice(&1u32.to_le_bytes());
        // p_flags = R|X (5)
        buf[68..72].copy_from_slice(&5u32.to_le_bytes());
        // p_offset = 0
        buf[72..80].copy_from_slice(&0u64.to_le_bytes());
        // p_vaddr = segment_base
        buf[80..88].copy_from_slice(&segment_base.to_le_bytes());
        // p_paddr = segment_base
        buf[88..96].copy_from_slice(&segment_base.to_le_bytes());
        // p_filesz = total_size
        buf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
        // p_memsz = total_size
        buf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
        // p_align = 0x1000
        buf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

        // Code bytes.
        buf[code_offset..code_offset + code.len()].copy_from_slice(code);

        let _ = INTEL64_TARGET_PROFILE;
        buf
    }

    #[test]
    fn runtime_loads_and_executes_nop_ret() -> Result<(), RuntimeError> {
        // Code: NOP; NOP; RET
        let code = [0x90, 0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;
        assert_eq!(entry, 0x400078);
        assert_eq!(process.pc()?, entry);

        // Step 1: NOP at entry
        let outcome = runtime.step(&mut process)?;
        assert!(matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry && next_pc == entry + 1));
        assert_eq!(process.pc()?, entry + 1);

        // Step 2: NOP at entry+1
        let outcome = runtime.step(&mut process)?;
        assert!(matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry + 1 && next_pc == entry + 2));
        assert_eq!(process.pc()?, entry + 2);

        // Step 3: RET at entry+2
        // The RET semantic provider is simplified: it increments RSP and
        // falls through to the next instruction (the actual indirect jump
        // to the return address is deferred to a later memory-load pass).
        let outcome = runtime.step(&mut process)?;
        assert!(matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry + 2 && next_pc == entry + 3));
        assert_eq!(process.pc()?, entry + 3);

        // Run summary.
        let summary = RunSummary {
            steps: process.step_count,
            final_pc: process.pc()?,
            simproc_dispatches: process.simproc_dispatches,
            terminated: process.terminated,
        };
        assert_eq!(summary.steps, 3);
        assert!(!summary.terminated);

        Ok(())
    }

    #[test]
    fn runtime_caches_lowered_blocks() -> Result<(), RuntimeError> {
        let code = [0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;

        // Execute NOP.
        runtime.step(&mut process)?;

        // Block cache should contain the lowered block at entry.
        assert!(process.block_cache.contains_key(&entry));
        let block = &process.block_cache[&entry];
        assert!(!block.instructions.is_empty());

        Ok(())
    }

    #[test]
    fn runtime_dispatches_simproc_exit() -> Result<(), RuntimeError> {
        // Code: NOP; RET (but we hook the NOP address as exit)
        let code = [0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;

        // Hook the entry address as "exit".
        process.hook_simproc(entry, "exit");

        // Step should dispatch the exit SimProcedure.
        let outcome = runtime.step(&mut process)?;
        assert!(
            matches!(outcome, StepOutcome::SimProcedure { address, ref name } if address == entry && name == "exit")
        );
        assert!(process.terminated);
        assert_eq!(process.simproc_dispatches, 1);

        Ok(())
    }

    #[test]
    fn runtime_run_respects_step_limit() -> Result<(), RuntimeError> {
        // Code: NOP; NOP; NOP; RET
        let code = [0x90, 0x90, 0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;

        // Run with step limit of 2 (should hit limit before RET).
        let result = runtime.run(&mut process, 2);
        assert!(matches!(result, Err(RuntimeError::StepLimitExceeded)));
        assert_eq!(process.step_count, 2);
        assert!(!process.terminated);

        Ok(())
    }
}
