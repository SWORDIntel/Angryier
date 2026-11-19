//! Smoke test: the A64 registry resolves decoded forms and the providers
//! emit structured IR into a mock builder without error.

use angryier_arch::Decoder;
use angryier_arch_arm64::{Arm64Decoder, forms};
use angryier_semantics::{
    DecodedInstructionView, EffectId, FloatingPointPolicy, FormId, OperandDescriptor, RegisterId, SemanticBuilder,
    SemanticContext, SemanticError, SemanticOp, SemanticRegistry, SemanticType, SideEffect, TileRepresentation,
    ValueId, VectorRepresentation,
};
use angryier_semantics_arm64::Arm64CorpusRegistry;
use angryier_types::{Address, FidelityProfile, SemanticVersion, TargetProfileId};

/// Minimal DecodedInstructionView wrapper over the arch crate's decode output.
#[derive(Debug)]
struct View {
    inner: angryier_arch::DecodedInstruction,
    operands: Vec<OperandDescriptor>,
}

impl View {
    fn new(inner: angryier_arch::DecodedInstruction) -> Self {
        let operands = inner
            .operands
            .iter()
            .enumerate()
            .map(|(i, op)| OperandDescriptor {
                index: i as u8,
                width_bits: op.width_bits,
                read: true,
                written: false,
                class: match op.kind {
                    angryier_arch::OperandKind::Register(_) => angryier_semantics::OperandClass::Register,
                    angryier_arch::OperandKind::Memory(_) => angryier_semantics::OperandClass::Memory,
                    angryier_arch::OperandKind::Immediate(_) => angryier_semantics::OperandClass::Immediate,
                    angryier_arch::OperandKind::RelativeBranch(_) => angryier_semantics::OperandClass::RelativeBranch,
                    _ => angryier_semantics::OperandClass::Register,
                },
                kind: op.kind,
            })
            .collect();
        Self { inner, operands }
    }
}

impl DecodedInstructionView for View {
    fn address(&self) -> Address {
        self.inner.address
    }
    fn form_id(&self) -> FormId {
        self.inner.form_id
    }
    fn length(&self) -> u8 {
        self.inner.length
    }
    fn feature_ids(&self) -> &[angryier_arch::FeatureId] {
        &self.inner.features
    }
    fn operand_count(&self) -> usize {
        self.operands.len()
    }
    fn operand(&self, index: u8) -> Option<OperandDescriptor> {
        self.operands.get(usize::from(index)).cloned()
    }
}

/// Counting mock builder: every IR op returns a fresh ValueId.
#[derive(Default, Debug)]
struct Mock {
    values: u32,
    effects: Vec<String>,
}

impl SemanticBuilder for Mock {
    fn constant(&mut self, _ty: SemanticType, _bytes_le: &[u8]) -> Result<ValueId, SemanticError> {
        self.values += 1;
        Ok(self.values)
    }
    fn read_register(&mut self, reg: RegisterId, _ty: SemanticType) -> Result<ValueId, SemanticError> {
        self.values += 1;
        self.effects.push(format!("read r{}", reg.0));
        Ok(self.values)
    }
    fn read_operand(&mut self, operand_index: u8, _ty: SemanticType) -> Result<ValueId, SemanticError> {
        self.values += 1;
        self.effects.push(format!("read op{operand_index}"));
        Ok(self.values)
    }
    fn read_predicated_operand(
        &mut self,
        _operand_index: u8,
        _mask: ValueId,
        _ty: SemanticType,
    ) -> Result<ValueId, SemanticError> {
        self.values += 1;
        Ok(self.values)
    }
    fn emit(&mut self, _op: SemanticOp, _ty: SemanticType, _inputs: &[ValueId]) -> Result<ValueId, SemanticError> {
        self.values += 1;
        Ok(self.values)
    }
    fn write_register(&mut self, reg: RegisterId, _value: ValueId) -> Result<EffectId, SemanticError> {
        self.effects.push(format!("write r{}", reg.0));
        Ok(self.effects.len() as u32)
    }
    fn write_operand(&mut self, operand_index: u8, _value: ValueId) -> Result<EffectId, SemanticError> {
        self.effects.push(format!("write op{operand_index}"));
        Ok(self.effects.len() as u32)
    }
    fn side_effect(&mut self, effect: SideEffect, _inputs: &[ValueId]) -> Result<EffectId, SemanticError> {
        self.effects.push(format!("side {effect:?}"));
        Ok(self.effects.len() as u32)
    }
    fn jump(&mut self, _target: ValueId) -> Result<EffectId, SemanticError> {
        self.effects.push("jump".into());
        Ok(self.effects.len() as u32)
    }
    fn jump_indirect(&mut self, _target: ValueId) -> Result<EffectId, SemanticError> {
        self.effects.push("jump_indirect".into());
        Ok(self.effects.len() as u32)
    }
    fn branch(&mut self, _condition: ValueId, _taken: ValueId, _not_taken: ValueId) -> Result<EffectId, SemanticError> {
        self.effects.push("branch".into());
        Ok(self.effects.len() as u32)
    }
}

fn context() -> SemanticContext {
    SemanticContext {
        semantic_version: SemanticVersion(1),
        target_profile: TargetProfileId(7),
        fidelity: FidelityProfile::Explore,
        vector_representation: VectorRepresentation::Packed,
        tile_representation: TileRepresentation::LazyChunked,
        floating_point_policy: FloatingPointPolicy::ControlledBitVectorFallback,
    }
}

fn decode(word: u32) -> Result<View, std::io::Error> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    let bytes = word.to_le_bytes();
    decoder
        .decode(0x1000, &bytes)
        .map(View::new)
        .map_err(std::io::Error::other)
}

#[test]
fn add_imm_emits_and_writes() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arm64CorpusRegistry::new();
    let insn = decode(0x9100_a108)?; // add x8, x8, #0x28
    let resolution = registry
        .resolve(&insn, SemanticVersion(1))
        .map_err(|err| std::io::Error::other(format!("ADD_X_IMM resolve failed: {err:?}")))?;
    let provider = registry
        .provider_for(insn.form_id())
        .ok_or_else(|| std::io::Error::other("ADD_X_IMM provider registered"))?;
    let mut mock = Mock::default();
    let receipt = provider
        .emit(&context(), &insn, &mut mock)
        .map_err(|err| std::io::Error::other(format!("ADD_X_IMM emit failed: {err:?}")))?;
    assert_eq!(receipt.rule_id, resolution.rule_id);
    assert!(mock.effects.iter().any(|e| e == "write op0"));
    assert!(mock.effects.iter().any(|e| e == "jump"));
    Ok(())
}

#[test]
fn subs_imm_writes_nzcv() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arm64CorpusRegistry::new();
    let insn = decode(0x7100_0408)?; // subs w8, w8, #0x2
    let provider = registry
        .provider_for(insn.form_id())
        .ok_or_else(|| std::io::Error::other("SUBS_W_IMM registered"))?;
    let mut mock = Mock::default();
    provider
        .emit(&context(), &insn, &mut mock)
        .map_err(|err| std::io::Error::other(format!("SUBS_W_IMM emit failed: {err:?}")))?;
    assert!(mock.effects.iter().any(|e| e == "write r33")); // NZCV
    Ok(())
}

#[test]
fn store_emits_memory_write() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arm64CorpusRegistry::new();
    let insn = decode(0xb900_0be8)?; // str w8, [sp, #8]
    let provider = registry
        .provider_for(insn.form_id())
        .ok_or_else(|| std::io::Error::other("STR_W registered"))?;
    let mut mock = Mock::default();
    provider
        .emit(&context(), &insn, &mut mock)
        .map_err(|err| std::io::Error::other(format!("STR_W emit failed: {err:?}")))?;
    assert!(mock.effects.iter().any(|e| e.starts_with("side MemoryWrite")));
    Ok(())
}

#[test]
fn bl_writes_link_and_jumps() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arm64CorpusRegistry::new();
    let insn = decode(0x9400_0001)?; // bl +4
    let provider = registry
        .provider_for(insn.form_id())
        .ok_or_else(|| std::io::Error::other("BL registered"))?;
    let mut mock = Mock::default();
    provider
        .emit(&context(), &insn, &mut mock)
        .map_err(|err| std::io::Error::other(format!("BL emit failed: {err:?}")))?;
    assert!(mock.effects.iter().any(|e| e == "write r30"));
    assert!(mock.effects.iter().any(|e| e == "jump"));
    Ok(())
}

#[test]
fn every_registered_form_is_emittable() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arm64CorpusRegistry::new();
    // A representative decoded instruction per registered form must emit
    // without error against the mock builder.
    let words: &[(u32, &str)] = &[
        (0xd503_201f, "NOP"),
        (0xd65f_03c0, "RET"),
        (0xd61f_0100, "BR"),
        (0xd63f_0280, "BLR"),
        (0x1400_0002, "B"),
        (0x5400_0000, "B.EQ"),
        (0xb400_0040, "CBZ X"),
        (0x3600_0040, "TBZ"),
        (0x1000_0148, "ADR"),
        (0x9000_0008, "ADRP"),
        (0x5280_06a8, "MOVZ W"),
        (0x72a0_06a8, "MOVK W"),
        (0x8a08_0000, "AND X reg"),
        (0xaa09_0113, "ORR X reg"),
        (0x4b08_0908, "SUB W reg"),
        (0x1a82_0020, "CSEL W"),
        (0x1b08_0908, "MADD W"),
        (0xf940_02a8, "LDR X"),
        (0xb980_1268, "LDRSW"),
        (0xf85d_83a0, "LDUR X"),
        (0xf81d_03a8, "STUR X"),
        (0xa9bf_7bfd, "STP X pre"),
        (0xaa1f_03e0, "MOV X (ORR ZR)"),
    ];
    for (word, name) in words {
        let insn = decode(*word)?;
        let provider = registry
            .provider_for(insn.form_id())
            .ok_or_else(|| std::io::Error::other(format!("{name}: form 0x{:x} not registered", insn.form_id())))?;
        let mut mock = Mock::default();
        provider
            .emit(&context(), &insn, &mut mock)
            .map_err(|err| std::io::Error::other(format!("{name}: emit failed: {err:?}")))?;
    }
    Ok(())
}

#[test]
fn unsupported_form_reports_error() {
    let registry = Arm64CorpusRegistry::new();
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    // fmov s0, #0.5 — FCVT, still outside the subset.
    let bytes = 0x1E70_0020u32.to_le_bytes();
    assert!(
        decoder.decode(0x2000, &bytes).is_err(),
        "FCVT subset must remain unsupported"
    );
    let _ = registry;
    let _ = forms::B;
}
