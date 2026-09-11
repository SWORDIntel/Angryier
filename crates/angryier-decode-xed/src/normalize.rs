use crate::{
    error::XedAdapterError,
    metadata::{
        XedAccess, XedDecodedMetadata, XedEncoding, XedFarPointerOperand, XedGprView,
        XedImmediateOperand, XedInstructionModifiers, XedMachineMode, XedMemoryBase,
        XedMemoryIndex, XedMemoryOperand, XedOperand, XedOperandKind, XedOperandVisibility,
        XedPredicateMask, XedRegisterRef, XedRelativeBranchOperand, XedRepetition,
        XedRoundingMode, XedSegment, XedVectorView,
    },
    XedDecodeConfig,
};
use angryier_arch::{
    AccessKind, Broadcast, DecodedInstruction, EncodingClass, FarPointerOperand, FeatureId,
    ImmediateOperand, InstructionModifiers, MemoryBase, MemoryIndex, MemoryOperand, Operand,
    OperandKind, OperandVisibility, PredicateMask, PredicateMode, RegisterView,
    RelativeBranchOperand, RepetitionKind, RoundingMode, SegmentId,
};
use angryier_arch_intel64::{
    encoding_class, gpr_view, mmx_view, opmask_view, register_id, segment_id, tile_view,
    vector_view, x87_view, GprViewKind, IntelFeature, VectorViewKind,
};
use angryier_types::Address;
use std::collections::BTreeSet;

pub fn normalize_decoded(
    config: &XedDecodeConfig,
    address: Address,
    available_bytes: usize,
    metadata: XedDecodedMetadata,
) -> Result<DecodedInstruction, XedAdapterError> {
    match config.mode {
        XedMachineMode::Intel64 => {}
    }

    if available_bytes == 0 {
        return Err(XedAdapterError::EmptyInput);
    }
    if metadata.length == 0
        || metadata.length > 15
        || usize::from(metadata.length) > available_bytes
    {
        return Err(XedAdapterError::InvalidLength {
            reported: metadata.length,
            available: available_bytes,
        });
    }

    let mut features = Vec::with_capacity(metadata.features.len());
    for feature in metadata.features {
        if !config.profile.features.features.contains(&feature) {
            return Err(XedAdapterError::TargetProfileViolation);
        }
        features.push(intel_feature_id(feature));
    }
    features.sort_by_key(|feature| feature.0);
    features.dedup_by_key(|feature| feature.0);

    let mut seen_operands = BTreeSet::new();
    let mut operands = Vec::with_capacity(metadata.operands.len());
    for operand in metadata.operands {
        if !seen_operands.insert(operand.index) {
            return Err(XedAdapterError::DuplicateOperandIndex(operand.index));
        }
        operands.push(normalize_operand(operand)?);
    }
    operands.sort_by_key(|operand| operand.index);

    Ok(DecodedInstruction {
        address,
        length: metadata.length,
        form_id: metadata.form_id,
        features,
        operands,
        modifiers: normalize_modifiers(metadata.modifiers)?,
    })
}

fn intel_feature_id(feature: IntelFeature) -> FeatureId {
    FeatureId(match feature {
        IntelFeature::Sse => 0x0001,
        IntelFeature::Sse2 => 0x0002,
        IntelFeature::Sse3 => 0x0003,
        IntelFeature::Ssse3 => 0x0004,
        IntelFeature::Sse41 => 0x0005,
        IntelFeature::Sse42 => 0x0006,
        IntelFeature::AesNi => 0x0007,
        IntelFeature::Sha => 0x0008,
        IntelFeature::Bmi1 => 0x0009,
        IntelFeature::Bmi2 => 0x000a,
        IntelFeature::Avx => 0x000b,
        IntelFeature::Avx2 => 0x000c,
        IntelFeature::Avx512 => 0x000d,
        IntelFeature::AvxVnni => 0x000e,
        IntelFeature::Avx10 => 0x000f,
        IntelFeature::Amx => 0x0010,
        IntelFeature::Cet => 0x0011,
        IntelFeature::Apx => 0x0012,
    })
}

fn normalize_operand(operand: XedOperand) -> Result<Operand, XedAdapterError> {
    let kind = normalize_operand_kind(operand.kind)?;
    let width_bits = if operand.width_bits == 0 {
        match kind {
            OperandKind::AddressGeneration(memory) => memory.address_width_bits,
            _ => {
                return Err(XedAdapterError::InvalidOperandWidth {
                    operand: operand.index,
                    width_bits: 0,
                })
            }
        }
    } else {
        operand.width_bits
    };

    Ok(Operand {
        index: operand.index,
        width_bits,
        access: match operand.access {
            XedAccess::Read => AccessKind::Read,
            XedAccess::Write => AccessKind::Write,
            XedAccess::ReadWrite => AccessKind::ReadWrite,
        },
        visibility: match operand.visibility {
            XedOperandVisibility::Explicit => OperandVisibility::Explicit,
            XedOperandVisibility::Implicit => OperandVisibility::Implicit,
            XedOperandVisibility::Suppressed => OperandVisibility::Suppressed,
        },
        kind,
    })
}

fn normalize_operand_kind(kind: XedOperandKind) -> Result<OperandKind, XedAdapterError> {
    Ok(match kind {
        XedOperandKind::Register(register) => OperandKind::Register(normalize_register(register)?),
        XedOperandKind::Memory(memory) => OperandKind::Memory(normalize_memory(memory)?),
        XedOperandKind::AddressGeneration(memory) => {
            OperandKind::AddressGeneration(normalize_memory(memory)?)
        }
        XedOperandKind::Immediate(immediate) => OperandKind::Immediate(normalize_immediate(immediate)),
        XedOperandKind::RelativeBranch(branch) => {
            OperandKind::RelativeBranch(normalize_relative_branch(branch)?)
        }
        XedOperandKind::FarPointer(pointer) => OperandKind::FarPointer(normalize_far_pointer(pointer)?),
    })
}

fn normalize_register(register: XedRegisterRef) -> Result<RegisterView, XedAdapterError> {
    let result = match register {
        XedRegisterRef::Gpr { index, view } => gpr_view(
            index,
            match view {
                XedGprView::Qword => GprViewKind::Qword,
                XedGprView::Dword => GprViewKind::Dword,
                XedGprView::Word => GprViewKind::Word,
                XedGprView::LowByte => GprViewKind::LowByte,
                XedGprView::HighByte => GprViewKind::HighByte,
            },
        ),
        XedRegisterRef::InstructionPointer => Ok(RegisterView::full(register_id::RIP, 64)),
        XedRegisterRef::Flags => Ok(RegisterView::full(register_id::RFLAGS, 64)),
        XedRegisterRef::Vector { index, view } => vector_view(
            index,
            match view {
                XedVectorView::Xmm128 => VectorViewKind::Xmm128,
                XedVectorView::Ymm256 => VectorViewKind::Ymm256,
                XedVectorView::Zmm512 => VectorViewKind::Zmm512,
            },
        ),
        XedRegisterRef::Opmask { index } => opmask_view(index),
        XedRegisterRef::X87 { index } => x87_view(index),
        XedRegisterRef::Mmx { index } => mmx_view(index),
        XedRegisterRef::Tile { index } => tile_view(index),
        XedRegisterRef::TileConfig => Ok(RegisterView::full(register_id::TILECFG, 512)),
        XedRegisterRef::Mxcsr => Ok(RegisterView::full(register_id::MXCSR, 32)),
    };

    result.map_err(|_| XedAdapterError::InvalidRegisterMetadata)
}

fn normalize_address_register(register: XedRegisterRef) -> Result<RegisterView, XedAdapterError> {
    match register {
        XedRegisterRef::Gpr {
            view: XedGprView::Qword | XedGprView::Dword,
            ..
        } => normalize_register(register),
        _ => Err(XedAdapterError::InvalidRegisterMetadata),
    }
}

fn normalize_vsib_register(register: XedRegisterRef) -> Result<RegisterView, XedAdapterError> {
    match register {
        XedRegisterRef::Vector { .. } => normalize_register(register),
        _ => Err(XedAdapterError::InvalidRegisterMetadata),
    }
}

fn normalize_memory(memory: XedMemoryOperand) -> Result<MemoryOperand, XedAdapterError> {
    if !matches!(memory.address_width_bits, 32 | 64) {
        return Err(XedAdapterError::InvalidMemoryAddressWidth(
            memory.address_width_bits,
        ));
    }
    if !matches!(memory.displacement_width_bits, 0 | 8 | 16 | 32 | 64) {
        return Err(XedAdapterError::InvalidDisplacementWidth(
            memory.displacement_width_bits,
        ));
    }

    let base = match memory.base {
        None => None,
        Some(XedMemoryBase::Register(register)) => {
            Some(MemoryBase::Register(normalize_address_register(register)?))
        }
        Some(XedMemoryBase::InstructionPointer { width_bits }) => {
            if memory.address_width_bits != 64 || width_bits != 64 {
                return Err(XedAdapterError::InvalidMemoryAddressWidth(width_bits));
            }
            Some(MemoryBase::InstructionPointer { width_bits })
        }
    };

    let index = match memory.index {
        None => None,
        Some(XedMemoryIndex::Register(register)) => {
            Some(MemoryIndex::Register(normalize_address_register(register)?))
        }
        Some(XedMemoryIndex::Vsib {
            register,
            element_width_bits,
        }) => {
            if !matches!(element_width_bits, 32 | 64) {
                return Err(XedAdapterError::InvalidVsibElementWidth(element_width_bits));
            }
            Some(MemoryIndex::Vsib {
                register: normalize_vsib_register(register)?,
                element_width_bits,
            })
        }
    };

    let scale = match index {
        None if matches!(memory.scale, 0 | 1) => 1,
        None => return Err(XedAdapterError::ScaleWithoutIndex),
        Some(_) if matches!(memory.scale, 1 | 2 | 4 | 8) => memory.scale,
        Some(_) => return Err(XedAdapterError::InvalidMemoryScale(memory.scale)),
    };

    Ok(MemoryOperand {
        memory_index: memory.memory_index,
        address_width_bits: memory.address_width_bits,
        segment: memory.segment.map(normalize_segment),
        base,
        index,
        scale,
        displacement: memory.displacement,
        displacement_width_bits: memory.displacement_width_bits,
    })
}

fn normalize_segment(segment: XedSegment) -> SegmentId {
    match segment {
        XedSegment::Es => segment_id::ES,
        XedSegment::Cs => segment_id::CS,
        XedSegment::Ss => segment_id::SS,
        XedSegment::Ds => segment_id::DS,
        XedSegment::Fs => segment_id::FS,
        XedSegment::Gs => segment_id::GS,
    }
}

fn normalize_immediate(immediate: XedImmediateOperand) -> ImmediateOperand {
    ImmediateOperand {
        value: immediate.value,
        signed: immediate.signed,
    }
}

fn normalize_relative_branch(
    branch: XedRelativeBranchOperand,
) -> Result<RelativeBranchOperand, XedAdapterError> {
    if !matches!(branch.displacement_width_bits, 8 | 16 | 32) {
        return Err(XedAdapterError::InvalidBranchWidth(
            branch.displacement_width_bits,
        ));
    }
    Ok(RelativeBranchOperand {
        displacement: branch.displacement,
        displacement_width_bits: branch.displacement_width_bits,
    })
}

fn normalize_far_pointer(
    pointer: XedFarPointerOperand,
) -> Result<FarPointerOperand, XedAdapterError> {
    if !matches!(pointer.offset_width_bits, 16 | 32 | 64) {
        return Err(XedAdapterError::InvalidFarPointerWidth(
            pointer.offset_width_bits,
        ));
    }
    Ok(FarPointerOperand {
        segment: pointer.segment,
        offset: pointer.offset,
        offset_width_bits: pointer.offset_width_bits,
    })
}

fn normalize_modifiers(
    modifiers: XedInstructionModifiers,
) -> Result<InstructionModifiers, XedAdapterError> {
    let predicate = modifiers.predicate.map(normalize_predicate).transpose()?;
    let broadcast = modifiers
        .broadcast
        .map(|broadcast| {
            if broadcast.copies == 0 {
                Err(XedAdapterError::InvalidBroadcastCount(0))
            } else {
                Ok(Broadcast {
                    copies: broadcast.copies,
                })
            }
        })
        .transpose()?;

    Ok(InstructionModifiers {
        encoding: normalize_encoding(modifiers.encoding),
        lock: modifiers.lock,
        repetition: modifiers.repetition.map(|repetition| match repetition {
            XedRepetition::Rep => RepetitionKind::Rep,
            XedRepetition::Repe => RepetitionKind::Repe,
            XedRepetition::Repne => RepetitionKind::Repne,
        }),
        predicate,
        rounding: modifiers.rounding.map(|rounding| match rounding {
            XedRoundingMode::NearestEven => RoundingMode::NearestEven,
            XedRoundingMode::Down => RoundingMode::Down,
            XedRoundingMode::Up => RoundingMode::Up,
            XedRoundingMode::TowardZero => RoundingMode::TowardZero,
        }),
        suppress_all_exceptions: modifiers.suppress_all_exceptions,
        no_flags: modifiers.no_flags,
        broadcast,
    })
}

fn normalize_encoding(encoding: XedEncoding) -> EncodingClass {
    match encoding {
        XedEncoding::Legacy => encoding_class::LEGACY,
        XedEncoding::Vex => encoding_class::VEX,
        XedEncoding::Evex => encoding_class::EVEX,
        XedEncoding::Rex2 => encoding_class::REX2,
    }
}

fn normalize_predicate(predicate: XedPredicateMask) -> Result<PredicateMask, XedAdapterError> {
    let register = match predicate.register {
        XedRegisterRef::Opmask { .. } => normalize_register(predicate.register)?,
        _ => return Err(XedAdapterError::InvalidPredicateMetadata),
    };

    Ok(PredicateMask {
        register,
        mode: if predicate.zeroing {
            PredicateMode::Zero
        } else {
            PredicateMode::Merge
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::XedInstructionModifiers;
    use angryier_arch::RegisterWriteBehavior;
    use angryier_arch_intel64::{FeatureSet, Intel64ProfileKind, Intel64TargetProfile};
    use angryier_types::TargetProfileId;

    fn config(features: Vec<IntelFeature>) -> XedDecodeConfig {
        XedDecodeConfig {
            mode: XedMachineMode::Intel64,
            profile: Intel64TargetProfile {
                id: TargetProfileId(1),
                kind: Intel64ProfileKind::Custom,
                features: FeatureSet { features, xcr0: 0 },
            },
        }
    }

    #[test]
    fn eax_normalizes_to_zero_extending_rax_view() -> Result<(), XedAdapterError> {
        let metadata = XedDecodedMetadata {
            length: 2,
            form_id: 7,
            features: Vec::new(),
            operands: vec![XedOperand {
                index: 0,
                width_bits: 32,
                access: XedAccess::Write,
                visibility: XedOperandVisibility::Explicit,
                kind: XedOperandKind::Register(XedRegisterRef::Gpr {
                    index: 0,
                    view: XedGprView::Dword,
                }),
            }],
            modifiers: XedInstructionModifiers::default(),
        };

        let decoded = normalize_decoded(&config(Vec::new()), 0x1000, 2, metadata)?;
        let OperandKind::Register(view) = decoded.operands[0].kind else {
            panic!("expected register operand")
        };
        assert_eq!(view.parent.0, register_id::GPR_BASE);
        assert_eq!(view.width_bits, 32);
        assert_eq!(view.write_behavior, RegisterWriteBehavior::ZeroExtendParent);
        Ok(())
    }

    #[test]
    fn no_index_scale_is_canonicalized() -> Result<(), XedAdapterError> {
        let memory = normalize_memory(XedMemoryOperand {
            memory_index: 0,
            address_width_bits: 64,
            segment: None,
            base: Some(XedMemoryBase::Register(XedRegisterRef::Gpr {
                index: 0,
                view: XedGprView::Qword,
            })),
            index: None,
            scale: 0,
            displacement: 0,
            displacement_width_bits: 0,
        })?;

        assert_eq!(memory.scale, 1);
        assert!(memory.index.is_none());
        Ok(())
    }

    #[test]
    fn vsib_requires_vector_index() {
        let memory = XedMemoryOperand {
            memory_index: 0,
            address_width_bits: 64,
            segment: None,
            base: None,
            index: Some(XedMemoryIndex::Vsib {
                register: XedRegisterRef::Gpr {
                    index: 0,
                    view: XedGprView::Qword,
                },
                element_width_bits: 32,
            }),
            scale: 4,
            displacement: 0,
            displacement_width_bits: 0,
        };

        assert_eq!(
            normalize_memory(memory),
            Err(XedAdapterError::InvalidRegisterMetadata)
        );
    }

    #[test]
    fn target_feature_violation_fails_closed() {
        let metadata = XedDecodedMetadata {
            length: 4,
            form_id: 9,
            features: vec![IntelFeature::Avx2],
            operands: Vec::new(),
            modifiers: XedInstructionModifiers::default(),
        };

        assert_eq!(
            normalize_decoded(&config(vec![IntelFeature::Sse2]), 0x1000, 4, metadata),
            Err(XedAdapterError::TargetProfileViolation)
        );
    }
}
