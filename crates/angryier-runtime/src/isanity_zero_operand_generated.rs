// Generated candidate identities from ISANITY's pinned zero-operand sidecar.
// Candidate source artifact SHA-256 is exposed by the parent module.

const ZERO_OPERAND_CANDIDATES: &[ZeroOperandCandidate] = &[
    ZeroOperandCandidate {
        canonical_id: "isanity:form:v2:sha256:bea5aa469f3906fef14815e3617e6a719460d4ea807662fa761ba97d508c8748",
        iform: "XED_IFORM_SAHF",
        iform_value: 2603,
        witness: &[0x9e],
        feature_predicate: "lahf",
        suppressed_operands: [
            SuppressedOperand {
                index: 0,
                width_bits: 8,
                access: AccessKind::Read,
                parent_register_id: 0,
                bit_offset: 8,
                view_width_bits: 8,
                write_behavior: RegisterWriteBehavior::PreserveParent,
            },
            SuppressedOperand {
                index: 1,
                width_bits: 64,
                access: AccessKind::Write,
                parent_register_id: 0x0021,
                bit_offset: 0,
                view_width_bits: 64,
                write_behavior: RegisterWriteBehavior::ReplaceParent,
            },
        ],
    },
    ZeroOperandCandidate {
        canonical_id: "isanity:form:v2:sha256:f0e7d8a6c5c20415dffbf337edec457f10ddea3979cd505836a6c4f8689fba7e",
        iform: "XED_IFORM_LAHF",
        iform_value: 1486,
        witness: &[0x9f],
        feature_predicate: "lahf",
        suppressed_operands: [
            SuppressedOperand {
                index: 0,
                width_bits: 8,
                access: AccessKind::Write,
                parent_register_id: 0,
                bit_offset: 8,
                view_width_bits: 8,
                write_behavior: RegisterWriteBehavior::PreserveParent,
            },
            SuppressedOperand {
                index: 1,
                width_bits: 64,
                access: AccessKind::Read,
                parent_register_id: 0x0021,
                bit_offset: 0,
                view_width_bits: 64,
                write_behavior: RegisterWriteBehavior::ReplaceParent,
            },
        ],
    },
];
