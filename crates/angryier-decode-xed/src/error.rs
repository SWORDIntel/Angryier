use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XedAdapterError {
    NotLinked,
    DecodeFailed,
    UnsupportedMode,
    EmptyInput,
    InvalidLength {
        reported: u8,
        available: usize,
    },
    DuplicateOperandIndex(u8),
    InvalidOperandWidth {
        operand: u8,
        width_bits: u16,
    },
    InvalidRegisterMetadata,
    InvalidMemoryAddressWidth(u16),
    InvalidMemoryScale(u8),
    ScaleWithoutIndex,
    InvalidVsibElementWidth(u16),
    InvalidDisplacementWidth(u8),
    InvalidBranchWidth(u8),
    InvalidFarPointerWidth(u16),
    InvalidPredicateMetadata,
    InvalidBroadcastCount(u16),
    TargetProfileViolation,
}

impl fmt::Display for XedAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => formatter.write_str("native Intel XED backend is not linked"),
            Self::DecodeFailed => formatter.write_str("Intel XED decode failed"),
            Self::UnsupportedMode => formatter.write_str("unsupported XED machine mode"),
            Self::EmptyInput => formatter.write_str("cannot decode an empty byte slice"),
            Self::InvalidLength {
                reported,
                available,
            } => write!(
                formatter,
                "invalid decoded length {reported}; available input bytes: {available}"
            ),
            Self::DuplicateOperandIndex(index) => {
                write!(formatter, "duplicate decoded operand index: {index}")
            }
            Self::InvalidOperandWidth {
                operand,
                width_bits,
            } => write!(
                formatter,
                "invalid width {width_bits} bits for decoded operand {operand}"
            ),
            Self::InvalidRegisterMetadata => {
                formatter.write_str("invalid Intel register metadata")
            }
            Self::InvalidMemoryAddressWidth(width) => {
                write!(formatter, "invalid Intel memory address width: {width} bits")
            }
            Self::InvalidMemoryScale(scale) => {
                write!(formatter, "invalid Intel memory index scale: {scale}")
            }
            Self::ScaleWithoutIndex => {
                formatter.write_str("memory scale is present without an index register")
            }
            Self::InvalidVsibElementWidth(width) => {
                write!(formatter, "invalid VSIB element width: {width} bits")
            }
            Self::InvalidDisplacementWidth(width) => {
                write!(formatter, "invalid displacement width: {width} bits")
            }
            Self::InvalidBranchWidth(width) => {
                write!(formatter, "invalid relative branch width: {width} bits")
            }
            Self::InvalidFarPointerWidth(width) => {
                write!(formatter, "invalid far-pointer offset width: {width} bits")
            }
            Self::InvalidPredicateMetadata => {
                formatter.write_str("invalid EVEX predicate-mask metadata")
            }
            Self::InvalidBroadcastCount(copies) => {
                write!(formatter, "invalid broadcast copy count: {copies}")
            }
            Self::TargetProfileViolation => {
                formatter.write_str("decoded instruction violates target profile")
            }
        }
    }
}

impl std::error::Error for XedAdapterError {}
