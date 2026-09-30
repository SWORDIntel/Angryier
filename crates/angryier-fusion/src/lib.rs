#![forbid(unsafe_code)]

use angryier_types::fx::FxHashMap;
use angryier_types::{ContentId, EmbeddingModelVersion, EmbeddingSchemaVersion, SolverOutcomeKind};
use std::fmt;
use std::sync::Mutex;

/// Default embedding dimension for specialist encoders and fusion.
pub const DEFAULT_EMBEDDING_DIM: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Modality {
    SemanticIr,
    CfgPath,
    ConstraintDag,
    TaintFlow,
    MemoryBehavior,
    SolverProfile,
    DynamicBehavior,
    FidelityProvenance,
    FindingContext,
    AnalystAnnotation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModalityVector {
    pub modality: Modality,
    pub values: Vec<f32>,
    pub masked: bool,
}

impl ModalityVector {
    /// Construct a new non-masked modality vector.
    pub fn new(modality: Modality, values: Vec<f32>) -> Self {
        Self {
            modality,
            values,
            masked: false,
        }
    }

    /// Construct a masked modality vector of the given dimension (zero-filled).
    pub fn masked(modality: Modality, dimension: usize) -> Self {
        Self {
            modality,
            values: vec![0.0; dimension],
            masked: true,
        }
    }

    /// Set the masked flag on this vector.
    pub fn with_masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FusedEmbedding {
    pub artifact: ContentId,
    pub model: EmbeddingModelVersion,
    pub schema: EmbeddingSchemaVersion,
    pub values: Vec<f32>,
    pub contributions: Vec<(Modality, f32)>,
}

impl FusedEmbedding {
    /// Returns the contribution weight for a given modality, if present.
    pub fn contribution(&self, modality: Modality) -> Option<f32> {
        self.contributions
            .iter()
            .find(|(m, _)| *m == modality)
            .map(|(_, w)| *w)
    }

    /// Returns the dimension of the fused embedding.
    pub fn dimension(&self) -> usize {
        self.values.len()
    }
}

pub trait SpecialistEncoder: Send + Sync {
    type Input;
    fn modality(&self) -> Modality;
    fn encode(&self, input: &Self::Input) -> ModalityVector;
}

pub trait FusionModel: Send + Sync {
    type Error;
    fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error>;
}

/// Errors that can arise during fusion of modality vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FusionError {
    /// No modality vectors were supplied.
    NoModalities,
    /// Every supplied modality vector was masked.
    AllMasked,
    /// Non-masked modality vectors disagreed on dimensionality.
    DimensionMismatch,
    /// The fusion state was poisoned by a prior panic.
    Poisoned,
}

impl fmt::Display for FusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoModalities => f.write_str("no modality vectors were supplied"),
            Self::AllMasked => f.write_str("all modality vectors were masked"),
            Self::DimensionMismatch => f.write_str("non-masked modality vectors have mismatched dimensions"),
            Self::Poisoned => f.write_str("fusion state was poisoned"),
        }
    }
}

impl std::error::Error for FusionError {}

/// In-place L2 normalization helper. Leaves zero vectors intact without dividing by zero.
fn l2_normalize(values: &mut [f32]) {
    let sum_sq: f32 = values.iter().map(|&x| x * x).sum();
    let norm = sum_sq.sqrt();
    if norm > 1e-12 {
        for v in values.iter_mut() {
            *v /= norm;
        }
    }
}

// ---------------------------------------------------------------------------
// Existing identity & constant encoders
// ---------------------------------------------------------------------------

/// A specialist encoder that passes its input through unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdentityEncoder;

impl SpecialistEncoder for IdentityEncoder {
    type Input = Vec<f32>;

    fn modality(&self) -> Modality {
        Modality::SemanticIr
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        ModalityVector {
            modality: self.modality(),
            values: input.clone(),
            masked: false,
        }
    }
}

/// A specialist encoder that emits a single constant value as a one-element vector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConstantEncoder;

impl SpecialistEncoder for ConstantEncoder {
    type Input = f32;

    fn modality(&self) -> Modality {
        Modality::CfgPath
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        ModalityVector {
            modality: self.modality(),
            values: vec![*input],
            masked: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Specialist Encoders (Phase 11)
// ---------------------------------------------------------------------------

/// Categorical summary of IR opcode classes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IrCategoryCounts {
    pub arithmetic: usize,
    pub bitwise: usize,
    pub comparison: usize,
    pub control_flow: usize,
    pub memory_read: usize,
    pub memory_write: usize,
    pub simd_vector: usize,
    pub other: usize,
}

/// Input distribution of IR opcodes and opcode categories.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IrOpcodeDistribution {
    /// Histogram counts indexed by opcode ID or bucket.
    pub counts: Vec<usize>,
    /// High-level category distribution.
    pub categories: IrCategoryCounts,
}

impl IrOpcodeDistribution {
    /// Construct a distribution from raw opcode bucket counts.
    pub fn from_counts(counts: impl Into<Vec<usize>>) -> Self {
        Self {
            counts: counts.into(),
            categories: IrCategoryCounts::default(),
        }
    }

    /// Construct a distribution from category counts.
    pub fn from_categories(categories: IrCategoryCounts) -> Self {
        Self {
            counts: Vec::new(),
            categories,
        }
    }

    /// Construct a distribution with both bucket counts and category counts.
    pub fn new(counts: impl Into<Vec<usize>>, categories: IrCategoryCounts) -> Self {
        Self {
            counts: counts.into(),
            categories,
        }
    }

    /// Total number of instructions represented.
    pub fn total_instructions(&self) -> usize {
        let count_sum: usize = self.counts.iter().sum();
        let cat_sum = self.categories.arithmetic
            + self.categories.bitwise
            + self.categories.comparison
            + self.categories.control_flow
            + self.categories.memory_read
            + self.categories.memory_write
            + self.categories.simd_vector
            + self.categories.other;
        count_sum.max(cat_sum)
    }
}

impl From<Vec<usize>> for IrOpcodeDistribution {
    fn from(counts: Vec<usize>) -> Self {
        Self::from_counts(counts)
    }
}

impl From<&[usize]> for IrOpcodeDistribution {
    fn from(counts: &[usize]) -> Self {
        Self::from_counts(counts.to_vec())
    }
}

/// Specialist encoder for IR opcode distributions (`Modality::SemanticIr`).
///
/// Encodes opcode histograms and semantic categories into a fixed-length
/// L2-normalized embedding vector.
#[derive(Clone, Debug)]
pub struct IrSpecialistEncoder {
    pub dimension: usize,
}

impl Default for IrSpecialistEncoder {
    fn default() -> Self {
        Self::new(DEFAULT_EMBEDDING_DIM)
    }
}

impl IrSpecialistEncoder {
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension: dimension.max(1),
        }
    }

    /// Helper to encode a slice of counts directly.
    pub fn encode_counts(&self, counts: &[usize]) -> ModalityVector {
        let dist = IrOpcodeDistribution::from_counts(counts);
        self.encode(&dist)
    }
}

impl SpecialistEncoder for IrSpecialistEncoder {
    type Input = IrOpcodeDistribution;

    fn modality(&self) -> Modality {
        Modality::SemanticIr
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        let mut values = vec![0.0_f32; self.dimension];

        // Project categorical bins into the first 8 slots.
        let cats = [
            input.categories.arithmetic,
            input.categories.bitwise,
            input.categories.comparison,
            input.categories.control_flow,
            input.categories.memory_read,
            input.categories.memory_write,
            input.categories.simd_vector,
            input.categories.other,
        ];
        for (i, &c) in cats.iter().enumerate() {
            if c > 0 {
                values[i % self.dimension] += c as f32;
            }
        }

        // Project opcode histogram into buckets.
        for (i, &count) in input.counts.iter().enumerate() {
            if count > 0 {
                let slot = (i + 8) % self.dimension;
                values[slot] += count as f32;
            }
        }

        l2_normalize(&mut values);

        ModalityVector {
            modality: self.modality(),
            values,
            masked: false,
        }
    }
}

/// Topological features of a Control Flow Graph.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CfgFeatures {
    /// Number of basic blocks / CFG nodes.
    pub node_count: usize,
    /// Cyclomatic complexity (E - N + 2P).
    pub cyclomatic_complexity: usize,
    /// Number of natural loops / back-edges.
    pub loop_count: usize,
    /// Total edge count in the CFG.
    pub edge_count: usize,
    /// Number of conditional and indirect branch sites.
    pub branch_count: usize,
}

impl CfgFeatures {
    pub fn new(node_count: usize, cyclomatic_complexity: usize, loop_count: usize) -> Self {
        Self {
            node_count,
            cyclomatic_complexity,
            loop_count,
            edge_count: 0,
            branch_count: 0,
        }
    }

    pub fn with_edges(mut self, edge_count: usize) -> Self {
        self.edge_count = edge_count;
        self
    }

    pub fn with_branches(mut self, branch_count: usize) -> Self {
        self.branch_count = branch_count;
        self
    }
}

/// Specialist encoder for CFG topological features (`Modality::CfgPath`).
///
/// Encodes node count, cyclomatic complexity, loop count, and derived ratios
/// into a fixed-length L2-normalized vector.
#[derive(Clone, Debug)]
pub struct CfgSpecialistEncoder {
    pub dimension: usize,
}

impl Default for CfgSpecialistEncoder {
    fn default() -> Self {
        Self::new(DEFAULT_EMBEDDING_DIM)
    }
}

impl CfgSpecialistEncoder {
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension: dimension.max(1),
        }
    }

    /// Convenience helper to encode the core three topological features.
    pub fn encode_topology(&self, node_count: usize, cyclomatic_complexity: usize, loop_count: usize) -> ModalityVector {
        let feat = CfgFeatures::new(node_count, cyclomatic_complexity, loop_count);
        self.encode(&feat)
    }
}

impl SpecialistEncoder for CfgSpecialistEncoder {
    type Input = CfgFeatures;

    fn modality(&self) -> Modality {
        Modality::CfgPath
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        let mut values = vec![0.0_f32; self.dimension];

        let n = input.node_count as f32;
        let c = input.cyclomatic_complexity as f32;
        let l = input.loop_count as f32;
        let e = input.edge_count as f32;
        let b = input.branch_count as f32;

        let density = if input.node_count > 0 { e / n } else { 0.0 };
        let loop_ratio = if input.node_count > 0 { l / n } else { 0.0 };
        let complexity_ratio = if input.node_count > 0 { c / n } else { 0.0 };

        let features = [n, c, l, e, b, density, loop_ratio, complexity_ratio];
        for (i, &f) in features.iter().enumerate() {
            values[i % self.dimension] += f;
        }

        l2_normalize(&mut values);

        ModalityVector {
            modality: self.modality(),
            values,
            masked: false,
        }
    }
}

/// Features characterizing constraint complexity and solver performance profiles.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConstraintFeatures {
    /// Number of assertion clauses in the constraint DAG.
    pub assertion_count: usize,
    /// Maximum AST / expression DAG depth.
    pub max_depth: usize,
    /// Number of distinct symbolic / free variables.
    pub variable_count: usize,
    /// Count of nonlinear arithmetic operations (mul, div, mod).
    pub nonlinear_ops: usize,
    /// Count of bitwise/vector operations.
    pub bitwise_ops: usize,
    /// Count of array/load/store expressions.
    pub array_ops: usize,
    /// Solver solve duration in microseconds.
    pub solve_duration_us: u64,
    /// Number of learned conflict clauses.
    pub conflicts: usize,
    /// Number of solver decisions.
    pub decisions: usize,
    /// Solver outcome (Sat, Unsat, Timeout, etc.).
    pub outcome: Option<SolverOutcomeKind>,
}

impl ConstraintFeatures {
    pub fn new(assertion_count: usize, max_depth: usize, variable_count: usize) -> Self {
        Self {
            assertion_count,
            max_depth,
            variable_count,
            ..Default::default()
        }
    }

    pub fn with_complexity(mut self, nonlinear_ops: usize, bitwise_ops: usize, array_ops: usize) -> Self {
        self.nonlinear_ops = nonlinear_ops;
        self.bitwise_ops = bitwise_ops;
        self.array_ops = array_ops;
        self
    }

    pub fn with_solver_profile(
        mut self,
        solve_duration_us: u64,
        conflicts: usize,
        decisions: usize,
        outcome: SolverOutcomeKind,
    ) -> Self {
        self.solve_duration_us = solve_duration_us;
        self.conflicts = conflicts;
        self.decisions = decisions;
        self.outcome = Some(outcome);
        self
    }
}

/// Specialist encoder for constraint complexity and solver profiles.
///
/// Supports either `Modality::ConstraintDag` or `Modality::SolverProfile`.
#[derive(Clone, Debug)]
pub struct ConstraintSpecialistEncoder {
    pub dimension: usize,
    pub modality: Modality,
}

impl Default for ConstraintSpecialistEncoder {
    fn default() -> Self {
        Self::new(DEFAULT_EMBEDDING_DIM)
    }
}

impl ConstraintSpecialistEncoder {
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension: dimension.max(1),
            modality: Modality::ConstraintDag,
        }
    }

    pub fn with_modality(mut self, modality: Modality) -> Self {
        self.modality = modality;
        self
    }

    pub fn constraint_dag(dimension: usize) -> Self {
        Self::new(dimension).with_modality(Modality::ConstraintDag)
    }

    pub fn solver_profile(dimension: usize) -> Self {
        Self::new(dimension).with_modality(Modality::SolverProfile)
    }

    pub fn encode_complexity(&self, assertion_count: usize, max_depth: usize, variable_count: usize) -> ModalityVector {
        let feat = ConstraintFeatures::new(assertion_count, max_depth, variable_count);
        self.encode(&feat)
    }
}

impl SpecialistEncoder for ConstraintSpecialistEncoder {
    type Input = ConstraintFeatures;

    fn modality(&self) -> Modality {
        self.modality
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        let mut values = vec![0.0_f32; self.dimension];

        let assertions = input.assertion_count as f32;
        let depth = input.max_depth as f32;
        let vars = input.variable_count as f32;
        let nonlinear = input.nonlinear_ops as f32;
        let bitwise = input.bitwise_ops as f32;
        let array = input.array_ops as f32;
        let duration_log = (input.solve_duration_us as f32 + 1.0).ln();
        let conflicts = input.conflicts as f32;
        let decisions = input.decisions as f32;

        let outcome_val = match input.outcome {
            None => 0.0,
            Some(SolverOutcomeKind::Sat) => 1.0,
            Some(SolverOutcomeKind::Unsat) => 2.0,
            Some(SolverOutcomeKind::Unknown) => 3.0,
            Some(SolverOutcomeKind::Timeout) => 4.0,
            Some(SolverOutcomeKind::ResourceLimit) => 5.0,
            Some(SolverOutcomeKind::BackendError) => 6.0,
        };

        let assertion_density = if input.variable_count > 0 { assertions / vars } else { 0.0 };
        let conflict_ratio = if input.decisions > 0 { conflicts / decisions } else { 0.0 };

        let features = [
            assertions,
            depth,
            vars,
            nonlinear,
            bitwise,
            array,
            duration_log,
            conflicts,
            decisions,
            outcome_val,
            assertion_density,
            conflict_ratio,
        ];

        for (i, &f) in features.iter().enumerate() {
            values[i % self.dimension] += f;
        }

        l2_normalize(&mut values);

        ModalityVector {
            modality: self.modality(),
            values,
            masked: false,
        }
    }
}

/// Distribution of memory accesses by segment, alignment, and operand size.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryAccessDistribution {
    pub read_count: usize,
    pub write_count: usize,
    pub stack_accesses: usize,
    pub heap_accesses: usize,
    pub global_accesses: usize,
    pub unaligned_accesses: usize,
    pub distinct_pages: usize,
    pub byte_accesses: usize,
    pub word_accesses: usize,
    pub dword_accesses: usize,
    pub qword_accesses: usize,
    pub vector_accesses: usize,
}

impl MemoryAccessDistribution {
    pub fn new(read_count: usize, write_count: usize) -> Self {
        Self {
            read_count,
            write_count,
            ..Default::default()
        }
    }

    pub fn with_segments(mut self, stack: usize, heap: usize, global: usize) -> Self {
        self.stack_accesses = stack;
        self.heap_accesses = heap;
        self.global_accesses = global;
        self
    }

    pub fn with_pages(mut self, distinct_pages: usize, unaligned: usize) -> Self {
        self.distinct_pages = distinct_pages;
        self.unaligned_accesses = unaligned;
        self
    }

    pub fn total_accesses(&self) -> usize {
        self.read_count + self.write_count
    }
}

/// Specialist encoder for memory access distributions (`Modality::MemoryBehavior`).
///
/// Encodes read/write ratios, locality, segments, and access size distribution
/// into a fixed-length L2-normalized vector.
#[derive(Clone, Debug)]
pub struct MemorySpecialistEncoder {
    pub dimension: usize,
}

impl Default for MemorySpecialistEncoder {
    fn default() -> Self {
        Self::new(DEFAULT_EMBEDDING_DIM)
    }
}

impl MemorySpecialistEncoder {
    pub fn new(dimension: usize) -> Self {
        Self {
            dimension: dimension.max(1),
        }
    }

    pub fn encode_counts(&self, read_count: usize, write_count: usize) -> ModalityVector {
        let dist = MemoryAccessDistribution::new(read_count, write_count);
        self.encode(&dist)
    }
}

impl SpecialistEncoder for MemorySpecialistEncoder {
    type Input = MemoryAccessDistribution;

    fn modality(&self) -> Modality {
        Modality::MemoryBehavior
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        let mut values = vec![0.0_f32; self.dimension];

        let reads = input.read_count as f32;
        let writes = input.write_count as f32;
        let total = reads + writes;
        let stack = input.stack_accesses as f32;
        let heap = input.heap_accesses as f32;
        let global = input.global_accesses as f32;
        let unaligned = input.unaligned_accesses as f32;
        let pages = input.distinct_pages as f32;
        let b = input.byte_accesses as f32;
        let w = input.word_accesses as f32;
        let dw = input.dword_accesses as f32;
        let qw = input.qword_accesses as f32;
        let vec = input.vector_accesses as f32;

        let read_ratio = if total > 0.0 { reads / total } else { 0.0 };
        let write_ratio = if total > 0.0 { writes / total } else { 0.0 };
        let unaligned_ratio = if total > 0.0 { unaligned / total } else { 0.0 };

        let features = [
            reads,
            writes,
            stack,
            heap,
            global,
            unaligned,
            pages,
            b,
            w,
            dw,
            qw,
            vec,
            read_ratio,
            write_ratio,
            unaligned_ratio,
        ];

        for (i, &f) in features.iter().enumerate() {
            values[i % self.dimension] += f;
        }

        l2_normalize(&mut values);

        ModalityVector {
            modality: self.modality(),
            values,
            masked: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Fusion Models
// ---------------------------------------------------------------------------

/// An in-memory `FusionModel` that averages non-masked modality vectors.
#[derive(Debug)]
pub struct InMemoryFusionModel {
    model: EmbeddingModelVersion,
    schema: EmbeddingSchemaVersion,
    last_result: Mutex<Option<FusedEmbedding>>,
}

impl InMemoryFusionModel {
    /// Construct a new in-memory fusion model with the given model and schema versions.
    pub fn new(model: EmbeddingModelVersion, schema: EmbeddingSchemaVersion) -> Self {
        Self {
            model,
            schema,
            last_result: Mutex::new(None),
        }
    }

    /// Returns a snapshot of the most recently fused embedding, if any.
    pub fn last_result(&self) -> Option<FusedEmbedding> {
        let guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }
}

impl FusionModel for InMemoryFusionModel {
    type Error = FusionError;

    fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error> {
        if modalities.is_empty() {
            return Err(FusionError::NoModalities);
        }

        // Collect the non-masked vectors we will actually fuse.
        let active: Vec<&ModalityVector> = modalities.iter().filter(|m| !m.masked).collect();
        if active.is_empty() {
            return Err(FusionError::AllMasked);
        }

        // Validate that all active vectors share the same dimensionality.
        let dim = active[0].values.len();
        if active.iter().any(|m| m.values.len() != dim) {
            return Err(FusionError::DimensionMismatch);
        }

        let count = active.len() as f32;
        let weight = 1.0 / count;

        // Element-wise average across active vectors.
        let mut summed = vec![0.0_f32; dim];
        for mv in &active {
            for (i, v) in mv.values.iter().enumerate() {
                summed[i] += *v;
            }
        }
        let values: Vec<f32> = summed.iter().map(|v| v / count).collect();

        // Record contributions for each contributing modality.
        let contributions: Vec<(Modality, f32)> = active.iter().map(|mv| (mv.modality, weight)).collect();

        let fused = FusedEmbedding {
            artifact,
            model: self.model,
            schema: self.schema,
            values,
            contributions,
        };

        let mut guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(fused.clone());

        Ok(fused)
    }
}

/// A learned or configured gated fusion model that dynamically computes
/// softmax-normalized gating weights across active (non-masked) modalities.
#[derive(Debug)]
pub struct GatedFusionModel {
    model: EmbeddingModelVersion,
    schema: EmbeddingSchemaVersion,
    modality_weights: Mutex<FxHashMap<Modality, f32>>,
    default_weight: f32,
    last_result: Mutex<Option<FusedEmbedding>>,
}

impl GatedFusionModel {
    /// Construct a new gated fusion model with default modality weights (0.0).
    pub fn new(model: EmbeddingModelVersion, schema: EmbeddingSchemaVersion) -> Self {
        Self {
            model,
            schema,
            modality_weights: Mutex::new(FxHashMap::default()),
            default_weight: 0.0,
            last_result: Mutex::new(None),
        }
    }

    /// Construct a gated fusion model with pre-configured or learned modality weights.
    pub fn with_weights(
        model: EmbeddingModelVersion,
        schema: EmbeddingSchemaVersion,
        weights: impl IntoIterator<Item = (Modality, f32)>,
    ) -> Self {
        let mut map = FxHashMap::default();
        for (m, w) in weights {
            map.insert(m, w);
        }
        Self {
            model,
            schema,
            modality_weights: Mutex::new(map),
            default_weight: 0.0,
            last_result: Mutex::new(None),
        }
    }

    /// Update or set the weight for a specific modality.
    pub fn set_weight(&self, modality: Modality, weight: f32) {
        let mut guard = self.modality_weights.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(modality, weight);
    }

    /// Get the currently configured weight for a modality.
    pub fn weight(&self, modality: Modality) -> f32 {
        let guard = self.modality_weights.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(&modality).copied().unwrap_or(self.default_weight)
    }

    /// Returns a snapshot of the most recently fused embedding, if any.
    pub fn last_result(&self) -> Option<FusedEmbedding> {
        let guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }
}

impl FusionModel for GatedFusionModel {
    type Error = FusionError;

    fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error> {
        if modalities.is_empty() {
            return Err(FusionError::NoModalities);
        }

        // Collect non-masked vectors.
        let active: Vec<&ModalityVector> = modalities.iter().filter(|m| !m.masked).collect();
        if active.is_empty() {
            return Err(FusionError::AllMasked);
        }

        // Validate dimension consistency across all active modalities.
        let dim = active[0].values.len();
        if active.iter().any(|m| m.values.len() != dim) {
            return Err(FusionError::DimensionMismatch);
        }

        // Retrieve weights for active modalities.
        let weights_guard = self.modality_weights.lock().unwrap_or_else(|e| e.into_inner());
        let raw_weights: Vec<f32> = active
            .iter()
            .map(|mv| weights_guard.get(&mv.modality).copied().unwrap_or(self.default_weight))
            .collect();
        drop(weights_guard);

        // Numerically stable softmax: subtract max logit.
        let max_w = raw_weights.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = raw_weights.iter().map(|&w| (w - max_w).exp()).collect();
        let exp_sum: f32 = exps.iter().sum();

        let gated_weights: Vec<f32> = if exp_sum > 0.0 && !exp_sum.is_nan() {
            exps.iter().map(|&e| e / exp_sum).collect()
        } else {
            let uniform = 1.0 / active.len() as f32;
            vec![uniform; active.len()]
        };

        // Linear combination using softmax gated weights.
        let mut values = vec![0.0_f32; dim];
        for (mv, &g) in active.iter().zip(gated_weights.iter()) {
            for (i, v) in mv.values.iter().enumerate() {
                values[i] += *v * g;
            }
        }

        // Record contributions tracking per-modality influence.
        let contributions: Vec<(Modality, f32)> = active
            .iter()
            .zip(gated_weights.iter())
            .map(|(mv, &g)| (mv.modality, g))
            .collect();

        let fused = FusedEmbedding {
            artifact,
            model: self.model,
            schema: self.schema,
            values,
            contributions,
        };

        let mut guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(fused.clone());

        Ok(fused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content_id(n: u8) -> ContentId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ContentId(bytes)
    }

    fn new_model() -> InMemoryFusionModel {
        InMemoryFusionModel::new(EmbeddingModelVersion(1), EmbeddingSchemaVersion(1))
    }

    fn new_gated_model() -> GatedFusionModel {
        GatedFusionModel::new(EmbeddingModelVersion(1), EmbeddingSchemaVersion(1))
    }

    #[test]
    fn identity_encoder_returns_semantic_ir_modality() {
        let encoder = IdentityEncoder;
        assert_eq!(encoder.modality(), Modality::SemanticIr);
    }

    #[test]
    fn identity_encoder_passes_values_through_unchanged() {
        let encoder = IdentityEncoder;
        let input = vec![1.0, 2.0, 3.0];
        let mv = encoder.encode(&input);
        assert_eq!(mv.modality, Modality::SemanticIr);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 3);
        for (a, b) in mv.values.iter().zip(input.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn constant_encoder_returns_cfg_path_modality() {
        let encoder = ConstantEncoder;
        assert_eq!(encoder.modality(), Modality::CfgPath);
    }

    #[test]
    fn constant_encoder_produces_single_element_vector() {
        let encoder = ConstantEncoder;
        let mv = encoder.encode(&4.2);
        assert_eq!(mv.modality, Modality::CfgPath);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 1);
        assert!((mv.values[0] - 4.2).abs() < 1e-6);
    }

    #[test]
    fn fuse_with_no_modalities_errors() {
        let model = new_model();
        let result = model.fuse(content_id(1), &[]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::NoModalities);
        }
    }

    #[test]
    fn fuse_with_all_masked_errors() {
        let model = new_model();
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0],
            masked: true,
        };
        let result = model.fuse(content_id(1), &[mv]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::AllMasked);
        }
    }

    #[test]
    fn fuse_with_dimension_mismatch_errors() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![3.0, 4.0, 5.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[a, b]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::DimensionMismatch);
        }
    }

    #[test]
    fn fuse_with_single_modality_returns_same_values() {
        let model = new_model();
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0, 3.0],
            masked: false,
        };
        let result = model.fuse(content_id(7), &[mv]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.values.len(), 3);
            for (a, b) in fused.values.iter().zip(&[1.0_f32, 2.0, 3.0]) {
                assert!((a - b).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn fuse_with_two_modalities_averages_correctly() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![0.0, 2.0, 4.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![2.0, 4.0, 6.0],
            masked: false,
        };
        let result = model.fuse(content_id(3), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            let expected = [1.0_f32, 3.0, 5.0];
            for (a, b) in fused.values.iter().zip(expected.iter()) {
                assert!((a - b).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn fuse_contributions_are_recorded() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![3.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.contributions.len(), 2);
            let mut found_semantic = false;
            let mut found_cfg = false;
            for (m, w) in &fused.contributions {
                assert!((w - 0.5).abs() < 1e-6);
                match m {
                    Modality::SemanticIr => found_semantic = true,
                    Modality::CfgPath => found_cfg = true,
                    _ => {}
                }
            }
            assert!(found_semantic);
            assert!(found_cfg);
        }
    }

    #[test]
    fn fuse_with_mixed_masked_unmasked_uses_only_unmasked() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![10.0, 20.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![0.0, 0.0],
            masked: true,
        };
        let result = model.fuse(content_id(2), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            for (a, b) in fused.values.iter().zip(&[10.0_f32, 20.0]) {
                assert!((a - b).abs() < 1e-6);
            }
            assert_eq!(fused.contributions.len(), 1);
            assert_eq!(fused.contributions[0].0, Modality::SemanticIr);
            assert!((fused.contributions[0].1 - 1.0).abs() < 1e-6);
        }
    }

    #[test]
    fn fused_embedding_has_correct_model_and_schema_versions() {
        let model = InMemoryFusionModel::new(EmbeddingModelVersion(42), EmbeddingSchemaVersion(7));
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[mv]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.model, EmbeddingModelVersion(42));
            assert_eq!(fused.schema, EmbeddingSchemaVersion(7));
            assert_eq!(fused.artifact, content_id(1));
        }
    }

    #[test]
    fn last_result_is_stored_after_successful_fuse() {
        let model = new_model();
        assert!(model.last_result().is_none());
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![5.0],
            masked: false,
        };
        let result = model.fuse(content_id(9), &[mv]);
        assert!(result.is_ok());
        let stored = model.last_result();
        assert!(stored.is_some());
        if let Some(stored) = stored {
            assert_eq!(stored.artifact, content_id(9));
            assert!((stored.values[0] - 5.0).abs() < 1e-6);
        }
    }

    #[test]
    fn fusion_error_implements_display_and_error() {
        let err = FusionError::NoModalities;
        let s = format!("{err}");
        assert!(!s.is_empty());
        let _e: &dyn std::error::Error = &err;
    }

    // --- Phase 11 Specialist Encoder Tests ---

    #[test]
    fn ir_specialist_encoder_modality_and_encoding() {
        let encoder = IrSpecialistEncoder::new(32);
        assert_eq!(encoder.modality(), Modality::SemanticIr);

        let dist = IrOpcodeDistribution {
            counts: vec![10, 20, 30, 40],
            categories: IrCategoryCounts {
                arithmetic: 5,
                control_flow: 3,
                ..Default::default()
            },
        };

        let mv = encoder.encode(&dist);
        assert_eq!(mv.modality, Modality::SemanticIr);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 32);

        // Check L2 normalization: sum of squares ≈ 1.0.
        let norm_sq: f32 = mv.values.iter().map(|&x| x * x).sum();
        assert!((norm_sq - 1.0).abs() < 1e-5, "norm_sq was {norm_sq}");

        // Empty distribution produces zero vector.
        let empty_dist = IrOpcodeDistribution::default();
        let empty_mv = encoder.encode(&empty_dist);
        for &v in &empty_mv.values {
            assert_eq!(v, 0.0);
        }

        // Test helper encode_counts.
        let counts_mv = encoder.encode_counts(&[1, 2, 3]);
        assert_eq!(counts_mv.values.len(), 32);
        let counts_norm: f32 = counts_mv.values.iter().map(|&x| x * x).sum();
        assert!((counts_norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn cfg_specialist_encoder_modality_and_encoding() {
        let encoder = CfgSpecialistEncoder::new(16);
        assert_eq!(encoder.modality(), Modality::CfgPath);

        let feat = CfgFeatures::new(10, 4, 2).with_edges(14).with_branches(3);
        let mv = encoder.encode(&feat);

        assert_eq!(mv.modality, Modality::CfgPath);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 16);

        let norm_sq: f32 = mv.values.iter().map(|&x| x * x).sum();
        assert!((norm_sq - 1.0).abs() < 1e-5);

        // Topological feature difference produces distinct embeddings.
        let feat2 = CfgFeatures::new(100, 40, 20).with_edges(140).with_branches(30);
        let mv2 = encoder.encode(&feat2);
        assert_ne!(mv.values, mv2.values);

        // Test encode_topology helper.
        let topo_mv = encoder.encode_topology(5, 2, 1);
        assert_eq!(topo_mv.values.len(), 16);
    }

    #[test]
    fn constraint_specialist_encoder_modalities_and_encoding() {
        let dag_encoder = ConstraintSpecialistEncoder::constraint_dag(32);
        assert_eq!(dag_encoder.modality(), Modality::ConstraintDag);

        let solver_encoder = ConstraintSpecialistEncoder::solver_profile(32);
        assert_eq!(solver_encoder.modality(), Modality::SolverProfile);

        let feat = ConstraintFeatures::new(50, 12, 15)
            .with_complexity(4, 10, 2)
            .with_solver_profile(1500, 8, 30, SolverOutcomeKind::Sat);

        let mv_dag = dag_encoder.encode(&feat);
        assert_eq!(mv_dag.modality, Modality::ConstraintDag);
        assert_eq!(mv_dag.values.len(), 32);
        let norm_dag: f32 = mv_dag.values.iter().map(|&x| x * x).sum();
        assert!((norm_dag - 1.0).abs() < 1e-5);

        let mv_solver = solver_encoder.encode(&feat);
        assert_eq!(mv_solver.modality, Modality::SolverProfile);
        assert_eq!(mv_solver.values.len(), 32);
        let norm_solver: f32 = mv_solver.values.iter().map(|&x| x * x).sum();
        assert!((norm_solver - 1.0).abs() < 1e-5);
    }

    #[test]
    fn memory_specialist_encoder_modality_and_encoding() {
        let encoder = MemorySpecialistEncoder::new(24);
        assert_eq!(encoder.modality(), Modality::MemoryBehavior);

        let dist = MemoryAccessDistribution::new(100, 40)
            .with_segments(80, 50, 10)
            .with_pages(8, 2);

        let mv = encoder.encode(&dist);
        assert_eq!(mv.modality, Modality::MemoryBehavior);
        assert_eq!(mv.values.len(), 24);

        let norm_sq: f32 = mv.values.iter().map(|&x| x * x).sum();
        assert!((norm_sq - 1.0).abs() < 1e-5);

        // Helper encode_counts
        let counts_mv = encoder.encode_counts(20, 5);
        assert_eq!(counts_mv.values.len(), 24);
    }

    // --- Phase 11 Gated Fusion Model Tests ---

    #[test]
    fn gated_fusion_equal_weights_matches_averaging() {
        let model = new_gated_model();
        let a = ModalityVector::new(Modality::SemanticIr, vec![0.0, 2.0, 4.0]);
        let b = ModalityVector::new(Modality::CfgPath, vec![2.0, 4.0, 6.0]);

        let result = model.fuse(content_id(1), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            let expected = [1.0_f32, 3.0, 5.0];
            for (v, exp) in fused.values.iter().zip(expected.iter()) {
                assert!((v - exp).abs() < 1e-5);
            }
            assert_eq!(fused.contributions.len(), 2);
            for (_, w) in &fused.contributions {
                assert!((w - 0.5).abs() < 1e-5);
            }
        }
    }

    #[test]
    fn gated_fusion_differential_weights() {
        let model = GatedFusionModel::with_weights(
            EmbeddingModelVersion(1),
            EmbeddingSchemaVersion(1),
            [(Modality::SemanticIr, 2.0), (Modality::CfgPath, 0.0)],
        );

        let a = ModalityVector::new(Modality::SemanticIr, vec![1.0, 0.0]);
        let b = ModalityVector::new(Modality::CfgPath, vec![0.0, 1.0]);

        let result = model.fuse(content_id(2), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            let w_ir = fused.contribution(Modality::SemanticIr).unwrap_or(0.0);
            let w_cfg = fused.contribution(Modality::CfgPath).unwrap_or(0.0);

            assert!((w_ir + w_cfg - 1.0).abs() < 1e-5);
            assert!(w_ir > 0.85);
            assert!(w_cfg < 0.15);

            assert!((fused.values[0] - w_ir).abs() < 1e-5);
            assert!((fused.values[1] - w_cfg).abs() < 1e-5);
        }
    }

    #[test]
    fn gated_fusion_missing_modality_mask() {
        let model = GatedFusionModel::with_weights(
            EmbeddingModelVersion(1),
            EmbeddingSchemaVersion(1),
            [
                (Modality::SemanticIr, 5.0),
                (Modality::CfgPath, 0.0),
                (Modality::MemoryBehavior, 0.0),
            ],
        );

        // SemanticIr is masked, even though it has the highest weight!
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![100.0, 200.0],
            masked: true,
        };
        let b = ModalityVector::new(Modality::CfgPath, vec![2.0, 4.0]);
        let c = ModalityVector::new(Modality::MemoryBehavior, vec![6.0, 8.0]);

        let result = model.fuse(content_id(3), &[a, b, c]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            // Only CfgPath and MemoryBehavior should contribute (50% each).
            assert_eq!(fused.contributions.len(), 2);
            assert!(fused.contribution(Modality::SemanticIr).is_none());

            let w_cfg = fused.contribution(Modality::CfgPath).unwrap_or(0.0);
            let w_mem = fused.contribution(Modality::MemoryBehavior).unwrap_or(0.0);
            assert!((w_cfg - 0.5).abs() < 1e-5);
            assert!((w_mem - 0.5).abs() < 1e-5);

            assert!((fused.values[0] - 4.0).abs() < 1e-5);
            assert!((fused.values[1] - 6.0).abs() < 1e-5);
        }
    }

    #[test]
    fn gated_fusion_all_masked_returns_error() {
        let model = new_gated_model();
        let a = ModalityVector::masked(Modality::SemanticIr, 4);
        let b = ModalityVector::masked(Modality::CfgPath, 4);

        let result = model.fuse(content_id(4), &[a, b]);
        assert_eq!(result, Err(FusionError::AllMasked));
    }

    #[test]
    fn gated_fusion_no_modalities_returns_error() {
        let model = new_gated_model();
        let result = model.fuse(content_id(5), &[]);
        assert_eq!(result, Err(FusionError::NoModalities));
    }

    #[test]
    fn gated_fusion_dimension_mismatch_returns_error() {
        let model = new_gated_model();
        let a = ModalityVector::new(Modality::SemanticIr, vec![1.0, 2.0]);
        let b = ModalityVector::new(Modality::CfgPath, vec![1.0, 2.0, 3.0]);

        let result = model.fuse(content_id(6), &[a, b]);
        assert_eq!(result, Err(FusionError::DimensionMismatch));
    }

    #[test]
    fn gated_fusion_all_encoders_end_to_end() {
        let dim = 32;
        let ir_enc = IrSpecialistEncoder::new(dim);
        let cfg_enc = CfgSpecialistEncoder::new(dim);
        let constr_enc = ConstraintSpecialistEncoder::constraint_dag(dim);
        let mem_enc = MemorySpecialistEncoder::new(dim);

        let ir_vec = ir_enc.encode_counts(&[5, 10, 15, 20]);
        let cfg_vec = cfg_enc.encode_topology(20, 8, 3);
        let constr_vec = constr_enc.encode_complexity(40, 10, 12);
        let mem_vec = mem_enc.encode_counts(50, 25);

        let model = GatedFusionModel::with_weights(
            EmbeddingModelVersion(2),
            EmbeddingSchemaVersion(3),
            [
                (Modality::SemanticIr, 1.0),
                (Modality::CfgPath, 0.5),
                (Modality::ConstraintDag, 0.0),
                (Modality::MemoryBehavior, -0.5),
            ],
        );

        let result = model.fuse(content_id(10), &[ir_vec, cfg_vec, constr_vec, mem_vec]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.dimension(), dim);
            assert_eq!(fused.contributions.len(), 4);

            let w_ir = fused.contribution(Modality::SemanticIr).unwrap_or(0.0);
            let w_cfg = fused.contribution(Modality::CfgPath).unwrap_or(0.0);
            let w_constr = fused.contribution(Modality::ConstraintDag).unwrap_or(0.0);
            let w_mem = fused.contribution(Modality::MemoryBehavior).unwrap_or(0.0);

            // Weights strictly follow softmax ordering: ir > cfg > constr > mem
            assert!(w_ir > w_cfg);
            assert!(w_cfg > w_constr);
            assert!(w_constr > w_mem);

            let total_w = w_ir + w_cfg + w_constr + w_mem;
            assert!((total_w - 1.0).abs() < 1e-5);

            // Verify last_result is stored
            let stored = model.last_result();
            assert!(stored.is_some());
            if let Some(s) = stored {
                assert_eq!(s.artifact, content_id(10));
                assert_eq!(s.values, fused.values);
            }
        }
    }

    #[test]
    fn gated_fusion_dynamic_weight_update() {
        let model = new_gated_model();
        let a = ModalityVector::new(Modality::SemanticIr, vec![1.0, 0.0]);
        let b = ModalityVector::new(Modality::CfgPath, vec![0.0, 1.0]);

        // Initially equal weights (default 0.0).
        let first = model.fuse(content_id(11), &[a.clone(), b.clone()]);
        assert!(first.is_ok());
        if let Ok(first) = first {
            assert!((first.contribution(Modality::SemanticIr).unwrap_or(0.0) - 0.5).abs() < 1e-5);
        }

        // Dynamically boost SemanticIr.
        model.set_weight(Modality::SemanticIr, 10.0);
        let second = model.fuse(content_id(11), &[a, b]);
        assert!(second.is_ok());
        if let Ok(second) = second {
            let w_ir_second = second.contribution(Modality::SemanticIr).unwrap_or(0.0);
            assert!(w_ir_second > 0.99);
        }
    }

    #[test]
    fn modality_vector_and_fused_embedding_helpers() {
        let mv = ModalityVector::masked(Modality::TaintFlow, 16);
        assert!(mv.masked);
        assert_eq!(mv.values.len(), 16);
        assert_eq!(mv.modality, Modality::TaintFlow);

        let unmasked = mv.with_masked(false);
        assert!(!unmasked.masked);

        let fused = FusedEmbedding {
            artifact: content_id(1),
            model: EmbeddingModelVersion(1),
            schema: EmbeddingSchemaVersion(1),
            values: vec![1.0, 2.0, 3.0],
            contributions: vec![(Modality::SemanticIr, 1.0)],
        };
        assert_eq!(fused.dimension(), 3);
        assert_eq!(fused.contribution(Modality::SemanticIr), Some(1.0));
        assert_eq!(fused.contribution(Modality::CfgPath), None);
    }
}
