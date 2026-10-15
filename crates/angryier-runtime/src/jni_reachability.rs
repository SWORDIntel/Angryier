#![forbid(unsafe_code)]

//! JNI sink reachability analyzer: symbolic path exploration from exported JNI
//! entry points to native vulnerability sinks (ANG-052).
//!
//! Provides [`JniSinkReachabilityAnalyzer`] to verify whether tainted Android Java
//! inputs (e.g. `jstring`, `jbyteArray`, `jint`, `jlong`) can reach native
//! vulnerability sinks (such as `memcpy`, `strcpy`, or arbitrary memory stores)
//! with input-controlled destination pointers or length parameters, and solves for
//! satisfying concrete exploit/replay models.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use angryier_arch::Decoder;
use angryier_arch_intel64::register_id;
use angryier_execution::{SymbolBinding, SymbolicArena};
use angryier_expr::{ExprArena, ExprArenaError, ExprNode, ExprOp, ExprSort, ShardedExprArena};
use angryier_ir::IrType;
use angryier_memory::LayeredMemory;
use angryier_replay::{ExpectedCheckpoints, REPLAY_SCHEMA_V2, RecordedInputs, ReplayCapsule, capsule_domain_id};
use angryier_solver::{CanonicalConstraint, SolverBackend, SolverOutcomeKind, SolverQuery};
use angryier_taint::TaintLabel;
use angryier_types::{
    Address, AnalysisContext, ConstraintCanonicalizationVersion, ConstraintId, ContentId, DependencyKey,
    ExpressionNormalizationVersion, FidelityProfile, ReplayCapsuleId, RetentionProfile, RunId, SecurityContext,
    SolverQueryId, TaintId,
};

use crate::jni::JniEnvironment;
use crate::{ExplorationPolicy, Process, Runtime, RuntimeError, SymbolicSession, SymbolicState};

// ---------------------------------------------------------------------------
// JNI Taint Specifications
// ---------------------------------------------------------------------------

/// Specification for tainting a JNI entry point argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JniArgumentTaint {
    /// String argument (`jstring`): initialized with a value and marked tainted/symbolic.
    String {
        arg_index: usize,
        initial_value: String,
        taint_id: TaintId,
        label: TaintLabel,
        symbolic: bool,
    },
    /// Byte array argument (`jbyteArray`): initialized with bytes and marked tainted/symbolic.
    ByteArray {
        arg_index: usize,
        initial_bytes: Vec<u8>,
        taint_id: TaintId,
        label: TaintLabel,
        symbolic_bytes: bool,
        symbolic_length: bool,
    },
    /// Integer argument (`jint` / `jsize`): 32-bit integer passed directly in GPR.
    Int {
        arg_index: usize,
        initial_value: i32,
        taint_id: TaintId,
        label: TaintLabel,
        symbolic: bool,
    },
    /// Long integer argument (`jlong`): 64-bit integer passed directly in GPR.
    Long {
        arg_index: usize,
        initial_value: i64,
        taint_id: TaintId,
        label: TaintLabel,
        symbolic: bool,
    },
    /// Specific general-purpose register tainted directly.
    Register {
        register_index: u32,
        initial_value: u64,
        taint_id: TaintId,
        label: TaintLabel,
    },
}

// ---------------------------------------------------------------------------
// Sink Descriptors & Constraints
// ---------------------------------------------------------------------------

/// Classification of native vulnerability sinks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JniSinkKind {
    /// Memory copy sink (`memcpy(dest, src, n)`).
    Memcpy,
    /// String copy sink (`strcpy(dest, src)`).
    Strcpy,
    /// Memory store instruction.
    Store,
    /// Custom sink function or location.
    Custom(String),
}

/// Parameter at the sink site subject to user control checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkControlledParam {
    /// Destination pointer (Arg 0 / RDI in System V AMD64 ABI).
    Destination,
    /// Source pointer (Arg 1 / RSI in System V AMD64 ABI).
    Source,
    /// Length / count parameter (Arg 2 / RDX in System V AMD64 ABI).
    Length,
    /// Custom GPR register (0 = RAX, 1 = RCX, 2 = RDX, 3 = RBX, etc.).
    CustomRegister(u32),
}

/// Constraint predicate to assert at the sink site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkConstraintPredicate {
    /// Controlled parameter must be strictly greater than `bound`.
    GreaterThan(u64),
    /// Controlled parameter must be greater than or equal to `bound`.
    GreaterOrEqual(u64),
    /// Controlled parameter must equal `val`.
    Equal(u64),
    /// Controlled parameter must be non-zero.
    NonZero,
    /// Custom expression ID asserting a constraint formula.
    Custom(angryier_types::ExprId),
}

/// Complete descriptor of a vulnerability sink target.
#[derive(Clone, Debug)]
pub struct JniSinkDescriptor {
    /// Address of the sink call, stub, or instruction.
    pub sink_pc: Address,
    /// Kind of sink.
    pub kind: JniSinkKind,
    /// Which parameter must be controlled by tainted JNI inputs.
    pub controlled_param: Option<SinkControlledParam>,
    /// Optional constraint to assert at the sink site (e.g. length > buffer_size).
    pub constraint_predicate: Option<SinkConstraintPredicate>,
}

impl JniSinkDescriptor {
    /// Creates a `memcpy` sink descriptor at `sink_pc`, checking that length (RDX) is controlled,
    /// optionally asserting `length > length_bound`.
    pub fn memcpy(sink_pc: Address, length_bound: Option<u64>) -> Self {
        Self {
            sink_pc,
            kind: JniSinkKind::Memcpy,
            controlled_param: Some(SinkControlledParam::Length),
            constraint_predicate: length_bound.map(SinkConstraintPredicate::GreaterThan),
        }
    }

    /// Creates a `strcpy` sink descriptor at `sink_pc`, checking that source (RSI) is controlled.
    pub fn strcpy(sink_pc: Address) -> Self {
        Self {
            sink_pc,
            kind: JniSinkKind::Strcpy,
            controlled_param: Some(SinkControlledParam::Source),
            constraint_predicate: None,
        }
    }

    /// Creates a `Store` sink descriptor at `sink_pc`.
    pub fn store(sink_pc: Address, param: SinkControlledParam, constraint: Option<SinkConstraintPredicate>) -> Self {
        Self {
            sink_pc,
            kind: JniSinkKind::Store,
            controlled_param: Some(param),
            constraint_predicate: constraint,
        }
    }

    /// Creates a custom sink descriptor at `sink_pc`.
    pub fn custom(sink_pc: Address, name: impl Into<String>) -> Self {
        Self {
            sink_pc,
            kind: JniSinkKind::Custom(name.into()),
            controlled_param: None,
            constraint_predicate: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reachability Results & Replay Metadata
// ---------------------------------------------------------------------------

/// Path feasibility outcome for reaching the sink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JniPathStatus {
    /// Path reaches the sink and all constraints are satisfiable.
    Feasible,
    /// Path or sink condition is mathematically unsatisfiable.
    Unsat,
    /// Exploration did not reach the sink within bounds (step budget, timeout, state pruning,
    /// or depth limit exceeded) — Honoring Honest Incompleteness.
    BoundedUnknown { reason: String },
}

/// Metadata describing a deterministic replay capsule for verified reachability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JniReplayCapsuleMetadata {
    pub capsule_id: ReplayCapsuleId,
    pub image_hash: ContentId,
    pub entry_pc: Address,
    pub sink_pc: Address,
    pub initial_registers: Vec<(u32, u64)>,
    pub model_inputs: Vec<(u64, Vec<u8>)>,
    pub capsule: Option<ReplayCapsule>,
}

/// Full analysis result from [`JniSinkReachabilityAnalyzer`].
#[derive(Clone, Debug)]
pub struct JniReachabilityResult {
    /// Feasibility status of the path to sink.
    pub status: JniPathStatus,
    /// Address trace of executed blocks/instructions from entry point to sink.
    pub trace: Vec<Address>,
    /// Model values satisfying the path and sink constraints.
    pub model_values: Vec<(u64, Vec<u8>)>,
    /// Deterministic replay capsule metadata when feasible.
    pub replay_metadata: Option<JniReplayCapsuleMetadata>,
    /// The evaluated sink descriptor.
    pub sink: JniSinkDescriptor,
    /// Steps taken during exploration.
    pub steps_taken: u64,
    /// Model debt and bounds encountered during analysis.
    pub model_debt: Vec<String>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration options for the reachability analysis.
#[derive(Clone, Debug)]
pub struct JniReachabilityConfig {
    /// Maximum steps permitted across exploration.
    pub max_steps: u64,
    /// Maximum concurrent states during path exploration.
    pub max_states: usize,
    /// Wall-clock timeout for exploration and solving.
    pub timeout: Duration,
    /// Maximum execution depth (trace length / call depth).
    pub max_depth: Option<u64>,
    /// Optional pre-condition or path constraints to seed initial state with.
    pub initial_constraints: Vec<angryier_types::ExprId>,
}

impl Default for JniReachabilityConfig {
    fn default() -> Self {
        Self {
            max_steps: 1000,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(100),
            initial_constraints: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Analyzer Implementation
// ---------------------------------------------------------------------------

/// Symbolic path reachability analyzer from exported JNI entry points to native sinks.
pub struct JniSinkReachabilityAnalyzer<'a, D: Decoder> {
    runtime: &'a Runtime<D>,
    config: JniReachabilityConfig,
    arena: Arc<ShardedExprArena>,
}

impl<'a, D: Decoder> JniSinkReachabilityAnalyzer<'a, D> {
    /// Creates a new reachability analyzer using the given runtime.
    pub fn new(runtime: &'a Runtime<D>) -> Self {
        Self {
            runtime,
            config: JniReachabilityConfig::default(),
            arena: Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1))),
        }
    }

    /// Sets custom analysis configuration.
    pub fn with_config(mut self, config: JniReachabilityConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets custom shared expression arena.
    pub fn with_arena(mut self, arena: Arc<ShardedExprArena>) -> Self {
        self.arena = arena;
        self
    }

    /// Returns a reference-counted handle to the shared expression arena.
    pub fn arena(&self) -> Arc<ShardedExprArena> {
        self.arena.clone()
    }

    /// Analyzes path reachability from an ELF binary image.
    pub fn analyze_elf(
        &self,
        elf_bytes: &[u8],
        entry_pc: Address,
        taint_specs: &[JniArgumentTaint],
        sink: JniSinkDescriptor,
        backend: &mut dyn SolverBackend,
    ) -> Result<JniReachabilityResult, RuntimeError> {
        let mut process = self.runtime.load_elf(elf_bytes)?;
        self.analyze(&mut process, entry_pc, taint_specs, sink, backend)
    }

    /// Analyzes path reachability in an initialized process.
    pub fn analyze(
        &self,
        process: &mut Process,
        entry_pc: Address,
        taint_specs: &[JniArgumentTaint],
        sink: JniSinkDescriptor,
        backend: &mut dyn SolverBackend,
    ) -> Result<JniReachabilityResult, RuntimeError> {
        let mut model_debt = Vec::new();

        // 1. Set entry PC.
        process.write_pc(entry_pc)?;

        // 2. Attach JNI Environment.
        let env_arc = JniEnvironment::new();
        let env_ptr = self.runtime.attach_jni_environment(process, env_arc.clone())?;

        // In System V AMD64 JNI calling convention:
        // Arg 0 (RDI): JNIEnv*
        // Arg 1 (RSI): jobject (thiz or clazz)
        process.write_register(register_id::GPR_BASE + 7, env_ptr)?;
        let thiz_handle = {
            let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
            guard.create_class("com/example/NativeBridge")
        };
        process.write_register(register_id::GPR_BASE + 6, thiz_handle)?;

        let mut initial_registers = vec![
            (register_id::GPR_BASE + 7, env_ptr),
            (register_id::GPR_BASE + 6, thiz_handle),
        ];

        // Ensure stack has a valid return PC for call returns.
        let rsp = process
            .read_register(register_id::GPR_BASE + 4)
            .unwrap_or(0x7fff_0000_0000);
        let stack_top = if rsp >= 0x7fff_0000_0000 { rsp - 8 } else { rsp };
        process.write_register(register_id::GPR_BASE + 4, stack_top)?;
        let exit_ret_pc = 0x7fff_ffff_1000u64;
        if let Ok(new_mem) = process.state.memory.write(
            stack_top,
            &exit_ret_pc.to_le_bytes().map(angryier_memory::ByteValue::Concrete),
        ) {
            process.state.memory = new_mem;
        }

        // 3. Setup arena and tainted arguments.
        let arena = self.arena.clone();
        let mut tainted_expr_ids = BTreeSet::new();
        let mut next_symbol_idx: u64 = 1000;
        let mut initial_symbolic_regs: Vec<(u32, angryier_types::ExprId)> = Vec::new();

        for spec in taint_specs {
            match spec {
                JniArgumentTaint::String {
                    arg_index,
                    initial_value,
                    taint_id,
                    label,
                    symbolic,
                } => {
                    let handle = {
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.create_string(initial_value)
                    };
                    if *symbolic {
                        let mut sym_bytes = Vec::with_capacity(initial_value.len());
                        for (i, _) in initial_value.bytes().enumerate() {
                            let sym_id = arena
                                .intern(ExprNode {
                                    sort: ExprSort::BitVec(8),
                                    op: ExprOp::Symbol,
                                    operands: Vec::new(),
                                    immediate: (next_symbol_idx + i as u64).to_le_bytes().to_vec(),
                                })
                                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                            tainted_expr_ids.insert(sym_id);
                            sym_bytes.push(sym_id);
                        }
                        next_symbol_idx += initial_value.len() as u64;
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.mark_string_symbolic(handle, *taint_id, *label, sym_bytes);
                    } else {
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.mark_string_tainted(handle, *taint_id, *label);
                    }

                    if let Some(reg_id) = jni_arg_to_register_id(*arg_index) {
                        process.write_register(reg_id, handle)?;
                        initial_registers.push((reg_id, handle));
                    }
                }
                JniArgumentTaint::ByteArray {
                    arg_index,
                    initial_bytes,
                    taint_id,
                    label,
                    symbolic_bytes,
                    symbolic_length,
                } => {
                    let handle = {
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.create_byte_array(initial_bytes.clone())
                    };

                    let sym_bytes = if *symbolic_bytes {
                        let mut bytes = Vec::with_capacity(initial_bytes.len());
                        for (i, _) in initial_bytes.iter().enumerate() {
                            let sym_id = arena
                                .intern(ExprNode {
                                    sort: ExprSort::BitVec(8),
                                    op: ExprOp::Symbol,
                                    operands: Vec::new(),
                                    immediate: (next_symbol_idx + i as u64).to_le_bytes().to_vec(),
                                })
                                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                            tainted_expr_ids.insert(sym_id);
                            bytes.push(sym_id);
                        }
                        next_symbol_idx += initial_bytes.len() as u64;
                        Some(bytes)
                    } else {
                        None
                    };

                    let sym_len = if *symbolic_length {
                        let len_sym = arena
                            .intern(ExprNode {
                                sort: ExprSort::BitVec(64),
                                op: ExprOp::Symbol,
                                operands: Vec::new(),
                                immediate: next_symbol_idx.to_le_bytes().to_vec(),
                            })
                            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                        next_symbol_idx += 1;
                        tainted_expr_ids.insert(len_sym);
                        Some(len_sym)
                    } else {
                        None
                    };

                    if sym_bytes.is_some() || sym_len.is_some() {
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.mark_byte_array_symbolic(
                            handle,
                            *taint_id,
                            *label,
                            sym_bytes.unwrap_or_default(),
                            sym_len,
                        );
                    } else {
                        let mut guard = env_arc.write().unwrap_or_else(|e| e.into_inner());
                        guard.mark_byte_array_tainted(handle, *taint_id, *label);
                    }

                    if let Some(reg_id) = jni_arg_to_register_id(*arg_index) {
                        process.write_register(reg_id, handle)?;
                        initial_registers.push((reg_id, handle));
                    }
                }
                JniArgumentTaint::Int {
                    arg_index,
                    initial_value,
                    taint_id: _,
                    label: _,
                    symbolic,
                } => {
                    let val = *initial_value as u64;
                    if let Some(reg_id) = jni_arg_to_register_id(*arg_index) {
                        process.write_register(reg_id, val)?;
                        initial_registers.push((reg_id, val));

                        if *symbolic {
                            let sym_id = arena
                                .intern(ExprNode {
                                    sort: ExprSort::BitVec(64),
                                    op: ExprOp::Symbol,
                                    operands: Vec::new(),
                                    immediate: next_symbol_idx.to_le_bytes().to_vec(),
                                })
                                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                            next_symbol_idx += 1;
                            tainted_expr_ids.insert(sym_id);
                            initial_symbolic_regs.push((reg_id, sym_id));
                        }
                    }
                }
                JniArgumentTaint::Long {
                    arg_index,
                    initial_value,
                    taint_id: _,
                    label: _,
                    symbolic,
                } => {
                    let val = *initial_value as u64;
                    if let Some(reg_id) = jni_arg_to_register_id(*arg_index) {
                        process.write_register(reg_id, val)?;
                        initial_registers.push((reg_id, val));

                        if *symbolic {
                            let sym_id = arena
                                .intern(ExprNode {
                                    sort: ExprSort::BitVec(64),
                                    op: ExprOp::Symbol,
                                    operands: Vec::new(),
                                    immediate: next_symbol_idx.to_le_bytes().to_vec(),
                                })
                                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                            next_symbol_idx += 1;
                            tainted_expr_ids.insert(sym_id);
                            initial_symbolic_regs.push((reg_id, sym_id));
                        }
                    }
                }
                JniArgumentTaint::Register {
                    register_index,
                    initial_value,
                    taint_id: _,
                    label: _,
                } => {
                    let reg_id = register_id::GPR_BASE + *register_index;
                    process.write_register(reg_id, *initial_value)?;
                    initial_registers.push((reg_id, *initial_value));

                    let sym_id = arena
                        .intern(ExprNode {
                            sort: ExprSort::BitVec(64),
                            op: ExprOp::Symbol,
                            operands: Vec::new(),
                            immediate: next_symbol_idx.to_le_bytes().to_vec(),
                        })
                        .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                    next_symbol_idx += 1;
                    tainted_expr_ids.insert(sym_id);
                    initial_symbolic_regs.push((reg_id, sym_id));
                }
            }
        }

        // 4. Initialize SymbolicSession.
        let mut session = SymbolicSession::new(self.runtime, arena.as_ref(), process.clone());

        // Bind initial symbolic registers into session state 0.
        if !session.states.is_empty() {
            for (reg_id, sym_id) in initial_symbolic_regs {
                session.states[0].registers.insert(reg_id, (sym_id, IrType::Bits(64)));
                session.states[0].symbols.push(SymbolBinding {
                    register: reg_id,
                    expression: sym_id,
                    width: 64,
                });
            }

            if !self.config.initial_constraints.is_empty() {
                session.states[0]
                    .constraints
                    .extend(self.config.initial_constraints.iter().copied());
            }
        }

        // 5. Explore paths toward sink.
        let policy = ExplorationPolicy {
            find: vec![sink.sink_pc],
            ..Default::default()
        };

        let report = session.run_with_policy(
            self.config.max_steps,
            self.config.max_states,
            Some(backend),
            self.config.timeout,
            true,
            &policy,
        )?;

        // 6. Evaluate reachability & Honest Incompleteness.
        if report.found.is_empty() {
            if report.timed_out {
                model_debt.push("Exploration halted by wall-clock timeout".into());
                return Ok(JniReachabilityResult {
                    status: JniPathStatus::BoundedUnknown {
                        reason: "Wall-clock timeout during symbolic path exploration".into(),
                    },
                    trace: Vec::new(),
                    model_values: Vec::new(),
                    replay_metadata: None,
                    sink,
                    steps_taken: self.config.max_steps,
                    model_debt,
                });
            } else if report.pruned_states > 0 {
                model_debt.push(format!(
                    "State capacity limit exceeded: {} state(s) pruned",
                    report.pruned_states
                ));
                return Ok(JniReachabilityResult {
                    status: JniPathStatus::BoundedUnknown {
                        reason: format!(
                            "State capacity exceeded; {} paths dropped before finding sink",
                            report.pruned_states
                        ),
                    },
                    trace: Vec::new(),
                    model_values: Vec::new(),
                    replay_metadata: None,
                    sink,
                    steps_taken: self.config.max_steps,
                    model_debt,
                });
            } else if !session.states.is_empty() {
                model_debt.push(format!(
                    "Step budget exhausted: {} active states remained",
                    session.states.len()
                ));
                return Ok(JniReachabilityResult {
                    status: JniPathStatus::BoundedUnknown {
                        reason: format!("Exceeded maximum step budget of {} steps", self.config.max_steps),
                    },
                    trace: Vec::new(),
                    model_values: Vec::new(),
                    replay_metadata: None,
                    sink,
                    steps_taken: self.config.max_steps,
                    model_debt,
                });
            } else {
                return Ok(JniReachabilityResult {
                    status: JniPathStatus::Unsat,
                    trace: Vec::new(),
                    model_values: Vec::new(),
                    replay_metadata: None,
                    sink,
                    steps_taken: report.found.len() as u64,
                    model_debt,
                });
            }
        }

        // 7. Check feasibility of found states.
        let mut best_unknown_reason: Option<String> = None;
        let mut all_unsat = true;

        for found_state in &report.found {
            let mut state_trace = found_state.process.trace.clone();
            if state_trace.last().copied() != Some(sink.sink_pc) {
                state_trace.push(sink.sink_pc);
            }

            // Check recursion / depth limit bounds.
            if let Some(max_depth) = self.config.max_depth
                && state_trace.len() as u64 > max_depth
            {
                model_debt.push(format!(
                    "Trace depth {} exceeds max_depth bound {}",
                    state_trace.len(),
                    max_depth
                ));
                best_unknown_reason = Some(format!(
                    "Exceeded maximum execution depth of {} blocks (trace: {})",
                    max_depth,
                    state_trace.len()
                ));
                all_unsat = false;
                continue;
            }

            let (outcome, model, state_debt) = check_state_feasibility(
                found_state,
                arena.as_ref(),
                &env_arc,
                &sink,
                &tainted_expr_ids,
                backend,
                self.config.timeout,
            )?;
            model_debt.extend(state_debt);

            match outcome {
                SolverOutcomeKind::Sat => {
                    let mut sorted_regs = initial_registers.clone();
                    sorted_regs.sort_by_key(|(reg, _)| *reg);
                    let inputs = RecordedInputs {
                        registers: sorted_regs.clone(),
                        stdin: Vec::new(),
                    };
                    let image_hash = capsule_domain_id(&[]);
                    let scheduler_seed = 0x5EED_0000_0000_0001u64;
                    let capsule_id = derive_capsule_id(image_hash, &inputs, scheduler_seed);

                    let capsule = ReplayCapsule {
                        id: capsule_id,
                        schema: REPLAY_SCHEMA_V2,
                        context: AnalysisContext {
                            run_id: RunId(0),
                            target_profile: self.runtime.target_profile,
                            fidelity: FidelityProfile::Prove,
                            retention: RetentionProfile::Forensic,
                            security: SecurityContext {
                                classification: 0,
                                compartment: 0,
                            },
                        },
                        initial_state: process.state.id,
                        semantic_version: self.runtime.semantic_version,
                        semantic_content: ContentId::default(),
                        code_versions: Vec::new(),
                        environment_key: DependencyKey(capsule_domain_id(b"angryier:environment:jni-native:1").0),
                        scheduler_seed,
                        image_hash,
                        inputs,
                        expected: ExpectedCheckpoints::default(),
                    };

                    let replay_metadata = JniReplayCapsuleMetadata {
                        capsule_id,
                        image_hash,
                        entry_pc,
                        sink_pc: sink.sink_pc,
                        initial_registers: sorted_regs,
                        model_inputs: model.clone(),
                        capsule: Some(capsule),
                    };

                    let steps_taken = state_trace.len() as u64;
                    return Ok(JniReachabilityResult {
                        status: JniPathStatus::Feasible,
                        trace: state_trace,
                        model_values: model,
                        replay_metadata: Some(replay_metadata),
                        sink,
                        steps_taken,
                        model_debt,
                    });
                }
                SolverOutcomeKind::Unsat => {
                    // Continue checking other candidates
                }
                SolverOutcomeKind::Timeout => {
                    all_unsat = false;
                    best_unknown_reason = Some("Solver query timed out".into());
                    model_debt.push("Solver query timed out; inconclusive feasibility".into());
                }
                SolverOutcomeKind::ResourceLimit => {
                    all_unsat = false;
                    best_unknown_reason = Some("Solver exceeded resource limit".into());
                    model_debt.push("Solver resource limit exceeded".into());
                }
                SolverOutcomeKind::BackendError => {
                    all_unsat = false;
                    best_unknown_reason = Some("Solver backend error encountered".into());
                    model_debt.push("Solver backend error".into());
                }
                SolverOutcomeKind::Unknown => {
                    all_unsat = false;
                    best_unknown_reason = Some("Solver returned Unknown for sink feasibility query".into());
                }
            }
        }

        if let Some(reason) = best_unknown_reason {
            Ok(JniReachabilityResult {
                status: JniPathStatus::BoundedUnknown { reason },
                trace: Vec::new(),
                model_values: Vec::new(),
                replay_metadata: None,
                sink,
                steps_taken: 0,
                model_debt,
            })
        } else if all_unsat {
            Ok(JniReachabilityResult {
                status: JniPathStatus::Unsat,
                trace: Vec::new(),
                model_values: Vec::new(),
                replay_metadata: None,
                sink,
                steps_taken: 0,
                model_debt,
            })
        } else {
            Ok(JniReachabilityResult {
                status: JniPathStatus::BoundedUnknown {
                    reason: "Exploration yielded inconclusive results across candidate paths".into(),
                },
                trace: Vec::new(),
                model_values: Vec::new(),
                replay_metadata: None,
                sink,
                steps_taken: 0,
                model_debt,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Maps a 0-based JNI argument index to its System V AMD64 GPR register id.
pub fn jni_arg_to_register_id(arg_index: usize) -> Option<u32> {
    match arg_index {
        0 => Some(register_id::GPR_BASE + 7), // RDI
        1 => Some(register_id::GPR_BASE + 6), // RSI
        2 => Some(register_id::GPR_BASE + 2), // RDX
        3 => Some(register_id::GPR_BASE + 1), // RCX
        4 => Some(register_id::GPR_BASE + 8), // R8
        5 => Some(register_id::GPR_BASE + 9), // R9
        _ => None,
    }
}

/// Recursively checks whether an expression depends on any tainted symbol.
pub fn is_expression_tainted(
    arena: &dyn ExprArena<Error = ExprArenaError>,
    expr: angryier_types::ExprId,
    tainted_ids: &BTreeSet<angryier_types::ExprId>,
) -> bool {
    if tainted_ids.is_empty() {
        return true;
    }
    let mut stack = vec![expr];
    let mut visited = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if visited.insert(id) {
            if tainted_ids.contains(&id) {
                return true;
            }
            if let Some(node) = arena.get(id) {
                if node.op == ExprOp::Symbol && tainted_ids.contains(&id) {
                    return true;
                }
                stack.extend(node.operands);
            }
        }
    }
    false
}

/// Helper that converts path constraint expressions into canonical constraints.
fn checked_path_constraints_helper(
    arena: &SymbolicArena,
    path: &[angryier_types::ExprId],
) -> Result<Vec<CanonicalConstraint>, RuntimeError> {
    path.iter()
        .enumerate()
        .map(|(index, expr)| {
            let summary = arena.dependency_summary(*expr).ok_or_else(|| {
                RuntimeError::Symbolic(format!(
                    "incomplete solver path: constraint #{index} (expression {}) lacks dependency metadata",
                    expr.0
                ))
            })?;
            Ok(CanonicalConstraint {
                id: ConstraintId(index as u64),
                key: summary.key,
                expr: *expr,
            })
        })
        .collect()
}

/// Feasibility outcome tuple: (SolverOutcomeKind, model values, model debt).
type StateFeasibilityResult = (SolverOutcomeKind, Vec<(u64, Vec<u8>)>, Vec<String>);

/// Checks the constraint feasibility of a candidate state at the sink site.
fn check_state_feasibility(
    state: &SymbolicState,
    arena: &SymbolicArena,
    env: &Arc<std::sync::RwLock<JniEnvironment>>,
    sink: &JniSinkDescriptor,
    tainted_ids: &BTreeSet<angryier_types::ExprId>,
    backend: &mut dyn SolverBackend,
    timeout: Duration,
) -> Result<StateFeasibilityResult, RuntimeError> {
    let mut model_debt = Vec::new();

    // 1. Identify register corresponding to the controlled parameter.
    let reg_id = match sink.controlled_param {
        Some(SinkControlledParam::Destination) => register_id::GPR_BASE + 7,
        Some(SinkControlledParam::Source) => register_id::GPR_BASE + 6,
        Some(SinkControlledParam::Length) => register_id::GPR_BASE + 2,
        Some(SinkControlledParam::CustomRegister(r)) => register_id::GPR_BASE + r,
        None => match sink.kind {
            JniSinkKind::Memcpy => register_id::GPR_BASE + 2,
            JniSinkKind::Strcpy => register_id::GPR_BASE + 6,
            JniSinkKind::Store => register_id::GPR_BASE + 7,
            JniSinkKind::Custom(_) => register_id::GPR_BASE + 2,
        },
    };

    // 2. Determine if parameter is controlled by tainted JNI inputs.
    let mut is_controlled = false;
    let mut param_expr_opt = None;

    if let Some(&(expr_id, _)) = state.registers.get(&reg_id) {
        param_expr_opt = Some(expr_id);
        if is_expression_tainted(arena, expr_id, tainted_ids) {
            is_controlled = true;
        }
    }

    if !is_controlled {
        let concrete_val = state
            .concrete_registers
            .get(&reg_id)
            .copied()
            .or_else(|| state.process.read_register(reg_id).ok());
        if let Some(addr) = concrete_val {
            let guard = env.read().map_err(|e| RuntimeError::Environment(format!("{e:?}")))?;
            if guard.taint_tracker.is_memory_tainted(addr) || guard.taint_tracker.get_buffer(addr).is_some() {
                is_controlled = true;
            }
        }
    }

    if !is_controlled && !tainted_ids.is_empty() && sink.controlled_param.is_some() {
        model_debt.push(format!(
            "Parameter in register {} at sink {:#x} is not controlled by tainted JNI input",
            reg_id, sink.sink_pc
        ));
        return Ok((SolverOutcomeKind::Unsat, Vec::new(), model_debt));
    }

    // 3. Build predicate expression for sink constraints.
    let mut extra_constraints = Vec::new();

    if let Some(ref pred_spec) = sink.constraint_predicate {
        let param_expr = if let Some(e) = param_expr_opt {
            e
        } else {
            let val = state
                .concrete_registers
                .get(&reg_id)
                .copied()
                .or_else(|| state.process.read_register(reg_id).ok())
                .unwrap_or(0);
            arena
                .intern(ExprNode {
                    sort: ExprSort::BitVec(64),
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: val.to_le_bytes().to_vec(),
                })
                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?
        };

        let constraint_expr = match pred_spec {
            SinkConstraintPredicate::GreaterThan(bound) => {
                let bound_expr = arena
                    .intern(ExprNode {
                        sort: ExprSort::BitVec(64),
                        op: ExprOp::Constant,
                        operands: Vec::new(),
                        immediate: bound.to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                // param_expr > bound <=> bound < param_expr
                arena
                    .intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Ult,
                        operands: vec![bound_expr, param_expr],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?
            }
            SinkConstraintPredicate::GreaterOrEqual(bound) => {
                let bound_expr = arena
                    .intern(ExprNode {
                        sort: ExprSort::BitVec(64),
                        op: ExprOp::Constant,
                        operands: Vec::new(),
                        immediate: bound.to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                // param_expr >= bound <=> bound <= param_expr
                arena
                    .intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Ule,
                        operands: vec![bound_expr, param_expr],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?
            }
            SinkConstraintPredicate::Equal(val) => {
                let val_expr = arena
                    .intern(ExprNode {
                        sort: ExprSort::BitVec(64),
                        op: ExprOp::Constant,
                        operands: Vec::new(),
                        immediate: val.to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                arena
                    .intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Eq,
                        operands: vec![param_expr, val_expr],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?
            }
            SinkConstraintPredicate::NonZero => {
                let zero_expr = arena
                    .intern(ExprNode {
                        sort: ExprSort::BitVec(64),
                        op: ExprOp::Constant,
                        operands: Vec::new(),
                        immediate: 0u64.to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                let eq_zero = arena
                    .intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Eq,
                        operands: vec![param_expr, zero_expr],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                arena
                    .intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Not,
                        operands: vec![eq_zero],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?
            }
            SinkConstraintPredicate::Custom(expr_id) => *expr_id,
        };
        extra_constraints.push(constraint_expr);
    }

    // 4. Combine path constraints with sink constraint.
    let mut all_exprs = state.constraints.clone();
    all_exprs.extend(extra_constraints.iter().copied());

    let canonical_constraints = checked_path_constraints_helper(arena, &all_exprs)?;

    // Build the query predicate. If there's an extra constraint or path constraint, use it;
    // if parameter is symbolic, ensure the query predicate references it so its symbols
    // are in the solver's model-extraction universe.
    let (predicate, key) = if let Some(&last_expr) = extra_constraints.last() {
        let key = arena
            .dependency_summary(last_expr)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing summary for sink constraint".into()))?;
        (last_expr, key)
    } else if let Some(&last_constraint) = state.constraints.last() {
        let key = arena
            .dependency_summary(last_constraint)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing summary for path constraint".into()))?;
        (last_constraint, key)
    } else if let Some(param_expr) = param_expr_opt {
        // Trivial self-equality predicate that brings param_expr symbols into solver universe:
        let id_expr = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![param_expr, param_expr],
                immediate: Vec::new(),
            })
            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
        let key = arena
            .dependency_summary(id_expr)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing summary for self-equality predicate".into()))?;
        (id_expr, key)
    } else {
        let true_expr = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![1],
            })
            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
        let key = arena
            .dependency_summary(true_expr)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing summary for true predicate".into()))?;
        (true_expr, key)
    };

    let query = SolverQuery::canonical(
        SolverQueryId(state.id),
        &canonical_constraints,
        predicate,
        key,
        state.process.target_profile,
        ConstraintCanonicalizationVersion(1),
        timeout,
    )
    .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;

    let solve_result = backend.solve(&query);
    Ok((solve_result.outcome, solve_result.model, model_debt))
}

/// Derives a deterministic replay capsule ID from image hash, inputs, and seed.
pub fn derive_capsule_id(image: ContentId, inputs: &RecordedInputs, scheduler_seed: u64) -> ReplayCapsuleId {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&image.0);
    canonical.extend_from_slice(&(inputs.registers.len() as u64).to_le_bytes());
    for (register, value) in &inputs.registers {
        canonical.extend_from_slice(&register.to_le_bytes());
        canonical.extend_from_slice(&value.to_le_bytes());
    }
    canonical.extend_from_slice(&(inputs.stdin.len() as u64).to_le_bytes());
    canonical.extend_from_slice(&inputs.stdin);
    canonical.extend_from_slice(&scheduler_seed.to_le_bytes());
    let derived = u64::from_le_bytes(capsule_domain_id(&canonical).0[..8].try_into().unwrap_or([0; 8]));
    ReplayCapsuleId(if derived == 0 { 1 } else { derived })
}
