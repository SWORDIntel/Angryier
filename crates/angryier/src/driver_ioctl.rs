//! Reproducible x64 IOCTL-dispatch seeding and verdict classification.
//!
//! The synthetic addresses and structure offsets mirror KP14's current
//! POPKORN seeding contract. This module prepares [`RunOptions`] and classifies
//! completed symbolic execution outcomes into the canonical KP14 POPKORN
//! verdict taxonomy (`symbolic_verdict.schema.json`).

use crate::{ApiError, RunOptions, RunReport};

/// Synthetic base address for the `DRIVER_OBJECT`.
pub const DRIVER_OBJECT_ADDR: u64 = 0x444c_0000;
/// Synthetic base address for the `DEVICE_OBJECT`.
pub const DEVICE_OBJECT_ADDR: u64 = 0x444d_0000;
/// Synthetic base address for the `DEVICE_EXTENSION`.
pub const DEVICE_EXTENSION_ADDR: u64 = 0x444e_0000;
/// Synthetic base address for bump allocations in the kernel harness.
pub const BUMP_ALLOC_BASE: u64 = 0x444f_0000;
/// Synthetic base address for the `IRP`.
pub const IRP_ADDR: u64 = 0x0133_7000;
/// Synthetic base address for the `IO_STACK_LOCATION`.
pub const IRP_STACK_ADDR: u64 = 0x0600_0000;
/// Synthetic base address for attacker-controlled input buffer.
pub const INPUT_BUFFER_ADDR: u64 = 0x0700_0000;

/// Byte length allocated for synthetic `DRIVER_OBJECT`.
pub const DRIVER_OBJECT_BYTES: usize = 0x200;
/// Byte length allocated for synthetic `DEVICE_OBJECT`.
pub const DEVICE_OBJECT_BYTES: usize = 0x100;
/// Byte length allocated for synthetic `DEVICE_EXTENSION`.
pub const DEVICE_EXTENSION_BYTES: usize = 0x200;
/// Byte length allocated for synthetic `IRP`.
pub const IRP_BYTES: usize = 0x200;
/// Byte length allocated for synthetic `IO_STACK_LOCATION`.
pub const IRP_STACK_BYTES: usize = 0x48;
/// Byte length allocated for synthetic input buffer.
pub const INPUT_BUFFER_BYTES: usize = 0x200;

/// Offset of `SystemBuffer` in an x64 `IRP`.
pub const IRP_SYSTEM_BUFFER_OFFSET: u64 = 0x18;
/// Offset of `UserBuffer` in an x64 `IRP`.
pub const IRP_USER_BUFFER_OFFSET: u64 = 0x70;
/// Offset of `CurrentStackLocation` in an x64 `IRP`.
pub const IRP_CURRENT_STACK_OFFSET: u64 = 0xb8;
/// Offset of `Parameters.DeviceIoControl.IoControlCode` in an x64 `IO_STACK_LOCATION`.
pub const STACK_IOCTL_CODE_OFFSET: u64 = 0x18;
/// Offset of `Parameters.DeviceIoControl.Type3InputBuffer` in an x64 `IO_STACK_LOCATION`.
pub const STACK_TYPE3_INPUT_OFFSET: u64 = 0x20;
/// Major function code `IRP_MJ_DEVICE_CONTROL` (0x0e).
pub const IRP_MJ_DEVICE_CONTROL: u64 = 0x0e;

/// Architecture-dependent Windows kernel structure layout offsets matching POPKORN / KP14.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelLayout {
    /// Pointer size in bytes (8 for x64, 4 for x86).
    pub pointer_size: usize,
    /// Offset of `MdlAddress` in `IRP`.
    pub irp_mdl_address: u64,
    /// Offset of `AssociatedIrp.SystemBuffer` in `IRP`.
    pub irp_system_buffer: u64,
    /// Offset of `CurrentLocation` in `IRP`.
    pub irp_current_location: u64,
    /// Offset of `UserBuffer` in `IRP`.
    pub irp_user_buffer: u64,
    /// Offset of `Tail.Overlay.CurrentStackLocation` in `IRP`.
    pub irp_current_stack_location: u64,
    /// Offset of `Parameters.DeviceIoControl.OutputBufferLength` in `IO_STACK_LOCATION`.
    pub io_stack_output_buffer_length: u64,
    /// Offset of `Parameters.DeviceIoControl.InputBufferLength` in `IO_STACK_LOCATION`.
    pub io_stack_input_buffer_length: u64,
    /// Offset of `Parameters.DeviceIoControl.IoControlCode` in `IO_STACK_LOCATION`.
    pub io_stack_io_control_code: u64,
    /// Offset of `Parameters.DeviceIoControl.Type3InputBuffer` in `IO_STACK_LOCATION`.
    pub io_stack_type3_input_buffer: u64,
    /// Size of `IO_STACK_LOCATION` structure in bytes.
    pub io_stack_location_size: u64,
    /// Offset of `DeviceExtension` in `DEVICE_OBJECT`.
    pub device_object_device_extension: u64,
    /// Offset of `MajorFunction` dispatch table array in `DRIVER_OBJECT`.
    pub driver_object_major_function: u64,
    /// Number of entries in `MajorFunction` array.
    pub driver_object_major_function_count: usize,
}

impl KernelLayout {
    /// x64 (_AMD64_) Windows kernel structure layout.
    pub const X64: Self = Self {
        pointer_size: 8,
        irp_mdl_address: 0x08,
        irp_system_buffer: 0x18,
        irp_current_location: 0x43,
        irp_user_buffer: 0x70,
        irp_current_stack_location: 0xb8,
        io_stack_output_buffer_length: 0x08,
        io_stack_input_buffer_length: 0x10,
        io_stack_io_control_code: 0x18,
        io_stack_type3_input_buffer: 0x20,
        io_stack_location_size: 0x48,
        device_object_device_extension: 0x40,
        driver_object_major_function: 0x70,
        driver_object_major_function_count: 28,
    };

    /// x86 (_IX86_) Windows kernel structure layout.
    pub const X86: Self = Self {
        pointer_size: 4,
        irp_mdl_address: 0x04,
        irp_system_buffer: 0x0c,
        irp_current_location: 0x23,
        irp_user_buffer: 0x3c,
        irp_current_stack_location: 0x60,
        io_stack_output_buffer_length: 0x04,
        io_stack_input_buffer_length: 0x08,
        io_stack_io_control_code: 0x0c,
        io_stack_type3_input_buffer: 0x10,
        io_stack_location_size: 0x24,
        device_object_device_extension: 0x28,
        driver_object_major_function: 0x38,
        driver_object_major_function_count: 28,
    };

    /// Resolves the layout for a given architecture string ("x64", "x86").
    pub fn for_arch(arch: &str) -> Option<Self> {
        match arch.to_ascii_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => Some(Self::X64),
            "x86" | "i386" | "ix86" => Some(Self::X86),
            _ => None,
        }
    }
}

impl Default for KernelLayout {
    fn default() -> Self {
        Self::X64
    }
}

/// Classification of a targeted IOCTL run matching KP14 POPKORN verdict taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverVerdict {
    /// Sink reached with attacker-controlled input unconstrained or multiple satisfying solutions.
    PathFeasibleUnchecked,
    /// Sink reached with attacker-controlled input constrained or pinned.
    PathFeasibleConstrained,
    /// Exploration completed/exhausted without finding any path to the sink.
    PathUnreachable,
    /// Wall-clock or step budget was exceeded before exploration completed.
    TimeoutBudgetExceeded,
    /// Exploration terminated due to state explosion cap or engine error.
    ExplosionSuppressed,
}

impl DriverVerdict {
    /// Canonical wire-format string representation matching `symbolic_verdict.schema.json`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            DriverVerdict::PathFeasibleUnchecked => "PATH_FEASIBLE_UNCHECKED",
            DriverVerdict::PathFeasibleConstrained => "PATH_FEASIBLE_CONSTRAINED",
            DriverVerdict::PathUnreachable => "PATH_UNREACHABLE",
            DriverVerdict::TimeoutBudgetExceeded => "TIMEOUT_BUDGET_EXCEEDED",
            DriverVerdict::ExplosionSuppressed => "EXPLOSION_SUPPRESSED",
        }
    }
}

/// Attacker-input byte range flowing into a sink argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriverOffsetConstraint {
    /// Byte offset in the input buffer.
    pub offset: u64,
    /// Byte length of the constrained slice.
    pub size: u64,
    /// Semantic constraint role or description (e.g. `symbolic_physical_address`).
    pub constraint: String,
}

/// Evaluated attacker constraints for a feasible verdict.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DriverConstraintsSolved {
    /// Minimum input buffer size required to reach the sink.
    pub input_buffer_min_size: Option<u64>,
    /// Byte-range constraints on attacker inputs.
    pub offset_constraints: Vec<DriverOffsetConstraint>,
}

/// Detailed result of a targeted driver IOCTL symbolic verification run.
#[derive(Clone, Debug, PartialEq)]
pub struct DriverIoctlVerdict {
    /// Target identifier (e.g. `TGT-VBOXUSBMON-001`).
    pub target_id: String,
    /// 64-character lowercase hex SHA-256 of the analyzed binary.
    pub binary_sha256: String,
    /// Discrete POPKORN verdict.
    pub verdict: DriverVerdict,
    /// Name of the target sink function (e.g. `MmMapIoSpace`).
    pub sink_name: String,
    /// Total wall-clock execution time in seconds.
    pub execution_time_sec: f64,
    /// Concrete IOCTL code solved for, if any.
    pub ioctl_code: Option<u32>,
    /// Absolute virtual address of the dispatch routine.
    pub handler_va: u64,
    /// Absolute virtual address of the sink call site.
    pub sink_va: u64,
    /// Symbolic instruction steps consumed.
    pub steps_taken: u64,
    /// Evaluated input constraints, if path was feasible.
    pub constraints_solved: Option<DriverConstraintsSolved>,
    /// Optional engine notes or error annotations.
    pub notes: Option<String>,
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

impl DriverIoctlVerdict {
    /// Sets a custom target identifier.
    pub fn with_target_id(mut self, target_id: impl Into<String>) -> Self {
        self.target_id = target_id.into();
        self
    }

    /// Sets the binary SHA-256 identity anchor.
    pub fn with_binary_sha256(mut self, binary_sha256: impl Into<String>) -> Self {
        self.binary_sha256 = binary_sha256.into();
        self
    }

    /// Sets the sink symbol name.
    pub fn with_sink_name(mut self, sink_name: impl Into<String>) -> Self {
        self.sink_name = sink_name.into();
        self
    }

    /// Sets engine notes or diagnostic annotations.
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Sets evaluated constraints.
    pub fn with_constraints(mut self, constraints: DriverConstraintsSolved) -> Self {
        self.constraints_solved = Some(constraints);
        self
    }

    /// Serializes the verdict to JSON conforming to KP14 `symbolic_verdict.schema.json`.
    pub fn to_json(&self) -> String {
        let mut json = String::new();
        json.push('{');
        json.push_str(&format!("\"target_id\":\"{}\",", escape_json(&self.target_id)));
        json.push_str(&format!("\"binary_sha256\":\"{}\",", escape_json(&self.binary_sha256)));
        json.push_str(&format!("\"verdict\":\"{}\",", self.verdict.as_str()));
        json.push_str(&format!("\"sink_name\":\"{}\",", escape_json(&self.sink_name)));
        json.push_str(&format!("\"execution_time_sec\":{:.6},", self.execution_time_sec));
        if let Some(code) = self.ioctl_code {
            json.push_str(&format!("\"ioctl_code\":\"0x{:x}\",", code));
        }
        json.push_str(&format!("\"steps_taken\":{},", self.steps_taken));
        json.push_str(&format!("\"handler_rva\":\"0x{:x}\",", self.handler_va));
        json.push_str(&format!("\"sink_rva\":\"0x{:x}\",", self.sink_va));
        if let Some(ref notes) = self.notes {
            json.push_str(&format!("\"notes\":\"{}\",", escape_json(notes)));
        }
        if let Some(ref cs) = self.constraints_solved {
            json.push_str("\"constraints_solved\":{");
            let mut inner_first = true;
            if let Some(min_size) = cs.input_buffer_min_size {
                json.push_str(&format!("\"input_buffer_min_size\":{}", min_size));
                inner_first = false;
            }
            if !inner_first {
                json.push(',');
            }
            json.push_str("\"offset_constraints\":[");
            for (i, oc) in cs.offset_constraints.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"offset\":{},\"size\":{},\"constraint\":\"{}\"}}",
                    oc.offset, oc.size, escape_json(&oc.constraint)
                ));
            }
            json.push_str("]},");
        } else {
            json.push_str("\"constraints_solved\":null,");
        }
        json.push_str("\"keystone_upserted\":false");
        json.push('}');
        json
    }
}

impl std::fmt::Display for DriverIoctlVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Driver IOCTL Verdict Report:")?;
        writeln!(f, "  Target ID           : {}", self.target_id)?;
        writeln!(f, "  Binary SHA-256      : {}", self.binary_sha256)?;
        writeln!(f, "  Verdict             : {}", self.verdict.as_str())?;
        writeln!(f, "  Sink Function       : {} ({:#x})", self.sink_name, self.sink_va)?;
        writeln!(f, "  Handler VA          : {:#x}", self.handler_va)?;
        if let Some(code) = self.ioctl_code {
            writeln!(f, "  IOCTL Code          : {code:#010x}")?;
        } else {
            writeln!(f, "  IOCTL Code          : <symbolic>")?;
        }
        writeln!(f, "  Steps Taken         : {}", self.steps_taken)?;
        writeln!(f, "  Execution Time      : {:.6}s", self.execution_time_sec)?;
        if let Some(ref cs) = self.constraints_solved {
            if let Some(min_size) = cs.input_buffer_min_size {
                writeln!(f, "  Input Buffer Min    : {min_size} byte(s)")?;
            }
            if !cs.offset_constraints.is_empty() {
                writeln!(
                    f,
                    "  Offset Constraints  : {} constraint(s)",
                    cs.offset_constraints.len()
                )?;
                for oc in &cs.offset_constraints {
                    writeln!(f, "    offset {}+{} : {}", oc.offset, oc.size, oc.constraint)?;
                }
            }
        }
        if let Some(ref notes) = self.notes {
            writeln!(f, "  Diagnostic Notes    : {notes}")?;
        }
        Ok(())
    }
}

/// One x64 IOCTL dispatch path selected by static analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverIoctlTarget {
    /// Absolute virtual address of the dispatch routine entry.
    pub handler_va: u64,
    /// Absolute virtual address of the sink call site to seek.
    pub sink_va: u64,
    /// Concrete IOCTL code, or `None` to leave the code symbolic.
    pub ioctl_code: Option<u32>,
}

impl DriverIoctlTarget {
    /// Build bounded options with POPKORN-compatible synthetic x64 input
    /// objects. The caller supplies instruction and live-state limits.
    ///
    /// `Engine::run` still requires a PE32+ driver image with matching image
    /// base and kernel models. A target hit is evidence of reachability under
    /// the current model, not yet a classified KP14 verdict.
    pub fn run_options(self, steps: u64, max_states: usize) -> Result<RunOptions, ApiError> {
        self.run_options_with_layout(KernelLayout::X64, steps, max_states)
    }

    /// Build bounded options with synthetic input objects using a specific [`KernelLayout`].
    pub fn run_options_with_layout(
        self,
        layout: KernelLayout,
        steps: u64,
        max_states: usize,
    ) -> Result<RunOptions, ApiError> {
        if self.handler_va == 0 || self.sink_va == 0 {
            return Err(ApiError::InvalidArgument(
                "IOCTL handler and sink addresses must be nonzero".to_string(),
            ));
        }
        if steps == 0 || max_states == 0 {
            return Err(ApiError::InvalidArgument(
                "IOCTL step and state budgets must be positive".to_string(),
            ));
        }

        let mut poke = vec![
            (DEVICE_OBJECT_ADDR + layout.device_object_device_extension, DEVICE_EXTENSION_ADDR),
            (IRP_ADDR + layout.irp_system_buffer, INPUT_BUFFER_ADDR),
            (IRP_ADDR + layout.irp_user_buffer, INPUT_BUFFER_ADDR),
            (IRP_ADDR + layout.irp_current_stack_location, IRP_STACK_ADDR),
            (IRP_STACK_ADDR, IRP_MJ_DEVICE_CONTROL),
            (IRP_STACK_ADDR + layout.io_stack_type3_input_buffer, INPUT_BUFFER_ADDR),
        ];
        if let Some(code) = self.ioctl_code {
            poke.push((IRP_STACK_ADDR + layout.io_stack_io_control_code, u64::from(code)));
        }

        Ok(RunOptions {
            regs: vec![("rcx".to_string(), DEVICE_OBJECT_ADDR), ("rdx".to_string(), IRP_ADDR)],
            poke,
            symbolic_memory: vec![
                (DEVICE_OBJECT_ADDR, DEVICE_OBJECT_BYTES),
                (IRP_ADDR, IRP_BYTES),
                (IRP_STACK_ADDR, IRP_STACK_BYTES),
                (INPUT_BUFFER_ADDR, INPUT_BUFFER_BYTES),
            ],
            entry: Some(self.handler_va),
            find: vec![self.sink_va],
            steps,
            max_states,
            solve: true,
            ..RunOptions::default()
        })
    }

    /// Classify a completed symbolic run according to the KP14 POPKORN verdict taxonomy.
    pub fn classify_run(&self, report: &RunReport, elapsed_secs: f64) -> DriverIoctlVerdict {
        self.classify_run_with_metadata(report, elapsed_secs, None, None, None)
    }

    /// Classify a completed symbolic run with optional metadata anchors.
    pub fn classify_run_with_metadata(
        &self,
        report: &RunReport,
        elapsed_secs: f64,
        target_id: Option<&str>,
        sink_name: Option<&str>,
        binary_sha256: Option<&str>,
    ) -> DriverIoctlVerdict {
        let hit_sink = report.found_pcs.contains(&self.sink_va);

        let (verdict, notes, constraints) = if hit_sink {
            let mut cs = DriverConstraintsSolved::default();
            if let Some(first_model) = report.inputs.first() {
                let total_input_bytes: usize = first_model.iter().map(|b| b.len()).sum();
                if total_input_bytes > 0 {
                    cs.input_buffer_min_size = Some(total_input_bytes as u64);
                }
            }
            if report.unconstrained_inputs || report.inputs.len() > 1 {
                (
                    DriverVerdict::PathFeasibleUnchecked,
                    report.last_error.clone().or_else(|| {
                        Some(format!(
                            "sink reached: {} input model(s) solved, unconstrained={}",
                            report.inputs.len(),
                            report.unconstrained_inputs
                        ))
                    }),
                    Some(cs),
                )
            } else {
                (
                    DriverVerdict::PathFeasibleConstrained,
                    report.last_error.clone().or_else(|| {
                        Some(format!(
                            "sink reached: constrained input solved ({} model(s))",
                            report.inputs.len()
                        ))
                    }),
                    Some(cs),
                )
            }
        } else if let Some(ref err) = report.last_error {
            (
                DriverVerdict::ExplosionSuppressed,
                Some(format!("engine_error: {err}")),
                None,
            )
        } else if report.pruned_states > 0 {
            (
                DriverVerdict::ExplosionSuppressed,
                Some(format!(
                    "explosion_threshold_hit: {} states pruned, {} peak states",
                    report.pruned_states, report.peak_states
                )),
                None,
            )
        } else if report.timed_out || (report.live_states > 0 && report.steps > 0) {
            (
                DriverVerdict::TimeoutBudgetExceeded,
                Some(format!(
                    "search_budget_exhausted: completed {} steps, {} live states remained, timed_out={}",
                    report.steps, report.live_states, report.timed_out
                )),
                None,
            )
        } else if report.live_states == 0 {
            (
                DriverVerdict::PathUnreachable,
                Some(format!(
                    "exploration_exhausted: 0 live states remaining after {} steps (failed={}, terminated={})",
                    report.steps, report.failed, report.terminated
                )),
                None,
            )
        } else {
            (
                DriverVerdict::TimeoutBudgetExceeded,
                Some(format!(
                    "budget_exhausted_edge: steps={}, live_states={}",
                    report.steps, report.live_states
                )),
                None,
            )
        };

        DriverIoctlVerdict {
            target_id: target_id
                .map(str::to_string)
                .unwrap_or_else(|| format!("target_{:x}_{:x}", self.handler_va, self.sink_va)),
            binary_sha256: binary_sha256
                .map(str::to_string)
                .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            verdict,
            sink_name: sink_name.map(str::to_string).unwrap_or_else(|| "unknown_sink".to_string()),
            execution_time_sec: if elapsed_secs >= 0.0 { elapsed_secs } else { 0.0 },
            ioctl_code: self.ioctl_code,
            handler_va: self.handler_va,
            sink_va: self.sink_va,
            steps_taken: report.steps,
            constraints_solved: constraints,
            notes,
        }
    }

    /// Create driver IOCTL exploration targets from a dispatch handler VA, sink VA,
    /// and candidate IOCTL codes (e.g. from static analysis export).
    ///
    /// If `candidate_ioctl_codes` is empty, emits a single target with symbolic IOCTL (`None`).
    /// Otherwise, emits one target per candidate code.
    pub fn from_static_candidates(
        handler_va: u64,
        sink_va: u64,
        candidate_ioctl_codes: &[u32],
    ) -> Vec<Self> {
        if candidate_ioctl_codes.is_empty() {
            vec![Self {
                handler_va,
                sink_va,
                ioctl_code: None,
            }]
        } else {
            candidate_ioctl_codes
                .iter()
                .map(|&code| Self {
                    handler_va,
                    sink_va,
                    ioctl_code: Some(code),
                })
                .collect()
        }
    }

    /// Create targets resolving RVAs against a known image base.
    pub fn from_static_rva_candidates(
        image_base: u64,
        handler_rva: u64,
        sink_rva: u64,
        candidate_ioctl_codes: &[u32],
    ) -> Vec<Self> {
        Self::from_static_candidates(
            image_base.wrapping_add(handler_rva),
            image_base.wrapping_add(sink_rva),
            candidate_ioctl_codes,
        )
    }
}

/// Single target entry parsed from a static handoff (METHRA static analysis / POPKORN `symbolic_targets.schema.json`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticHandoffTarget {
    /// Stable target identifier, e.g. `TGT-VBOXUSBMON-001`.
    pub target_id: String,
    /// RVA of the IOCTL dispatch routine entry.
    pub handler_rva: u64,
    /// RVA of the target sink call site.
    pub sink_rva: u64,
    /// Sink symbol name, e.g. `MmMapIoSpace`.
    pub sink_name: String,
    /// Candidate IOCTL codes extracted by static analysis.
    pub candidate_ioctl_codes: Vec<u32>,
    /// Static analysis finding rule, e.g. `VULN.PROBE.MISSING`.
    pub static_finding_rule: Option<String>,
    /// Triage confidence: HIGH, MEDIUM, LOW.
    pub confidence: Option<String>,
    /// Call depth between handler and sink (0 = direct call).
    pub interprocedural_depth: u32,
    /// Per-target timeout in seconds (default 60).
    pub timeout_sec: u32,
}

impl StaticHandoffTarget {
    /// Converts this target into driver IOCTL execution targets by resolving RVAs against `image_base`.
    pub fn to_driver_targets(&self, image_base: u64) -> Vec<DriverIoctlTarget> {
        DriverIoctlTarget::from_static_rva_candidates(
            image_base,
            self.handler_rva,
            self.sink_rva,
            &self.candidate_ioctl_codes,
        )
    }
}

/// Ingested static handoff document produced by METHRA (or legacy POPKORN adapters)
/// conforming to `symbolic_targets.schema.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticHandoff {
    /// 64-character lowercase hexadecimal SHA-256 of the analyzed binary.
    pub binary_sha256: String,
    /// File name of the driver (e.g. `VBoxUSBMon.sys`).
    pub binary_name: Option<String>,
    /// Architecture: "x64" or "x86".
    pub arch: String,
    /// Preferred load image base.
    pub image_base: u64,
    /// Driver entry RVA, if known.
    pub entry_rva: Option<u64>,
    /// Emitting producer provenance (e.g. `METHRA-re v1` or legacy `GhidraPostProcessPipeline`).
    pub producer: Option<String>,
    /// Extracted exploration targets.
    pub targets: Vec<StaticHandoffTarget>,
}

impl StaticHandoff {
    /// Parses a JSON static handoff document matching `symbolic_targets.schema.json`
    /// or `kp14.native.handoff.v1` (`NativeHandoffEnvelopeV1`).
    pub fn from_json(json_str: &str) -> Result<Self, ApiError> {
        let mut parser = JsonParser::new(json_str);
        let root = parser
            .parse_value()
            .map_err(|e| ApiError::InvalidArgument(format!("JSON parse error: {e}")))?;

        if root.get("schema").and_then(|v| v.as_str()) == Some("kp14.native.handoff.v1") {
            return Self::from_native_handoff_json(&root);
        }

        let binary_sha256 = root
            .get("binary_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'binary_sha256'".into()))?
            .to_string();
        if binary_sha256.len() != 64 || !binary_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ApiError::InvalidArgument(format!(
                "invalid binary_sha256 '{binary_sha256}': expected 64 hex characters"
            )));
        }

        let arch = root
            .get("arch")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'arch'".into()))?
            .to_string();
        if arch != "x64" && arch != "x86" {
            return Err(ApiError::InvalidArgument(format!(
                "unsupported architecture '{arch}': expected 'x64' or 'x86'"
            )));
        }

        let image_base_str = root
            .get("image_base")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'image_base'".into()))?;
        let image_base = u64::from_str_radix(
            image_base_str
                .strip_prefix("0x")
                .or_else(|| image_base_str.strip_prefix("0X"))
                .ok_or_else(|| ApiError::InvalidArgument("image_base must be a 0x-prefixed hex string".into()))?,
            16,
        )
        .map_err(|e| ApiError::InvalidArgument(format!("invalid image_base '{image_base_str}': {e}")))?;

        let binary_name = root.get("binary_name").and_then(|v| v.as_str()).map(str::to_string);
        let producer = root.get("producer").and_then(|v| v.as_str()).map(str::to_string);
        let entry_rva = root.get("entry_rva").and_then(|v| v.as_str()).and_then(|s| {
            let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
            u64::from_str_radix(hex, 16).ok()
        });

        let raw_targets = root
            .get("targets")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::InvalidArgument("missing required field 'targets' array".into()))?;

        let mut targets = Vec::with_capacity(raw_targets.len());
        for (idx, item) in raw_targets.iter().enumerate() {
            let target_id = item
                .get("target_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}] missing 'target_id'")))?
                .to_string();

            let handler_rva_str = item
                .get("handler_rva")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}] missing 'handler_rva'")))?;
            let handler_rva = u64::from_str_radix(
                handler_rva_str
                    .strip_prefix("0x")
                    .or_else(|| handler_rva_str.strip_prefix("0X"))
                    .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}].handler_rva must be 0x-prefixed hex")))?
                , 16
            ).map_err(|e| ApiError::InvalidArgument(format!("targets[{idx}] invalid handler_rva: {e}")))?;

            let sink_rva_str = item
                .get("sink_rva")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}] missing 'sink_rva'")))?;
            let sink_rva = u64::from_str_radix(
                sink_rva_str
                    .strip_prefix("0x")
                    .or_else(|| sink_rva_str.strip_prefix("0X"))
                    .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}].sink_rva must be 0x-prefixed hex")))?
                , 16
            ).map_err(|e| ApiError::InvalidArgument(format!("targets[{idx}] invalid sink_rva: {e}")))?;

            let sink_name = item
                .get("sink_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ApiError::InvalidArgument(format!("targets[{idx}] missing 'sink_name'")))?
                .to_string();

            let candidate_ioctl_codes = item
                .get("candidate_ioctl_codes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|c| c.as_u32()).collect())
                .unwrap_or_default();

            let static_finding_rule = item.get("static_finding_rule").and_then(|v| v.as_str()).map(str::to_string);
            let confidence = item.get("confidence").and_then(|v| v.as_str()).map(str::to_string);
            let interprocedural_depth = item.get("interprocedural_depth").and_then(|v| v.as_u32()).unwrap_or(0);
            let timeout_sec = item.get("timeout_sec").and_then(|v| v.as_u32()).unwrap_or(60);

            targets.push(StaticHandoffTarget {
                target_id,
                handler_rva,
                sink_rva,
                sink_name,
                candidate_ioctl_codes,
                static_finding_rule,
                confidence,
                interprocedural_depth,
                timeout_sec,
            });
        }

        Ok(StaticHandoff {
            binary_sha256,
            binary_name,
            arch,
            image_base,
            entry_rva,
            producer,
            targets,
        })
    }

    /// Converts all targets into driver IOCTL execution targets by resolving RVAs against `image_base`.
    pub fn to_driver_targets(&self) -> Vec<(StaticHandoffTarget, Vec<DriverIoctlTarget>)> {
        self.targets
            .iter()
            .map(|t| {
                let targets = t.to_driver_targets(self.image_base);
                (t.clone(), targets)
            })
            .collect()
    }

    /// Ingests a versioned KP14-SUITE native handoff envelope (`kp14.native.handoff.v1`).
    fn from_native_handoff_json(root: &SimpleJson) -> Result<Self, ApiError> {
        let binary_digest_val = root.get("binary_digest");
        let binary_sha256 = if let Some(SimpleJson::Object(entries)) = binary_digest_val {
            entries.iter().find(|(k, _)| k == "hex").and_then(|(_, v)| v.as_str())
        } else {
            binary_digest_val.and_then(|v| v.as_str())
        }
        .ok_or_else(|| ApiError::InvalidArgument("missing 'binary_digest' in native handoff".into()))?
        .to_string();

        if (binary_sha256.len() != 64 && binary_sha256.len() != 96)
            || !binary_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(ApiError::InvalidArgument(format!(
                "invalid binary_digest '{binary_sha256}': expected 64 or 96 hex characters"
            )));
        }

        let raw_arch = root
            .get("architecture")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidArgument("missing 'architecture' in native handoff".into()))?;
        let arch = match raw_arch.to_ascii_lowercase().as_str() {
            "x64" | "x86_64" | "amd64" => "x64".to_string(),
            "x86" | "i386" => "x86".to_string(),
            other => return Err(ApiError::InvalidArgument(format!("unsupported architecture '{other}'"))),
        };

        let image_base = root
            .get("image_base")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ApiError::InvalidArgument("missing or invalid 'image_base' in native handoff".into()))?;

        let producer = if let Some(p_obj @ SimpleJson::Object(_)) = root.get("producer") {
            let name = p_obj.get("name").and_then(|v| v.as_str()).unwrap_or("radare3");
            let version = p_obj.get("version").and_then(|v| v.as_str()).unwrap_or("");
            Some(format!("{name} {version}").trim().to_string())
        } else {
            root.get("producer").and_then(|v| v.as_str()).map(str::to_string)
        };

        let entry_rva = root
            .get("analysis_options")
            .and_then(|opts| opts.get("entrypoints"))
            .and_then(|arr| arr.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_u64())
            .map(|va| va.saturating_sub(image_base));

        let raw_hints = root
            .get("target_hints")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ApiError::InvalidArgument("missing 'target_hints' array in native handoff".into()))?;

        let default_timeout = root
            .get("analysis_options")
            .and_then(|opts| opts.get("timeout_ms"))
            .and_then(|v| v.as_u64())
            .map(|ms| (ms / 1000) as u32)
            .unwrap_or(60);

        let mut targets = Vec::with_capacity(raw_hints.len());
        for (idx, hint) in raw_hints.iter().enumerate() {
            let handler_rva = hint
                .get("handler_rva")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ApiError::InvalidArgument(format!("target_hints[{idx}] missing 'handler_rva'")))?;
            let sink_rva = hint
                .get("sink_rva")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ApiError::InvalidArgument(format!("target_hints[{idx}] missing 'sink_rva'")))?;
            let sink_name = hint
                .get("sink_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown_sink")
                .to_string();

            let candidate_ioctl_codes: Vec<u32> = hint
                .get("candidate_ioctls")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|c| c.as_u32()).collect())
                .unwrap_or_default();

            let static_finding_rule = hint
                .get("static_rule")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let confidence = hint
                .get("confidence")
                .and_then(|v| match v {
                    SimpleJson::Number(n) => {
                        if *n >= 0.9 {
                            Some("HIGH".to_string())
                        } else if *n >= 0.5 {
                            Some("MEDIUM".to_string())
                        } else {
                            Some("LOW".to_string())
                        }
                    }
                    SimpleJson::String(s) => Some(s.clone()),
                    _ => None,
                });

            let interprocedural_depth = if hint
                .get("interprocedural_gap")
                .and_then(|v| match v {
                    SimpleJson::Bool(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(false)
            {
                1
            } else {
                0
            };

            targets.push(StaticHandoffTarget {
                target_id: format!("TGT-{:08X}-{:08X}", handler_rva, sink_rva),
                handler_rva,
                sink_rva,
                sink_name,
                candidate_ioctl_codes,
                static_finding_rule,
                confidence,
                interprocedural_depth,
                timeout_sec: default_timeout,
            });
        }

        Ok(Self {
            binary_sha256,
            binary_name: None,
            arch,
            image_base,
            entry_rva,
            producer,
            targets,
        })
    }
}

// ---------------------------------------------------------------------------
// Zero-dependency JSON parser for static handoff ingestion
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum SimpleJson {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<SimpleJson>),
    Object(Vec<(String, SimpleJson)>),
}

impl SimpleJson {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if *n >= 0.0 && n.is_finite() => Some(*n as u64),
            Self::String(s) => {
                let trimmed = s.trim();
                if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    trimmed.parse::<u64>().ok()
                }
            }
            _ => None,
        }
    }

    fn as_u32(&self) -> Option<u32> {
        self.as_u64().and_then(|v| u32::try_from(v).ok())
    }

    fn as_array(&self) -> Option<&[SimpleJson]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> Option<&SimpleJson> {
        match self {
            Self::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    chars: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.chars.len() {
            match self.chars[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_whitespace();
        if self.pos < self.chars.len() {
            Some(self.chars[self.pos])
        } else {
            None
        }
    }

    fn next(&mut self) -> Option<u8> {
        self.skip_whitespace();
        if self.pos < self.chars.len() {
            let b = self.chars[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    fn parse_value(&mut self) -> Result<SimpleJson, String> {
        self.skip_whitespace();
        let b = self.peek().ok_or_else(|| "unexpected end of input".to_string())?;
        match b {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(SimpleJson::String),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(format!("unexpected character '{}' at offset {}", b as char, self.pos)),
        }
    }

    fn parse_null(&mut self) -> Result<SimpleJson, String> {
        if self.chars[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(SimpleJson::Null)
        } else {
            Err(format!("invalid literal at offset {}", self.pos))
        }
    }

    fn parse_bool(&mut self) -> Result<SimpleJson, String> {
        if self.chars[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(SimpleJson::Bool(true))
        } else if self.chars[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(SimpleJson::Bool(false))
        } else {
            Err(format!("invalid boolean at offset {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.next() != Some(b'"') {
            return Err(format!("expected '\"' at offset {}", self.pos));
        }
        let mut s = String::new();
        while self.pos < self.chars.len() {
            let b = self.chars[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(s),
                b'\\' => {
                    if self.pos >= self.chars.len() {
                        return Err("unterminated escape sequence".to_string());
                    }
                    let esc = self.chars[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'b' => s.push('\x08'),
                        b'f' => s.push('\x0c'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.chars.len() {
                                return Err("unterminated \\u escape sequence".to_string());
                            }
                            let hex = std::str::from_utf8(&self.chars[self.pos..self.pos + 4])
                                .map_err(|e| format!("utf8 error in \\u: {e}"))?;
                            self.pos += 4;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|e| format!("invalid hex in \\u: {e}"))?;
                            let ch = char::from_u32(cp).ok_or_else(|| "invalid unicode codepoint".to_string())?;
                            s.push(ch);
                        }
                        _ => return Err(format!("unknown escape '\\{}'", esc as char)),
                    }
                }
                _ => s.push(b as char),
            }
        }
        Err("unterminated string literal".to_string())
    }

    fn parse_number(&mut self) -> Result<SimpleJson, String> {
        let start = self.pos;
        if self.pos < self.chars.len() && self.chars[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        if self.pos < self.chars.len() && self.chars[self.pos] == b'.' {
            self.pos += 1;
            while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        if self.pos < self.chars.len() && (self.chars[self.pos] == b'e' || self.chars[self.pos] == b'E') {
            self.pos += 1;
            if self.pos < self.chars.len() && (self.chars[self.pos] == b'+' || self.chars[self.pos] == b'-') {
                self.pos += 1;
            }
            while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.chars[start..self.pos])
            .map_err(|e| format!("invalid number: {e}"))?;
        let n = s.parse::<f64>().map_err(|e| format!("failed to parse float: {e}"))?;
        Ok(SimpleJson::Number(n))
    }

    fn parse_array(&mut self) -> Result<SimpleJson, String> {
        if self.next() != Some(b'[') {
            return Err("expected '['".to_string());
        }
        let mut vec = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.next();
            return Ok(SimpleJson::Array(vec));
        }
        loop {
            let val = self.parse_value()?;
            vec.push(val);
            self.skip_whitespace();
            match self.next() {
                Some(b',') => {
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        self.next();
                        break;
                    }
                }
                Some(b']') => break,
                other => return Err(format!("expected ',' or ']', got {:?}", other.map(|b| b as char))),
            }
        }
        Ok(SimpleJson::Array(vec))
    }

    fn parse_object(&mut self) -> Result<SimpleJson, String> {
        if self.next() != Some(b'{') {
            return Err("expected '{'".to_string());
        }
        let mut map = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.next();
            return Ok(SimpleJson::Object(map));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.next() != Some(b':') {
                return Err("expected ':' after object key".to_string());
            }
            let val = self.parse_value()?;
            map.push((key, val));
            self.skip_whitespace();
            match self.next() {
                Some(b',') => {
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        self.next();
                        break;
                    }
                }
                Some(b'}') => break,
                other => return Err(format!("expected ',' or '}}', got {:?}", other.map(|b| b as char))),
            }
        }
        Ok(SimpleJson::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_pinned_ioctl_and_kernel_pointers() {
        let target = DriverIoctlTarget {
            handler_va: 0x0001_4000_1000,
            sink_va: 0x0001_4000_1100,
            ioctl_code: Some(0x0022_0004),
        };
        let options = target.run_options(2_000, 32).expect("valid target");
        assert_eq!(options.entry, Some(target.handler_va));
        assert_eq!(options.find, vec![target.sink_va]);
        assert_eq!(options.regs[0], ("rcx".to_string(), DEVICE_OBJECT_ADDR));
        assert_eq!(options.regs[1], ("rdx".to_string(), IRP_ADDR));
        assert!(
            options
                .poke
                .contains(&(IRP_ADDR + IRP_CURRENT_STACK_OFFSET, IRP_STACK_ADDR))
        );
        assert!(options.poke.contains(&(IRP_STACK_ADDR, IRP_MJ_DEVICE_CONTROL)));
        assert!(
            options
                .poke
                .contains(&(IRP_STACK_ADDR + STACK_IOCTL_CODE_OFFSET, 0x0022_0004))
        );
        assert_eq!(options.symbolic_memory.len(), 4);
        assert!(options.solve);
    }

    #[test]
    fn leaves_unspecified_ioctl_symbolic_and_rejects_invalid_budgets() {
        let target = DriverIoctlTarget {
            handler_va: 0x0001_4000_1000,
            sink_va: 0x0001_4000_1100,
            ioctl_code: None,
        };
        let options = target.run_options(1, 1).expect("valid target");
        assert!(
            !options
                .poke
                .iter()
                .any(|(address, _)| *address == IRP_STACK_ADDR + STACK_IOCTL_CODE_OFFSET)
        );
        assert!(target.run_options(0, 1).is_err());
        assert!(target.run_options(1, 0).is_err());
    }

    #[test]
    fn classifies_sink_hit_unconstrained_and_constrained() {
        let target = DriverIoctlTarget {
            handler_va: 0x140001000,
            sink_va: 0x140002000,
            ioctl_code: Some(0x220004),
        };

        // Constrained single-solution model
        let constrained_report = RunReport {
            steps: 45,
            found_pcs: vec![0x140002000],
            inputs: vec![vec![vec![1, 2, 3, 4]]],
            unconstrained_inputs: false,
            ..RunReport::default()
        };
        let verdict = target.classify_run(&constrained_report, 1.25);
        assert_eq!(verdict.verdict, DriverVerdict::PathFeasibleConstrained);
        assert_eq!(verdict.verdict.as_str(), "PATH_FEASIBLE_CONSTRAINED");
        assert!(verdict.constraints_solved.is_some());
        assert_eq!(verdict.steps_taken, 45);
        assert_eq!(verdict.handler_va, 0x140001000);
        assert_eq!(verdict.sink_va, 0x140002000);

        // Unconstrained input via flag
        let unconstrained_report = RunReport {
            steps: 50,
            found_pcs: vec![0x140002000],
            inputs: vec![vec![vec![0; 8]]],
            unconstrained_inputs: true,
            ..RunReport::default()
        };
        let v2 = target.classify_run(&unconstrained_report, 0.8);
        assert_eq!(v2.verdict, DriverVerdict::PathFeasibleUnchecked);
        assert_eq!(v2.verdict.as_str(), "PATH_FEASIBLE_UNCHECKED");

        // Multi-solution input models -> unchecked
        let multi_solution_report = RunReport {
            steps: 60,
            found_pcs: vec![0x140002000],
            inputs: vec![vec![vec![1]], vec![vec![2]]],
            unconstrained_inputs: false,
            ..RunReport::default()
        };
        let v3 = target.classify_run(&multi_solution_report, 1.0);
        assert_eq!(v3.verdict, DriverVerdict::PathFeasibleUnchecked);
    }

    #[test]
    fn classifies_path_unreachable_on_exhausted_exploration() {
        let target = DriverIoctlTarget {
            handler_va: 0x140001000,
            sink_va: 0x140002000,
            ioctl_code: Some(0x220004),
        };
        let exhausted_report = RunReport {
            steps: 120,
            live_states: 0,
            dead_states: 3,
            terminated: 1,
            found_pcs: Vec::new(),
            timed_out: false,
            ..RunReport::default()
        };
        let verdict = target.classify_run(&exhausted_report, 0.5);
        assert_eq!(verdict.verdict, DriverVerdict::PathUnreachable);
        assert_eq!(verdict.verdict.as_str(), "PATH_UNREACHABLE");
        assert!(verdict.constraints_solved.is_none());
    }

    #[test]
    fn classifies_timeout_on_budget_exhaustion_or_flag() {
        let target = DriverIoctlTarget {
            handler_va: 0x140001000,
            sink_va: 0x140002000,
            ioctl_code: None,
        };

        // Timed out via boolean
        let timed_out_report = RunReport {
            steps: 200,
            live_states: 4,
            timed_out: true,
            found_pcs: Vec::new(),
            ..RunReport::default()
        };
        let v1 = target.classify_run(&timed_out_report, 60.0);
        assert_eq!(v1.verdict, DriverVerdict::TimeoutBudgetExceeded);
        assert_eq!(v1.verdict.as_str(), "TIMEOUT_BUDGET_EXCEEDED");

        // Step budget exhausted with live states remaining
        let steps_exhausted_report = RunReport {
            steps: 500,
            live_states: 2,
            timed_out: false,
            found_pcs: Vec::new(),
            ..RunReport::default()
        };
        let v2 = target.classify_run(&steps_exhausted_report, 15.0);
        assert_eq!(v2.verdict, DriverVerdict::TimeoutBudgetExceeded);
    }

    #[test]
    fn classifies_explosion_on_pruned_states_and_engine_error() {
        let target = DriverIoctlTarget {
            handler_va: 0x140001000,
            sink_va: 0x140002000,
            ioctl_code: None,
        };

        // Pruned states -> explosion suppressed
        let explosion_report = RunReport {
            steps: 80,
            pruned_states: 12,
            live_states: 16,
            found_pcs: Vec::new(),
            ..RunReport::default()
        };
        let v1 = target.classify_run(&explosion_report, 4.0);
        assert_eq!(v1.verdict, DriverVerdict::ExplosionSuppressed);
        assert_eq!(v1.verdict.as_str(), "EXPLOSION_SUPPRESSED");
        assert!(v1.notes.as_deref().unwrap_or("").contains("explosion_threshold_hit"));

        // Engine error -> explosion suppressed with engine_error: note
        let error_report = RunReport {
            steps: 10,
            last_error: Some("memory access out of bounds".to_string()),
            found_pcs: Vec::new(),
            ..RunReport::default()
        };
        let v2 = target.classify_run(&error_report, 0.1);
        assert_eq!(v2.verdict, DriverVerdict::ExplosionSuppressed);
        assert!(v2.notes.as_deref().unwrap_or("").starts_with("engine_error:"));
    }

    #[test]
    fn expands_static_candidates_and_rvas() {
        let base = 0x140000000;
        let handler_rva = 0x1000;
        let sink_rva = 0x2000;

        // Multiple candidates
        let targets = DriverIoctlTarget::from_static_rva_candidates(
            base,
            handler_rva,
            sink_rva,
            &[0x220004, 0x220008],
        );
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].handler_va, 0x140001000);
        assert_eq!(targets[0].sink_va, 0x140002000);
        assert_eq!(targets[0].ioctl_code, Some(0x220004));
        assert_eq!(targets[1].ioctl_code, Some(0x220008));

        // Empty candidates -> single target with None
        let targets_empty = DriverIoctlTarget::from_static_candidates(
            0x140001000,
            0x140002000,
            &[],
        );
        assert_eq!(targets_empty.len(), 1);
        assert_eq!(targets_empty[0].ioctl_code, None);
    }

    #[test]
    fn serializes_verdict_to_json_matching_schema() {
        let target = DriverIoctlTarget {
            handler_va: 0x140001000,
            sink_va: 0x140002000,
            ioctl_code: Some(0x220004),
        };
        let report = RunReport {
            steps: 42,
            found_pcs: vec![0x140002000],
            inputs: vec![vec![vec![0xaa, 0xbb]]],
            unconstrained_inputs: false,
            ..RunReport::default()
        };
        let verdict = target
            .classify_run(&report, 2.5)
            .with_target_id("TGT-TEST-001")
            .with_sink_name("MmMapIoSpace")
            .with_binary_sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .with_notes("test run notes")
            .with_constraints(DriverConstraintsSolved {
                input_buffer_min_size: Some(16),
                offset_constraints: vec![DriverOffsetConstraint {
                    offset: 0,
                    size: 8,
                    constraint: "symbolic_physical_address".to_string(),
                }],
            });

        let json_str = verdict.to_json();
        assert!(json_str.contains("\"target_id\":\"TGT-TEST-001\""));
        assert!(json_str.contains("\"verdict\":\"PATH_FEASIBLE_CONSTRAINED\""));
        assert!(json_str.contains("\"sink_name\":\"MmMapIoSpace\""));
        assert!(json_str.contains("\"ioctl_code\":\"0x220004\""));
        assert!(json_str.contains("\"input_buffer_min_size\":16"));
        assert!(json_str.contains("\"symbolic_physical_address\""));

        let display_str = format!("{verdict}");
        assert!(display_str.contains("Driver IOCTL Verdict Report:"));
        assert!(display_str.contains("TGT-TEST-001"));
        assert!(display_str.contains("PATH_FEASIBLE_CONSTRAINED"));
        assert!(display_str.contains("MmMapIoSpace"));
        assert!(display_str.contains("0x00220004"));
        assert!(display_str.contains("16 byte(s)"));
        assert!(display_str.contains("symbolic_physical_address"));
        assert!(display_str.contains("test run notes"));
    }

    #[test]
    fn parses_valid_static_handoff_matching_schema() {
        let json = r#"{
            "binary_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "binary_name": "VBoxUSBMon.sys",
            "arch": "x64",
            "image_base": "0x140000000",
            "entry_rva": "0x1000",
            "producer": "GhidraPostProcessPipeline 11.1",
            "targets": [
                {
                    "target_id": "TGT-VBOXUSBMON-001",
                    "handler_rva": "0x1200",
                    "sink_rva": "0x3400",
                    "sink_name": "MmMapIoSpace",
                    "candidate_ioctl_codes": [2228228, 2228232],
                    "static_finding_rule": "VULN.PROBE.MISSING",
                    "confidence": "HIGH",
                    "interprocedural_depth": 1,
                    "timeout_sec": 30
                }
            ]
        }"#;

        let handoff = StaticHandoff::from_json(json).expect("valid handoff JSON");
        assert_eq!(handoff.binary_sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(handoff.binary_name.as_deref(), Some("VBoxUSBMon.sys"));
        assert_eq!(handoff.arch, "x64");
        assert_eq!(handoff.image_base, 0x140000000);
        assert_eq!(handoff.entry_rva, Some(0x1000));
        assert_eq!(handoff.targets.len(), 1);

        let target = &handoff.targets[0];
        assert_eq!(target.target_id, "TGT-VBOXUSBMON-001");
        assert_eq!(target.handler_rva, 0x1200);
        assert_eq!(target.sink_rva, 0x3400);
        assert_eq!(target.sink_name, "MmMapIoSpace");
        assert_eq!(target.candidate_ioctl_codes, vec![2228228, 2228232]);
        assert_eq!(target.confidence.as_deref(), Some("HIGH"));
        assert_eq!(target.timeout_sec, 30);

        let driver_targets = handoff.to_driver_targets();
        assert_eq!(driver_targets.len(), 1);
        let (_, ioctl_targets) = &driver_targets[0];
        assert_eq!(ioctl_targets.len(), 2);
        assert_eq!(ioctl_targets[0].handler_va, 0x140001200);
        assert_eq!(ioctl_targets[0].sink_va, 0x140003400);
        assert_eq!(ioctl_targets[0].ioctl_code, Some(2228228));
        assert_eq!(ioctl_targets[1].ioctl_code, Some(2228232));
    }

    #[test]
    fn rejects_malformed_static_handoff() {
        // Missing binary_sha256
        let bad1 = r#"{"arch": "x64", "image_base": "0x140000000", "targets": []}"#;
        assert!(StaticHandoff::from_json(bad1).is_err());

        // Invalid sha256 length
        let bad2 = r#"{"binary_sha256": "1234", "arch": "x64", "image_base": "0x140000000", "targets": []}"#;
        assert!(StaticHandoff::from_json(bad2).is_err());

        // Unsupported arch
        let bad3 = r#"{"binary_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "arch": "arm64", "image_base": "0x140000000", "targets": []}"#;
        assert!(StaticHandoff::from_json(bad3).is_err());

        // Missing 0x prefix on image_base
        let bad4 = r#"{"binary_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "arch": "x64", "image_base": "140000000", "targets": []}"#;
        assert!(StaticHandoff::from_json(bad4).is_err());
    }

    #[test]
    fn kernel_layouts_match_architecture_spec() {
        let x64 = KernelLayout::X64;
        assert_eq!(x64.pointer_size, 8);
        assert_eq!(x64.irp_system_buffer, 0x18);
        assert_eq!(x64.irp_user_buffer, 0x70);
        assert_eq!(x64.irp_current_stack_location, 0xb8);
        assert_eq!(x64.io_stack_io_control_code, 0x18);
        assert_eq!(x64.io_stack_type3_input_buffer, 0x20);
        assert_eq!(x64.device_object_device_extension, 0x40);

        let x86 = KernelLayout::X86;
        assert_eq!(x86.pointer_size, 4);
        assert_eq!(x86.irp_system_buffer, 0x0c);
        assert_eq!(x86.irp_current_stack_location, 0x60);
        assert_eq!(x86.io_stack_io_control_code, 0x0c);

        assert_eq!(KernelLayout::for_arch("x64"), Some(KernelLayout::X64));
        assert_eq!(KernelLayout::for_arch("AMD64"), Some(KernelLayout::X64));
        assert_eq!(KernelLayout::for_arch("x86"), Some(KernelLayout::X86));
        assert_eq!(KernelLayout::for_arch("arm64"), None);
    }

    #[test]
    fn parses_valid_kp14_native_handoff_envelope() {
        let json = r#"{
            "schema": "kp14.native.handoff.v1",
            "binary_digest": {
                "algorithm": "sha-384",
                "hex": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0fedcba9876543210fedcba9876543210"
            },
            "architecture": "x86_64",
            "image_base": 5368709120,
            "producer": {
                "name": "radare3",
                "version": "0.0.1"
            },
            "analysis_options": {
                "entrypoints": [5368713216],
                "timeout_ms": 45000
            },
            "fidelity": "canonical",
            "target_hints": [
                {
                    "handler_rva": 4096,
                    "candidate_ioctls": [2236416, 2236420],
                    "sink_rva": 4176,
                    "sink_name": "MmMapIoSpace",
                    "static_rule": "driver_dispatch_sink",
                    "confidence": 0.95,
                    "interprocedural_gap": false
                }
            ]
        }"#;

        let handoff = StaticHandoff::from_json(json).expect("valid native handoff JSON");
        assert_eq!(
            handoff.binary_sha256,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0fedcba9876543210fedcba9876543210"
        );
        assert_eq!(handoff.arch, "x64");
        assert_eq!(handoff.image_base, 5368709120);
        assert_eq!(handoff.producer.as_deref(), Some("radare3 0.0.1"));
        assert_eq!(handoff.entry_rva, Some(4096));
        assert_eq!(handoff.targets.len(), 1);

        let target = &handoff.targets[0];
        assert_eq!(target.target_id, "TGT-00001000-00001050");
        assert_eq!(target.handler_rva, 4096);
        assert_eq!(target.sink_rva, 4176);
        assert_eq!(target.sink_name, "MmMapIoSpace");
        assert_eq!(target.candidate_ioctl_codes, vec![2236416, 2236420]);
        assert_eq!(target.confidence.as_deref(), Some("HIGH"));
        assert_eq!(target.interprocedural_depth, 0);
        assert_eq!(target.timeout_sec, 45);

        let driver_targets = handoff.to_driver_targets();
        assert_eq!(driver_targets.len(), 1);
        let (_, ioctl_targets) = &driver_targets[0];
        assert_eq!(ioctl_targets.len(), 2);
        assert_eq!(ioctl_targets[0].handler_va, 5368709120 + 4096);
        assert_eq!(ioctl_targets[0].sink_va, 5368709120 + 4176);
        assert_eq!(ioctl_targets[0].ioctl_code, Some(2236416));
        assert_eq!(ioctl_targets[1].ioctl_code, Some(2236420));
    }
}
