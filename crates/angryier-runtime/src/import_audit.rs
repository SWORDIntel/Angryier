//! PE IAT stub fidelity classification.
//!
//! A synthetic RET is a *call/return mechanism*, not a Windows API model.
//! Critical user-mode imports must not return through the stub in PROVE or
//! exploratory modes without a registered, explicit model. The deterministic
//! bool surrogate for IsProcessorFeaturePresent is reported as approximate.

use angryier_types::Address;

use crate::Process;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportBehavior {
    /// An analyst or host explicitly installed a call-correct SimProcedure.
    ExplicitHook,
    /// A known hand-coded scalar response; not guaranteed real Windows.
    ApproximateScalar,
    /// A userland API whose side effects are absent from the synthetic RET.
    UnsupportedUserland,
    /// Synthetic RET with no modeled effects; not equivalent to an API.
    SyntheticReturn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportFinding {
    pub stub: Address,
    pub dll: String,
    pub export: String,
    pub behavior: ImportBehavior,
}

/// These DLL families are not valid native PE-driver imports. Treating calls
/// as no-op RETs can silently skip thread creation, synchronization, memory
/// and graphics initialization. Name matching follows Windows DLL semantics;
/// ordinal imports in these libraries are also unmodeled.
pub fn is_userland_dll(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "kernel32.dll"
            | "kernelbase.dll"
            | "ntdll.dll"
            | "user32.dll"
            | "gdi32.dll"
            | "gdi32full.dll"
            | "advapi32.dll"
            | "ole32.dll"
            | "combase.dll"
            | "ws2_32.dll"
            | "ucrtbase.dll"
    )
}

pub fn classify(dll: &str, export: &str, explicit_hook: bool) -> ImportBehavior {
    if explicit_hook {
        return ImportBehavior::ExplicitHook;
    }
    if dll.eq_ignore_ascii_case("kernel32.dll") && export == "IsProcessorFeaturePresent" {
        return ImportBehavior::ApproximateScalar;
    }
    if is_userland_dll(dll) {
        ImportBehavior::UnsupportedUserland
    } else {
        ImportBehavior::SyntheticReturn
    }
}

pub fn inspect_imports(process: &Process) -> Vec<ImportFinding> {
    process
        .pe_import_stubs
        .iter()
        .map(|(&stub, (dll, export))| ImportFinding {
            stub,
            dll: dll.clone(),
            export: export.clone(),
            behavior: classify(dll, export, process.simproc_instances.contains_key(&stub)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_api_imports_never_claim_stub_equivalence() {
        assert_eq!(
            classify("KERNEL32.dll", "CreateThread", false),
            ImportBehavior::UnsupportedUserland
        );
        assert_eq!(
            classify("kernelbase.dll", "WaitForSingleObject", false),
            ImportBehavior::UnsupportedUserland
        );
        assert_eq!(
            classify("gdi32.dll", "GdiplusStartup", false),
            ImportBehavior::UnsupportedUserland
        );
        assert_eq!(
            classify("KERNEL32.dll", "CreateThread", true),
            ImportBehavior::ExplicitHook
        );
        assert_eq!(
            classify("ntoskrnl.exe", "DbgPrint", false),
            ImportBehavior::SyntheticReturn
        );
        assert_eq!(
            classify("kernel32.dll", "IsProcessorFeaturePresent", false),
            ImportBehavior::ApproximateScalar,
        );
    }
}
