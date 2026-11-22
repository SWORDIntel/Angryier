//! Minimal kernel-API models for `ET_REL` Linux kernel modules.
//!
//! A relocatable module imports kernel symbols it never defines. The loader
//! gives each referenced import a writable stub slot (see
//! [`angryier_loader::EtRelInfo::externals`]); executing that slot would fault
//! and defer the path as unknown. This module attaches a small model to the
//! imports it understands so exploration can continue:
//!
//! - allocation imports return a fresh, deterministic kernel-heap address;
//! - `kfree`/`vfree`/`kmem_cache_free` return as void;
//! - `copy_from_user`/`copy_to_user`, locking, refcount and atomic helpers
//!   return success.
//!
//! This is deliberately shallow. It models *calling convention and return
//! value*, not heap identity, reference-count arithmetic, or fault injection:
//! a double free is not detected here, and an unknown import still yields no
//! hook, so its path defers honestly. Anything not in [`model_for`] must stay
//! unmodeled rather than silently returning success.

use std::sync::Arc;

use angryier_loader::Symbol;
use angryier_models::{SimProcedure, SimResult, SimState};

use crate::Process;

/// Base of the synthesized kernel heap used by allocation models. Distinct
/// from the loader's stub/GOT region (`0x1000_0000`) so pointers returned by a
/// model never alias a relocation slot.
pub const KERNEL_MODEL_HEAP_BASE: u64 = 0x2000_0000;
/// Size of the synthesized kernel heap (512 KiB). Compact so the entire
/// image plus heap and stack stays within the ELF 64 MiB sustained snapshot
/// pinning budget (`mapped * 4 < 64 MiB`).
pub const KERNEL_MODEL_HEAP_SIZE: u64 = 512 * 1024;
/// Every model this module installs is a pure function of its slot address,
/// which is what makes it safe to bind into the sustained replay digest.
pub const DETERMINISTIC_MODEL_NAMES: &[&str] = &[
    "linux_kernel_alloc",
    "linux_kernel_free",
    "linux_kernel_success",
    "linux_kernel_return_thunk",
];

/// What a modeled import does at the call boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelModelKind {
    /// Returns a fresh kernel-heap address in RAX.
    Allocate,
    /// Returns a zero-length "void" result (RAX = 0).
    Release,
    /// Returns success (RAX = 0).
    Success,
    /// Simulates a retpoline/SLS return thunk (`jmp __x86_return_thunk` -> `ret`
    /// without clobbering RAX).
    ReturnThunk,
}

/// One installed kernel-API model.
///
/// Models are pure functions of their stub-slot address: no counters, no
/// allocation bookkeeping. Sustained replay pins the environment, so a model
/// that mutated internal state between runs would make replay unsound. The
/// trade-off is explicit — the same import returns the same heap address on
/// every call, which is not heap-faithful and cannot witness a double free.
pub struct KernelModel {
    kind: KernelModelKind,
    slot: u64,
}

impl KernelModel {
    fn new(kind: KernelModelKind, slot: u64) -> Self {
        Self { kind, slot }
    }

    /// Deterministic heap address handed out by an allocation import. Derived
    /// only from the stub slot, so replaying the same image yields the same
    /// pointer.
    fn allocation_address(&self) -> u64 {
        KERNEL_MODEL_HEAP_BASE | (self.slot & 0x0FFF_FFFF)
    }
}

impl SimProcedure for KernelModel {
    fn name(&self) -> &'static str {
        match self.kind {
            KernelModelKind::Allocate => "linux_kernel_alloc",
            KernelModelKind::Release => "linux_kernel_free",
            KernelModelKind::Success => "linux_kernel_success",
            KernelModelKind::ReturnThunk => "linux_kernel_return_thunk",
        }
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        match self.kind {
            KernelModelKind::Allocate => SimResult::Return(self.allocation_address()),
            KernelModelKind::Release | KernelModelKind::Success => SimResult::Return(0),
            KernelModelKind::ReturnThunk => SimResult::Continue(SimState::new()),
        }
    }
}

/// Classifies one imported kernel symbol. `None` means "do not model this",
/// which keeps the path honest: the stub slot stays unexecutable and the
/// exploration defers rather than inventing a return value.
pub fn model_for(symbol: &str) -> Option<KernelModelKind> {
    // Allocation family. Checked before the free family so `kfree_sensitive`
    // style names cannot be mistaken for an allocator.
    const ALLOCATE: &[&str] = &[
        "kmalloc",
        "kzalloc",
        "kcalloc",
        "krealloc",
        "vmalloc",
        "kvmalloc",
        "kmem_cache_alloc",
        "devm_kmalloc",
        "devm_kzalloc",
        "dma_alloc",
    ];
    const RELEASE: &[&str] = &["kfree", "vfree", "kvfree", "kmem_cache_free", "dma_free"];
    const SUCCESS: &[&str] = &[
        // ftrace entry hook: `call __fentry__` is emitted at the start of
        // nearly every compiled kernel function. It returns immediately and
        // its value is unused, so a call-site no-op is faithful.
        "__fentry__",
        "fentry",
        "copy_from_user",
        "copy_to_user",
        "get_user",
        "put_user",
        "mutex_",
        "spin_lock",
        "spin_unlock",
        "refcount_",
        "atomic_",
        "try_module_get",
        "__module_get",
        "module_put",
        "down",
        "up",
        "wait_for_completion",
        "init_completion",
        "complete",
        "printk",
        "dev_err",
        "dev_warn",
        "dev_info",
        "dev_dbg",
        "request_irq",
        "free_irq",
    ];

    if RELEASE.iter().any(|prefix| symbol.starts_with(prefix)) {
        return Some(KernelModelKind::Release);
    }
    if ALLOCATE.iter().any(|prefix| symbol.contains(prefix)) {
        return Some(KernelModelKind::Allocate);
    }
    // Subsystem allocators (`devm_iio_device_alloc`, `alloc_netdev`, ...)
    // return an owned pointer. Modeling the return as a fresh kernel-heap
    // address keeps the shallow contract: pointer identity, not layout.
    if symbol.contains("alloc") {
        return Some(KernelModelKind::Allocate);
    }
    if symbol == "__x86_return_thunk" {
        return Some(KernelModelKind::ReturnThunk);
    }
    if SUCCESS.iter().any(|prefix| symbol.contains(prefix)) {
        return Some(KernelModelKind::Success);
    }
    // Driver/core registration helpers (`__pci_register_driver`,
    // `i2c_register_driver`, `bus_register`, `misc_register`, ...) record the
    // caller's ops and report success. They are the single largest class of
    // blocking import across the corpus, so modelling the family keeps
    // `init_module` from faulting at its first registration call.
    if symbol.contains("register") && !symbol.contains("unregister") {
        return Some(KernelModelKind::Success);
    }
    None
}

/// Installs a model at each import stub slot the classifier recognizes, and
/// returns how many hooks were attached. Unknown imports are left alone.
///
/// Every installed model is deterministic, and
/// `sustained_initial_digest` binds the resulting `(address, model)` set into
/// the root pin, so a peer with a different model set fails replay instead of
/// silently diverging.
pub fn install(process: &mut Process, externals: &[Symbol]) -> usize {
    let mut installed = 0;
    for external in externals {
        let Some(kind) = model_for(&external.name) else {
            continue;
        };
        process
            .simproc_instances
            .insert(external.address, Arc::new(KernelModel::new(kind, external.address)));
        installed += 1;
    }
    installed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_covers_alloc_free_and_success_families() {
        assert_eq!(model_for("__kmalloc"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("kzalloc"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("kmem_cache_alloc_trace"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("devm_iio_device_alloc"), Some(KernelModelKind::Allocate));
        // Registration family: the census's dominant blocker class.
        for symbol in [
            "__pci_register_driver",
            "i2c_register_driver",
            "__spi_register_driver",
            "usb_register_driver",
            "__platform_driver_register",
            "__hid_register_driver",
            "bus_register",
            "misc_register",
        ] {
            assert_eq!(model_for(symbol), Some(KernelModelKind::Success), "{symbol}");
        }
        assert_eq!(model_for("pci_unregister_driver"), None);
        assert_eq!(model_for("kfree"), Some(KernelModelKind::Release));
        assert_eq!(model_for("kfree_sensitive"), Some(KernelModelKind::Release));
        assert_eq!(model_for("copy_from_user"), Some(KernelModelKind::Success));
        assert_eq!(model_for("mutex_lock"), Some(KernelModelKind::Success));
        assert_eq!(model_for("refcount_dec_and_test"), Some(KernelModelKind::Success));
        assert_eq!(model_for("__fentry__"), Some(KernelModelKind::Success));
        assert_eq!(model_for("__x86_return_thunk"), Some(KernelModelKind::ReturnThunk));
        // Unknown symbols stay unmapped so their paths defer honestly.
        assert_eq!(model_for("i2c_transfer"), None);
        assert_eq!(model_for("regmap_read"), None);
    }

    #[test]
    fn return_thunk_model_returns_continue() {
        let state = SimState::new();
        let thunk = KernelModel::new(KernelModelKind::ReturnThunk, 0x1000_0008);
        assert_eq!(thunk.name(), "linux_kernel_return_thunk");
        assert_eq!(thunk.apply(&state), SimResult::Continue(SimState::new()));
    }

    #[test]
    fn allocation_models_are_deterministic_per_slot() {
        let state = SimState::new();
        let a = KernelModel::new(KernelModelKind::Allocate, 0x1000_0040);
        let b = KernelModel::new(KernelModelKind::Allocate, 0x1000_0048);
        let first = a.apply(&state);
        let again = a.apply(&state);
        let other = b.apply(&state);
        assert_eq!(first, again, "a slot must replay to the same pointer");
        assert_ne!(first, other, "distinct slots get distinct pointers");
        let SimResult::Return(address) = first else {
            panic!("allocation model must return a value");
        };
        assert!(address >= KERNEL_MODEL_HEAP_BASE);
    }

    #[test]
    fn release_and_success_models_return_zero() {
        for kind in [KernelModelKind::Release, KernelModelKind::Success] {
            let model = KernelModel::new(kind, 0x1000_0000);
            assert_eq!(model.apply(&SimState::new()), SimResult::Return(0));
        }
    }
}
