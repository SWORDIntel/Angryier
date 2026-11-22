//! Kernel-API models and path-local heap/refcount state for `ET_REL` Linux kernel modules.
//!
//! A relocatable module imports kernel symbols it never defines. The loader
//! gives each referenced import a writable stub slot (see
//! [`angryier_loader::EtRelInfo::externals`]); executing that slot would fault
//! and defer the path as unknown. This module attaches deterministic, path-local
//! models inside `process.state.memory` so exploration can continue and detect
//! double-free / refcount-underflow violations without breaking sustained replay:
//!
//! - allocation imports bump-allocate distinct 4 KiB slots inside
//!   [`KERNEL_MODEL_HEAP_BASE`] and mark each slot live;
//! - `kfree`/`vfree`/`kvfree`/`devm_kfree`/`kmem_cache_free` mark slots freed
//!   and flag a verified double free if a freed slot is freed again;
//! - `refcount_*` / `kref_*` track initialized refcount words in memory and
//!   flag an underflow when an initialized refcount is decremented below zero;
//! - `copy_from_user`/`copy_to_user`, `__put_user_*`/`__get_user_*`, locking,
//!   atomic, `__fentry__`, and registration helpers return success;
//! - `__x86_return_thunk` pops the return address without clobbering `RAX`.
//!
//! All mutable heap and refcount state lives inside `Process.state.memory`
//! (copy-on-write across symbolic forks), so every path stays isolated and
//! replay-sound. Anything not in [`model_for`] stays unmodeled.

use std::sync::Arc;

use angryier_arch_intel64::register_id;
use angryier_loader::Symbol;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_models::{SimProcedure, SimResult, SimState};
use angryier_state::RegisterState;
use angryier_types::Address;

use crate::{Process, RuntimeError};

/// Base of the synthesized kernel heap used by allocation models. Distinct
/// from the loader's stub/GOT region (`0x1000_0000`) so pointers returned by a
/// model never alias a relocation slot.
pub const KERNEL_MODEL_HEAP_BASE: u64 = 0x2000_0000;
/// Size of the synthesized kernel heap (512 KiB). Compact so the entire
/// image plus heap, ABI scratch, and stack stays within the ELF 64 MiB
/// sustained snapshot pinning budget (`mapped * 4 < 64 MiB`).
pub const KERNEL_MODEL_HEAP_SIZE: u64 = 512 * 1024;

const HEAP_SLOTS_BASE: u64 = KERNEL_MODEL_HEAP_BASE + 0x1000;
const HEAP_SLOT_STRIDE: u64 = 0x1000;
const MAX_HEAP_SLOTS: u64 = 111; // 0x2000_1000..0x2007_0000
const HEAP_META_BASE: u64 = KERNEL_MODEL_HEAP_BASE + 0x7_0000; // 0x2007_0000..0x2008_0000
const HEAP_NEXT_SLOT_ADDR: u64 = HEAP_META_BASE;
const HEAP_SLOT_STATE_ADDR: u64 = HEAP_META_BASE + 0x0100;
const REFCOUNT_INIT_COUNT_ADDR: u64 = HEAP_META_BASE + 0x0200;
const REFCOUNT_INIT_ADDRS_BASE: u64 = HEAP_META_BASE + 0x0208;
const MAX_TRACKED_REFCOUNTS: usize = 32;

const SLOT_UNALLOCATED: u8 = 0;
const SLOT_LIVE: u8 = 1;
const SLOT_FREED: u8 = 2;

/// Base of the Linux SysV ABI scratch region mapped for `ET_REL` modules
/// (analogous to `PE_DRIVER_SCRATCH_BASE`).
pub const KERNEL_ABI_SCRATCH_BASE: u64 = 0x3000_0000;
/// 64 KiB RW region (16 x 4 KiB pages) for seeded kernel handler structs/args.
pub const KERNEL_ABI_SCRATCH_SIZE: u64 = 0x0001_0000;
/// Initial `RDI` for `ET_REL`: page 0 (`struct file *`, `struct device *`, ...).
pub const KERNEL_ABI_ARG0: u64 = KERNEL_ABI_SCRATCH_BASE;
/// Initial `RSI` for `ET_REL`: page 8 (4 KiB RW user/arg buffer).
pub const KERNEL_ABI_ARG1: u64 = KERNEL_ABI_SCRATCH_BASE + 0x8000;
/// Initial `RDX` for `ET_REL`: page 10 (4 KiB RW arg2/`ppos` buffer).
pub const KERNEL_ABI_ARG2: u64 = KERNEL_ABI_SCRATCH_BASE + 0xa000;
/// Initial `RCX` for `ET_REL`: page 12 (4 KiB RW arg3 buffer).
pub const KERNEL_ABI_ARG3: u64 = KERNEL_ABI_SCRATCH_BASE + 0xc000;

/// Every model this module installs is deterministic and path-local, which is
/// what makes it safe to bind into the sustained replay digest.
pub const DETERMINISTIC_MODEL_NAMES: &[&str] = &[
    "linux_kernel_alloc",
    "linux_kernel_free",
    "linux_kernel_free_arg1",
    "linux_kernel_release",
    "linux_kernel_refcount_init",
    "linux_kernel_refcount_set",
    "linux_kernel_refcount_inc",
    "linux_kernel_refcount_dec",
    "linux_kernel_refcount_dec_and_test",
    "linux_kernel_success",
    "linux_kernel_return_thunk",
];

/// Seeds two levels of valid RW pointer slots inside [`KERNEL_ABI_SCRATCH_BASE`]
/// so Linux `ioctl`/`read`/`write`/`probe` handlers reading `file->private_data`
/// (`[rdi+0x18]`), `file->f_inode` (`[rdi+0x20]`), or `dev->driver_data`
/// (`[rdi+0x08]`) land in zeroed mapped memory instead of faulting at `[0x18]`.
pub(crate) fn seed_abi_scratch(memory: &mut angryier_memory::PersistentMemory) -> Result<(), RuntimeError> {
    let page1 = (KERNEL_ABI_SCRATCH_BASE + 0x1000).to_le_bytes();
    let page2 = (KERNEL_ABI_SCRATCH_BASE + 0x2000).to_le_bytes();
    for offset in [0x00u64, 0x08, 0x10, 0x18, 0x20, 0x28] {
        *memory = memory
            .clone()
            .load_concrete(KERNEL_ABI_ARG0 + offset, &page1)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
    }
    for offset in [0x00u64, 0x08, 0x10, 0x18, 0x20] {
        *memory = memory
            .clone()
            .load_concrete(KERNEL_ABI_SCRATCH_BASE + 0x1000 + offset, &page2)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
    }
    Ok(())
}

/// What a modeled import does at the call boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelModelKind {
    /// Allocates a distinct 4 KiB slot in `KERNEL_MODEL_HEAP_BASE` and returns its address in `RAX`.
    Allocate,
    /// Frees pointer in `RDI` (arg0) and detects double frees against live slots.
    FreeArg0,
    /// Frees pointer in `RSI` (arg1, e.g. `devm_kfree(dev, ptr)`) and detects double frees.
    FreeArg1,
    /// Non-heap void release (`dma_free*`, `free_irq`, etc.).
    Release,
    /// `kref_init(r)`: initializes `[rdi]` to 1 and marks `rdi` tracked.
    RefcountInit,
    /// `refcount_set(r, n)`: sets `[rdi]` to `esi as u32` and marks `rdi` tracked.
    RefcountSet,
    /// `refcount_inc(r)` / `kref_get(r)`: increments `[rdi]` and marks `rdi` tracked.
    RefcountInc,
    /// `refcount_dec(r)`: decrements tracked `[rdi]`, detecting underflow.
    RefcountDec,
    /// `refcount_dec_and_test(r)` / `kref_put(r, rel)`: decrements `[rdi]`, returns 1 iff zero, detecting underflow.
    RefcountDecAndTest,
    /// Returns success (RAX = 0).
    Success,
    /// Simulates a retpoline/SLS return thunk (`jmp __x86_return_thunk` -> `ret`
    /// without clobbering RAX).
    ReturnThunk,
}

/// One installed kernel-API model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelModel {
    kind: KernelModelKind,
    slot: u64,
}

impl KernelModel {
    pub const fn new(kind: KernelModelKind, slot: u64) -> Self {
        Self { kind, slot }
    }
}

impl SimProcedure for KernelModel {
    fn name(&self) -> &'static str {
        match self.kind {
            KernelModelKind::Allocate => "linux_kernel_alloc",
            KernelModelKind::FreeArg0 => "linux_kernel_free",
            KernelModelKind::FreeArg1 => "linux_kernel_free_arg1",
            KernelModelKind::Release => "linux_kernel_release",
            KernelModelKind::RefcountInit => "linux_kernel_refcount_init",
            KernelModelKind::RefcountSet => "linux_kernel_refcount_set",
            KernelModelKind::RefcountInc => "linux_kernel_refcount_inc",
            KernelModelKind::RefcountDec => "linux_kernel_refcount_dec",
            KernelModelKind::RefcountDecAndTest => "linux_kernel_refcount_dec_and_test",
            KernelModelKind::Success => "linux_kernel_success",
            KernelModelKind::ReturnThunk => "linux_kernel_return_thunk",
        }
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        match self.kind {
            KernelModelKind::Allocate => {
                // Fallback when called outside a mapped ET_REL heap.
                SimResult::Return(KERNEL_MODEL_HEAP_BASE | (self.slot & 0xFFFF))
            }
            KernelModelKind::FreeArg0
            | KernelModelKind::FreeArg1
            | KernelModelKind::Release
            | KernelModelKind::RefcountInit
            | KernelModelKind::RefcountSet
            | KernelModelKind::RefcountInc
            | KernelModelKind::RefcountDec
            | KernelModelKind::RefcountDecAndTest
            | KernelModelKind::Success => SimResult::Return(0),
            KernelModelKind::ReturnThunk => SimResult::Continue(SimState::new()),
        }
    }
}

/// Classifies one imported kernel symbol. `None` means "do not model this",
/// which keeps the path honest: the stub slot stays unexecutable and the
/// exploration defers rather than inventing a return value.
pub fn model_for(symbol: &str) -> Option<KernelModelKind> {
    // Non-function data variables or predicates that happen to contain "alloc".
    const UNMODELED_DATA_OR_PRED: &[&str] = &["kmalloc_caches", "random_kmalloc_seed", "is_vmalloc_addr"];
    if UNMODELED_DATA_OR_PRED.contains(&symbol) {
        return None;
    }

    const FREE_ARG0: &[&str] = &["kfree", "kfree_sensitive", "kfree_const", "vfree", "kvfree"];
    const FREE_ARG1: &[&str] = &["devm_kfree", "kmem_cache_free"];
    const RELEASE: &[&str] = &["dma_free"];
    const ALLOCATE: &[&str] = &[
        "kmalloc",
        "__kmalloc",
        "kzalloc",
        "kcalloc",
        "krealloc",
        "vmalloc",
        "kvmalloc",
        "kmem_cache_alloc",
        "devm_kmalloc",
        "devm_kzalloc",
        "dma_alloc",
        "memdup_user",
    ];
    const SUCCESS: &[&str] = &[
        "__fentry__",
        "fentry",
        "copy_from_user",
        "copy_to_user",
        "validate_usercopy_range",
        "get_user",
        "put_user",
        "__get_user_",
        "__put_user_",
        "mutex_",
        "spin_lock",
        "spin_unlock",
        "refcount_warn_saturate",
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
        "__SCT__might_resched",
    ];

    if symbol == "__x86_return_thunk" {
        return Some(KernelModelKind::ReturnThunk);
    }
    if FREE_ARG1.iter().any(|prefix| symbol.starts_with(prefix)) {
        return Some(KernelModelKind::FreeArg1);
    }
    if FREE_ARG0
        .iter()
        .any(|prefix| symbol == *prefix || symbol.starts_with(prefix))
    {
        return Some(KernelModelKind::FreeArg0);
    }
    if RELEASE.iter().any(|prefix| symbol.starts_with(prefix)) {
        return Some(KernelModelKind::Release);
    }
    if symbol == "kref_init" {
        return Some(KernelModelKind::RefcountInit);
    }
    if symbol == "refcount_set" {
        return Some(KernelModelKind::RefcountSet);
    }
    if symbol == "refcount_inc" || symbol == "kref_get" {
        return Some(KernelModelKind::RefcountInc);
    }
    if symbol == "refcount_dec" {
        return Some(KernelModelKind::RefcountDec);
    }
    if symbol == "refcount_dec_and_test" || symbol == "refcount_dec_if_one" || symbol == "kref_put" {
        return Some(KernelModelKind::RefcountDecAndTest);
    }
    if ALLOCATE.iter().any(|prefix| symbol.contains(prefix)) {
        return Some(KernelModelKind::Allocate);
    }
    if symbol.contains("alloc") {
        return Some(KernelModelKind::Allocate);
    }
    if SUCCESS.iter().any(|prefix| symbol.contains(prefix)) {
        return Some(KernelModelKind::Success);
    }
    if symbol.contains("register") && !symbol.contains("unregister") {
        return Some(KernelModelKind::Success);
    }
    None
}

/// Installs a model at each import stub slot the classifier recognizes, and
/// returns how many hooks were attached. Unknown imports are left alone.
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

fn read_concrete_u64(process: &Process, addr: Address) -> Option<u64> {
    let bytes = process.state.memory.read(addr, 8).ok()?;
    let mut buf = [0u8; 8];
    for (i, b) in bytes.iter().enumerate() {
        match b {
            ByteValue::Concrete(v) => buf[i] = *v,
            ByteValue::Symbolic(_) => return None,
        }
    }
    Some(u64::from_le_bytes(buf))
}

fn read_concrete_u32(process: &Process, addr: Address) -> Option<u32> {
    let bytes = process.state.memory.read(addr, 4).ok()?;
    let mut buf = [0u8; 4];
    for (i, b) in bytes.iter().enumerate() {
        match b {
            ByteValue::Concrete(v) => buf[i] = *v,
            ByteValue::Symbolic(_) => return None,
        }
    }
    Some(u32::from_le_bytes(buf))
}

fn read_concrete_u8(process: &Process, addr: Address) -> Option<u8> {
    let bytes = process.state.memory.read(addr, 1).ok()?;
    match bytes.first()? {
        ByteValue::Concrete(v) => Some(*v),
        ByteValue::Symbolic(_) => None,
    }
}

fn write_concrete_bytes(process: &mut Process, addr: Address, bytes: &[u8]) -> Result<(), RuntimeError> {
    let values: Vec<ByteValue> = bytes.iter().map(|b| ByteValue::Concrete(*b)).collect();
    process.state.memory = process
        .state
        .memory
        .write(addr, &values)
        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
    Ok(())
}

fn read_gpr_u64(process: &Process, reg_index: u32) -> Option<u64> {
    let raw = process.state.registers.read(register_id::GPR_BASE + reg_index).ok()?;
    if raw.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&raw[..8]);
    Some(u64::from_le_bytes(buf))
}

fn has_mapped_heap(process: &Process) -> bool {
    process
        .state
        .memory
        .regions()
        .iter()
        .any(|r| r.base == KERNEL_MODEL_HEAP_BASE && r.size >= KERNEL_MODEL_HEAP_SIZE && r.writable)
}

fn refcount_is_tracked(process: &Process, ptr: u64) -> bool {
    let Some(count) = read_concrete_u64(process, REFCOUNT_INIT_COUNT_ADDR) else {
        return false;
    };
    let n = (count as usize).min(MAX_TRACKED_REFCOUNTS);
    for i in 0..n {
        if read_concrete_u64(process, REFCOUNT_INIT_ADDRS_BASE + (i as u64) * 8) == Some(ptr) {
            return true;
        }
    }
    false
}

fn mark_refcount_tracked(process: &mut Process, ptr: u64) -> Result<(), RuntimeError> {
    if refcount_is_tracked(process, ptr) {
        return Ok(());
    }
    let count = read_concrete_u64(process, REFCOUNT_INIT_COUNT_ADDR).unwrap_or(0);
    if (count as usize) < MAX_TRACKED_REFCOUNTS {
        write_concrete_bytes(process, REFCOUNT_INIT_ADDRS_BASE + count * 8, &ptr.to_le_bytes())?;
        write_concrete_bytes(process, REFCOUNT_INIT_COUNT_ADDR, &(count + 1).to_le_bytes())?;
    }
    Ok(())
}

/// Applies stateful path-local heap and refcount models directly on `process.state.memory`.
/// Returns `Ok(Some(ret_val))` when handled (caller should pop return and write `RAX`),
/// or `Ok(None)` to defer to the stateless `SimProcedure::apply`.
pub(crate) fn apply_stateful(process: &mut Process, model_name: &str) -> Result<Option<u64>, RuntimeError> {
    if !has_mapped_heap(process) {
        return Ok(None);
    }
    match model_name {
        "linux_kernel_alloc" => {
            let next_slot = read_concrete_u64(process, HEAP_NEXT_SLOT_ADDR).unwrap_or(MAX_HEAP_SLOTS);
            if next_slot >= MAX_HEAP_SLOTS {
                return Ok(Some(0));
            }
            let ptr = HEAP_SLOTS_BASE + next_slot * HEAP_SLOT_STRIDE;
            write_concrete_bytes(process, HEAP_NEXT_SLOT_ADDR, &(next_slot + 1).to_le_bytes())?;
            write_concrete_bytes(process, HEAP_SLOT_STATE_ADDR + next_slot, &[SLOT_LIVE])?;
            Ok(Some(ptr))
        }
        "linux_kernel_free" | "linux_kernel_free_arg1" => {
            let reg_idx = if model_name == "linux_kernel_free_arg1" { 6 } else { 7 }; // rsi or rdi
            let Some(ptr) = read_gpr_u64(process, reg_idx) else {
                return Ok(Some(0));
            };
            if ptr == 0 {
                return Ok(Some(0));
            }
            if (HEAP_SLOTS_BASE..HEAP_META_BASE).contains(&ptr)
                && (ptr - HEAP_SLOTS_BASE).is_multiple_of(HEAP_SLOT_STRIDE)
            {
                let slot = (ptr - HEAP_SLOTS_BASE) / HEAP_SLOT_STRIDE;
                match read_concrete_u8(process, HEAP_SLOT_STATE_ADDR + slot) {
                    Some(SLOT_LIVE) => {
                        write_concrete_bytes(process, HEAP_SLOT_STATE_ADDR + slot, &[SLOT_FREED])?;
                    }
                    Some(SLOT_FREED) => {
                        process.kernel_violation = Some("kernel double-free detected");
                        process.terminated = true;
                    }
                    Some(SLOT_UNALLOCATED) | Some(_) | None => {}
                }
            }
            Ok(Some(0))
        }
        "linux_kernel_refcount_init" => {
            if let Some(ptr) = read_gpr_u64(process, 7)
                && ptr != 0
                && read_concrete_u32(process, ptr).is_some()
            {
                write_concrete_bytes(process, ptr, &1u32.to_le_bytes())?;
                mark_refcount_tracked(process, ptr)?;
            }
            Ok(Some(0))
        }
        "linux_kernel_refcount_set" => {
            if let Some(ptr) = read_gpr_u64(process, 7)
                && ptr != 0
                && read_concrete_u32(process, ptr).is_some()
            {
                let value = read_gpr_u64(process, 6).unwrap_or(1) as u32;
                write_concrete_bytes(process, ptr, &value.to_le_bytes())?;
                mark_refcount_tracked(process, ptr)?;
            }
            Ok(Some(0))
        }
        "linux_kernel_refcount_inc" => {
            if let Some(ptr) = read_gpr_u64(process, 7)
                && ptr != 0
                && let Some(val) = read_concrete_u32(process, ptr)
            {
                write_concrete_bytes(process, ptr, &val.saturating_add(1).to_le_bytes())?;
                mark_refcount_tracked(process, ptr)?;
            }
            Ok(Some(0))
        }
        "linux_kernel_refcount_dec" | "linux_kernel_refcount_dec_and_test" => {
            let is_test = model_name == "linux_kernel_refcount_dec_and_test";
            if let Some(ptr) = read_gpr_u64(process, 7)
                && ptr != 0
                && let Some(val) = read_concrete_u32(process, ptr)
            {
                if val == 0 {
                    if refcount_is_tracked(process, ptr) {
                        process.kernel_violation = Some("kernel refcount underflow detected");
                        process.terminated = true;
                    }
                    return Ok(Some(u64::from(is_test)));
                }
                let next = val - 1;
                write_concrete_bytes(process, ptr, &next.to_le_bytes())?;
                return Ok(Some(u64::from(is_test && next == 0)));
            }
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{DecodedInstruction, Decoder};
    use angryier_loader::{LoadedImage, Segment};
    use angryier_types::{ImageId, SemanticVersion, TargetProfileId};

    #[derive(Debug)]
    struct TestDecoder;
    impl Decoder for TestDecoder {
        type Error = std::convert::Infallible;
        fn decode(&self, _address: Address, _bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
            unreachable!()
        }
    }

    #[test]
    fn classifier_covers_alloc_free_and_success_families() {
        assert_eq!(model_for("__kmalloc"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("__kmalloc_noprof"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("kzalloc"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("memdup_user"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("kmem_cache_alloc_trace"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("devm_iio_device_alloc"), Some(KernelModelKind::Allocate));
        assert_eq!(model_for("kmalloc_caches"), None);
        assert_eq!(model_for("random_kmalloc_seed"), None);
        assert_eq!(model_for("is_vmalloc_addr"), None);
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
        assert_eq!(model_for("kfree"), Some(KernelModelKind::FreeArg0));
        assert_eq!(model_for("kfree_sensitive"), Some(KernelModelKind::FreeArg0));
        assert_eq!(model_for("devm_kfree"), Some(KernelModelKind::FreeArg1));
        assert_eq!(model_for("kmem_cache_free"), Some(KernelModelKind::FreeArg1));
        assert_eq!(model_for("refcount_set"), Some(KernelModelKind::RefcountSet));
        assert_eq!(model_for("refcount_inc"), Some(KernelModelKind::RefcountInc));
        assert_eq!(model_for("refcount_dec"), Some(KernelModelKind::RefcountDec));
        assert_eq!(
            model_for("refcount_dec_and_test"),
            Some(KernelModelKind::RefcountDecAndTest)
        );
        assert_eq!(model_for("refcount_warn_saturate"), Some(KernelModelKind::Success));
        assert_eq!(model_for("_copy_from_user"), Some(KernelModelKind::Success));
        assert_eq!(model_for("validate_usercopy_range"), Some(KernelModelKind::Success));
        assert_eq!(model_for("__put_user_4"), Some(KernelModelKind::Success));
        assert_eq!(model_for("mutex_lock"), Some(KernelModelKind::Success));
        assert_eq!(model_for("__fentry__"), Some(KernelModelKind::Success));
        assert_eq!(model_for("__x86_return_thunk"), Some(KernelModelKind::ReturnThunk));
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
    fn stateful_heap_allocates_distinct_slots_and_detects_double_free() {
        let rt = crate::Runtime::new(TestDecoder, SemanticVersion(1), TargetProfileId(1));
        let image = LoadedImage {
            id: ImageId(1),
            entry: 0x0100_0000,
            target_profile: angryier_loader::INTEL64_TARGET_PROFILE,
            segments: vec![Segment {
                address: 0x0100_0000,
                bytes: vec![0x90; 16],
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
            et_rel: Some(angryier_loader::EtRelInfo {
                sections: Vec::new(),
                externals: Vec::new(),
            }),
        };
        let mut proc_a = rt.load_image(image).expect("load synthetic et_rel");
        let p1 = apply_stateful(&mut proc_a, "linux_kernel_alloc")
            .expect("alloc 1")
            .expect("handled");
        let p2 = apply_stateful(&mut proc_a, "linux_kernel_alloc")
            .expect("alloc 2")
            .expect("handled");
        assert_ne!(p1, p2);
        assert_eq!(p1, HEAP_SLOTS_BASE);
        assert_eq!(p2, HEAP_SLOTS_BASE + HEAP_SLOT_STRIDE);

        // Fork before freeing: path B stays independent of path A.
        let mut proc_b = proc_a.clone();
        proc_a.write_register(register_id::GPR_BASE + 7, p1).expect("rdi");
        apply_stateful(&mut proc_a, "linux_kernel_free").expect("first free");
        assert!(proc_a.kernel_violation.is_none());
        assert!(!proc_a.terminated);

        // Second free on path A detects double free.
        apply_stateful(&mut proc_a, "linux_kernel_free").expect("second free");
        assert_eq!(proc_a.kernel_violation, Some("kernel double-free detected"));
        assert!(proc_a.terminated);

        // Sibling path B can still free p1 once without violation.
        proc_b.write_register(register_id::GPR_BASE + 7, p1).expect("rdi");
        apply_stateful(&mut proc_b, "linux_kernel_free").expect("sibling free");
        assert!(proc_b.kernel_violation.is_none());
    }

    #[test]
    fn stateful_refcount_tracks_decrements_and_detects_underflow() {
        let rt = crate::Runtime::new(TestDecoder, SemanticVersion(1), TargetProfileId(1));
        let image = LoadedImage {
            id: ImageId(2),
            entry: 0x0100_0000,
            target_profile: angryier_loader::INTEL64_TARGET_PROFILE,
            segments: vec![Segment {
                address: 0x0100_0000,
                bytes: vec![0x90; 16],
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
            et_rel: Some(angryier_loader::EtRelInfo {
                sections: Vec::new(),
                externals: Vec::new(),
            }),
        };
        let mut process = rt.load_image(image).expect("load");
        let obj = apply_stateful(&mut process, "linux_kernel_alloc")
            .expect("alloc")
            .expect("handled");
        process.write_register(register_id::GPR_BASE + 7, obj).expect("rdi");
        process.write_register(register_id::GPR_BASE + 6, 1).expect("esi");
        apply_stateful(&mut process, "linux_kernel_refcount_set").expect("set 1");
        let reached_zero = apply_stateful(&mut process, "linux_kernel_refcount_dec_and_test")
            .expect("dec_and_test")
            .expect("handled");
        assert_eq!(reached_zero, 1);
        assert!(process.kernel_violation.is_none());

        // Decrementing a tracked zero refcount triggers underflow violation.
        apply_stateful(&mut process, "linux_kernel_refcount_dec").expect("underflow");
        assert_eq!(process.kernel_violation, Some("kernel refcount underflow detected"));
        assert!(process.terminated);

        // Untracked scratch zero refcount must not false-positive.
        let mut clean = rt
            .load_image(LoadedImage {
                id: ImageId(3),
                entry: 0x0100_0000,
                target_profile: angryier_loader::INTEL64_TARGET_PROFILE,
                segments: vec![Segment {
                    address: 0x0100_0000,
                    bytes: vec![0x90; 16],
                    readable: true,
                    writable: false,
                    executable: true,
                }],
                symbols: Vec::new(),
                program_headers: None,
                dynamic: None,
                pe: None,
                et_rel: Some(angryier_loader::EtRelInfo {
                    sections: Vec::new(),
                    externals: Vec::new(),
                }),
            })
            .expect("load");
        clean
            .write_register(register_id::GPR_BASE + 7, KERNEL_ABI_ARG0)
            .expect("rdi");
        apply_stateful(&mut clean, "linux_kernel_refcount_dec").expect("untracked");
        assert!(clean.kernel_violation.is_none());
    }
}
