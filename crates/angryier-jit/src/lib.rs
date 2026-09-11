#![forbid(unsafe_code)]

use angryier_core::CodeVersionSource;
use angryier_ir::IrBlockKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JitTier {
    Interpreter,
    SpecializedCached,
    NativeTranslated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NativeIsolation {
    TrustedTranslatedInProcess,
    RestrictedWorker,
}

/// Canonical identity for a compiled block.
///
/// Semantic content, target profile, and code-page guards are owned solely by
/// `IrBlockKey`. Duplicating them here would create two sources of truth and
/// permit a stale outer validity record to disagree with the source IR key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledBlockKey {
    pub source: IrBlockKey,
}

impl From<IrBlockKey> for CompiledBlockKey {
    fn from(source: IrBlockKey) -> Self {
        Self { source }
    }
}

pub trait JitCompiler: Send + Sync {
    type Artifact;
    type Error;
    fn compile(&self, key: &CompiledBlockKey, tier: JitTier) -> Result<Self::Artifact, Self::Error>;
}

pub trait JitValidity: Send + Sync {
    fn valid(&self, key: &CompiledBlockKey) -> bool;
}

/// Fail-closed JIT validity oracle backed by an abstract code-page version
/// source. Compiled blocks without any executable-page guards are not valid.
#[derive(Clone, Copy, Debug)]
pub struct GuardedJitValidity<'a, V> {
    versions: &'a V,
}

impl<'a, V> GuardedJitValidity<'a, V> {
    pub const fn new(versions: &'a V) -> Self {
        Self { versions }
    }
}

impl<V: CodeVersionSource> JitValidity for GuardedJitValidity<'_, V> {
    fn valid(&self, key: &CompiledBlockKey) -> bool {
        !key.source.code_versions.is_empty() && self.versions.guards_match(&key.source.code_versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_ir::IrBlockKey;
    use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
    use angryier_types::{BlockId, ContentId, ImageId, ObjectId, TargetProfileId};

    fn executable_memory() -> Result<PersistentMemory, angryier_memory::MemoryError> {
        PersistentMemory::new(vec![MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x4000,
            readable: true,
            writable: true,
            executable: true,
        }])
    }

    fn compiled_key(address: u64, code_versions: Vec<angryier_types::CodeVersionGuard>) -> CompiledBlockKey {
        IrBlockKey {
            image: ImageId(1),
            block: BlockId(address),
            address,
            semantic_content: ContentId([0x5a; 32]),
            target_profile: TargetProfileId(1),
            code_versions,
        }
        .into()
    }

    #[test]
    fn unguarded_compiled_block_fails_closed() -> Result<(), angryier_memory::MemoryError> {
        let memory = executable_memory()?;
        let validity = GuardedJitValidity::new(&memory);
        let key = compiled_key(0x1000, Vec::new());

        assert!(!validity.valid(&key));
        Ok(())
    }

    #[test]
    fn executable_write_invalidates_old_compiled_block() -> Result<(), angryier_memory::MemoryError> {
        let memory = executable_memory()?;
        let guards = memory.code_version_guards_for_range(0x1100, 16)?;
        let key = compiled_key(0x1100, guards);
        assert!(GuardedJitValidity::new(&memory).valid(&key));

        let changed = memory.write(0x1104, &[ByteValue::Concrete(0xcc)])?;

        assert!(!GuardedJitValidity::new(&changed).valid(&key));
        assert!(GuardedJitValidity::new(&memory).valid(&key));
        Ok(())
    }

    #[test]
    fn unaffected_page_remains_valid() -> Result<(), angryier_memory::MemoryError> {
        let memory = executable_memory()?;
        let first_key = compiled_key(0x1100, memory.code_version_guards_for_range(0x1100, 16)?);
        let second_key = compiled_key(0x3100, memory.code_version_guards_for_range(0x3100, 16)?);

        let changed = memory.write(0x1104, &[ByteValue::Concrete(0xcc)])?;
        let validity = GuardedJitValidity::new(&changed);

        assert!(!validity.valid(&first_key));
        assert!(validity.valid(&second_key));
        Ok(())
    }

    #[test]
    fn multi_page_block_invalidates_when_any_guarded_page_changes() -> Result<(), angryier_memory::MemoryError> {
        let memory = executable_memory()?;
        let key = compiled_key(0x1ff8, memory.code_version_guards_for_range(0x1ff8, 16)?);
        assert_eq!(key.source.code_versions.len(), 2);
        assert!(GuardedJitValidity::new(&memory).valid(&key));

        let changed = memory.write(0x2004, &[ByteValue::Concrete(0x90)])?;

        assert!(!GuardedJitValidity::new(&changed).valid(&key));
        Ok(())
    }
}
