#![forbid(unsafe_code)]

use core::fmt::{Debug, Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PluginApiVersion {
    pub major: u16,
    pub minor: u16,
}

pub trait AngryierPlugin: Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn api_version(&self) -> PluginApiVersion;
}
pub trait PluginRegistry: Send + Sync {
    type Error;
    fn register(&self, plugin: &'static dyn AngryierPlugin) -> Result<(), Self::Error>;
}

/// Errors that can occur while interacting with the plugin registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginError {
    /// A plugin with the same name has already been registered.
    DuplicateName,
    /// The internal mutex was poisoned by a panicking thread.
    Poisoned,
}

impl Display for PluginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            PluginError::DuplicateName => {
                write!(f, "a plugin with this name has already been registered")
            }
            PluginError::Poisoned => write!(f, "plugin registry lock was poisoned"),
        }
    }
}

impl std::error::Error for PluginError {}

/// A simple, thread-safe in-memory implementation of [`PluginRegistry`].
///
/// Plugins are stored in a [`Vec`] guarded by a [`std::sync::Mutex`].
/// Registration order is preserved, but [`InMemoryPluginRegistry::names`]
/// returns a sorted view for deterministic output.
#[derive(Debug, Default)]
pub struct InMemoryPluginRegistry {
    plugins: std::sync::Mutex<Vec<&'static dyn AngryierPlugin>>,
}

impl InMemoryPluginRegistry {
    /// Creates a new, empty registry.
    pub fn new() -> Self {
        Self {
            plugins: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns the number of currently registered plugins.
    pub fn len(&self) -> usize {
        let guard = self.plugins.lock().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }

    /// Returns `true` if no plugins are currently registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a sorted list of the names of all registered plugins.
    ///
    /// Sorting guarantees deterministic ordering regardless of registration
    /// order.
    pub fn names(&self) -> Vec<&'static str> {
        let guard = self.plugins.lock().unwrap_or_else(|e| e.into_inner());
        let mut names: Vec<&'static str> = guard.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        names
    }

    /// Finds a registered plugin by name, if present.
    pub fn find(&self, name: &str) -> Option<&'static dyn AngryierPlugin> {
        let guard = self.plugins.lock().unwrap_or_else(|e| e.into_inner());
        guard.iter().copied().find(|p| p.name() == name)
    }
}

impl PluginRegistry for InMemoryPluginRegistry {
    type Error = PluginError;

    fn register(&self, plugin: &'static dyn AngryierPlugin) -> Result<(), Self::Error> {
        let mut guard = self.plugins.lock().unwrap_or_else(|e| e.into_inner());
        if guard.iter().any(|p| p.name() == plugin.name()) {
            return Err(PluginError::DuplicateName);
        }
        guard.push(plugin);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test plugins
// ---------------------------------------------------------------------------

/// A minimal test plugin used by the crate's test suite.
#[derive(Debug)]
pub struct TestPluginA;

impl AngryierPlugin for TestPluginA {
    fn name(&self) -> &'static str {
        "plugin-a"
    }
    fn api_version(&self) -> PluginApiVersion {
        PluginApiVersion { major: 1, minor: 0 }
    }
}

/// A second minimal test plugin used by the crate's test suite.
#[derive(Debug)]
pub struct TestPluginB;

impl AngryierPlugin for TestPluginB {
    fn name(&self) -> &'static str {
        "plugin-b"
    }
    fn api_version(&self) -> PluginApiVersion {
        PluginApiVersion { major: 1, minor: 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Static instances so they can be passed as `&'static dyn AngryierPlugin`.
    static PLUGIN_A: TestPluginA = TestPluginA;
    static PLUGIN_B: TestPluginB = TestPluginB;

    fn plugin_a() -> &'static dyn AngryierPlugin {
        &PLUGIN_A
    }

    fn plugin_b() -> &'static dyn AngryierPlugin {
        &PLUGIN_B
    }

    #[test]
    fn register_single_plugin_succeeds() {
        let registry = InMemoryPluginRegistry::new();
        let result = registry.register(plugin_a());
        assert!(result.is_ok());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn register_two_different_plugins_succeeds() {
        let registry = InMemoryPluginRegistry::new();
        assert!(registry.register(plugin_a()).is_ok());
        assert!(registry.register(plugin_b()).is_ok());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn register_duplicate_name_fails() {
        let registry = InMemoryPluginRegistry::new();
        assert!(registry.register(plugin_a()).is_ok());
        let result = registry.register(plugin_a());
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, PluginError::DuplicateName);
        }
    }

    #[test]
    fn len_tracks_registrations() {
        let registry = InMemoryPluginRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.register(plugin_a()).is_ok());
        assert_eq!(registry.len(), 1);
        assert!(registry.register(plugin_b()).is_ok());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn names_returns_sorted_list() {
        let registry = InMemoryPluginRegistry::new();
        // Register out of order to verify sorting.
        assert!(registry.register(plugin_b()).is_ok());
        assert!(registry.register(plugin_a()).is_ok());
        let names = registry.names();
        assert_eq!(names, vec!["plugin-a", "plugin-b"]);
    }

    #[test]
    fn find_existing_plugin_returns_some() {
        let registry = InMemoryPluginRegistry::new();
        assert!(registry.register(plugin_a()).is_ok());
        let found = registry.find("plugin-a");
        assert!(found.is_some());
        if let Some(plugin) = found {
            assert_eq!(plugin.name(), "plugin-a");
            assert_eq!(plugin.api_version(), PluginApiVersion { major: 1, minor: 0 });
        }
    }

    #[test]
    fn find_non_existent_returns_none() {
        let registry = InMemoryPluginRegistry::new();
        assert!(registry.register(plugin_a()).is_ok());
        assert!(registry.find("does-not-exist").is_none());
    }

    #[test]
    fn register_same_plugin_twice_fails_as_duplicate() {
        let registry = InMemoryPluginRegistry::new();
        assert!(registry.register(plugin_a()).is_ok());
        let second = registry.register(plugin_a());
        assert!(second.is_err());
        if let Err(err) = second {
            assert_eq!(err, PluginError::DuplicateName);
        }
    }

    #[test]
    fn empty_registry_has_len_zero() {
        let registry = InMemoryPluginRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
        assert!(registry.names().is_empty());
        assert!(registry.find("plugin-a").is_none());
    }
}
