#![forbid(unsafe_code)]

use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PluginApiVersion { pub major: u16, pub minor: u16 }

pub trait AngryierPlugin: Debug + Send + Sync { fn name(&self) -> &'static str; fn api_version(&self) -> PluginApiVersion; }
pub trait PluginRegistry: Send + Sync { type Error; fn register(&self, plugin: &'static dyn AngryierPlugin) -> Result<(), Self::Error>; }
