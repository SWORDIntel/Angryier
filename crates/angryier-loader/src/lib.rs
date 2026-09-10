#![forbid(unsafe_code)]

use angryier_types::{Address, ImageId, TargetProfileId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportKind { StaticBinary, Snapshot, Checkpoint, LiveProcessCapture }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment { pub address: Address, pub bytes: Vec<u8>, pub readable: bool, pub writable: bool, pub executable: bool }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedImage { pub id: ImageId, pub entry: Address, pub target_profile: TargetProfileId, pub segments: Vec<Segment> }

pub trait ImageLoader: Send + Sync { type Error; fn load(&self, bytes: &[u8]) -> Result<LoadedImage, Self::Error>; }
pub trait StateImporter: Send + Sync { type State; type Error; fn import(&self, kind: ImportKind, source: &[u8]) -> Result<Self::State, Self::Error>; }
