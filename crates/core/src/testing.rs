//! Test doubles and builders for the storage of spec 020-store-files, used
//! by the tests of `core`, the fuzz targets and, through the feature
//! `test-support`, the tests of `store`.
//!
//! It compiles outside `cfg(test)`, where the test relaxations of AGENTS 4 do
//! not apply, so it is written like production code. Nothing in it reaches a
//! release build: the feature is enabled only in `store`'s dev-dependency.

mod builders;
mod compare;
mod faults;
mod memory;

pub use self::builders::{batch, record, settings, state_for};
pub use self::compare::{records_eq, settings_eq, state_eq};
pub use self::faults::{FailingStore, FailingVault, Faults};
pub use self::memory::{MemoryStore, MemoryVault};

#[cfg(test)]
mod tests;
