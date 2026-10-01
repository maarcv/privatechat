//! Test doubles and builders for the storage of spec 020-store-files, used
//! by the tests of `core`, the fuzz targets and, through the feature
//! `test-support`, the tests of `store`.
//!
//! It compiles outside `cfg(test)`, where the test relaxations of AGENTS 4 do
//! not apply, so it is written like production code. Nothing in it reaches a
//! release build: the feature is enabled only in `store`'s dev-dependency.

mod builders;
mod compare;

pub use self::builders::{batch, record, state_for};
pub use self::compare::{records_eq, state_eq};

#[cfg(test)]
mod tests;
