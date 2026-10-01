//! The bytes the client keeps on disk (spec 020-store-files): the records of
//! `state.bin`, `messages.log` and `settings.bin`, and the functions that seal
//! and open them. Every byte that is encrypted or encoded is decided here;
//! the `store` crate owns the system calls and the plaintext framing, and
//! reaches the codec and `crypto` only through these functions.
//!
//! What each state field means, and when it changes, belongs to the spec that
//! changes it (specs 021–027).

use crate::proto::record::RecordError;

mod state;

#[cfg(test)]
mod tests;

/// The longest stored name: a label, one's own display name, a channel's
/// local name, a peer's last display name (spec 020 Limits). Specs 021, 022
/// and 027 use it.
pub(crate) const MAX_NAME: usize = 64;

/// Why the storage failed, one variant per condition of spec 020 (R26). No
/// variant carries an OS error, a path or a byte of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// A system call failed, or the store is poisoned by an earlier failure
    /// (R11).
    Io,
    /// Another holder has the data directory or the channel directory (R17,
    /// R20).
    Locked,
    /// A file that does not open or does not decode (R7).
    Corrupt,
    /// A file written by a newer version of the app (R7, R8).
    UnsupportedVersion,
    /// The log would pass its limit (R16).
    LogFull,
    /// More `outbox` entries than a state holds (R27).
    OutboxFull,
}

/// Every codec failure of a stored record is `Corrupt` (R7).
impl From<RecordError> for StoreError {
    fn from(_: RecordError) -> StoreError {
        StoreError::Corrupt
    }
}
