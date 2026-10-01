//! The bytes the client keeps on disk (spec 020-store-files): the records of
//! `state.bin`, `messages.log` and `settings.bin`, and the functions that seal
//! and open them. Every byte that is encrypted or encoded is decided here;
//! the `store` crate owns the system calls and the plaintext framing, and
//! reaches the codec and `crypto` only through these functions.
//!
//! What each state field means, and when it changes, belongs to the spec that
//! changes it (specs 021–027).

use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError, Nonce, Secret, TAG_LEN};
use crate::proto::record::RecordError;

mod log;
mod settings;
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

/// Every libsodium failure of a seal or an open is `Corrupt`: a box that does
/// not open is (R7), and the others, which only a failed initialisation can
/// cause, have no variant of their own (R26).
impl From<CryptoError> for StoreError {
    fn from(_: CryptoError) -> StoreError {
        StoreError::Corrupt
    }
}

/// The domain tag of a channel's file key (R3).
const STORE_TAG: &[u8; 20] = b"privatechat/store/v1";

/// The domain tag of the settings key (R3).
const SETTINGS_TAG: &[u8; 23] = b"privatechat/settings/v1";

/// The domain tag of a channel directory's name (R18).
const DIR_TAG: &[u8; 18] = b"privatechat/dir/v1";

/// Bytes of a nonce, before every box (R4, R5).
pub(crate) const NONCE_LEN: usize = 24;

/// The shortest `nonce ‖ box`: a nonce and an empty record's tag (R7).
pub(crate) const MIN_SEALED: usize = NONCE_LEN + TAG_LEN;

/// `K_db`, the key of everything on disk (`docs/spec.md` §8). It enters once,
/// zeroing its input, and no function hands it out: every file is sealed
/// under a key derived from it (R3).
pub struct StorageKey {
    key: Secret<32>,
}

impl StorageKey {
    /// Takes `K_db` from `bytes` and fills them with zeros (R24).
    pub fn from_bytes(bytes: &mut [u8; 32]) -> StorageKey {
        let key = Secret::copy_from(bytes);
        bytes.zeroize();
        StorageKey { key }
    }
}

impl fmt::Debug for StorageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// The name of a channel directory: the first 16 bytes of a keyed hash of its
/// `channel_id` (R18), which the store writes as 32 lowercase hex characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DirName(pub [u8; 16]);

/// The directory name of `channel_id` under `key` (R18).
///
/// # Errors
///
/// `Corrupt` when libsodium fails, which only a failed initialisation can
/// cause.
pub fn dir_name(key: &StorageKey, channel_id: &[u8; 16]) -> Result<DirName, StoreError> {
    let digest = crypto::keyed_hash(&key.key, &[&DIR_TAG[..], channel_id].concat())?;
    let (name, _) = digest
        .expose()
        .split_first_chunk::<16>()
        .ok_or(StoreError::Corrupt)?;
    Ok(DirName(*name))
}

/// `K_store` of the channel directory `name` (R3), derived at each seal and
/// open and dropped after it.
fn store_key(key: &StorageKey, name: &DirName) -> Result<Secret<32>, StoreError> {
    Ok(crypto::keyed_hash(
        &key.key,
        &[&STORE_TAG[..], &name.0].concat(),
    )?)
}

/// `K_settings` (R3), derived at each seal and open and dropped after it.
fn settings_key(key: &StorageKey) -> Result<Secret<32>, StoreError> {
    Ok(crypto::keyed_hash(&key.key, SETTINGS_TAG)?)
}

/// `nonce ‖ secretbox_seal(key, nonce, record)` under a fresh nonce (R4, R5).
///
/// # Errors
///
/// `Corrupt` when libsodium fails.
fn seal_box(key: &Secret<32>, record: &[u8]) -> Result<Vec<u8>, StoreError> {
    let nonce = Nonce(crypto::random_bytes()?);
    let sealed = crypto::secretbox_seal(key, &nonce, record)?;
    Ok([&nonce.0[..], &sealed].concat())
}

/// The record inside `nonce ‖ box`, checked in the order of R7: at least
/// [`MIN_SEALED`] bytes, then the box.
///
/// # Errors
///
/// `Corrupt` for fewer bytes or a box that does not open.
fn open_box(key: &Secret<32>, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    if sealed.len() < MIN_SEALED {
        return Err(StoreError::Corrupt);
    }
    let (nonce, boxed) = sealed
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(StoreError::Corrupt)?;
    Ok(crypto::secretbox_open(key, &Nonce(*nonce), boxed)?)
}
