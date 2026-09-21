//! Typed wrappers over the libsodium primitives of `docs/spec.md` §4.
//!
//! This module is the only place in the workspace that calls libsodium, holds
//! key material or compares fixed-size bytes (AGENTS 2, 5, 12, 22). It knows
//! nothing about the protocol: domain tags, the key hierarchy and the envelope
//! arrive with specs 011-014 and are built from what is defined here. It
//! imposes no size limit of its own: it rejects what libsodium would abort on
//! or reject, and every protocol or storage bound lives in the spec of the
//! caller (spec 010, R14).

use core::fmt;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

mod ffi;
mod secret;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vectors;

pub(crate) use secret::Secret;

/// The types that hold key material, as the PR checklist of AGENTS 5 names
/// them. A new secret type is added here and to the redacted-`Debug` test.
pub(crate) const SECRET_TYPES: [&str; 2] = ["Secret<32>", "Secret<64>"];

/// Result of the one initialisation this process performs (spec 010, R2).
static SODIUM: OnceLock<Result<(), CryptoError>> = OnceLock::new();

/// How many times the initialisation body actually ran. Test hook of R2: the
/// `OnceLock` alone cannot show that it ran once rather than twice.
#[cfg(test)]
static INIT_CALLS: AtomicUsize = AtomicUsize::new(0);

/// One variant per failing condition, in the order of spec 010, R15. No
/// variant carries data: an error never becomes a channel for key material
/// (AGENTS 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoError {
    InitFailed,
    TooLong,
    BadLength,
    Forged,
    BadPadding,
    OutOfMemory,
}

/// The 24-byte nonce of the XChaCha20 primitives. Public data.
#[derive(Clone, Copy)]
pub(crate) struct Nonce(pub(crate) [u8; 24]);

/// The 16-byte salt of the password hash. Public data.
#[derive(Clone, Copy)]
pub(crate) struct Salt(pub(crate) [u8; 16]);

/// The 8-byte context of a key derivation: a protocol literal, never a
/// secret, fixed by the specs that derive keys.
#[derive(Clone, Copy)]
pub(crate) struct KdfContext([u8; 8]);

/// An Ed25519 public key. Public data, but an identifier: its `Debug` shows
/// four bytes, which is all a log may carry (AGENTS 19).
#[derive(Clone, Copy)]
pub(crate) struct PublicKey(pub(crate) [u8; 32]);

/// An Ed25519 detached signature. Public data.
#[derive(Clone, Copy)]
pub(crate) struct Signature(pub(crate) [u8; 64]);

impl KdfContext {
    /// A context is exactly eight bytes, so a caller cannot shorten one.
    pub(crate) const fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for KdfContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for PublicKey {
    /// Four bytes and an ellipsis: enough to tell two keys apart in a bug
    /// report, not enough to identify a member (`docs/spec.md` §8).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.0.get(..4).unwrap_or_default())?;
        f.write_str("…")
    }
}

impl PartialEq for Nonce {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl PartialEq for Salt {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

/// Initialises libsodium once per process (spec 010, R2).
///
/// Every wrapper calls it first, because any of them may be the first call of
/// the process.
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium reports that it cannot
/// initialise. It is returned, never panicked.
pub(crate) fn init() -> Result<(), CryptoError> {
    *SODIUM.get_or_init(|| {
        #[cfg(test)]
        INIT_CALLS.fetch_add(1, Ordering::Relaxed);
        if ffi::sodium_init() < 0 {
            Err(CryptoError::InitFailed)
        } else {
            Ok(())
        }
    })
}

/// The version of the libsodium linked into this binary (spec 010, R16).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise or reports a
/// version string that is not text.
pub(crate) fn version() -> Result<&'static str, CryptoError> {
    init()?;
    ffi::version_string().ok_or(CryptoError::InitFailed)
}

/// Constant-time equality, the only comparison of fixed-size bytes in `core`
/// (AGENTS 22, spec 010 R4).
///
/// Needs no initialisation: `sodium_memcmp` reads no library state, which is
/// why this is the one wrapper that does not return a `Result`.
pub(crate) fn ct_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    ffi::memcmp(a, b)
}

/// `N` bytes from libsodium's random source, the only one in `core`
/// (spec 010, R5).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    init()?;
    let mut bytes = [0u8; N];
    ffi::random_bytes(&mut bytes);
    Ok(bytes)
}

/// How many times the initialisation body ran (test hook of R2).
#[cfg(test)]
pub(crate) fn init_calls() -> usize {
    INIT_CALLS.load(Ordering::Relaxed)
}

/// Lowercase hexadecimal, the encoding every vector and every identifier in
/// the specification uses.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
