//! The only home of key material in the workspace (AGENTS 5, spec 010 R3).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CryptoError, ct_eq, random_bytes};

/// Fixed-size secret: root, master, header and message keys, seeds, keys
/// derived from a password (`Secret<32>`) and Ed25519 secret keys
/// (`Secret<64>`).
///
/// It deliberately implements nothing that could copy it, order it, hash it,
/// print it or hand out its bytes: the whole list is in spec 010, R3, and the
/// test `s010_t04_r03_secret_has_no_forbidden_traits` reads this file to check
/// it. The bytes are reachable only through `expose`, inside this crate.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Takes ownership of key material the caller already holds.
    pub(crate) fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// A fresh secret from libsodium's random source (spec 010, R5).
    ///
    /// # Errors
    ///
    /// `CryptoError::InitFailed` when libsodium cannot initialise.
    pub(crate) fn random() -> Result<Self, CryptoError> {
        Ok(Self(random_bytes::<N>()?))
    }

    /// The bytes, for the wrappers of this module and nothing else.
    pub(crate) fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}
