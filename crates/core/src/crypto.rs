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

/// Bytes the authenticated primitives add to a message: the Poly1305 tag of
/// the AEAD and the mac of the secret box (`docs/spec.md` §4).
pub(crate) const TAG_LEN: usize = 16;

/// Length of every hash and every derived key of the protocol
/// (`docs/spec.md` §4).
pub(crate) const HASH_LEN: usize = 32;

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

/// `len + extra`, or `TooLong` when the sum would not fit (spec 010, R14).
///
/// This is the whole of the wrapper's size policy: it holds no protocol
/// number, and libsodium aborts rather than returns when a length exceeds
/// what it can express, so the check happens here, before the call.
///
/// # Errors
///
/// `CryptoError::TooLong` when `len + extra` overflows `usize`.
pub(crate) fn checked_output_len(len: usize, extra: usize) -> Result<usize, CryptoError> {
    len.checked_add(extra).ok_or(CryptoError::TooLong)
}

/// Seals `plaintext` with XChaCha20-Poly1305 IETF: ciphertext followed by its
/// 16-byte tag, with `aad` authenticated but not encrypted (spec 010, R6).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the sealed length cannot be expressed.
pub(crate) fn aead_encrypt(
    key: &Secret<32>,
    nonce: &Nonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    init()?;
    let mut sealed = vec![0u8; checked_output_len(plaintext.len(), TAG_LEN)?];
    if ffi::aead_encrypt(key.expose(), &nonce.0, aad, plaintext, &mut sealed) {
        Ok(sealed)
    } else {
        Err(CryptoError::TooLong)
    }
}

/// Opens what `aead_encrypt` sealed, under the same key, nonce and `aad`
/// (spec 010, R6).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::Forged` when the tag does not verify, which includes a
/// ciphertext too short to hold one.
pub(crate) fn aead_decrypt(
    key: &Secret<32>,
    nonce: &Nonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    init()?;
    let len = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(CryptoError::Forged)?;
    let mut plaintext = vec![0u8; len];
    if ffi::aead_decrypt(key.expose(), &nonce.0, aad, ciphertext, &mut plaintext) {
        Ok(plaintext)
    } else {
        Err(CryptoError::Forged)
    }
}

/// Applies the XChaCha20 keystream to `buf` in place; applying it twice with
/// the same key and nonce restores the buffer (spec 010, R7).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the length cannot be expressed.
pub(crate) fn stream_xor(
    key: &Secret<32>,
    nonce: &Nonce,
    buf: &mut [u8],
) -> Result<(), CryptoError> {
    init()?;
    if ffi::stream_xor(key.expose(), &nonce.0, buf) {
        Ok(())
    } else {
        Err(CryptoError::TooLong)
    }
}

/// Seals `plaintext` with `crypto_secretbox_easy`: the 16-byte mac followed
/// by the ciphertext (spec 010, R12).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the sealed length cannot be expressed.
pub(crate) fn secretbox_seal(
    key: &Secret<32>,
    nonce: &Nonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    init()?;
    let mut sealed = vec![0u8; checked_output_len(plaintext.len(), TAG_LEN)?];
    if ffi::secretbox_seal(key.expose(), &nonce.0, plaintext, &mut sealed) {
        Ok(sealed)
    } else {
        Err(CryptoError::TooLong)
    }
}

/// Opens what `secretbox_seal` sealed (spec 010, R12).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::Forged` when the mac does not verify, which includes a
/// ciphertext too short to hold one.
pub(crate) fn secretbox_open(
    key: &Secret<32>,
    nonce: &Nonce,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    init()?;
    let len = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(CryptoError::Forged)?;
    let mut plaintext = vec![0u8; len];
    if ffi::secretbox_open(key.expose(), &nonce.0, sealed, &mut plaintext) {
        Ok(plaintext)
    } else {
        Err(CryptoError::Forged)
    }
}

/// Derives a 32-byte subkey from `key` and an 8-byte context, with
/// `subkey_id = 0` (spec 010, R8).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::BadLength` if libsodium refuses the fixed lengths this
/// wrapper passes, which its own constants make unreachable.
pub(crate) fn kdf_derive(
    key: &Secret<32>,
    context: &KdfContext,
) -> Result<Secret<32>, CryptoError> {
    init()?;
    let mut subkey = [0u8; HASH_LEN];
    if !ffi::kdf_derive(key.expose(), &context.0, &mut subkey) {
        return Err(CryptoError::BadLength);
    }
    let derived = Secret::from_bytes(subkey);
    // The array is `Copy`, so wrapping it left this copy behind (R18).
    ffi::memzero(&mut subkey);
    Ok(derived)
}

/// BLAKE2b of `input` at 32 bytes, unkeyed (spec 010, R9).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the input length cannot be expressed.
pub(crate) fn hash(input: &[u8]) -> Result<[u8; HASH_LEN], CryptoError> {
    init()?;
    let mut digest = [0u8; HASH_LEN];
    if ffi::generichash(None, input, &mut digest) {
        Ok(digest)
    } else {
        Err(CryptoError::TooLong)
    }
}

/// BLAKE2b of `input` at 32 bytes under a 32-byte key. The result is key
/// material, so it comes back as a secret (spec 010, R9).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the input length cannot be expressed.
pub(crate) fn keyed_hash(key: &Secret<32>, input: &[u8]) -> Result<Secret<32>, CryptoError> {
    init()?;
    let mut digest = [0u8; HASH_LEN];
    if !ffi::generichash(Some(key.expose()), input, &mut digest) {
        return Err(CryptoError::TooLong);
    }
    let hashed = Secret::from_bytes(digest);
    // The array is `Copy`, so wrapping it left this copy behind (R18).
    ffi::memzero(&mut digest);
    Ok(hashed)
}

/// The Ed25519 key pair of `seed`, which is what makes an identity
/// reproducible from stored key material (spec 010, R10).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::BadLength` if libsodium refuses the fixed lengths this
/// wrapper passes, which its own constants make unreachable.
pub(crate) fn sign_keypair_from_seed(
    seed: &Secret<32>,
) -> Result<(PublicKey, Secret<64>), CryptoError> {
    init()?;
    let mut public_key = [0u8; 32];
    let mut secret_key = [0u8; 64];
    if !ffi::sign_keypair_from_seed(seed.expose(), &mut public_key, &mut secret_key) {
        return Err(CryptoError::BadLength);
    }
    let pair = (PublicKey(public_key), Secret::from_bytes(secret_key));
    // The array is `Copy`, so wrapping it left this copy behind (R18).
    ffi::memzero(&mut secret_key);
    Ok(pair)
}

/// A fresh Ed25519 key pair from libsodium's random source (spec 010, R10).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::BadLength` if libsodium refuses the fixed lengths this
/// wrapper passes, which its own constants make unreachable.
pub(crate) fn sign_keypair() -> Result<(PublicKey, Secret<64>), CryptoError> {
    init()?;
    let mut public_key = [0u8; 32];
    let mut secret_key = [0u8; 64];
    if !ffi::sign_keypair(&mut public_key, &mut secret_key) {
        return Err(CryptoError::BadLength);
    }
    let pair = (PublicKey(public_key), Secret::from_bytes(secret_key));
    // The array is `Copy`, so wrapping it left this copy behind (R18).
    ffi::memzero(&mut secret_key);
    Ok(pair)
}

/// Signs `message` detached with an Ed25519 secret key (spec 010, R10).
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise, and
/// `CryptoError::TooLong` when the message length cannot be expressed.
pub(crate) fn sign_detached(
    secret_key: &Secret<64>,
    message: &[u8],
) -> Result<Signature, CryptoError> {
    init()?;
    let mut signature = [0u8; 64];
    if ffi::sign_detached(secret_key.expose(), message, &mut signature) {
        Ok(Signature(signature))
    } else {
        Err(CryptoError::TooLong)
    }
}

/// Verifies a detached signature (spec 010, R10).
///
/// Strictness is libsodium's: a non-canonical `S`, an identity or small-order
/// public key, a small-order `R` and a non-canonical public key are all
/// refused, and the negative vectors of the spec prove it at test time.
///
/// # Errors
///
/// `CryptoError::InitFailed` when libsodium cannot initialise;
/// `CryptoError::Forged` when the signature does not verify.
pub(crate) fn verify_detached(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    init()?;
    if ffi::sign_verify_detached(&public_key.0, message, &signature.0) {
        Ok(())
    } else {
        Err(CryptoError::Forged)
    }
}
