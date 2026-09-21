//! The single point of contact with `libsodium-sys-stable` (AGENTS 12).
//!
//! Every function here wraps one libsodium call with typed arguments, so the
//! rest of `core` never sees a raw pointer or a length parameter. Each block
//! states, in its SAFETY comment, the invariant that makes it sound:
//! in every case that the pointers come from Rust references or arrays whose
//! length is the one passed alongside them.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{CStr, c_void};
use core::ptr;

/// Initialises the library. Negative on failure, `0` on the first call and
/// `1` when it had already been initialised (spec 010, R2).
pub(super) fn sodium_init() -> i32 {
    // SAFETY: takes no argument and touches only libsodium's own global
    // state. It is the documented entry point and is safe to call twice.
    unsafe { libsodium_sys::sodium_init() }
}

/// The version of the libsodium actually linked into this binary.
pub(super) fn version_string() -> Option<&'static str> {
    // SAFETY: libsodium returns a pointer to a static, NUL-terminated string
    // that lives for the whole process, so the borrow is `'static`.
    let raw = unsafe { CStr::from_ptr(libsodium_sys::sodium_version_string()) };
    raw.to_str().ok()
}

/// Fills `buf` with cryptographically secure random bytes (spec 010, R5).
pub(super) fn random_bytes(buf: &mut [u8]) {
    // SAFETY: the pointer comes from a mutable borrow of `buf` and the length
    // passed is that same slice's length, so libsodium writes inside it.
    unsafe { libsodium_sys::randombytes_buf(buf.as_mut_ptr().cast::<c_void>(), buf.len()) }
}

/// Constant-time equality of two slices of the same length (spec 010, R4).
///
/// The caller passes arrays of one fixed size `N`, so the lengths are equal
/// by construction.
pub(super) fn memcmp(a: &[u8], b: &[u8]) -> bool {
    // SAFETY: both pointers come from borrows of slices of length `a.len()`,
    // which the caller guarantees equals `b.len()`; libsodium reads that many
    // bytes from each.
    let equal =
        unsafe { libsodium_sys::sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) };
    equal == 0
}

/// Seals `plaintext` with XChaCha20-Poly1305 IETF into `out`, which the
/// caller sized as `plaintext.len() + 16` (spec 010, R6).
///
/// `false` means libsodium refused the call, which after the caller's checks
/// can only be a length the C interface cannot express.
pub(super) fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> bool {
    let (Ok(plaintext_len), Ok(aad_len)) =
        (u64::try_from(plaintext.len()), u64::try_from(aad.len()))
    else {
        return false;
    };
    // SAFETY: `out` holds `plaintext.len() + 16` bytes, which is what this
    // primitive writes; the other pointers come from borrows whose length is
    // passed beside them; the secret nonce is unused and must be null; the
    // written length is not needed, so no pointer is given for it.
    let written = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.as_mut_ptr(),
            ptr::null_mut(),
            plaintext.as_ptr(),
            plaintext_len,
            aad.as_ptr(),
            aad_len,
            ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    written == 0
}

/// Opens a sealed message into `out`, which the caller sized as
/// `ciphertext.len() - 16`. `false` is a failed tag (spec 010, R6).
pub(super) fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    out: &mut [u8],
) -> bool {
    let (Ok(ciphertext_len), Ok(aad_len)) =
        (u64::try_from(ciphertext.len()), u64::try_from(aad.len()))
    else {
        return false;
    };
    // SAFETY: `out` holds `ciphertext.len() - 16` bytes, the plaintext length
    // this primitive writes; the other pointers come from borrows whose length
    // is passed beside them; the secret nonce is unused and must be null.
    let opened = unsafe {
        libsodium_sys::crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext_len,
            aad.as_ptr(),
            aad_len,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    opened == 0
}

/// Applies the XChaCha20 keystream to `buf` in place (spec 010, R7).
pub(super) fn stream_xor(key: &[u8; 32], nonce: &[u8; 24], buf: &mut [u8]) -> bool {
    let Ok(len) = u64::try_from(buf.len()) else {
        return false;
    };
    // SAFETY: libsodium supports the output and the input being the same
    // buffer, and both pointers here come from the same mutable borrow, whose
    // length is the one passed.
    let applied = unsafe {
        libsodium_sys::crypto_stream_xchacha20_xor(
            buf.as_mut_ptr(),
            buf.as_ptr(),
            len,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    applied == 0
}

/// Seals `plaintext` with `crypto_secretbox_easy` into `out`, which the
/// caller sized as `plaintext.len() + 16` (spec 010, R12).
pub(super) fn secretbox_seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    out: &mut [u8],
) -> bool {
    let Ok(len) = u64::try_from(plaintext.len()) else {
        return false;
    };
    // SAFETY: `out` holds `plaintext.len() + 16` bytes, the mac and the
    // ciphertext this primitive writes; the other pointers come from borrows
    // whose length is passed beside them.
    let sealed = unsafe {
        libsodium_sys::crypto_secretbox_easy(
            out.as_mut_ptr(),
            plaintext.as_ptr(),
            len,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    sealed == 0
}

/// Opens a secret box into `out`, which the caller sized as
/// `sealed.len() - 16`. `false` is a failed mac (spec 010, R12).
pub(super) fn secretbox_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    sealed: &[u8],
    out: &mut [u8],
) -> bool {
    let Ok(len) = u64::try_from(sealed.len()) else {
        return false;
    };
    // SAFETY: `out` holds `sealed.len() - 16` bytes, the plaintext length this
    // primitive writes; the other pointers come from borrows whose length is
    // passed beside them.
    let opened = unsafe {
        libsodium_sys::crypto_secretbox_open_easy(
            out.as_mut_ptr(),
            sealed.as_ptr(),
            len,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    opened == 0
}
