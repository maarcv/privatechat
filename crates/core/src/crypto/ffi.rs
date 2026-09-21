//! The single point of contact with `libsodium-sys-stable` (AGENTS 12).
//!
//! Every function here wraps one libsodium call with typed arguments, so the
//! rest of `core` never sees a raw pointer or a length parameter. Each block
//! states, in its SAFETY comment, the invariant that makes it sound:
//! in every case that the pointers come from Rust references or arrays whose
//! length is the one passed alongside them.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{CStr, c_char, c_void};
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

/// Constant-time equality of two arrays of the same size (spec 010, R4).
pub(super) fn memcmp<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    // SAFETY: both pointers come from borrows of arrays of `N` bytes, the
    // length passed beside them: the type, not the caller, makes the two
    // lengths equal.
    let equal = unsafe { libsodium_sys::sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), N) };
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
    if plaintext.len().checked_add(super::TAG_LEN) != Some(out.len()) {
        return false;
    }
    let (Ok(plaintext_len), Ok(aad_len)) =
        (u64::try_from(plaintext.len()), u64::try_from(aad.len()))
    else {
        return false;
    };
    // SAFETY: the check above makes `out` exactly the `plaintext.len() + 16`
    // bytes this primitive writes; the other pointers come from borrows whose
    // length is passed beside them; the secret nonce is unused and must be
    // null; the written length is not needed, so no pointer is given for it.
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
    if ciphertext.len().checked_sub(super::TAG_LEN) != Some(out.len()) {
        return false;
    }
    let (Ok(ciphertext_len), Ok(aad_len)) =
        (u64::try_from(ciphertext.len()), u64::try_from(aad.len()))
    else {
        return false;
    };
    // SAFETY: the check above makes `out` exactly the `ciphertext.len() - 16`
    // bytes this primitive writes; the other pointers come from borrows whose
    // length is passed beside them; the secret nonce is unused and must be
    // null.
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
    // Both arguments are the same pointer: taking a second, shared borrow of
    // `buf` for the input would invalidate the mutable one under Rust's
    // aliasing rules, and libsodium would then write through a dead pointer.
    let pointer = buf.as_mut_ptr();
    // SAFETY: libsodium supports the output and the input being the same
    // buffer; the pointer comes from a mutable borrow of `buf` and the length
    // passed is that same slice's length.
    let applied = unsafe {
        libsodium_sys::crypto_stream_xchacha20_xor(
            pointer,
            pointer.cast_const(),
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
    if plaintext.len().checked_add(super::TAG_LEN) != Some(out.len()) {
        return false;
    }
    let Ok(len) = u64::try_from(plaintext.len()) else {
        return false;
    };
    // SAFETY: the check above makes `out` exactly the `plaintext.len() + 16`
    // bytes of mac and ciphertext this primitive writes; the other pointers
    // come from borrows whose length is passed beside them.
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
    if sealed.len().checked_sub(super::TAG_LEN) != Some(out.len()) {
        return false;
    }
    let Ok(len) = u64::try_from(sealed.len()) else {
        return false;
    };
    // SAFETY: the check above makes `out` exactly the `sealed.len() - 16`
    // bytes of plaintext this primitive writes; the other pointers come from
    // borrows whose length is passed beside them.
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

/// Derives a 32-byte subkey with `subkey_id = 0` from `key` and an 8-byte
/// context (spec 010, R8).
pub(super) fn kdf_derive(key: &[u8; 32], context: &[u8; 8], out: &mut [u8; 32]) -> bool {
    // SAFETY: the three buffers are fixed-size arrays of exactly the lengths
    // this primitive reads and writes; the context is eight bytes, which is
    // `crypto_kdf_CONTEXTBYTES`, and is read as characters, not as a C string.
    let derived = unsafe {
        libsodium_sys::crypto_kdf_derive_from_key(
            out.as_mut_ptr(),
            out.len(),
            0,
            context.as_ptr().cast::<c_char>(),
            key.as_ptr(),
        )
    };
    derived == 0
}

/// BLAKE2b at 32 bytes, keyed when `key` is given (spec 010, R9).
pub(super) fn generichash(key: Option<&[u8; 32]>, input: &[u8], out: &mut [u8; 32]) -> bool {
    let Ok(input_len) = u64::try_from(input.len()) else {
        return false;
    };
    let (key_pointer, key_len) = match key {
        Some(key) => (key.as_ptr(), key.len()),
        None => (ptr::null(), 0),
    };
    // SAFETY: `out` is 32 bytes, the output length passed beside it; the input
    // pointer comes from a borrow whose length is passed too; a null key with
    // length zero is how libsodium is asked for the unkeyed hash.
    let hashed = unsafe {
        libsodium_sys::crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr(),
            input_len,
            key_pointer,
            key_len,
        )
    };
    hashed == 0
}

/// The Ed25519 key pair of a seed (spec 010, R10).
pub(super) fn sign_keypair_from_seed(
    seed: &[u8; 32],
    public_key: &mut [u8; 32],
    secret_key: &mut [u8; 64],
) -> bool {
    // SAFETY: the three buffers are fixed-size arrays of exactly the lengths
    // this primitive reads and writes.
    let generated = unsafe {
        libsodium_sys::crypto_sign_seed_keypair(
            public_key.as_mut_ptr(),
            secret_key.as_mut_ptr(),
            seed.as_ptr(),
        )
    };
    generated == 0
}

/// A fresh Ed25519 key pair (spec 010, R10).
pub(super) fn sign_keypair(public_key: &mut [u8; 32], secret_key: &mut [u8; 64]) -> bool {
    // SAFETY: both buffers are fixed-size arrays of exactly the lengths this
    // primitive writes.
    let generated = unsafe {
        libsodium_sys::crypto_sign_keypair(public_key.as_mut_ptr(), secret_key.as_mut_ptr())
    };
    generated == 0
}

/// Signs `message` detached (spec 010, R10).
pub(super) fn sign_detached(secret_key: &[u8; 64], message: &[u8], out: &mut [u8; 64]) -> bool {
    let Ok(message_len) = u64::try_from(message.len()) else {
        return false;
    };
    // SAFETY: `out` is the 64 bytes of a detached signature; the message
    // pointer comes from a borrow whose length is passed beside it; the
    // written length is always 64, so no pointer is given for it.
    let signed = unsafe {
        libsodium_sys::crypto_sign_detached(
            out.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message_len,
            secret_key.as_ptr(),
        )
    };
    signed == 0
}

/// Verifies a detached signature. `false` is a forgery, and libsodium is
/// strict about non-canonical and small-order values (spec 010, R10).
pub(super) fn sign_verify_detached(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    let Ok(message_len) = u64::try_from(message.len()) else {
        return false;
    };
    // SAFETY: the signature and the key are fixed-size arrays of the lengths
    // this primitive reads; the message pointer comes from a borrow whose
    // length is passed beside it.
    let verified = unsafe {
        libsodium_sys::crypto_sign_verify_detached(
            signature.as_ptr(),
            message.as_ptr(),
            message_len,
            public_key.as_ptr(),
        )
    };
    verified == 0
}

/// Wipes a buffer that held key material, in a way the compiler may not
/// remove (spec 010, R18).
pub(super) fn memzero(buf: &mut [u8]) {
    // SAFETY: the pointer comes from a mutable borrow of `buf` and the length
    // passed is that same slice's length, so libsodium writes inside it.
    unsafe { libsodium_sys::sodium_memzero(buf.as_mut_ptr().cast::<c_void>(), buf.len()) }
}

/// The longest password `crypto_pwhash` accepts; beyond it, it refuses the
/// call with `EFBIG` (spec 010, R14).
pub(super) fn password_max() -> u64 {
    u64::from(libsodium_sys::crypto_pwhash_PASSWD_MAX)
}

/// Argon2id13 at the interactive parameters of `docs/spec.md` §4: two
/// passes over 64 MiB (spec 010, R11).
///
/// `false` is an allocation failure: the lengths are checked before the call.
pub(super) fn password_key(password: &[u8], salt: &[u8; 16], out: &mut [u8; 32]) -> bool {
    let Ok(password_len) = u64::try_from(password.len()) else {
        return false;
    };
    let Ok(out_len) = u64::try_from(out.len()) else {
        return false;
    };
    // Neither conversion can fail at these constants, and a guessed value
    // would be a memory request or an algorithm that is not the one §4 fixes.
    let Ok(memlimit) = usize::try_from(libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE) else {
        return false;
    };
    let Ok(algorithm) = i32::try_from(libsodium_sys::crypto_pwhash_ALG_ARGON2ID13) else {
        return false;
    };
    // SAFETY: `out` is 32 bytes, the output length passed beside it; the
    // password pointer comes from a borrow whose length is passed too and is
    // read as bytes, not as a C string; the salt is the fixed 16 bytes this
    // primitive reads.
    let derived = unsafe {
        libsodium_sys::crypto_pwhash(
            out.as_mut_ptr(),
            out_len,
            password.as_ptr().cast::<c_char>(),
            password_len,
            salt.as_ptr(),
            u64::from(libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE),
            memlimit,
            algorithm,
        )
    };
    derived == 0
}

/// Pads `buf` in place to `padded_len`, which the caller sized as the next
/// multiple of `block` (spec 010, R13).
pub(super) fn pad(buf: &mut [u8], unpadded_len: usize, block: usize) -> bool {
    if unpadded_len > buf.len() {
        return false;
    }
    let mut written = 0usize;
    // SAFETY: the check above puts the unpadded content inside `buf`, and
    // libsodium refuses the call unless the padded length fits as well,
    // because the maximum it may use is the length of that same slice.
    let padded = unsafe {
        libsodium_sys::sodium_pad(
            &raw mut written,
            buf.as_mut_ptr(),
            unpadded_len,
            block,
            buf.len(),
        )
    };
    padded == 0 && written == buf.len()
}

/// The unpadded length of `buf`, or `None` when it carries no valid padding
/// (spec 010, R13).
pub(super) fn unpad(buf: &[u8], block: usize) -> Option<usize> {
    let mut unpadded = 0usize;
    // SAFETY: the pointer comes from a borrow of `buf` and the length passed
    // is that same slice's length, so this primitive reads inside it; it
    // writes only the one length, through a pointer to a local.
    let unpadded_ok =
        unsafe { libsodium_sys::sodium_unpad(&raw mut unpadded, buf.as_ptr(), buf.len(), block) };
    (unpadded_ok == 0).then_some(unpadded)
}
