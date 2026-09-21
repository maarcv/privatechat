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
