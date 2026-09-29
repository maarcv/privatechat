//! The one error type of the core boundary (`docs/spec.md` §9, spec
//! 011-config-format R20).
//!
//! Written by hand, with no derive crate. Every variant is a unit variant, so
//! an error never carries a byte of a key or a password (spec 011 R21), and
//! there is no `Display`: the core produces no user-facing text (spec
//! 027-core-api R18). `Store` arrives with spec 020-store-files.

use crate::crypto::CryptoError;

#[cfg(test)]
mod tests;

/// Why a call of the core failed, one variant per condition of the specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A blob or field of the wrong size.
    BadLength,
    /// A version this build does not speak: the app needs an update.
    UnsupportedVersion,
    /// A message of another channel.
    WrongChannel,
    /// A message past its TTL.
    Expired,
    /// A message from a key its owner retired.
    RetiredKey,
    /// A new peer beyond the channel's limit.
    PeerLimit,
    /// A message already received.
    Replay,
    /// A signature that does not verify.
    BadSignature,
    /// A payload that does not decode or breaks its ranges.
    BadPayload,
    /// The send counter has no value left.
    CounterExhausted,
    /// A config that is malformed or out of range, in any of its forms.
    BadConfig,
    /// A config file that the password does not open: a wrong password and a
    /// corrupted file are one error on purpose (spec 011 R14).
    BadPassword,
    /// An invitation opened after its expiry.
    InviteExpired,
    /// A config for a channel already open with another server.
    ConfigMismatch,
    /// A failure the input cannot cause: libsodium failed (to initialise, to
    /// allocate the 64 MiB of Argon2id, or otherwise), an expiry overflowed,
    /// or a bug.
    Internal,
}

/// Every primitive failure is `Internal` (R20). A call site that expects
/// `Forged` or `BadPadding` matches it before this conversion.
impl From<CryptoError> for Error {
    fn from(_: CryptoError) -> Error {
        Error::Internal
    }
}
