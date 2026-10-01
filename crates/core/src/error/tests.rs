//! Tests of spec 011 R20: the variants of `core::Error` and the mapping
//! from `CryptoError`.

use super::Error;
use crate::crypto::CryptoError;

/// Spec 011, R20: every `CryptoError` becomes `Internal`, and the enum has
/// exactly the variants of `docs/spec.md` §9 but `Store`. Both lists are
/// checked by an exhaustive match, which fails to compile when a variant is
/// added or removed.
#[test]
fn s011_t20_r20_error_mapping() {
    for error in [
        CryptoError::InitFailed,
        CryptoError::TooLong,
        CryptoError::BadLength,
        CryptoError::Forged,
        CryptoError::BadPadding,
        CryptoError::OutOfMemory,
        CryptoError::BadEncoding,
    ] {
        let listed = match error {
            CryptoError::InitFailed
            | CryptoError::TooLong
            | CryptoError::BadLength
            | CryptoError::Forged
            | CryptoError::BadPadding
            | CryptoError::OutOfMemory
            | CryptoError::BadEncoding => true,
        };
        assert!(listed);
        assert_eq!(Error::from(error), Error::Internal, "{error:?}");
    }
    for error in [
        Error::BadLength,
        Error::UnsupportedVersion,
        Error::WrongChannel,
        Error::Expired,
        Error::RetiredKey,
        Error::PeerLimit,
        Error::Replay,
        Error::BadSignature,
        Error::BadPayload,
        Error::CounterExhausted,
        Error::BadConfig,
        Error::BadPassword,
        Error::InviteExpired,
        Error::ConfigMismatch,
        Error::Internal,
    ] {
        let name = match error {
            Error::BadLength => "BadLength",
            Error::UnsupportedVersion => "UnsupportedVersion",
            Error::WrongChannel => "WrongChannel",
            Error::Expired => "Expired",
            Error::RetiredKey => "RetiredKey",
            Error::PeerLimit => "PeerLimit",
            Error::Replay => "Replay",
            Error::BadSignature => "BadSignature",
            Error::BadPayload => "BadPayload",
            Error::CounterExhausted => "CounterExhausted",
            Error::BadConfig => "BadConfig",
            Error::BadPassword => "BadPassword",
            Error::InviteExpired => "InviteExpired",
            Error::ConfigMismatch => "ConfigMismatch",
            Error::Internal => "Internal",
        };
        assert_eq!(format!("{error:?}"), name);
    }
}
