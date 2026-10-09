//! Tests of spec 011 R20: the variants of `core::Error` and the mapping
//! from `CryptoError`.

use super::Error;
use crate::crypto::CryptoError;
use crate::storage::StoreError;

/// Spec 011, R20: every `CryptoError` becomes `Internal`, and the enum has
/// exactly the variants of `docs/spec.md` §9, `Store` since spec 020 and
/// `UnknownPeer`, `LabelInUse` and `OwnKey` since spec 022 and
/// `RetirementPending` since spec 025. Both
/// lists are checked by an exhaustive match, which fails to compile when a
/// variant is added or removed.
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
        Error::UnknownPeer,
        Error::LabelInUse,
        Error::OwnKey,
        Error::RetirementPending,
        Error::Internal,
        Error::Store(StoreError::Corrupt),
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
            Error::UnknownPeer => "UnknownPeer",
            Error::LabelInUse => "LabelInUse",
            Error::OwnKey => "OwnKey",
            Error::RetirementPending => "RetirementPending",
            Error::Internal => "Internal",
            Error::Store(_) => "Store(Corrupt)",
        };
        assert_eq!(format!("{error:?}"), name);
    }
}
