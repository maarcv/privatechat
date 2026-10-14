//! Tests of the boundary (spec 027-core-api R16–R18, R20); the signatures
//! are checked by `tests/api_surface.rs`, the absent traits and the hidden
//! `Config` by `compile_fail` doctests on `Device` and `Error`.

use super::{Fixture, NOW};
use crate::device::Device;
use crate::error::Error;
use crate::storage::StoreError;
use crate::testing::settings;
use crate::tests::section;

/// Spec 027, R16: `unreachable_pub` is denied in the workspace.
#[test]
fn s027_t16_r16_public_items() {
    let manifest = include_str!("../../../../../Cargo.toml");
    assert!(section(manifest, "[workspace.lints.rust]").contains(&"unreachable_pub = \"deny\""));
}

/// Spec 027, R17: no `dead_code` allow is left on the crate's modules, and
/// the decoders reached only through another are excluded with the target
/// that reaches them.
#[test]
fn s027_t17_r17_amendments() {
    // On the module's declaration or as an inner attribute of its file.
    for source in [
        include_str!("../../lib.rs"),
        include_str!("../../crypto.rs"),
        include_str!("../../proto.rs"),
        include_str!("../../session.rs"),
        include_str!("../../storage.rs"),
    ] {
        assert!(!source.contains("dead_code"));
    }
    let exclusions = include_str!("../../../../../scripts/fuzz_exclusions.txt");
    for decoder in [
        "PeerRecord::decode",
        "OutboxEntry::decode",
        "OldKey::decode",
        "TestRecord::decode",
    ] {
        assert!(
            exclusions
                .lines()
                .any(|line| line.starts_with(&format!("{decoder} # "))),
            "{decoder}"
        );
    }
}

/// Spec 027, R18: the variants of `Error`, in order, unit variants but
/// `Store`.
#[test]
fn s027_t18_r18_error_variants() {
    let order = [
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
        Error::UnknownChannel,
        Error::LabelInUse,
        Error::OwnKey,
        Error::RetirementPending,
        Error::Internal,
        Error::Store(StoreError::Io),
    ];
    // An exhaustive match ranks each variant: a new or moved variant fails.
    let rank = |error: &Error| match error {
        Error::BadLength => 0,
        Error::UnsupportedVersion => 1,
        Error::WrongChannel => 2,
        Error::Expired => 3,
        Error::RetiredKey => 4,
        Error::PeerLimit => 5,
        Error::Replay => 6,
        Error::BadSignature => 7,
        Error::BadPayload => 8,
        Error::CounterExhausted => 9,
        Error::BadConfig => 10,
        Error::BadPassword => 11,
        Error::InviteExpired => 12,
        Error::ConfigMismatch => 13,
        Error::UnknownPeer => 14,
        Error::UnknownChannel => 15,
        Error::LabelInUse => 16,
        Error::OwnKey => 17,
        Error::RetirementPending => 18,
        Error::Internal => 19,
        Error::Store(_) => 20,
    };
    for (expected, error) in order.iter().enumerate() {
        assert_eq!(rank(error), expected, "{error:?}");
    }
    let source = include_str!("../../error.rs");
    let declared: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.chars().next().is_some_and(char::is_uppercase)
                && (line.ends_with(',') || line.ends_with("),"))
        })
        .collect();
    let names: Vec<String> = order
        .iter()
        .map(|error| format!("{error:?}").replace("(Io)", "(StoreError)") + ",")
        .collect();
    assert_eq!(declared, names);
}

/// Spec 027, R20: `Device` is `Send`, and `create_channel` works whether
/// `init` was called or not.
#[test]
fn s027_t20_r20_device_traits() {
    fn is_send<T: Send>() {}
    is_send::<Device>();
    for with_init in [false, true] {
        if with_init {
            crate::device::init().unwrap();
        }
        let fixture = Fixture::new();
        fixture.save_settings(&settings("wss://example.org", 30, None));
        let mut device = fixture.open().unwrap();
        device
            .create_channel("wss://example.org", 3_600, "room", NOW)
            .unwrap();
    }
}

/// Spec 040-uniffi, R8: `generate_storage_key` fills the caller's 32 bytes
/// from libsodium's random source.
#[test]
fn s040_t08_r08_generate_storage_key_core() {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    crate::device::generate_storage_key(&mut first).unwrap();
    crate::device::generate_storage_key(&mut second).unwrap();
    // Every 8 bytes are drawn: two draws agree on a quarter with
    // probability 2^-64, and a quarter left as it was agrees always.
    for (first, second) in first.chunks(8).zip(second.chunks(8)) {
        assert_ne!(first, second);
    }
}
