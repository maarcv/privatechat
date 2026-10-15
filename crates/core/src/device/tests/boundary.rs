//! Tests of the boundary (spec 027-core-api R16–R18, R20); the signatures
//! are checked by `tests/api_surface.rs`, the absent traits and the hidden
//! `Config` by `compile_fail` doctests on `Device` and `Error`.

use super::{Fixture, NOW};
use crate::device::{BrokenChannel, Device};
use crate::error::Error;
use crate::session::frames::Frame;
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
    // `forbid` at the crate root makes an `allow` in any module a compile
    // error, inner attributes of a module file included.
    let lib = include_str!("../../lib.rs");
    assert!(lib.lines().any(|line| line == "#![forbid(dead_code)]"));
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

/// Spec 027, R20: `Device` is `Send`, and `create_channel` works after
/// `init`; without it, `crates/store/tests/without_init.rs` shows, in a
/// process where nothing initialised libsodium before.
#[test]
fn s027_t20_r20_device_traits() {
    fn is_send<T: Send>() {}
    is_send::<Device>();
    crate::device::init().unwrap();
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, None));
    let mut device = fixture.open().unwrap();
    device
        .create_channel("wss://example.org", 3_600, "room", NOW)
        .unwrap();
}

/// Spec 027, R20: the `Debug` of the records that carry a `channel_id`, a
/// key or a name shows at most the 4-byte prefix and no name, URL, SOCKS
/// username, signature, blob or free text.
#[test]
fn s027_t20_r20_debug_redacted() {
    let fixture = Fixture::new();
    fixture.save_settings(&settings("wss://example.org", 30, Some("127.0.0.1:9050")));
    let mut device = fixture.open().unwrap();
    let info = device
        .create_channel("wss://example.org", 3_600, "secret room", NOW)
        .unwrap();
    device.rename_channel(info.id, "my local name").unwrap();
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let id = hex(&info.id);
    let info = device.channels().remove(0);
    let plan = device.connections().remove(0);
    let username = plan.route.socks_username.clone().unwrap();
    let broken = BrokenChannel {
        name: "00".repeat(16),
        reason: StoreError::Io,
        channel_id: Some(info.id),
        channel_name: Some("broken name".to_owned()),
    };
    let frames = [
        Frame::Publish {
            channel_id: info.id,
            client_ref: [7; 16],
            blob: b"sealed blob".to_vec(),
        },
        Frame::Subscribe {
            pk_ch: [9; 32],
            ttl_seconds: 3_600,
            sig: [5; 64],
            since: None,
        },
        Frame::Error {
            code: "rate_limited".to_owned(),
            message: "free text".to_owned(),
            channel_id: Some(info.id),
            client_ref: None,
        },
    ];
    let mut shown = vec![
        format!("{info:?}"),
        format!("{plan:?}"),
        format!("{broken:?}"),
    ];
    shown.extend(frames.iter().map(|frame| format!("{frame:?}")));
    for text in &shown {
        for hidden in [
            id.as_str(),
            &id[8..],
            "secret room",
            "my local name",
            "example.org",
            "broken name",
            username.as_str(),
            &hex(&[9; 32])[8..],
            &hex(&[5; 64])[..16],
            "sealed blob",
            "free text",
        ] {
            assert!(!text.contains(hidden), "{hidden} in {text}");
        }
    }
    assert!(shown[0].contains(&id[..8]));
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
    // A byte left as the caller passed it stays zero in every draw; a drawn
    // byte is zero in eight draws with probability 2^-64.
    let mut drawn = [0u8; 32];
    for _ in 0..8 {
        let mut key = [0u8; 32];
        crate::device::generate_storage_key(&mut key).unwrap();
        for (index, byte) in key.iter().enumerate() {
            drawn[index] |= byte;
        }
    }
    assert!(!drawn.contains(&0), "{drawn:?}");
}
