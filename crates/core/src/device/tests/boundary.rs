//! Tests of the boundary (spec 027-core-api R16–R18, R20); the signatures
//! are checked by `tests/api_surface.rs`, the absent traits and the hidden
//! `Config` by `compile_fail` doctests on `Device` and `Error`.

use super::{Fixture, NOW};
use crate::device::{
    BrokenChannel, ChannelInfo, ConfigPreview, ConnectionPlan, Device, Route, SettingsView,
};
use crate::error::Error;
use crate::session::channel::{
    ChannelStatus, ClientRef, Message, MessageContent, Received, Sender, Stranger,
};
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

/// The bytes `start`, `start + 1`, …: each array of the test distinct from
/// the others, so that its bytes past the prefix name it.
fn bytes<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap_or_default()))
}

/// Spec 027, R20: the `Debug` of the records that carry a `channel_id`, a
/// `server_id`, a `client_ref`, a key or a name shows at most the 4-byte
/// prefix, in hex or in decimal, and no name, URL, proxy, SOCKS username,
/// signature, nonce, blob or free text.
#[test]
fn s027_t20_r20_debug_redacted() {
    let channel: [u8; 16] = bytes(0x10);
    let server_id: [u8; 16] = bytes(0x30);
    let client_ref: [u8; 16] = bytes(0x50);
    let pk: [u8; 32] = bytes(0x70);
    let sig: [u8; 64] = bytes(0x90);
    let nonce: [u8; 32] = bytes(0xd0);
    let claimed: [u8; 32] = bytes(0xf0);
    let status = ChannelStatus {
        own_key_used_elsewhere: false,
        read_only: false,
        retirement_pending: false,
        storage_full: false,
        ignored_keys: 0,
        unknown_limit_reached: false,
        labelled_limit_reached: false,
        clock_off: false,
        truncated_before: None,
    };
    let info = ChannelInfo {
        id: channel,
        server_url: "wss://server.example".to_owned(),
        suggested_name: "suggested room".to_owned(),
        local_name: Some("local room".to_owned()),
        own_display_name: Some("own name".to_owned()),
        ttl_seconds: 3_600,
        status,
        write_failed: false,
        needs_proxy: true,
    };
    let route = Route {
        host: "host.example".to_owned(),
        port: 443,
        tls: true,
        socks5_proxy: Some("proxy.example:9050".to_owned()),
        socks_username: Some("abcdef12".to_owned()),
    };
    let plan = ConnectionPlan {
        id: 1,
        route: route.clone(),
        channels: vec![channel],
    };
    let broken = BrokenChannel {
        name: "directory".to_owned(),
        reason: StoreError::Io,
        channel_id: Some(channel),
        channel_name: Some("broken room".to_owned()),
    };
    let previewed = ConfigPreview {
        suggested_name: "previewed room".to_owned(),
        server_url: "wss://previewed.example".to_owned(),
        ttl_seconds: 3_600,
        is_open: false,
        server_known: false,
        name_collides: false,
        needs_proxy: false,
        broken_reason: None,
    };
    let settings = SettingsView {
        default_server_url: "wss://default.example".to_owned(),
        lock_timeout_seconds: 60,
        socks5_proxy: Some("proxy.example:9050".to_owned()),
    };
    let content = || MessageContent::Text {
        body: "message body".to_owned(),
        display_name: Some("sender name".to_owned()),
    };
    let message = Message {
        server_id: Some(server_id),
        client_ref: Some(ClientRef { bytes: client_ref }),
        sender: Sender::Peer { pk },
        received_at: NOW,
        sent_at: Some(NOW),
        expires_at: NOW,
        content: content(),
        delivery: None,
        stranger: Some(Stranger {
            short: vec!["stranger word".to_owned()],
            claims_name_of: Some(claimed),
            claims_own_name: false,
        }),
    };
    let received = Received {
        server_id,
        sender: Sender::Peer { pk },
        received_at: NOW,
        sent_at: Some(NOW),
        expires_at: NOW,
        content: content(),
    };
    let blob = b"sealed blob".to_vec();
    let frames = [
        Frame::Hello {
            server_nonce: nonce,
            proto_versions: vec![1],
        },
        Frame::Subscribe {
            pk_ch: pk,
            ttl_seconds: 3_600,
            sig,
            since: None,
        },
        Frame::Ok {
            channel_id: channel,
        },
        Frame::Publish {
            channel_id: channel,
            client_ref,
            blob: blob.clone(),
        },
        Frame::Ack {
            client_ref,
            server_id,
            received_at: NOW,
        },
        Frame::Push {
            channel_id: channel,
            server_id,
            received_at: NOW,
            blob: blob.clone(),
        },
        Frame::Error {
            code: "rate_limited".to_owned(),
            message: "free text".to_owned(),
            channel_id: Some(channel),
            client_ref: Some(client_ref),
        },
    ];
    let mut shown = vec![
        format!("{info:?}"),
        format!("{route:?}"),
        format!("{plan:?}"),
        format!("{broken:?}"),
        format!("{settings:?}"),
        format!("{previewed:?}"),
        format!("{message:?}"),
        format!("{received:?}"),
        format!("{:?}", ClientRef { bytes: client_ref }),
    ];
    shown.extend(frames.iter().map(|frame| format!("{frame:?}")));
    // Every 4 bytes of each id and key but its first 4, and every 4 bytes of
    // a signature, a nonce or a blob, which show no prefix, as hex and as a
    // derived `Debug` prints them.
    let arrays: [(&[u8], usize); 8] = [
        (&channel, 1),
        (&server_id, 1),
        (&client_ref, 1),
        (&pk, 1),
        (&claimed, 1),
        (&sig, 0),
        (&nonce, 0),
        (&blob, 0),
    ];
    let tails: Vec<(String, String)> = arrays
        .iter()
        .flat_map(|(array, shown_prefix)| array.windows(4).skip(*shown_prefix))
        .map(|tail| {
            let hex = tail.iter().map(|byte| format!("{byte:02x}")).collect();
            let decimal = tail
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            (hex, decimal)
        })
        .collect();
    let words = [
        "server.example",
        "suggested room",
        "local room",
        "own name",
        "host.example",
        "proxy.example",
        "abcdef12",
        "broken room",
        "default.example",
        "previewed room",
        "previewed.example",
        "message body",
        "sender name",
        "sealed blob",
        "free text",
        "stranger word",
    ];
    for text in &shown {
        for (hex, decimal) in &tails {
            assert!(!text.contains(hex.as_str()), "{hex} in {text}");
            assert!(!text.contains(decimal.as_str()), "{decimal} in {text}");
        }
        for word in words {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }
    let prefix: String = channel[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // The records that name a channel show its prefix.
    for text in [
        format!("{info:?}"),
        format!("{plan:?}"),
        format!("{broken:?}"),
    ] {
        assert!(text.contains(&prefix), "no prefix in {text}");
    }
    // The records that hide the proxy say whether one is set.
    for text in [format!("{route:?}"), format!("{settings:?}")] {
        assert!(text.contains("proxied: true"), "no proxy flag in {text}");
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
